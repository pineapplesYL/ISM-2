from __future__ import annotations

import re
import sys
from ast import literal_eval
from enum import IntEnum


class Instruction(IntEnum):
    NOP = 0x00
    POP = 0x01
    ADD = 0x02
    SUB = 0x03
    MUL = 0x04
    DIV = 0x05
    MOD = 0x06
    AND = 0x07
    OR = 0x08
    XOR = 0x09
    NOT = 0x0A
    CALL = 0x0B
    JMP = 0x0C
    LEA = 0x0D
    PUSH1 = 0x0E
    PUSH2 = 0x0F
    PUSH4 = 0x10
    PUSH8 = 0x11
    MODCALL = 0x12
    JZ = 0x13
    JB = 0x14
    JA = 0x15
    DUP = 0x16
    HLT = 0x17
    SWAP = 0x18 # <--- 新增的指令


_OpType = tuple[Instruction] | tuple[Instruction, int | str]

_LABEL_REGEX = re.compile(r"^\[(?P<name>.*)\]<span class="math-inline">"\)
\_TIMES\_REGEX \= re\.compile\(
r"^times\\s\+\(?P<times\>\\d\+\)\\s\+\(?P<instruction\>\.\+\)</span>", re.IGNORECASE
)
_PUSH_SIZE = {
    Instruction.PUSH1: 1,
    Instruction.PUSH2: 2,
    Instruction.PUSH4: 4,
    Instruction.PUSH8: 8,
}


def assemble(asm: str, case_sensitive: bool = False) -> bytes:
    if not case_sensitive:
        asm = asm.casefold()
    # Remove empty lines and comments
    stripped_asm = [
        line_splitted for line in asm.splitlines() if (line_splitted := line.strip())
    ]

    instructions: list[_OpType] = []
    constants: dict[str, int] = {}
    labels: dict[int, str] = {} # Stores instruction index to label name

    # First pass: Parse instructions, identify labels and constants
    # Using a list of lines to handle 'times' directive expansion easily
    current_lines = list(stripped_asm)
    line_idx = 0
    while line_idx < len(current_lines):
        line = current_lines[line_idx]
        line_idx += 1

        if not line or line.startswith(";"):
            continue

        label_match = _LABEL_REGEX.match(line)
        if label_match:
            label_name = label_match.group("name")
            # Ensure label name is unique if it were to map to instruction objects directly
            # For now, we map instruction *index* to label name
            labels[len(instructions)] = label_name
            continue

        times_match = _TIMES_REGEX.match(line)
        if times_match:
            times = int(times_match.group("times"))
            instruction_line = times_match.group("instruction").strip()
            # Insert new lines to be processed
            current_lines[line_idx:line_idx] = [instruction_line] * times
            continue

        components = [
            stripped_component
            for component in line.split()
            if (stripped_component := component.strip())
        ]

        if not components: # Should not happen if line.strip() was checked, but good for safety
            continue

        op_str = components[0].upper()
        try:
            op = Instruction[op_str]
        except KeyError:
            raise ValueError(f"Unknown instruction: {components[0]} in line: '{line}'")


        if len(components) == 1:
            instructions.append((op,))
        elif len(components) == 2:
            arg_str = components[1]
            try:
                # Attempt to evaluate as a literal number (e.g., 0xFF, 10)
                arg_val = int(literal_eval(arg_str))
            except (ValueError, SyntaxError):
                # If not a number, it could be a constant or a label placeholder
                arg_val = constants.get(arg_str, arg_str) # Resolve constant now, label later
            instructions.append((op, arg_val))
        elif len(components) == 3 and components[1].lower() == "equ":
            constant_name = components[0] # case sensitivity for constants is preserved from original code
            if not case_sensitive:
                constant_name = constant_name.casefold()
            try:
                constants[constant_name] = int(literal_eval(components[2]))
            except (ValueError, SyntaxError):
                raise ValueError(f"Invalid value for constant '{components[0]}': {components[2]} in line: '{line}'")
        else:
            raise ValueError(f"Invalid line format: {line}")

    # Second pass: Calculate label offsets
    label_offsets: dict[str, int] = {} # Maps label name to bytecode address
    address = 0
    # Create a temporary instruction list to calculate addresses,
    # as PUSH8 might be inserted for instructions with non-PUSH arguments.
    # This mimics the structure that will be written to bytecode.
    temp_instruction_layout_for_addressing: list[tuple[Instruction, ...]] = []

    # Pre-populate label_offsets based on the *instruction index* before any PUSH8 insertions
    # This ensures that labels point to the correct logical instruction.
    # The actual address calculation will then account for any PUSH8 insertions.
    # We first map instruction *indices* to preliminary addresses.
    instruction_addresses: list[int] = []
    temp_addr = 0
    for idx, (op, *args) in enumerate(instructions):
        if label_name := labels.get(idx): # if a label was defined for this instruction index
            label_offsets[label_name] = temp_addr # Store preliminary address

        instruction_addresses.append(temp_addr)
        temp_addr += 1 # For the opcode itself
        if size := _PUSH_SIZE.get(op):
            if not args:
                 raise ValueError(f"Instruction {op.name} expects an argument but none was provided.")
            temp_addr += size
        elif args: # Argument present, but not a PUSH1-8, means PUSH8 will be prepended
            temp_addr += 1 + 8 # PUSH8 opcode + 8 bytes for argument

    # Re-iterate to finalize label_offsets based on actual addresses considering potential PUSH8
    address = 0
    final_label_offsets: dict[str, int] = {}
    for index, (op, *args) in enumerate(instructions):
        if label_name := labels.get(index): # Check if this instruction index has a label
            final_label_offsets[label_name] = address
        
        address += 1 # Opcode
        if _PUSH_SIZE.get(op):
            address += _PUSH_SIZE[op]
        elif args: # Other instructions with args implicitly use PUSH8
            address += 1 + 8 # PUSH8 opcode + 8-byte argument

    # Third pass: Generate bytecode
    bytecode = bytearray()
    for op, *args_tuple in instructions:
        current_arg = args_tuple[0] if args_tuple else None

        # Handle instructions that take arguments but aren't PUSH1-8
        # These will have a PUSH8 prepended implicitly by the old logic,
        # let's make it explicit here for clarity.
        # The original logic for PUSH8 insertion was a bit tricky: bytecode[-1:-1] = push
        # We need to decide if the argument needs a PUSH8 or if it's for PUSH1-8.

        is_push_variant = op in _PUSH_SIZE
        has_argument = current_arg is not None

        if has_argument and not is_push_variant:
            # This instruction takes an argument that is not directly part of PUSH1-8
            # So, a PUSH8 instruction is effectively used for its argument.
            bytecode.append(Instruction.PUSH8) # Add PUSH8 opcode
            if isinstance(current_arg, str): # Label
                label_target_name = current_arg
                label_match_arg = _LABEL_REGEX.match(label_target_name)
                if label_match_arg: # if it's in [label] format
                    label_target_name = label_match_arg.group("name")

                if not case_sensitive:
                    label_target_name = label_target_name.casefold()
                
                resolved_address = final_label_offsets.get(label_target_name)
                if resolved_address is None:
                    raise ValueError(f"Undefined label: {current_arg}")
                bytecode += resolved_address.to_bytes(8, "little")
            elif isinstance(current_arg, int):
                bytecode += current_arg.to_bytes(8, "little")
            else:
                raise ValueError(f"Invalid argument type for implicit PUSH8: {current_arg}")
        
        bytecode.append(op) # Add the actual instruction's opcode

        if is_push_variant: # For PUSH1, PUSH2, PUSH4, PUSH8
            if not has_argument:
                raise ValueError(f"Instruction {op.name} expects an argument.")
            
            arg_val_for_push = current_arg
            if isinstance(arg_val_for_push, str): # Label for PUSHX
                label_target_name = arg_val_for_push
                label_match_arg = _LABEL_REGEX.match(label_target_name)
                if label_match_arg:
                    label_target_name = label_match_arg.group("name")
                
                if not case_sensitive:
                    label_target_name = label_target_name.casefold()

                resolved_address = final_label_offsets.get(label_target_name)
                if resolved_address is None:
                    raise ValueError(f"Undefined label: {arg_val_for_push} used with {op.name}")
                arg_val_for_push = resolved_address
            
            if not isinstance(arg_val_for_push, int):
                 raise ValueError(f"Argument for {op.name} must be an integer or a resolvable label, got {arg_val_for_push}")

            bytecode += arg_val_for_push.to_bytes(_PUSH_SIZE[op], "little")

    return bytes(bytecode)


if __name__ == "__main__":
    program_name, *argv = sys.argv
    if len(argv) != 2:
        print(f"Usage: {program_name} <input file> <output file>")
        sys.exit(1)
    input_file, output_file = argv

    with open(input_file, "rt", encoding="utf-8") as file:
        asm_code = file.read()
    
    print(f"--- Assembling code from {input_file} ---")
    # print(asm_code) # Optional: print the source
    print("--- End of source ---")

    try:
        ret = assemble(asm_code, case_sensitive=False) # Default to case_sensitive=False as in original
        print(f"Assembly successful. Outputting {len(ret)} bytes to {output_file}")
        print(f"Bytecode (hex): {ret.hex()}")
    except ValueError as e:
        print(f"Assembly Error: {e}")
        sys.exit(1)

    with open(output_file, "wb") as file:
        file.write(ret)
