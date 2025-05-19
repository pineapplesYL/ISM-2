from __future__ import annotations

import re
import sys
from ast import literal_eval
from enum import IntEnum
from typing import Any, Literal # Required for Literal type hint

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
    SWAP = 0x18 # Added in a previous hypothetical change, keeping it for consistency


_OpType = tuple[Instruction] | tuple[Instruction, int | str]

_LABEL_REGEX = re.compile(r"^\[(?P<name>.*)\]$")
_TIMES_REGEX = re.compile(
    r"^times\s+(?P<times>\d+)\s+(?P<instruction>.+)$", re.IGNORECASE
)
_PUSH_SIZE = {
    Instruction.PUSH1: 1,
    Instruction.PUSH2: 2,
    Instruction.PUSH4: 4,
    Instruction.PUSH8: 8,
}


class AssemblyError(ValueError):
    def __init__(self, message: str, line_num: int | None = None, line_content: str | None = None):
        full_message = message
        if line_num is not None and line_content is not None:
            full_message = f"Error on line {line_num} ('{line_content.strip()}'): {message}"
        elif line_num is not None:
            full_message = f"Error on line {line_num}: {message}"
        super().__init__(full_message)
        self.line_num = line_num
        self.line_content = line_content


def _preprocess_assembly(asm: str, case_sensitive: bool) -> list[tuple[int, str, str]]:
    """
    Preprocesses the assembly code string.
    Removes comments, empty lines, handles case sensitivity, and tracks original line numbers.
    Expands 'times' directives.
    Returns: list of (original_line_number, original_line_text, cleaned_and_case_adjusted_line_content)
    """
    processed_lines_with_meta: list[tuple[int, str, str]] = []
    raw_lines = asm.splitlines()
    
    # Temporary list to handle 'times' expansion
    # Each item: (original_line_num, original_line_text, current_processing_text)
    temp_lines_to_process: list[tuple[int, str, str]] = []
    for i, line_content in enumerate(raw_lines):
        temp_lines_to_process.append((i + 1, line_content, line_content))

    idx = 0
    while idx < len(temp_lines_to_process):
        line_num, original_line_text, current_processing_text = temp_lines_to_process[idx]
        idx += 1

        # Remove full-line comments and strip whitespace
        line_for_logic = current_processing_text.split(';', 1)[0].strip()

        if not case_sensitive:
            line_for_logic = line_for_logic.casefold()
        
        if not line_for_logic: # Skip empty lines after comment removal
            continue

        times_match = _TIMES_REGEX.match(line_for_logic)
        if times_match:
            try:
                times_count_str = times_match.group("times")
                times_count = int(times_count_str)
                instruction_to_repeat = times_match.group("instruction").strip()
                if times_count < 0:
                    raise AssemblyError(f"Negative repeat count ({times_count}) for 'times' directive.", line_num, original_line_text)
                
                # Prepare expansion: new items will use the same original_line_num and original_line_text
                # for error context, but their 'current_processing_text' is the repeated instruction.
                expansion = [(line_num, original_line_text, instruction_to_repeat)] * times_count
                temp_lines_to_process[idx:idx] = expansion # Insert into the list for processing
            except ValueError: # Handles non-integer in times_count_str
                 raise AssemblyError(f"Invalid number '{times_count_str}' for 'times' directive.", line_num, original_line_text)
            continue
        
        processed_lines_with_meta.append((line_num, original_line_text, line_for_logic))
        
    return processed_lines_with_meta


def _parse_single_line(
    line_num: int,
    line_content: str, # This is the already preprocessed line (casefolded if needed, comments stripped)
    original_line_text: str, # For error messages
    constants: dict[str, int],
    case_sensitive_constants: bool
) -> tuple[Literal["instruction", "label", "constant_def"], Any]:
    """
    Parses a single preprocessed line of assembly.
    Returns a tuple indicating type (instruction, label, constant_def) and parsed data.
    """
    label_match = _LABEL_REGEX.match(line_content)
    if label_match:
        label_name = label_match.group("name")
        # Case sensitivity of label_name itself is determined by `case_sensitive_labels` later.
        # Here, it's derived from `line_content` which might be casefolded.
        return "label", label_name

    components = [comp for comp in line_content.split() if comp.strip()]
    # This check should be redundant if line_content is guaranteed to be non-empty
    # from _preprocess_assembly, but good for safety.
    if not components:
        raise AssemblyError("Line became empty after splitting, unexpected.", line_num, original_line_text)

    op_str_raw = components[0]
    # Instruction mnemonics are typically matched case-insensitively by converting to upper case.
    op_str_upper = op_str_raw.upper()

    # Constant definition: e.g., MY_CONST EQU 10
    if len(components) == 3 and components[1].upper() == "EQU": # EQU keyword itself is case-insensitive
        const_name_from_source = components[0]
        # Determine the key for the constants dictionary based on case sensitivity
        const_name_key = const_name_from_source if case_sensitive_constants else const_name_from_source.casefold()
        try:
            const_value_str = components[2]
            const_value = int(literal_eval(const_value_str))
            return "constant_def", (const_name_key, const_value, const_name_from_source) # Store key, value, and original name for errors
        except (ValueError, SyntaxError) as e:
            raise AssemblyError(f"Invalid value '{components[2]}' for constant '{const_name_from_source}'. Details: {e}", line_num, original_line_text)

    # Instruction parsing
    try:
        op = Instruction[op_str_upper]
    except KeyError:
        raise AssemblyError(f"Unknown instruction: '{op_str_raw}'", line_num, original_line_text)

    if len(components) == 1:
        return "instruction", (op,)
    elif len(components) == 2:
        arg_str = components[1]
        try:
            # Attempt to evaluate as a literal number (e.g., 0xFF, 10)
            arg_val = int(literal_eval(arg_str))
        except (ValueError, SyntaxError): # Not a number, could be a constant or a label placeholder
            # Resolve constant now if possible. Label placeholders (strings) are resolved later.
            # The case for constant lookup depends on case_sensitive_constants.
            constant_lookup_key = arg_str if case_sensitive_constants else arg_str.casefold()
            arg_val = constants.get(constant_lookup_key, arg_str) # Use arg_str (original or casefolded) if not in constants
        return "instruction", (op, arg_val)
    else:
        # This error implies something like "ADD 1, 2" or "PUSH1" with too many parts.
        raise AssemblyError(f"Invalid line format or too many components for instruction '{op_str_raw}'.", line_num, original_line_text)


def _resolve_addresses(
    parsed_instructions: list[tuple[int, str, _OpType]], # (line_num, original_line, op_tuple)
    labels_info: dict[int, tuple[int, str, str]], # instruction_index -> (line_num, original_line_text, label_name_from_source)
    case_sensitive_labels: bool
) -> dict[str, int]:
    """Calculates the bytecode address for each label."""
    final_label_offsets: dict[str, int] = {} # Maps label_key to address
    current_address = 0

    # Store where each label_key was first defined for better error messages
    label_definitions_meta: dict[str, tuple[int, str, str]] = {} # label_key -> (line_num, original_line, label_name_from_source)


    for idx, (line_num, original_line, op_tuple) in enumerate(parsed_instructions):
        op = op_tuple[0]
        args = op_tuple[1:]

        if idx in labels_info:
            label_line_num, label_original_line, label_name_from_source = labels_info[idx]
            label_key = label_name_from_source if case_sensitive_labels else label_name_from_source.casefold()
            
            if label_key in final_label_offsets:
                # Label redefined error
                first_def_line_num, _, first_def_name = label_definitions_meta[label_key]
                raise AssemblyError(f"Label '{label_name_from_source}' redefined. First defined as '{first_def_name}' on line {first_def_line_num}.",
                                    label_line_num, label_original_line)
            final_label_offsets[label_key] = current_address
            label_definitions_meta[label_key] = (label_line_num, label_original_line, label_name_from_source)
        
        current_address += 1  # For the opcode itself
        if op in _PUSH_SIZE:
            if not args: # This should ideally be caught during initial parsing or a validation step.
                raise AssemblyError(f"Instruction {op.name} expects an argument, but none found during address resolution.", line_num, original_line)
            current_address += _PUSH_SIZE[op]
        elif args:  # Argument present for non-PUSHX instruction, implies PUSH8 will be used for its argument.
            current_address += 1 + 8  # PUSH8 opcode + 8 bytes for argument
            
    return final_label_offsets


def _generate_bytecode_for_instruction(
    op_tuple: _OpType,
    final_label_offsets: dict[str, int],
    case_sensitive_labels: bool,
    line_num: int, # For error reporting
    original_line_text: str # For error reporting
) -> bytes:
    """Generates bytecode for a single instruction tuple."""
    bytecode_segment = bytearray()
    op = op_tuple[0]
    args = op_tuple[1:] # This will be an empty tuple if no args
    arg_value_runtime = args[0] if args else None # The actual value (int or string label name)

    is_push_variant = op in _PUSH_SIZE
    has_argument_value = arg_value_runtime is not None

    if has_argument_value and not is_push_variant: # Argument needs PUSH8
        bytecode_segment.append(Instruction.PUSH8)
        resolved_numeric_arg: int
        if isinstance(arg_value_runtime, str): # It's a label name string
            label_name_for_lookup = arg_value_runtime # This is already case-adjusted if assembler is case-insensitive
                                                    # or it's the original string if labels are case-sensitive,
                                                    # based on how it was stored in _OpType.
            
            # For _LABEL_REGEX match, use the raw string if it was stored that way.
            # Typically, PUSH8 [label] is not valid syntax, PUSH8 label is.
            # We assume arg_value_runtime is the clean label name here.
            label_key = label_name_for_lookup if case_sensitive_labels else label_name_for_lookup.casefold()
            
            resolved_address = final_label_offsets.get(label_key)
            if resolved_address is None:
                raise AssemblyError(f"Undefined label: '{arg_value_runtime}'", line_num, original_line_text)
            resolved_numeric_arg = resolved_address
        elif isinstance(arg_value_runtime, int):
            resolved_numeric_arg = arg_value_runtime
        else: # Should not happen if parsing is correct
            raise AssemblyError(f"Invalid argument type '{type(arg_value_runtime).__name__}' for implicit PUSH8.", line_num, original_line_text)
        bytecode_segment += resolved_numeric_arg.to_bytes(8, "little")

    bytecode_segment.append(op) # Actual instruction opcode

    if is_push_variant:
        if not has_argument_value: # Should be caught earlier
            raise AssemblyError(f"Instruction {op.name} expects an argument but none provided during bytecode generation.", line_num, original_line_text)
        
        resolved_numeric_arg_push: int
        if isinstance(arg_value_runtime, str): # Label for PUSHx
            label_name_for_lookup = arg_value_runtime
            label_key = label_name_for_lookup if case_sensitive_labels else label_name_for_lookup.casefold()
            
            resolved_address = final_label_offsets.get(label_key)
            if resolved_address is None:
                raise AssemblyError(f"Undefined label: '{arg_value_runtime}' used with {op.name}.", line_num, original_line_text)
            resolved_numeric_arg_push = resolved_address
        elif isinstance(arg_value_runtime, int):
            resolved_numeric_arg_push = arg_value_runtime
        else: # Should not happen
            raise AssemblyError(f"Argument for {op.name} must be an integer or a resolvable label, got type '{type(arg_value_runtime).__name__}'.", line_num, original_line_text)
        
        bytecode_segment += resolved_numeric_arg_push.to_bytes(_PUSH_SIZE[op], "little")
        
    return bytes(bytecode_segment)


def assemble(asm: str, case_sensitive: bool = False) -> bytes:
    # `case_sensitive` flag controls behavior for labels and constants.
    # Instruction mnemonics are always matched case-insensitively (via .upper()).
    case_sensitive_labels = case_sensitive
    case_sensitive_constants = case_sensitive

    # --- Preprocessing ---
    # Returns list of (original_line_number, original_line_text, cleaned_line_content)
    try:
        # `cleaned_line_content` is already case-adjusted by _preprocess_assembly if !case_sensitive
        preprocessed_asm_lines = _preprocess_assembly(asm, case_sensitive)
    except AssemblyError: # Preprocessing errors already have line info
        raise # Re-raise, error is already formatted.

    # --- First Pass: Parse lines, define constants, identify labels and instructions ---
    # Stores tuples of (original_line_num, original_line_text, _OpType instruction_tuple)
    parsed_instructions_with_meta: list[tuple[int, str, _OpType]] = []
    constants: dict[str, int] = {} # Stores const_key -> value
    
    # Stores label info by the index of the instruction they precede
    # instruction_index -> (line_num, original_line_text, label_name_from_source)
    labels_by_instruction_index: dict[int, tuple[int, str, str]] = {} 

    for line_num, original_line_text, cleaned_line_content in preprocessed_asm_lines:
        try:
            # `cleaned_line_content` is used for parsing logic.
            # `original_line_text` is for error messages.
            parse_type, parsed_data = _parse_single_line(
                line_num, cleaned_line_content, original_line_text, constants, case_sensitive_constants
            )

            if parse_type == "instruction":
                # parsed_data is the _OpType tuple (op,) or (op, arg_val)
                # arg_val for constants is int; for labels, it's str (label name, already case-adjusted by _parse_single_line if necessary)
                parsed_instructions_with_meta.append((line_num, original_line_text, parsed_data))
            elif parse_type == "label":
                # parsed_data is label_name (string, already case-adjusted by _parse_single_line if necessary)
                label_name_from_parser = parsed_data 
                current_instruction_index = len(parsed_instructions_with_meta)
                labels_by_instruction_index[current_instruction_index] = (line_num, original_line_text, label_name_from_parser)
            elif parse_type == "constant_def":
                # parsed_data is (const_key, const_value, const_name_from_source)
                const_key, const_value, const_name_from_source = parsed_data
                if const_key in constants: # Check for redefinition
                    # Find original definition for better error. This is a simplification.
                    # A more robust way would be to store (value, line_num, original_text) for constants.
                    raise AssemblyError(f"Constant '{const_name_from_source}' redefined.", line_num, original_line_text)
                constants[const_key] = const_value
        except AssemblyError: # Errors from _parse_single_line already have context
            raise
        except Exception as e: # Catch any other unexpected errors during this parsing phase
            raise AssemblyError(f"Unexpected parsing error: {e}", line_num, original_line_text)


    # --- Second Pass: Resolve label addresses ---
    try:
        # `labels_by_instruction_index` keys are instruction indices.
        # `label_name_from_source` within its tuple value is the name as it appeared (or casefolded).
        final_label_offsets = _resolve_addresses(parsed_instructions_with_meta, labels_by_instruction_index, case_sensitive_labels)
    except AssemblyError: # Errors from _resolve_addresses already have context
        raise

    # --- Third Pass: Generate bytecode ---
    final_bytecode = bytearray()
    for line_num, original_line_text, op_tuple in parsed_instructions_with_meta:
        try:
            # op_tuple contains instruction and its arg (which might be a label name string or int)
            # The label name string in op_tuple is already appropriately cased based on earlier logic.
            instruction_bytes = _generate_bytecode_for_instruction(
                op_tuple, final_label_offsets, case_sensitive_labels, line_num, original_line_text
            )
            final_bytecode.extend(instruction_bytes)
        except AssemblyError: # Errors from bytecode generation already have context
            raise
        except Exception as e: # Catch other unexpected errors during bytecode generation
             raise AssemblyError(f"Unexpected bytecode generation error: {e}", line_num, original_line_text)
             
    return bytes(final_bytecode)


if __name__ == "__main__":
    program_name, *argv = sys.argv
    if len(argv) not in [2, 3]: # Allow optional --case-sensitive flag
        print(f"Usage: {program_name} [--case-sensitive] <input file> <output file>")
        sys.exit(1)

    case_sensitive_arg = False
    input_file_arg = ""
    output_file_arg = ""

    if len(argv) == 3:
        if argv[0].lower() == "--case-sensitive":
            case_sensitive_arg = True
            input_file_arg = argv[1]
            output_file_arg = argv[2]
        else:
            print(f"Usage: {program_name} [--case-sensitive] <input file> <output file>")
            print(f"Unknown option: {argv[0]}")
            sys.exit(1)
    else: # len(argv) == 2
        input_file_arg = argv[0]
        output_file_arg = argv[1]


    try:
        with open(input_file_arg, "rt", encoding="utf-8") as file:
            asm_code_content = file.read()
    except FileNotFoundError:
        print(f"Error: Input file '{input_file_arg}' not found.")
        sys.exit(1)
    except Exception as e:
        print(f"Error reading input file '{input_file_arg}': {e}")
        sys.exit(1)
    
    print(f"--- Assembling code from {input_file_arg} (Case-sensitive: {case_sensitive_arg}) ---")
    try:
        result_bytecode = assemble(asm_code_content, case_sensitive=case_sensitive_arg)
        print(f"Assembly successful. Outputting {len(result_bytecode)} bytes to {output_file_arg}")
        # print(f"Bytecode (hex): {result_bytecode.hex()}") # Uncomment for debugging output
        
        with open(output_file_arg, "wb") as file:
            file.write(result_bytecode)
        print(f"Successfully wrote bytecode to {output_file_arg}")

    except AssemblyError as e: # Catch our custom assembly error
        print(f"Assembly Error: {e}") # The error message is already formatted
        sys.exit(1)
    except Exception as e: # Catch any other unexpected errors
        print(f"An unexpected critical error occurred: {e}")
        # import traceback # For more detailed debugging if needed
        # traceback.print_exc()
        sys.exit(1)
