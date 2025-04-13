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


def assemble(asm: str, case_sensitive: bool = False) -> bytes:
    if not case_sensitive:
        asm = asm.casefold()
    # Remove empty lines and comments
    stripped_asm = [
        line_splitted for line in asm.splitlines() if (line_splitted := line.strip())
    ]

    instructions: list[_OpType] = []
    constants: dict[str, int] = {}
    labels: dict[int, str] = {}

    offset = 0
    while offset < len(stripped_asm):
        line = stripped_asm[offset]
        offset += 1
        # Skip empty lines and comments
        if not line or line.startswith(";"):
            continue
        # Check for label
        label_match = _LABEL_REGEX.match(line)
        if label_match:
            label_name = label_match.group("name")
            labels[len(instructions)] = label_name
            continue
        # Expand repeated instructions
        times_match = _TIMES_REGEX.match(line)
        if times_match:
            times = int(times_match.group("times"))
            instruction = times_match.group("instruction")
            stripped_asm[offset:offset] = [instruction] * times
            continue
        components = [
            stripped_component
            for component in line.split()
            if (stripped_component := component.strip())
        ]
        if (components_len := len(components)) == 1:
            op = Instruction[components[0].upper()]
            instructions.append((op,))
        elif components_len == 2:
            op_str, arg = components
            op = Instruction[op_str.upper()]
            try:
                arg = int(literal_eval(arg))
            except ValueError:
                # If the argument is not a number, it must be a label
                arg = constants.get(arg, arg)
            instructions.append((op, arg))
        elif components_len == 3:
            constant, equ, value = components
            if equ != "equ":
                raise ValueError(f"Invalid constant definition: {line}")
            constants[constant] = int(literal_eval(value))
        else:
            raise ValueError(f"Invalid line: {line}")

    # Expand labels
    label_offsets: dict[str, int] = {}
    address = 0
    for index, (op, *args) in enumerate(instructions.copy()):
        if label_name := labels.get(index):
            label_offsets[label_name] = address
        address += 1
        if size := _PUSH_SIZE.get(op):
            address += size
            continue
        # If the instruction has an argument, prepend a PUSH8 instruction
        if args:
            address += 1 + 8

    # Generate bytecode
    bytecode = bytearray()
    for op, *args in instructions:
        bytecode.append(op)
        if not args:
            continue
        if isinstance(arg := args[0], str):
            matched = _LABEL_REGEX.match(arg)
            if not matched:
                raise ValueError(f"Invalid label: {arg}")
            arg = label_offsets.get(matched.group("name"))
            if arg is None:
                raise ValueError(f"Undefined label: {arg}")
        if size := _PUSH_SIZE.get(op):
            bytecode += arg.to_bytes(size, "little")
        else:
            push = bytes([Instruction.PUSH8, *arg.to_bytes(8, "little")])
            # Insert the PUSH8 instruction before the current instruction
            bytecode[-1:-1] = push
    return bytes(bytecode)


if __name__ == "__main__":
    program_name, *argv = sys.argv
    if len(argv) != 2:
        print(f"Usage: {program_name} <input file> <output file>")
        sys.exit(1)
    input_file, output_file = argv

    with open(input_file, "rt", encoding="utf-8") as file:
        ret = assemble(file.read())

    with open(output_file, "wb") as file:
        file.write(ret)
