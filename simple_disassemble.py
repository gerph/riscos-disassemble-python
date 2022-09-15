"""
Very simple example disassembly for RISC OS code.
"""

import struct
import sys

import disassemble


if len(sys.argv) < 2:
    print("Syntax: {} <filename>".format(sys.argv[0]))
    exit(1)

filename = sys.argv[1]

config = disassemble.DisassembleConfig()
dis = disassemble.Disassemble(config)

with open(filename, 'rb') as fh:
    addr = 0
    while True:
        data = fh.read(4)
        if len(data) < 4:
            break

        word = struct.unpack('<L', data)[0]

        arm = dis.disassemble_instruction(addr, data)

        def char(x):
            if x < 0x20 or x>=0x7f:
                return '.'
            return chr(x)

        print("{:08x} : {:08x} : {}{}{}{} : {}".format(addr, word,
                                                       char(word & 255),
                                                       char((word>>8) & 255),
                                                       char((word>>16) & 255),
                                                       char((word>>24) & 255),
                                                       arm))
        addr += 4
