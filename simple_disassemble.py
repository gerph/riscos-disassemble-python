#!/usr/bin/env python
"""
Very simple example disassembly for RISC OS code.
"""

import os
import struct
import sys

import riscos_disassemble


if len(sys.argv) < 2:
    print("Syntax: {} <filename>".format(sys.argv[0]))
    exit(1)

filename = sys.argv[1]

dis_cls = riscos_disassemble.get_disassembler('arm')
if dis_cls:
    dis = dis_cls()
else:
    exit("Could not find disassembler for ARM")


with open(filename, 'rb') as fh:
    addr = 0
    while True:
        data = fh.read(4)
        if len(data) < 4:
            break

        word = struct.unpack('<L', data)[0]

        (consumed, arm) = dis.disassemble(addr, data)

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
