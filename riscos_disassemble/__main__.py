#!/usr/bin/env python
"""
Disassembly of RISC OS code in a similar style to *DumpI.
"""

import argparse
import os
import struct
import sys

from . import disassemble


def setup_argparse():
    name = os.path.basename(sys.argv[0])
    if name == '__main__.py':
        name = 'riscos-dumpi'
    parser = argparse.ArgumentParser(usage="%s [<options>] <binary-file>" % (name,),
                                     description="Disassemble a file of ARM or Thumb code")
    parser.add_argument('--thumb', action='store_true',
                        help="Disassemble as Thumb code")
    parser.add_argument('filename',
                        help='File to disassemble')
    return parser


def main():
    parser = setup_argparse()
    options = parser.parse_args()

    config = disassemble.DisassembleConfig()
    dis = disassemble.Disassemble(config)

    thumb = options.thumb
    inst_width = 2 if thumb else 4

    with open(options.filename, 'rb') as fh:
        addr = 0
        while True:
            data = fh.read(inst_width)
            if len(data) < inst_width:
                break

            if thumb:
                word = struct.unpack('<H', data)[0]
            else:
                word = struct.unpack('<L', data)[0]

            (consumed, disassembly) = dis.disassemble(addr, data, thumb=thumb)

            def char(x):
                if x < 0x20 or x>=0x7f:
                    return '.'
                return chr(x)

            if thumb:
                text = ''.join((char(word & 255),
                                char((word>>8) & 255)))
                wordstr = "{:04x}".format(word)
            else:
                text = ''.join((char(word & 255),
                                char((word>>8) & 255),
                                char((word>>16) & 255),
                                char((word>>24) & 255)))
                wordstr = "{:08x}".format(word)

            print("{:08x} : {} : {} : {}".format(addr, wordstr, text,
                                                 disassembly or '<No disassembly available>'))
            addr += inst_width


if __name__ == '__main__':
    main()
