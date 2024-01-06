#!/usr/bin/env python
"""
Disassembly of RISC OS code in a similar style to *DumpI.
"""

import argparse
import os
import struct
import sys

from . import disassemble
from . import colours
from . import swis


class DisassembleTool(disassemble.Disassemble):

    swi_cache = None

    def get_swi_name(self, swi):
        """
        Decode a SWI number into a SWI name.

        @param swi: SWI number to decode

        @return:    SWI name, eg "OS_WriteC", "OS_WriteI+'B'", "XIIC_Control", or &XXXXX
        """
        if self.swi_cache is None:
            swi_cache = {}
            for name in dir(swis):
                if name[0] != '_' and '_' in name:
                    number = getattr(swis, name)
                    swi_cache[number] = name
            # Populate OS_WriteI
            for vdu in range(256):
                swi_cache[0x100 + vdu] = 'OS_WriteI+' + ('"%c"' % (vdu,) if 0x20 <= vdu < 0x7f else str(vdu))
            self.swi_cache = swi_cache

        xbit = swi & 0x20000
        name = self.swi_cache.get(swi & ~0x20000, None)
        if name:
            if xbit:
                name = 'X' + name
            return name
        return '&{:x}'.format(swi)


def setup_argparse():
    name = os.path.basename(sys.argv[0])
    if name == '__main__.py':
        name = 'riscos-dumpi'
    parser = argparse.ArgumentParser(usage="%s [<options>] <binary-file>" % (name,),
                                     description="Disassemble a file of ARM or Thumb code")
    parser.add_argument('--thumb', action='store_true',
                        help="Disassemble as Thumb code")
    parser.add_argument('--colour', action='store_true',
                        help="Use colours")
    parser.add_argument('--colour-8bit', action='store_true',
                        help="Use 8bit colours")
    parser.add_argument('filename',
                        help='File to disassemble')
    return parser


def main():
    parser = setup_argparse()
    options = parser.parse_args()

    config = disassemble.DisassembleConfig()
    dis = DisassembleTool(config)
    cdis = colours.ColourDisassemblyANSI()

    if options.colour_8bit:
        options.colour = True
        cdis.use_8bit()

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

            if options.colour and disassembly:
                coloured = cdis.colour(disassembly)
                coloured = [colour + s.encode('latin-1') for colour, s in coloured]
                try:
                    disassembly = sum(coloured, bytearray()) + cdis.colour_reset
                except TypeError:
                    # Python 3
                    disassembly = b''.join(bytes(b) for b in coloured) + cdis.colour_reset
                    disassembly = disassembly.decode('latin-1')

            sys.stdout.write("{:08x} : {} : {} : {}\n".format(addr, wordstr, text,
                                                              disassembly or '<No disassembly available>'))
            addr += inst_width


if __name__ == '__main__':
    main()
