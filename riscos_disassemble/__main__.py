#!/usr/bin/env python
"""
Disassembly of RISC OS code in a similar style to *DumpI.
"""

import argparse
import errno
import os
import struct
import sys
import textwrap

from . import disassemble
from . import colours
from . import swis
from . import postprocess


ENV_DEBUGGERPLUS = 'RISCOS_DUMPI_DEBUGGERPLUS'

def get_tool_name():
    tool_name = os.path.basename(sys.argv[0])
    if tool_name == '__main__.py':
        tool_name = 'riscos-dumpi'
    return tool_name


class ToolError(Exception):
    pass


class NoCapstoneError(ToolError):
    pass


class BadARMFlagError(ToolError):
    pass


class DisassembleSWIs(object):
    """
    Mixin for the Disassemble classes, which adds in SWI decoding.
    """

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


class DisassembleTool(DisassembleSWIs, disassemble.Disassemble):
    pass


def setup_argparse():
    parser = argparse.ArgumentParser(usage="%s [<options>] <binary-file>" % (get_tool_name(),),
                                     description="Disassemble a file of ARM or Thumb code")
    parser.add_argument('--help-debuggerplus', action='store_true',
                        help="Get help on the DebuggerPlus flags")
    parser.add_argument('--debuggerplus', action='append',
                        help="Specify a list of DebuggerPlus flags to apply, prefixed by '-' to disable flags")
    parser.add_argument('--thumb', action='store_true',
                        help="Disassemble as Thumb code")
    parser.add_argument('--colour', action='store_true',
                        help="Use colours")
    parser.add_argument('--colour-8bit', action='store_true',
                        help="Use 8bit colours")
    parser.add_argument('filename', nargs="?", default=None,
                        help='File to disassemble')
    return parser


def disassemble_file(filename, arch='arm', colourer=None, postprocess=None):
    """
    Disassemble a file into ARM/Thumb instructions.

    @param filename:        File to process
    @param arch:            'arm' or 'thumb'
    @param colourer:        A colouring object to process the content into output colours
                            Or None to not apply colouring
    @param postprocess:     A post processor function which takes the instruction and text to convert to another form
                            Or None to not apply post-processing
    """

    config = disassemble.DisassembleConfig()
    dis = DisassembleTool(config)

    if not dis.available:
        raise NoCapstoneError("The Python Capstone package must be installed. "
                              "Use 'pip{} install capstone'.".format('3' if sys.version_info.major == 3 else ''))

    inst_width = 2 if arch == 'thumb' else 4

    with open(filename, 'rb') as fh:
        addr = 0
        while True:
            data = fh.read(inst_width)
            if len(data) < inst_width:
                break

            if inst_width == 2:
                word = struct.unpack('<H', data)[0]
            else:
                word = struct.unpack('<L', data)[0]

            (consumed, disassembly) = dis.disassemble(addr, data, thumb=(arch=='thumb'))

            def char(x):
                if x < 0x20 or x>=0x7f:
                    return '.'
                return chr(x)

            if inst_width == 2:
                text = ''.join((char(word & 255),
                                char((word>>8) & 255)))
                wordstr = "{:04x}".format(word)
            else:
                text = ''.join((char(word & 255),
                                char((word>>8) & 255),
                                char((word>>16) & 255),
                                char((word>>24) & 255)))
                wordstr = "{:08x}".format(word)

            if postprocess and disassembly:
                disassembly = postprocess(word, disassembly)

            if colourer and disassembly:
                coloured = colourer.colour(disassembly)
                coloured = [colour + s.encode('latin-1') for colour, s in coloured]
                try:
                    disassembly = sum(coloured, bytearray()) + colourer.colour_reset
                except TypeError:
                    # Python 3
                    disassembly = b''.join(bytes(b) for b in coloured) + colourer.colour_reset
                    disassembly = disassembly.decode('latin-1')

            sys.stdout.write("{:08x} : {} : {} : {}\n".format(addr, wordstr, text,
                                                              disassembly or '<No disassembly available>'))
            addr += inst_width


def update_arm_flags(armflags, flags):
    """
    Given a list of flags, update the DebuggerARMFlags object.
    """
    for flag in flags.replace(' ', ',').split(','):
        negate = False
        if flag and flag[0] == '-':
            flag = flag[1:]
            negate = True
        (name, bit, desc) = armflags.flag_name_mapping.get(flag.upper(), (None, None, None))
        if not name:
            raise BadARMFlagError("DebuggerPlus flag '%s' is not understood" % (flag,))
        before = armflags.flags
        if negate:
            armflags.update(bic=bit, eor=0)
        else:
            armflags.update(bic=bit, eor=bit)
        if armflags.flags == before:
            raise BadARMFlagError("DebuggerPlus flag '%s' is not supported (cannot be changed)" % (flag,))


def help_debuggerplus(armflags):
    """
    Report how the DebuggerPlus options work.
    """
    message = """\
DebuggerPlus is a module by Darren Salt, which provides more options for disassembly than
the standard Debugger module provided by RISC OS. These options were indicated by flags
which could be set at the command line. This tool supports a subset of those flags."""

    for line in textwrap.wrap(message):
        print(line)

    print("")

    print("Supported flags (+ for enabled):")

    indent = 2
    spacing = 14

    for (flag, bit, desc) in sorted(armflags.flag_name_mapping.values()):
        if armflags.supported_flags & bit:
            # Only report on the supported flags
            enabled = armflags.flags & bit
            leader = "%*s%-*s" % (indent, '+' if enabled else ' ', spacing, flag)
            for line in textwrap.wrap(desc, width=70 - indent - spacing):
                print(leader + line)
                leader = ' ' * (indent + spacing)
    print("")

    message = """\
The flags may be specified on the command line with `--debuggerplus <flags>` repeated,
or as a comma-separated list. The flags may also be configured using the environment
variable %s.""" % (ENV_DEBUGGERPLUS,)

    for line in textwrap.wrap(message):
        print(line)


def main():
    parser = setup_argparse()
    options = parser.parse_args()

    armflags = postprocess.DebuggerARMFlags()
    try:
        # Environment variable comes first, so that the command line can override
        env_flags = os.environ.get(ENV_DEBUGGERPLUS)
        if env_flags:
            update_arm_flags(armflags, env_flags)

        # Command line options
        if options.debuggerplus:
            for flags in options.debuggerplus:
                update_arm_flags(armflags, flags)
    except ToolError as exc:
        sys.exit(str(exc))

    if options.help_debuggerplus:
        help_debuggerplus(armflags)
        sys.exit(0)

    if not options.filename:
        sys.exit("A filename must be supplied to %s" % (get_tool_name(),))

    cdis = colours.ColourDisassemblyANSI()
    if options.colour_8bit:
        options.colour = True
        cdis.use_8bit()

    try:
        arch = 'arm'
        if options.thumb:
            arch = 'thumb'
        disassemble_file(options.filename,
                         arch=arch,
                         colourer=cdis if options.colour else None,
                         postprocess=armflags.transform)

    except IOError as exc:
        if exc.errno == errno.EISDIR:
            sys.exit("'%s' is a directory" % (options.filename,))
        if exc.errno == errno.ENOENT:
            sys.exit("'%s' not found" % (options.filename,))
        if exc.errno == errno.EACCES:
            sys.exit("'%s' is not accessible" % (options.filename,))
        raise

    except ToolError as exc:
        sys.exit(str(exc))


if __name__ == '__main__':
    main()
