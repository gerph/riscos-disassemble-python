#!/usr/bin/env python
"""
Disassembly of RISC OS code in a similar style to *DumpI.
"""

import argparse
import errno
import fnmatch
import os
import struct
import sys
import textwrap

from .arm import colours
from .arm import postprocess

from .access import DisassembleAccess
from .access_helpers import DisassembleAccessDescriptions, DisassembleAccessSWIs
from .access_memory import DisassembleAccessFile
from .access_annotate import DisassembleAccessAnnotate
from . import get_disassembler

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


class BadArchitectureError(ToolError):
    pass


class BadARMFlagError(ToolError):
    pass


class OurAccess(DisassembleAccessSWIs,
                DisassembleAccessFile,
                DisassembleAccessDescriptions,
                DisassembleAccessAnnotate,
                DisassembleAccess):
    pass


def setup_argparse():
    parser = argparse.ArgumentParser(usage="%s [<options>] <binary-file>" % (get_tool_name(),),
                                     description="Disassemble a file of ARM or Thumb code.")
    parser.add_argument('--help-debuggerplus', action='store_true',
                        help="Get help on the DebuggerPlus flags")
    parser.add_argument('--debuggerplus', action='append',
                        help="Specify a list of DebuggerPlus flags to apply, prefixed by '-' to disable flags")
    parser.add_argument('--arm', action='store_true',
                        help="Disassemble as ARM 32bit (AArch32) code")
    parser.add_argument('--thumb', action='store_true',
                        help="Disassemble as Thumb code")
    parser.add_argument('--arm64', action='store_true',
                        help="Disassemble as ARM 64bit (AArch64) code")
    parser.add_argument('--colour', action='store_true',
                        help="Use colours")
    parser.add_argument('--colour-8bit', action='store_true',
                        help="Use 8bit colours")
    parser.add_argument('filename', nargs="?", default=None,
                        help='File to disassemble')
    parser.add_argument('baseaddr', nargs="?", type=lambda x: int(x, 16), default=None,
                        help='Base address to decode at (default to the default for the filetype)')

    # Function specific options
    group = parser.add_argument_group('Function specific options')
    group.add_argument('--function-map', action='store_true',
                        help="List the function addresses")
    group.add_argument('--match', action='store', default=None,
                        help="Match only the specific functions (may be wildcarded)")

    return parser


def disassemble_file(filename, arch='arm', colourer=None, postprocess=None, baseaddr=0, funcmatch=None):
    """
    Disassemble a file into ARM/Thumb/ARM64 instructions.

    @param filename:        File to process
    @param arch:            'arm', 'thumb', or 'arm64'
    @param colourer:        A colouring object to process the content into output colours
                            Or None to not apply colouring
    @param postprocess:     A post processor function which takes the instruction and text to convert to another form
                            Or None to not apply post-processing
    @param baseaddr:        Base address of the binary
    @param funcmatch:       Function matching string
    """

    access = OurAccess()
    access.baseaddr = baseaddr

    dis_cls = get_disassembler(arch)
    if dis_cls:
        dis = dis_cls(access=access)
    else:
        raise BadArchitectureError("Could not find disassembler for architecture '{}'".format(arch))

    if not dis.available:
        raise NoCapstoneError("The Python Capstone package must be installed. "
                              "Use 'pip{} install capstone'.".format('3' if sys.version_info.major == 3 else ''))

    inst_width = 2 if arch == 'thumb' else 4

    with open(filename, 'rb') as fh:
        access.fh = fh
        addr = baseaddr

        if guess_filetype(filename, access) == 'absolute':
            access.annotate_aif()

        enable = True if not funcmatch else False
        while True:
            access.fh_reset()
            data = fh.read(inst_width)
            if len(data) < inst_width:
                break

            if funcmatch:
                funcname = access.describe_code(addr)
                if funcname:
                    if fnmatch.fnmatchcase(funcname, funcmatch):
                        enable = True
                    else:
                        enable = False

            if enable:
                if inst_width == 2:
                    word = struct.unpack('<H', data)[0]
                else:
                    word = struct.unpack('<L', data)[0]

                if arch == 'arm64':
                    (consumed, disassembly) = dis.disassemble(addr, data, live_memory=True)
                else:
                    (consumed, disassembly) = dis.disassemble(addr, data, thumb=(arch=='thumb'), live_memory=True)

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


def map_functions(filename, baseaddr=0, funcmatch=None):
    """
    Produce a map of the functions that are present in the file.

    @param filename:        File to process
    @param baseaddr:        Base address of the binary
    @param funcmatch:       Function matching string
    """

    access = OurAccess()
    access.baseaddr = baseaddr

    with open(filename, 'rb') as fh:
        access.fh = fh
        addr = baseaddr
        while True:
            access.fh_reset()
            data = fh.read(4)
            if len(data) < 4:
                break

            funcname = access.describe_code(addr)
            if funcname:
                if not funcmatch or fnmatch.fnmatchcase(funcname, funcmatch):
                    print("%8X %s" % (addr, funcname))

            addr += 4


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


def guess_filetype(filename, access):
    filetype = None
    if filename.endswith(',ffa'):
        filetype = 'module'
    elif filename.endswith(',ff8'):
        filetype = 'absolute'
    elif filename.endswith(',ffc'):
        filetype = 'utility'
    return filetype


def guess_architecture(filename):
    """
    Read the file header to check what the architecture is.
    """

    filetype = guess_filetype(filename, None)
    if not filetype:
        # Don't recognise it, so it's ARM.
        return 'arm'

    def word_at(offset):
        fh.seek(offset, 0)
        data = fh.read(4)
        if len(data) < 4:
            return 0
        w = struct.unpack("<L", data)[0]
        return w

    with open(filename, 'rb') as fh:
        # Seek to end to get the length
        fh.seek(0, 2)
        length = fh.tell()

        if filetype == 'absolute':
            # Offset 0x10 should be SWI OS_Exit
            if word_at(0x10) == 0xEF000011:
                # This is an AIF file.
                # FIXME: We could be more careful in our checks.
                flags = word_at(0x30)
                if flags & 0xFF == 0x40:
                    return 'arm64'

            # All other cases are ARM (might be 26bit or 32bit, but it's irrelevant)
            return 'arm'

        elif filetype == 'utility':
            if word_at(0x4) == 0x79766748 and \
               word_at(0x8) == 0x216c6776:
                # This is a headered utility, so we can check it.
                flags = word_at(0x14)
                if flags & 0xFF == 0x40:
                    return 'arm64'

            # All other cases are ARM (might be 26bit or 32bit, but it's irrelevant)
            return 'arm'

        elif filetype == 'module':
            for offset in range(0, 0x34, 4):
                word = word_at(offset)
                if offset == 0x4:
                    word = word & ~0xC0000000   # Knock out the flag bits (squeezed, not ARM)
                if offset == 0x8:
                    word = word & ~0x80000000   # Knock out the flag bits
                if offset == 0x1c:
                    continue                    # Skip the SWI base
                if offset >= length:
                    break
                if offset == 0x30:
                    # This is the flags offset, which is the one that matters.
                    word = word_at(word)
                    arch_type = (word >> 4) & 15
                    if arch_type == 1:
                        return 'arm64'

        # All unrecognised file formats are ARM
        return 'arm'


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
        arch = 'guess'
        if options.arm:
            arch = 'arm'
        if options.thumb:
            arch = 'thumb'
        if options.arm64:
            arch = 'arm64'

        if arch == 'guess':
            arch = guess_architecture(options.filename)

        baseaddr = options.baseaddr
        if baseaddr is None:
            baseaddr = 0
            if options.filename.endswith(',ff8'):
                baseaddr = 0x8000

        if options.function_map:
            map_functions(options.filename,
                          baseaddr=baseaddr,
                          funcmatch=options.match)
        else:
            disassemble_file(options.filename,
                             arch=arch,
                             colourer=cdis if options.colour else None,
                             postprocess=armflags.transform,
                             baseaddr=baseaddr,
                             funcmatch=options.match)

    except IOError as exc:
        if exc.errno == errno.EISDIR:
            sys.exit("'%s' is a directory" % (options.filename,))
        if exc.errno == errno.ENOENT:
            sys.exit("'%s' not found" % (options.filename,))
        if exc.errno == errno.EACCES:
            sys.exit("'%s' is not accessible" % (options.filename,))
        if exc.errno == errno.EPIPE:
            # Broken pipe - probably means that they were more-ing the file,
            # and cancelled, or maybe piped through head or similar.
            # We don't want to report anything else, but just fail.
            # Close the stdout and stderr explicitly, ignoring errors, so
            # that the implicit close on exit doesn't report an error and
            # fail with 'close failed in file object destructor'.
            try:
                sys.stdout.close()
            except Exception:
                pass
            try:
                sys.stderr.close()
            except Exception:
                pass
            sys.exit(1)
        raise

    except KeyboardInterrupt:
        sys.exit("Interrupted")

    except ToolError as exc:
        sys.exit(str(exc))


if __name__ == '__main__':
    main()
