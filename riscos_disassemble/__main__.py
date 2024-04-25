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


class DisassembleMemory(object):
    """
    Mixin for the Disassemble classes, which adds in memory decoding by seeking.
    """

    # Initialise with the base address of the file
    baseaddr = 0

    # Initialise with the file handle for the file
    fh = None

    # Set to True when seek is needed to reset the file pointer
    fh_seek_needed = False
    fh_seek_pos = None

    # File extent, or None if not known
    _fh_extent = None

    # How close to the end we'll do the fast get_memory_string call
    fast_memory_string = 128

    @property
    def fh_extent(self):
        if self._fh_extent is None:
            if not self.fh_seek_needed:
                self.fh_seek_pos = self.fh.tell()
                self.fh_seek_needed = True
            self.fh.seek(0, 2)  # Seek to end
            self._fh_extent = self.fh.tell()
        return self._fh_extent

    def fh_reset(self):
        """
        Seek back to where the caller might have expected us to be.
        """
        if self.fh_seek_needed:
            self.fh.seek(self.fh_seek_pos)
            self.fh_seek_needed = False

    def get_memory_byte(self, addr):
        """
        Read the current value of a byte from memory (only used when live_memory is True).

        @param addr:    Address to read the value of

        @return:    Byte value from memory (unsigned)
                    None if no memory is present
        """
        if addr < self.baseaddr:
            return None
        if addr + 1 > self.baseaddr + self.fh_extent:
            return None

        if not self.fh_seek_needed:
            self.fh_seek_pos = self.fh.tell()
            self.fh_seek_needed = True
        self.fh.seek(addr - self.baseaddr)
        b = bytearray(self.fh.read(1))[0]
        return b

    def get_memory_word(self, addr):
        """
        Read the current value of a word from memory (only used when live_memory is True).

        @param addr:    Address to read the value of

        @return:    Word value from memory (unsigned 4 bytes, little endian)
                    None if no memory is present
        """
        if addr < self.baseaddr:
            return None
        if addr + 4 > self.baseaddr + self.fh_extent:
            return None

        if not self.fh_seek_needed:
            self.fh_seek_pos = self.fh.tell()
            self.fh_seek_needed = True
        self.fh.seek(addr - self.baseaddr)
        w = struct.unpack("<L", self.fh.read(4))[0]
        return w

    def get_memory_string(self, addr):
        """
        Read the current value of a control terminated string from memory
        (only used when live_memory is True).

        @param addr:    Address to read the value of

        @return:    String read (as a bytes sequence)
                    None if no memory is present
        """

        # Whether it can even be a string
        if addr < self.baseaddr:
            return None
        if addr + 1 > self.baseaddr + self.fh_extent:
            return None

        blist = []

        if addr + self.fast_memory_string < self.baseaddr + self.fh_extent:
            # There's at least 128 bytes, so we'll just try reading them
            if not self.fh_seek_needed:
                self.fh_seek_pos = self.fh.tell()
                self.fh_seek_needed = True
            self.fh.seek(addr - self.baseaddr)

            data = bytearray(self.fh.read(self.fast_memory_string))
            for b in data:
                if b < 32:
                    break
                blist.append(b)
            addr += len(blist)

        # This is near to the end of the file or we didn't find a terminator, so we'll try reading individual bytes
        while True:
            b = self.get_memory_byte(addr)
            if b is None:
                return None
            if b < 32:
                break
            blist.append(b)
            addr += 1
        bstr = bytes(bytearray(blist))
        return bstr.decode('latin-1').encode('ascii', 'backslashreplace')


class DisassembleDescriptions(object):

    def describe_address(self, addr, description=None):
        """
        Return a list of descriptions about the contents of an address.

        @param addr:        Address to describe the content of.
        @param description: Any additional information which is known, such as:
                                'pointer to string'
                                'pointer to code'
                                'pointer to error'
                                'corrupted'

        @return:    list of strings describing what's at that address
                    None if nothing known
        """
        if addr in (0, 0xFFFFFFFF):
            return []
        is_string = False
        not_string = False
        value_str = None
        words = None

        if description:
            if description.startswith('pointer to string'):
                # We know it's a string, so we try to fetch it
                value_str = self.get_memory_string(addr)
                if value_str is not None:
                    is_string = True

            if not value_str and (addr & 3) == 0:
                if description.startswith('pointer to code'):
                    # We know it's code, so we try to describe that
                    region = self.describe_code(addr)
                    if region:
                        return ['Function: %s' % (function,)]

                if description.startswith('pointer to error'):
                    errnum = self.get_memory_word(addr)
                    value_str = self.get_memory_string(addr + 1)
                    if value_str is not None and errnum is not None:
                        return ["Error &{:x}: \"{}\"".format(errnum,
                                                             value_str.decode('latin-1').encode('ascii', 'backslashreplace'))]

        if not value_str:
            # Let's have a guess at the string
            if not description or description.startswith('pointer to '):
                value_str = self.get_memory_string(addr)
                limit = 6
                if value_str and len(value_str) >= limit:
                    is_string = True
                else:
                    not_string = True

        if not not_string and not is_string:
            # We don't know if it's a string yet, so let's have a see whether
            # it looks like a string
            words = self.get_memory_words(addr, 4 * 4)
            word = words[0] if words else None
            if word is None:
                # It's not in mapped memory, so give up now.
                return []
            if 32 <= (word & 255) < 127 and \
               32 <= ((word>>8) & 255) < 127 and \
               32 <= ((word>>16) & 255) < 127 and \
               32 <= ((word>>24) & 255) < 127:
                # Looks like a plausible string; let's use it
                value_str = self.get_memory_string(addr)
                if len(value_str) < 250:
                    # So long as it's not too long, we'll say it's a string
                    is_string = True
                    not_string = False

        if is_string:
            return ["\"%s\"" % (self.decode_string(value_str),)]

        if (addr & 3) == 0:
            # It's aligned, so it might be a pointer to some words
            if not words:
                # If we've not already read the words, try now.
                words = self.get_memory_words(addr, 4 * 4)
            if words:
                words_str = ", ".join("&%08x" % (word,) for word in words)
                desc = ["[%s]" % (words_str,)]
                if not description or description.startswith('pointer to code'):
                    function = self.describe_code(addr)
                    if function:
                        #desc.insert(0, function)
                        desc = ['Function: %s' % (function,)]
                return desc

        return []


class DisassembleTool(DisassembleSWIs, DisassembleMemory, DisassembleDescriptions, disassemble.Disassemble):
    pass


def setup_argparse():
    parser = argparse.ArgumentParser(usage="%s [<options>] <binary-file>" % (get_tool_name(),),
                                     description="Disassemble a file of ARM or Thumb code.")
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
    Disassemble a file into ARM/Thumb instructions.

    @param filename:        File to process
    @param arch:            'arm' or 'thumb'
    @param colourer:        A colouring object to process the content into output colours
                            Or None to not apply colouring
    @param postprocess:     A post processor function which takes the instruction and text to convert to another form
                            Or None to not apply post-processing
    @param baseaddr:        Base address of the binary
    @param funcmatch:       Function matching string
    """

    config = disassemble.DisassembleConfig()
    dis = DisassembleTool(config)
    dis.baseaddr = baseaddr

    if not dis.available:
        raise NoCapstoneError("The Python Capstone package must be installed. "
                              "Use 'pip{} install capstone'.".format('3' if sys.version_info.major == 3 else ''))

    inst_width = 2 if arch == 'thumb' else 4

    with open(filename, 'rb') as fh:
        dis.fh = fh
        addr = baseaddr
        enable = True if not funcmatch else False
        while True:
            dis.fh_reset()
            data = fh.read(inst_width)
            if len(data) < inst_width:
                break

            if funcmatch:
                funcname = dis.describe_code(addr)
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

    config = disassemble.DisassembleConfig()
    dis = DisassembleTool(config)
    dis.baseaddr = baseaddr

    inst_width = 4

    with open(filename, 'rb') as fh:
        dis.fh = fh
        addr = baseaddr
        while True:
            dis.fh_reset()
            data = fh.read(inst_width)
            if len(data) < inst_width:
                break

            funcname = dis.describe_code(addr)
            if funcname:
                if not funcmatch or fnmatch.fnmatchcase(funcname, funcmatch):
                    print("%8X %s" % (addr, funcname))

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
