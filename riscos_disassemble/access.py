"""
Base class which provides access to the host system.

We provide a number of methods to access the file data and the host system:

Memory access functions:

* `get_memory_byte`:    Read a byte from memory
* `get_memory_word`:    Read a word from memory
* `get_memory_words`:   Read a multiple word from memory
* `get_memory_string`:  Read a string from memory

Decoding of the data in the system:

* `describe_content`:   Annotations that appear as comments on the address
* `describe_address`:   More information about a specific address
* `describe_region`:    More information about the region an address lies in
* `describe_code`:      Read the name of the function at an address
* `decode_swi`:         Decode a SWI number into a SWI name
* `decode_service`:     Decode a Service number into a service name

Register access functions:

* `get_reg`:            Read the current value of a register
* `get_pstate`:         Read the current value of the processor state
"""

import sys


class DisassembleAccess(object):
    """
    Base class to provide access to the source data, and details about the
    """

    def __init__(self, arch='unknown'):
        """
        DisassembleAccess provides access to the content within the core, and system information.

        @param arch:    Architecture name, or 'unknown' if not known (may be determined later)
        """
        self.arch = arch

    ##### Memory access functions #####

    def get_memory_byte(self, addr):
        """
        Read the current value of a byte from memory (only used when live_memory is True).

        @param addr:    Address to read the value of

        @return:    Byte value from memory (unsigned)
                    None if no memory is present
        """
        return None

    def get_memory_word(self, addr):
        """
        Read the current value of a word from memory (only used when live_memory is True).

        @param addr:    Address to read the value of

        @return:    Word value from memory (unsigned 4 bytes, little endian)
                    None if no memory is present
        """
        return None

    def get_memory_words(self, addr, size):
        """
        Read the current value of block of words from memory (only used when live_memory is True).

        @param addr:    Address to read the value of
        @param size:    Size in bytes to read

        @return:    List of word values from memory (unsigned 4 bytes, little endian)
                    None if no memory is present
        """
        words = []
        for i in range(0, size, 4):
            word = self.get_memory_word(addr + i)
            if word is None:
                return None
            words.append(word)
        return words

    def get_memory_string(self, addr, zeroterm=False):
        """
        Read the current value of a control terminated string from memory
        (only used when live_memory is True).

        @param addr:        Address to read the value of
        @param zeroterm:    True to terminiate only on 0

        @return:    String read (as a bytes sequence)
                    None if no memory is present
        """
        return None

    ##### Decoding functions #####

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
        return None

    def describe_region(self, addr, relative=False):
        """
        Describe the region that the given address is within.

        @param addr:    Address to describe (which might not be mapped)

        @return: tuple of (low, high, description) if the address is in a known region
                 None if the address cannot be described
        """
        return None

    def describe_content(self, addr):
        """
        Describe the content at a given address (data values, replacing disassembly)

        @param addr:    Address to describe (which might not be mapped)

        @return: Description of the content (eg 'header offset')
                 None if code is not known
        """
        return None

    def describe_code_comment(self, addr):
        """
        Describe the code at a given address (overrides anything else)

        @param addr:    Address to describe (which might not be mapped)

        @return: Name of the function (or function + offset)
                 None if code is not known
        """
        return None

    def describe_code(self, addr):
        """
        Describe the code function name at a given address.

        @param addr:    Address to describe (which might not be mapped)

        @return: Name of the function (or function + offset)
                 None if code is not known
        """
        signature = self.get_memory_word(addr - 4)
        if signature is not None:
            if signature & 0xFFFFFF03 == 0xFF000000:
                # This looks like a signature, so we can report it
                offset = (signature & 0xFF) + 4
                function_name = self.get_memory_string(addr - offset)
                return self.decode_string(function_name)
        return None

    def decode_swi(self, swi):
        """
        Decode a SWI number into a SWI name.

        @param swi: SWI number to decode

        @return:    SWI name, eg "OS_WriteC", "OS_WriteI+'B'", "XIIC_Control", or &XXXXX
        """
        return '&{:x}'.format(swi)

    def decode_service(self, service):
        """
        Decode a service number into a service name.

        @param service: Service number to decode

        @return:        Service name, eg "Service_Error"
                        Service number, eg "&XXXXXX"
        """
        return '&{:x}'.format(service)

    def decode_string(self, string):
        """
        Decode the bytes string supplied into something that we can present.

        The string supplied is in the encoding of the RISC OS system and we need
        to convert it to a string that we can show.
        """
        as_unicode = string.decode('latin-1')
        as_ascii = as_unicode.encode('ascii', 'backslashreplace')
        if sys.version_info > (3,):
            # Python 3 - turn back from a bytes into a str
            return as_ascii.decode('ascii')
        return as_ascii

    ##### Decoding functions #####

    def get_reg(self, regnum):
        """
        Return the current value of a register (only used when live_registers is True).

        @param regnum:  Register number to read (0-15)

        @return: Value of the register
        """
        return 0

    def get_pstate(self):
        """
        Return the current value of processor state (only used when live_registers is True).

        @return: Value of the processor state (eg CPSR)
        """
        return 0
