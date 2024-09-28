"""
Disassembly of instructions in RISC OS style.

This module is used to perform disassembly of ARM 64-bit instructions
in a form which is expected by RISC OS users. It uses the Capstone library
to perform most of the disassembly. The output is then modified to reformat
the output to reformat it for use in RISC OS.

The disassembly is managed through the `Disassemble` object. The method
`disassemble_instruction` is used to perform the disassembly of a 32bit or
16bit word value at a given address, and return a string describing it.
The string may include comments about the instruction.

The disassembly can be configured to have different functionality through the
`DisassembleConfig()` object.

The `disassemble_instruction` method can be told whether the register and/or
memory interfaces will contain valid information. When they are enabled (and
the corresponding configuration for showing referenced registers or pointers)
the `get_reg` and `get_memory_*` methods will be called to read register
and memory values.

To use the `Disassemble` class most effectively it should be subclassed and
alternative implementations provided for some of the methods. See the actual
method docstrings for more details:

* `describe_address`:   More information about a specific address
* `describe_region`:    More information about the region an address lies in
* `describe_code`:      Read the name of the function at an address
* `get_swi_name`:       Decode a SWI number into a SWI name
* `get_reg`:            Read the current value of a register
* `get_cpsr`:           Read the current value of the CPSR
* `get_memory_byte`:    Read a byte from memory
* `get_memory_word`:    Read a word from memory
* `get_memory_string`:  Read a string from memory


Simple usage of the `Disassemble` class for ARM code might be something like:

    import struct
    import disassemble

    config = disassemble.DisassembleConfig()
    dis = disassemble.Disassemble(config)

    for addr in range(0x8000, 0x8100):
        data = read_memory(addr, 4)
        word = struct.unpack('<L', data)[0]

        arm = dis.disassemble_instruction(addr, word)
        print("{:08x} : {:08x} : {}".format(addr, word, arm))


To disassemble the contents of an arbitrary file:

    import struct
    import disassemble

    filename = 'module,ffa'

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
            print("{:08x} : {:08x} : {}".format(addr, word, arm))
            addr += 4
"""

import struct
import sys


class DisassembleConfig(object):
    """
    Configuration for how the disassembly should be performed by the Disassemble class.
    """

    format = 'riscos'
    """
    Configures how the disassembly will be formatted. By default a RISC OS-like
    layout will be used for the disassembly. This takes more processing from the
    Capstone library's output, but will be more familiar. It is possible to use
    the raw Capstone format to save processing time.

    Formats supported:

        * `capstone` - Raw capstone disassembly.
        * `riscos` - Processed disassembly to be more like RISC OS forms.
    """

    show_referenced_registers = True
    """
    Controls whether disassembly will include details of the registers which are
    referenced in the instruction. The registers reported are the values before
    the instruction is executed. The register values can only be reported if
    the `live_registers` parameter is passed to the `disassemble_instruction`
    method.
    """

    show_referenced_pointers = True
    """
    Controls whether disassembly will include details of the pointer values in
    registers. The memory values can only be reported if the `live_memory`
    parameter is passed to the `disassemble_instruction` method.
    """


class Disassemble(object):

    def __init__(self, config):
        self._capstone = None
        self._capstone_version = None
        self._const = None
        self.config = config
        self.md = None

        self.bit_numbers = dict((1<<bit, "bit %s" % (bit,)) for bit in range(32))

        # Mapping of capstone registers to their names
        self.reg_map = {}
        self.capstone_map = {}

    @property
    def capstone(self):
        if self._capstone is not False:
            try:
                # Capstone is written by the same guy that provides Unicorn, which is
                # pretty neat.
                import capstone
                import capstone.arm64_const
                self._capstone = capstone
                self._capstone_version = capstone.cs_version()
                self._capstone_version_major = self._capstone_version[0]
                self._const = capstone.arm64_const
                self.md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
                self.md.syntax = capstone.CS_OPT_SYNTAX_NOREGNAME

                # Mapping of capstone register number to name, register number and width
                self.capstone_reg = {
                        capstone.arm64_const.ARM64_REG_W0:  ('w0', 0, 0xFFFFFFFF),
                        capstone.arm64_const.ARM64_REG_W1:  ('w1', 1, 0xFFFFFFFF),
                        capstone.arm64_const.ARM64_REG_W2:  ('w2', 2, 0xFFFFFFFF),
                        capstone.arm64_const.ARM64_REG_W3:  ('w3', 3, 0xFFFFFFFF),
                        capstone.arm64_const.ARM64_REG_W4:  ('w4', 4, 0xFFFFFFFF),
                        capstone.arm64_const.ARM64_REG_W5:  ('w5', 5, 0xFFFFFFFF),
                        capstone.arm64_const.ARM64_REG_W6:  ('w6', 6, 0xFFFFFFFF),
                        capstone.arm64_const.ARM64_REG_W7:  ('w7', 7, 0xFFFFFFFF),
                        capstone.arm64_const.ARM64_REG_W8:  ('w8', 8, 0xFFFFFFFF),
                        capstone.arm64_const.ARM64_REG_W9:  ('w9', 9, 0xFFFFFFFF),
                        capstone.arm64_const.ARM64_REG_W10: ('w10', 10, 0xFFFFFFFF),
                        capstone.arm64_const.ARM64_REG_W11: ('w11', 11, 0xFFFFFFFF),
                        capstone.arm64_const.ARM64_REG_W12: ('w12', 12, 0xFFFFFFFF),
                        capstone.arm64_const.ARM64_REG_W13: ('w13', 13, 0xFFFFFFFF),
                        capstone.arm64_const.ARM64_REG_W14: ('w14', 14, 0xFFFFFFFF),
                        capstone.arm64_const.ARM64_REG_W15: ('w15', 15, 0xFFFFFFFF),
                        capstone.arm64_const.ARM64_REG_W16: ('w16', 16, 0xFFFFFFFF),
                        capstone.arm64_const.ARM64_REG_W17: ('w17', 17, 0xFFFFFFFF),
                        capstone.arm64_const.ARM64_REG_W18: ('w18', 18, 0xFFFFFFFF),
                        capstone.arm64_const.ARM64_REG_W19: ('w19', 19, 0xFFFFFFFF),
                        capstone.arm64_const.ARM64_REG_W20: ('w20', 20, 0xFFFFFFFF),
                        capstone.arm64_const.ARM64_REG_W21: ('w21', 21, 0xFFFFFFFF),
                        capstone.arm64_const.ARM64_REG_W22: ('w22', 22, 0xFFFFFFFF),
                        capstone.arm64_const.ARM64_REG_W23: ('w23', 23, 0xFFFFFFFF),
                        capstone.arm64_const.ARM64_REG_W24: ('w24', 24, 0xFFFFFFFF),
                        capstone.arm64_const.ARM64_REG_W25: ('w25', 25, 0xFFFFFFFF),
                        capstone.arm64_const.ARM64_REG_W26: ('w26', 26, 0xFFFFFFFF),
                        capstone.arm64_const.ARM64_REG_W27: ('w27', 27, 0xFFFFFFFF),
                        capstone.arm64_const.ARM64_REG_W28: ('w28', 28, 0xFFFFFFFF),
                        capstone.arm64_const.ARM64_REG_W29: ('w29', 29, 0xFFFFFFFF),
                        capstone.arm64_const.ARM64_REG_W30: ('w30', 30, 0xFFFFFFFF),
                        capstone.arm64_const.ARM64_REG_X0:  ('x0', 0, 0xFFFFFFFFFFFFFFFF),
                        capstone.arm64_const.ARM64_REG_X1:  ('x1', 1, 0xFFFFFFFFFFFFFFFF),
                        capstone.arm64_const.ARM64_REG_X2:  ('x2', 2, 0xFFFFFFFFFFFFFFFF),
                        capstone.arm64_const.ARM64_REG_X3:  ('x3', 3, 0xFFFFFFFFFFFFFFFF),
                        capstone.arm64_const.ARM64_REG_X4:  ('x4', 4, 0xFFFFFFFFFFFFFFFF),
                        capstone.arm64_const.ARM64_REG_X5:  ('x5', 5, 0xFFFFFFFFFFFFFFFF),
                        capstone.arm64_const.ARM64_REG_X6:  ('x6', 6, 0xFFFFFFFFFFFFFFFF),
                        capstone.arm64_const.ARM64_REG_X7:  ('x7', 7, 0xFFFFFFFFFFFFFFFF),
                        capstone.arm64_const.ARM64_REG_X8:  ('x8', 8, 0xFFFFFFFFFFFFFFFF),
                        capstone.arm64_const.ARM64_REG_X9:  ('x9', 9, 0xFFFFFFFFFFFFFFFF),
                        capstone.arm64_const.ARM64_REG_X10: ('x10', 10, 0xFFFFFFFFFFFFFFFF),
                        capstone.arm64_const.ARM64_REG_X11: ('x11', 11, 0xFFFFFFFFFFFFFFFF),
                        capstone.arm64_const.ARM64_REG_X12: ('x12', 12, 0xFFFFFFFFFFFFFFFF),
                        capstone.arm64_const.ARM64_REG_X13: ('x13', 13, 0xFFFFFFFFFFFFFFFF),
                        capstone.arm64_const.ARM64_REG_X14: ('x14', 14, 0xFFFFFFFFFFFFFFFF),
                        capstone.arm64_const.ARM64_REG_X15: ('x15', 15, 0xFFFFFFFFFFFFFFFF),
                        capstone.arm64_const.ARM64_REG_X16: ('x16', 16, 0xFFFFFFFFFFFFFFFF),
                        capstone.arm64_const.ARM64_REG_X17: ('x17', 17, 0xFFFFFFFFFFFFFFFF),
                        capstone.arm64_const.ARM64_REG_X18: ('x18', 18, 0xFFFFFFFFFFFFFFFF),
                        capstone.arm64_const.ARM64_REG_X19: ('x19', 19, 0xFFFFFFFFFFFFFFFF),
                        capstone.arm64_const.ARM64_REG_X20: ('x20', 20, 0xFFFFFFFFFFFFFFFF),
                        capstone.arm64_const.ARM64_REG_X21: ('x21', 21, 0xFFFFFFFFFFFFFFFF),
                        capstone.arm64_const.ARM64_REG_X22: ('x22', 22, 0xFFFFFFFFFFFFFFFF),
                        capstone.arm64_const.ARM64_REG_X23: ('x23', 23, 0xFFFFFFFFFFFFFFFF),
                        capstone.arm64_const.ARM64_REG_X24: ('x24', 24, 0xFFFFFFFFFFFFFFFF),
                        capstone.arm64_const.ARM64_REG_X25: ('x25', 25, 0xFFFFFFFFFFFFFFFF),
                        capstone.arm64_const.ARM64_REG_X26: ('x26', 26, 0xFFFFFFFFFFFFFFFF),
                        capstone.arm64_const.ARM64_REG_X27: ('x27', 27, 0xFFFFFFFFFFFFFFFF),
                        capstone.arm64_const.ARM64_REG_X28: ('x28', 28, 0xFFFFFFFFFFFFFFFF),
                        capstone.arm64_const.ARM64_REG_X29: ('x29', 29, 0xFFFFFFFFFFFFFFFF),
                        capstone.arm64_const.ARM64_REG_X30: ('lr', 30, 0xFFFFFFFFFFFFFFFF),
                    }
                self.md.detail = True
                return self._capstone

            except ImportError:
                self._capstone = False

        return None

    @property
    def available(self):
        return bool(self.capstone)

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

    def describe_code(self, addr):
        """
        Describe the code at a given address.

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
                return function_name
        return None

    def get_swi_name(self, swi):
        """
        Decode a SWI number into a SWI name.

        @param swi: SWI number to decode

        @return:    SWI name, eg "OS_WriteC", "OS_WriteI+'B'", "XIIC_Control", or &XXXXX
        """
        return '&{:x}'.format(swi)

    def get_reg(self, regnum):
        """
        Return the current value of a register (only used when live_registers is True).

        @param regnum:  Register number to read (0-31)

        @return: Value of the register
        """
        return 0

    def get_cpsr(self):
        """
        Return the current value of CPSR (only used when live_registers is True).

        @return: Value of the CPSR
        """
        return 0

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

    def get_memory_string(self, addr):
        """
        Read the current value of a control terminated string from memory
        (only used when live_memory is True).

        @param addr:    Address to read the value of

        @return:    String read (as a bytes sequence)
                    None if no memory is present
        """
        return None

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

    def psr_name(self, psr, mask):
        """
        Decode the PSR into a string.

        @param psr:     The value of the PSR to decode, or None to use the actual CPSR
        @param mask:    The values from the PSR to decode into the string.

        @return:        String representation of the PSR values.
        """
        # FIXME: Decode PSR
        return "&{:08x}".format(psr)

    def _operand_constant(self, operand, negated=False):
        """
        Return a list of constant values if we can.
        """
        accumulator = []
        if operand.type == self._const.ARM64_OP_IMM:
            imm = operand.imm
            if negated:
                #imm = imm ^ 0xFFFFFFFF
                imm = imm ^ 0xFFFFFFFFFFFFFFFF
            if operand.shift and operand.shift.type == self._const.ARM64_SFT_LSL:
                imm = imm << operand.shift.value
                imm = imm & 0xFFFFFFFFFFFFFFFF
            if imm > 10 or imm < 0:
                values = []
                if imm >= 0x20 and imm < 0x7f:
                    values.append("%-3i" % (imm,))
                    values.append("'%s'" % (chr(imm),))
                elif negated:
                    values.append('&%08x' % (imm,))
                    values.append('%i' % (~operand.imm,))
                else:
                    values.append('%i' % (imm,))
                if imm in self.bit_numbers:
                    values.append(self.bit_numbers[imm])

                accumulator.append("#%s" % (' = '.join(values),))

        return accumulator

    def _value_description(self, value, negated=False):
        values = []
        if value >= 0x20 and value < 0x7f:
            values.append("%-3i" % (value,))
            values.append("'%s'" % (chr(value),))
        elif negated:
            values.append('&%016x' % (value,))
            #values.append('%i' % (~operand.value,))
        else:
            if value > 0xFFFFFFFF:
                values.append("&%016x" % (value,))
            else:
                values.append("&%08x" % (value,))
                if value < 0x100000:
                    values.append('%i' % (value,))
        if value in self.bit_numbers:
            values.append(self.bit_numbers[value])
        return ' = '.join(values)

    def _capstone_reg_assignment(self, regmap):
        """
        Return the string describing a register from the register mapping.

        @param cregnum: Capstone register number

        @return: String describing its current value
        """
        regnum = regmap[1]
        value = self.get_reg(regnum & 31)
        value = value & regmap[2]
        return "%s = %s" % (regmap[0], self._value_description(value))

    def _capstone_reg_value(self, regmap):
        """
        Return the current value of a register from the register mapping.

        @param cregnum: Capstone register number

        @return: Value of the register
        """
        regnum = regmap[1]
        value = self.get_reg(regnum & 31)
        value = value & regmap[2]
        return value

    def _operand_multiple_registers(self, operands, maybe_presentable=False):
        """
        Return a list of register values related to the list of operands supplied.

        We will omit operands which have been repeated in the arguments; this
        prevents us reporting R0 multiple times in AND r0, r0, r0 (for example).
        """
        accumulator = []
        seen = set()
        for operand in operands:
            if operand.type == self._const.ARM64_OP_REG:
                if operand.reg not in seen:
                    accumulator.extend(self._operand_registers(operand, maybe_presentable=maybe_presentable))
                    seen.add(operand.reg)
            else:
                accumulator.extend(self._operand_registers(operand, maybe_presentable=maybe_presentable))

        return accumulator

    def _operand_registers(self, operand, maybe_presentable=False):
        """
        Return a list of register values related to the operand supplied
        """
        accumulator = []
        if operand.type == self._const.ARM64_OP_REG:
            regmap = self.capstone_reg.get(operand.reg, None)
            if regmap is not None:
                accumulator.append(self._capstone_reg_assignment(regmap))

        if operand.type == self._const.ARM64_OP_MEM:
            # Base
            base = None
            regmap = self.capstone_reg.get(operand.mem.base, None)
            if regmap is not None:
                base = self._capstone_reg_value(regmap)
                accumulator.append(self._capstone_reg_assignment(regmap))

            # Index
            regmap = self.capstone_reg.get(operand.mem.index, None)
            if regmap is not None:
                accumulator.append(self._capstone_reg_assignment(regmap))
            else:
                # There's no index, so we'll check if there's a presentable value string at that position
                if base is not None and maybe_presentable and self.config.show_referenced_pointers:
                    desc = self.describe_address(base)
                    if desc:
                        # The description may have multiple elements, so comma separate them
                        desc = ', '.join(desc)
                        accumulator[-1] += ' ({})'.format(desc)

        return accumulator

    def _fixup_shifted_constant(self, op_str, operand):
        """
        If the constant has a shift in it, replace the shift with the literal value.
        """
        if operand.shift.type == self._const.ARM64_SFT_LSL:
            # Used for MOVK and others
            imm = operand.imm << operand.shift.value
            (left, right) = op_str.split('#', 1)
            left += '#&%x' % (imm,)
            op_str = left
        return op_str

    def disassemble_instruction(self, address, inst,
                                live_registers=False, live_memory=False):
        """
        Disassemble an instruction into broken down values.

        @param address:         Address the instruction comes from
        @param inst:            32bit instruction word
        @param live_registers:  Whether registers may be used to provide more information
        @param live_memory:     Whether memory reads may be used to provide more information

        @return: Tuple of (bytes-consumed, mnemonic string, operands string, comment string)
                 Mnemonic string, operands string and comment string will be None if no
                 disassembly was available.
        """
        if not self.capstone:
            return (4, None, None, None)

        self.md.mode = self._capstone.CS_MODE_ARM
        for i in self.md.disasm(inst, address):
            mnemonic = i.mnemonic.upper()
            op_str = i.op_str

            op_str = op_str.replace('0x', '&')
            comment = None
            if mnemonic[0:3] == 'SVC':
                # Manually replace the mnemonic, due to bug in earlier capstone
                mnemonic = 'SWI' + mnemonic[3:]

                swi = None
                if live_registers:
                    # If we have live registers, we can decode the SWI number.
                    system_swi = i.operands[0].imm
                    if system_swi == 0:
                        # This is a RISC OS system SWI

                        # Look up the SWI number, if we can.
                        swi = self.get_reg(10)

                        # Special cases for some SWIs
                        swic = swi & ~0x20000
                        if swic == 1:
                            # OS_WriteS
                            if live_memory:
                                # FIXME: Maybe this should be just safe_string, and we replace control characters with escapes?
                                # FIXME: Truncate this string if it's long?
                                string = self.get_memory_string(address + 4)
                                if string:
                                    string = "\"%s\"" % (string.decode('latin-1').encode('ascii', 'backslashreplace'),)
                                    comment = ' (PC+4 = {})'.format(string)

                        elif swic == 2:
                            # OS_Write0
                            if live_memory and live_registers:
                                r0 = self.get_reg(0)
                                string = self.get_memory_string(r0)
                                if string:
                                    string = "\"%s\"" % (string.decode('latin-1').encode('ascii', 'backslashreplace'),)
                                    comment = ' ({})'.format(string)
                elif live_memory:
                    # If we have live memory, we may be able to decode the SWI number
                    # If the sequence is MOVZ x10, #<value>
                    before_1 = self.get_memory_word(address - 4)
                    masked = before_1 & ~0x1fffe0
                    swi =  None
                    if masked == 0xd280000a:
                        # MOVZ instruction
                        swi = (before_1 >> 5) & 65535
                    elif masked == 0xf2a0000a:
                        # MOVK instruction
                        # The preceding instruction should be MOVZ
                        before_2 = self.get_memory_word(address - 8)
                        masked = before_2 & ~0x1fffe0
                        if masked == 0xd280000a:
                            swi = ((before_2 >> 5) & 65535)
                            swi |= ((before_1 >> 5) & 65535) << 16

                if swi is not None:
                    swi_name = self.get_swi_name(swi)
                    if swi_name is None:
                        comment = 'SWI &%06X' % (swi,)
                    else:
                        comment = "SWI %s" % (swi_name,)

            elif mnemonic in ('B', 'BL', 'BL.') or mnemonic[:2] == 'B.':
                if op_str[0:2] == '#&':
                    op_str = '&%08x' % (int(op_str[2:], 16),)
                if live_memory:
                    # We can allow this to be omitted in cases if the memory that's being debugged
                    # is not actually live memory (could be relocated, synthetic, etc).
                    addr = i.operands[0].imm
                    func = self.describe_code(addr)
                    if func:
                        comment = '-> Function: %s' % (func,)

            elif mnemonic[0:3] == 'ADR' and \
                 i.operands[1].type == self._const.ARM64_OP_IMM:
                imm = i.operands[1].imm
                op_prefix, _ = op_str.split(',', 1)
                op_suffix = '&%08X' % (imm,)
                op_str = '%s, %s' % (op_prefix, op_suffix)

                if live_memory:
                    desc = self.describe_address(imm)
                    if desc:
                        comment = '-> %s' % ('; '.join(desc),)

            elif mnemonic[0:3] in ('LDR', 'STR'):
                if live_registers and self.config.show_referenced_registers:
                    if mnemonic[0:3] == 'STR':
                        accumulator = self._operand_registers(i.operands[0])
                        accumulator.extend(self._operand_registers(i.operands[1]))
                        more = ', '.join(accumulator)
                        comment = '%s; %s' % (comment, more) if comment else more

                    elif mnemonic[0:3] == 'LDR':
                        # Show the values of the referenced registers
                        maybe_string = 'B' in mnemonic
                        accumulator = self._operand_registers(i.operands[1], maybe_presentable=maybe_string)
                        more = ', '.join(accumulator)
                        comment = '%s; %s' % (comment, more) if comment else more

                if '[' not in op_str and '#&' in op_str:
                    (before, after) = op_str.split('#&')
                    op_str = "{}&{:08x}".format(before, int(after, 16))
                    # FIXME: Include the quad/word/byte/halfword we loaded?

            elif (mnemonic[0:3] in ('ADD', 'SUB', 'ORR', 'AND', 'EOR', 'LSL', 'LSR') or
                  mnemonic in ('CSEL',)):

                accumulator = []
                if live_registers and self.config.show_referenced_registers:
                    accumulator.extend(self._operand_multiple_registers([i.operands[1],
                                                                         i.operands[2]]))

                accumulator.extend(self._operand_constant(i.operands[2]))

                if i.operands[2].type == self._const.ARM64_OP_IMM:
                    op_str = self._fixup_shifted_constant(op_str, i.operands[2])

                if accumulator:
                    comment = ', '.join(accumulator)

            elif mnemonic[0:3] in ('MOV', 'CMP'):

                accumulator = []

                if live_registers and self.config.show_referenced_registers:
                    if mnemonic[0:4] == 'MOVK' or mnemonic[0:3] == 'CMP':
                        accumulator.extend(self._operand_registers(i.operands[0]))
                    accumulator.extend(self._operand_registers(i.operands[1]))

                accumulator.extend(self._operand_constant(i.operands[1],))

                if i.operands[1].type == self._const.ARM64_OP_IMM:
                    op_str = self._fixup_shifted_constant(op_str, i.operands[1])

                if accumulator:
                    comment = ', '.join(accumulator)

            elif mnemonic in ('CBZ', 'CBNZ'):

                accumulator = []
                if live_registers and self.config.show_referenced_registers:
                    accumulator.extend(self._operand_registers(i.operands[0]))

                if '#&' in op_str:
                    (before, after) = op_str.split('#&')
                    op_str = "{}&{:08x}".format(before, int(after, 16))

                if live_memory:
                    # We can allow this to be omitted in cases if the memory that's being debugged
                    # is not actually live memory (could be relocated, synthetic, etc).
                    addr = i.operands[1].imm
                    func = self.describe_code(addr)
                    if func:
                        accumulator.append('-> Function: %s' % (func,))

                if accumulator:
                    comment = ', '.join(accumulator)

            elif mnemonic in ('CSINC', 'CSINV', 'CSNEG'):

                accumulator = []
                if live_registers and self.config.show_referenced_registers:
                    accumulator.extend(self._operand_multiple_registers(i.operands[1:3]))

                if accumulator:
                    comment = ', '.join(accumulator)

            if live_memory:
                # Check if this is a function entry point
                funcname = self.describe_code(address)
                if funcname and '+' not in funcname:
                    if comment:
                        comment = 'Function: %s  ; %s' % (funcname, comment)
                    else:
                        comment = 'Function: %s' % (funcname,)

            return (4, mnemonic, op_str, comment)

        return (4, 'Undefined instruction', None, None)

    def disassemble(self, address, inst,
                    live_registers=False, live_memory=False):
        """
        Disassemble an instruction into a formatted string.

        @param address:         Address the instruction comes from
        @param inst:            32bit/16bit instruction word
        @param live_registers:  Whether registers may be used to provide more information
        @param live_memory:     Whether memory reads may be used to provide more information

        @return:         Tuple of (consumed, string describing the instruction or None if not disassembly)
        """
        (consumed, mnemonic, op_str, comment) = self.disassemble_instruction(address, inst,
                                                                             live_registers=live_registers,
                                                                             live_memory=live_memory)
        if mnemonic:
            if comment:
                op_str = op_str + (' ' * (24 - len(op_str))) + "  ; " + comment
            if op_str:
                text = "%-8s%s" % (mnemonic, op_str)
            else:
                text = mnemonic
            return (consumed, text)

        return (consumed, mnemonic)
