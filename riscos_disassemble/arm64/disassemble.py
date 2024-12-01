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
the accessor object will be called to obtain more information.

The accessor object is initialised on class initialisation, and contains
functions which can read the memory, registers, and descriptions of the
state of the system. See the access.py file for more details.

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

import re
import struct
import sys

from .. import base


class DisassembleARM64Config(object):
    """
    Configuration for how the disassembly should be performed by the Disassemble class.
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


@base.register_disassembler
class DisassembleARM64(base.DisassembleBase):
    # Architecture name
    arch = "arm64"

    # Minimum width in bytes of instructions
    inst_width_min = 4

    # Maximum width in bytes of instructions
    inst_width_max = 4

    # The default class to use if no configuration is supplied
    default_config = DisassembleARM64Config

    # Colouring parameters
    inst_re = re.compile('([A-Za-z][A-Za-z0-9]+|B(?:\.[A-Z]+)?)(\s*)')

    operand_categories = base.DisassembleBase.operand_categories + [
            (re.compile(r'[XW]3[01]|[XW][12][0-9]|[XW][0-9]|xzr|wzr|sp|lr|pc', re.IGNORECASE), 'register'),
            (re.compile(r'p1[0-5]|p[0-9]|c[0-7]', re.IGNORECASE), 'register-control'),
            (re.compile(r'[+-]?([0-9]{1,9}|(&|0x)[0-9A-F]{1,16})', re.IGNORECASE), 'number'),
            (re.compile(r'LSR|LSL|ROR|ASR|uxtb|sxtb|uxth|sxth|uxtw|sxtw', re.IGNORECASE), 'shift'),
        ]

    inst_category = {
            'PUSH': 'inst-stack',  # PUSH
            'POP': 'inst-stack',
        }

    inst_category_prefix2 = {
            'B.': 'inst-branch',
            'BL': 'inst-branch',
        }

    inst_category_prefix3 = {
            'SWI': 'inst-swi',
            'LDR': 'inst-mem',
            'STR': 'inst-mem',
            'LDP': 'inst-memmultiple',
            'STP': 'inst-memmultiple',
            'BIC': 'inst',
        }

    def __init__(self, *args, **kwargs):
        super(DisassembleARM64, self).__init__(*args, **kwargs)
        self._capstone = None
        self._capstone_version = None
        self._const = None
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
                    desc = self.access.describe_address(base)
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

        if live_memory:
            # Check if this is has a data description
            content = self.access.describe_content(address)
            if content:
                return (4, None, None, content)

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
                                string = self.access.get_memory_string(address + 4)
                                if string:
                                    string = "\"%s\"" % (string.decode('latin-1').encode('ascii', 'backslashreplace'),)
                                    comment = ' (PC+4 = {})'.format(string)

                        elif swic == 2:
                            # OS_Write0
                            if live_memory and live_registers:
                                r0 = self.get_reg(0)
                                string = self.access.get_memory_string(r0)
                                if string:
                                    string = "\"%s\"" % (string.decode('latin-1').encode('ascii', 'backslashreplace'),)
                                    comment = ' ({})'.format(string)
                elif live_memory:
                    # If we have live memory, we may be able to decode the SWI number
                    # If the sequence is MOVZ x10, #<value>
                    before_1 = self.access.get_memory_word(address - 4)
                    masked = before_1 & ~0x1fffe0
                    swi =  None
                    if masked == 0xd280000a:
                        # MOVZ instruction
                        swi = (before_1 >> 5) & 65535
                    elif masked == 0xf2a0000a:
                        # MOVK instruction
                        # The preceding instruction should be MOVZ
                        before_2 = self.access.get_memory_word(address - 8)
                        masked = before_2 & ~0x1fffe0
                        if masked == 0xd280000a:
                            swi = ((before_2 >> 5) & 65535)
                            swi |= ((before_1 >> 5) & 65535) << 16

                if swi is not None:
                    swi_name = self.access.decode_swi(swi)
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
                    func = self.access.describe_code(addr)
                    if func:
                        comment = '-> Function: %s' % (func,)

            elif mnemonic[0:3] == 'ADR' and \
                 i.operands[1].type == self._const.ARM64_OP_IMM:
                imm = i.operands[1].imm
                op_prefix, _ = op_str.split(',', 1)
                op_suffix = '&%08x' % (imm,)
                op_str = '%s, %s' % (op_prefix, op_suffix)

                if live_memory:
                    desc = self.access.describe_address(imm)
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

                    if mnemonic == 'ADD':
                        if live_memory:
                            # Check whether we're preceeded by ADRP
                            this = self.access.get_memory_word(address)
                            before = self.access.get_memory_word(address - 4)
                            imm = i.operands[2].imm
                            if before is not None and \
                               (before & 0x90000000) == 0x90000000 and \
                               (before & 31) == ((this>>5) & 31):
                                # The instruction before is an ADRP,
                                # and the ADRP Xd is the same as ADD Xn.
                                # So we need to calculate the target address
                                immhi = ((before & ((1<<24) - 1)) >> 5)
                                immlo = ((before>>29) & 3)
                                offset = ((immhi << 2) | immlo) << 12
                                if offset & (1<<23):
                                    offset -= (1<<24)

                                target = ((address - 4) & ~4095) + offset + i.operands[2].imm

                                desc = self.access.describe_address(target)
                                if desc:
                                    accumulator.append('(long)-> &%08x = %s' % (target, '; '.join(desc),))

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
                    func = self.access.describe_code(addr)
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
                funcname = self.access.describe_code(address)
                if funcname and '+' not in funcname:
                    if comment:
                        comment = 'Function: %s  ; %s' % (funcname, comment)
                    else:
                        comment = 'Function: %s' % (funcname,)

                content = self.access.describe_code_comment(address)
                if content:
                    if comment:
                        comment = '%s  ; %s' % (content, comment)
                    else:
                        comment = content

            return (4, mnemonic, op_str, comment)

        # Undefined instructions can still have comments
        comment = None
        if live_memory:
            # Check if this is has a data description
            content = self.access.describe_content(address)
            if content:
                if comment:
                    comment = '%s  ; %s' % (content, comment)
                else:
                    comment = content

            content = self.access.describe_code_comment(address)
            if content:
                if comment:
                    comment = '%s  ; %s' % (content, comment)
                else:
                    comment = content

        return (4, self.undefined, None, comment)

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
                if op_str:
                    op_str = op_str + (' ' * (24 - len(op_str))) + "  ; " + comment
                else:
                    lmnem = len(mnemonic)
                    if lmnem < 8:
                        lmnem = 0
                    else:
                        lmnem -= 8
                    op_str = (' ' * (24 - lmnem)) + "  ; " + comment
            if op_str:
                text = "%-8s%s" % (mnemonic, op_str)
            else:
                text = mnemonic
            return (consumed, text)

        elif comment:
            return (consumed, "; %s" % (comment,))

        return (consumed, mnemonic)
