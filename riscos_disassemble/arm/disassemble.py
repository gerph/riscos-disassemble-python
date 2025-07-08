"""
Disassembly of instructions in RISC OS style.

This module is used to perform disassembly of ARM and Thumb instructions
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


class DisassembleARMConfig(object):
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

    support_fpa = True
    """
    Controls whether the FPA instructions will be disassembled. By default we enable
    this, as most of RISC OS will expect to use them and the generic instruction forms
    will not be familiar. However, the support for these instructions in the
    disassembler may be incomplete, so they may be disabled.
    """

    rename_r13_to_sp = True
    """
    Controls whether we use `sp` in place of `r13` in the disassembly. By default we
    make this change. In almost all RISC OS code, register 13 will refer to the stack
    pointer.
    """

    rename_r14_to_lr = True
    """
    Controls whether we use `lr` in place of `r14` in the disassembly. By default we
    make this change. In almost all RISC OS code, register 14 will refer to the link
    register.
    """


@base.register_disassembler
class DisassembleARM(base.DisassembleBase):
    # Architecture name
    arch = "arm"

    # Minimum width in bytes of instructions
    inst_width_min = 4

    # Maximum width in bytes of instructions
    inst_width_max = 4

    # The default class to use if no configuration is supplied
    default_config = DisassembleARMConfig

    cc_values = {
            0: "EQ",
            1: "NE",
            2: "CS",
            3: "CC",
            4: "MI",
            5: "PL",
            6: "VS",
            7: "VC",
            8: "HI",
            9: "LS",
            10: "GE",
            11: "LT",
            12: "GT",
            13: "LE",
            14: "AL",
            15: "NV",
        }

    psr_modes = [
            "USR",  "FIQ",  "IRQ",      "SVC",
            "0100", "0101", "MON/0110", "ABT/0111",
            "1000", "1001", "HYP/1010", "UND/1011",
            "1100", "1101", "1110",     "SYS/1111"
        ]

    # None is used to mark breaks in the flags
    psr_flags = [
            (6, 'c', 'f'),
            (7, 'c', 'i'),
            None,
            (8, 'x', 'a'),
            (9, 'x', 'e'),
            None,
            (27, 'f', 'q'),
            (28, 'f', 'v'),
            (29, 'f', 'c'),
            (30, 'f', 'z'),
            (31, 'f', 'n'),
        ]

    # Colouring parameters
    operand_categories = base.DisassembleBase.operand_categories + [
            (re.compile(r'R1[0-5]|R[0-9]|[ca]psr|spsr(_[a-z]+)?|sp|lr|pc', re.IGNORECASE), 'register'),
            (re.compile(r'F[0-7]', re.IGNORECASE), 'register-fp'),
            (re.compile(r'p1[0-5]|p[0-9]|c[0-7]', re.IGNORECASE), 'register-control'),
            (re.compile(r'[+-]?([0-9]{1,9}|&[0-9A-F]{1,8})', re.IGNORECASE), 'number'),
            (re.compile(r'LSR|LSL|ROL|ROR|RRX|ASR', re.IGNORECASE), 'shift'),
        ]

    inst_category = {
            'PUSH': 'inst-stack',  # PUSH
            'POP': 'inst-stack',
        }

    inst_category_prefix3 = {
            'SWI': 'inst-swi',
            'LDR': 'inst-mem',
            'STR': 'inst-mem',
            'LDM': 'inst-memmultiple',
            'STM': 'inst-memmultiple',
            'BIC': 'inst',

            # FP instructions:
            'LDF': 'inst-fp',
            'STF': 'inst-fp',
            'LFM': 'inst-fp',
            'SFM': 'inst-fp',

            'ADF': 'inst-fp',   #... binary ops
            'MUF': 'inst-fp',
            'SUF': 'inst-fp',
            'RSF': 'inst-fp',
            'DVF': 'inst-fp',
            'RDF': 'inst-fp',
            'POW': 'inst-fp',
            'RPW': 'inst-fp',
            'RMF': 'inst-fp',
            'FML': 'inst-fp',
            'FDV': 'inst-fp',
            'FRD': 'inst-fp',
            'POL': 'inst-fp',
            'F0D': 'inst-fp',  # ... undefined binary ops
            'F0E': 'inst-fp',
            'F0F': 'inst-fp',
            'MVF': 'inst-fp',  # ... unary ops
            'MNF': 'inst-fp',
            'ABS': 'inst-fp',
            'RND': 'inst-fp',
            'SQT': 'inst-fp',
            'LOG': 'inst-fp',
            'LGN': 'inst-fp',
            'EXP': 'inst-fp',
            'SIN': 'inst-fp',
            'COS': 'inst-fp',
            'TAN': 'inst-fp',
            'ASN': 'inst-fp',
            'ACS': 'inst-fp',
            'ATN': 'inst-fp',
            'URD': 'inst-fp',
            'NRM': 'inst-fp',

            'CMF': 'inst-fp',
            'CNF': 'inst-fp',
            'FLT': 'inst-fp',
            'FIX': 'inst-fp',
            'WFS': 'inst-fp',
            'RFS': 'inst-fp',
            'WFC': 'inst-fp',
            'RFC': 'inst-fp',
        }

    inst_category_prefix4 = {}
    inst_category_conditional = {}

    def __init__(self, *args, **kwargs):
        super(DisassembleARM, self).__init__(*args, **kwargs)
        self._capstone = None
        self._capstone_version = None
        self._const = None
        self.md = None

        # Values initialised when capstone is initialised
        self.mnemonic_replacements = {}
        self.reg_map = []
        self.inv_reg_map = {}
        self.cc_names = {}

        self.bit_numbers = dict((1<<bit, "bit %s" % (bit,)) for bit in range(32))

    @property
    def capstone(self):
        if self._capstone is not False:
            try:
                # Capstone is written by the same guy that provides Unicorn, which is
                # pretty neat.
                import capstone
                import capstone.arm_const
                self._capstone = capstone
                self._capstone_version = capstone.cs_version()
                self._capstone_version_major = self._capstone_version[0]
                self._const = capstone.arm_const
                self.md = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM)
                self.md.syntax = capstone.CS_OPT_SYNTAX_NOREGNAME

                self.reg_map = [
                        capstone.arm_const.ARM_REG_R0,
                        capstone.arm_const.ARM_REG_R1,
                        capstone.arm_const.ARM_REG_R2,
                        capstone.arm_const.ARM_REG_R3,
                        capstone.arm_const.ARM_REG_R4,
                        capstone.arm_const.ARM_REG_R5,
                        capstone.arm_const.ARM_REG_R6,
                        capstone.arm_const.ARM_REG_R7,
                        capstone.arm_const.ARM_REG_R8,
                        capstone.arm_const.ARM_REG_R9,
                        capstone.arm_const.ARM_REG_R10,
                        capstone.arm_const.ARM_REG_R11,
                        capstone.arm_const.ARM_REG_R12,
                        capstone.arm_const.ARM_REG_SP,
                        capstone.arm_const.ARM_REG_LR,
                        capstone.arm_const.ARM_REG_PC,
                    ]
                self.inv_reg_map = dict((regval, regnum) for regnum, regval in enumerate(self.reg_map))

                # Map of capstone constant to CC name
                self.cc_names = {}
                for cc in dir(capstone.arm_const):
                    if cc.startswith('ARM_CC_') and cc != 'ARM_CC_INVALID':
                        self.cc_names[getattr(capstone.arm_const, cc)] = cc[-2:]

                self.mnemonic_replacements = {}
                self.mnemonic_replacements.update(dict(('LDM%s' % (cc,), 'LDM%sIA' % (cc,)) for cc in self.cc_names.values()))
                self.mnemonic_replacements['LDM'] = 'LDMIA'
                self.mnemonic_replacements.update(dict(('STM%s' % (cc,), 'STM%sIA' % (cc,)) for cc in self.cc_names.values()))
                self.mnemonic_replacements['STM'] = 'STMIA'

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

        if mask is None:
            mask = 'fsxc'

        if mask == 'nzcvq':
            mask = 'f'

        # Logic taken from BTSDump/arm.c
        if psr is None:
            psr = self.get_pstate()
        is26bit = (psr & (1<<4)) == 0
        mode = psr & 15
        mode_name = self.psr_modes[mode]

        if 'c' in mask:
            if (is26bit and mode <= 3) or \
               (not is26bit and mode_name[0] not in ('0', '1')):
                if '/' in mode_name:
                    mode_name = mode_name[:3]
                mode_name += '-26' if is26bit else '-32'
            else:
                # Not a mode we understand:
                if '/' in mode_name[0]:
                    mode_name = mode_name[4:]
                mode_name = ('0' if is26bit else '1') + mode_name + '?'
            t_bit = psr & (1<<5)
            j_bit = psr & (1<<24)
            if t_bit:
                exec_mode = 'Thm'
            else:
                if j_bit:
                    exec_mode = 'Jav'
                else:
                    exec_mode = 'ARM'
        else:
            # This mode was not requested
            mode_name = '------'
            exec_mode = '---'

        flags = []
        for flag in self.psr_flags:
            if flag is None:
                flags.append(' ')
            else:
                (bit, masked, name) = flag
                if masked in mask:
                    if psr & (1<<bit):
                        flags.append(name.upper())
                    else:
                        flags.append(name)
                else:
                    flags.append('-')

        return '%s %s %s' % (mode_name, exec_mode, ''.join(flags))

    def _operand_constant(self, operand, shift=None, negated=False):
        """
        Return a list of constant values if we can.
        """
        accumulator = []
        if operand.type == self._const.ARM_OP_IMM:
            imm = operand.imm
            if negated:
                imm = imm ^ 0xFFFFFFFF
            if shift and shift.type == self._const.ARM_OP_IMM:
                # Has an explicit rotate
                imm = (imm << (32 - shift.imm)) | (imm >> shift.imm)
                imm = imm & 0xFFFFFFFF
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
                else:
                    imm32 = imm & 0xFFFFFFFF
                    if imm32 > 4096:
                        for bitshift, mask in ((28, 0xFFFFFFF),
                                               (24, 0xFFFFFF),
                                               (20, 0xFFFFF),
                                               (16, 0xFFFF),
                                               (12, 0xFFF),
                                               (8, 0xFF)):
                            if (imm32 & mask) == 0:
                                shifted = imm32 >> bitshift
                                if shifted != 1:
                                    # Never report 1<<bit as that's covered by the 'bit #' check
                                    values.append("%i<<%i" % (shifted, bitshift))
                                break

                accumulator.append("#%s" % (' = '.join(values),))

        return accumulator

    def _operand_multiple_registers(self, operands, shift=None, maybe_presentable=False):
        """
        Return a list of register values related to the list of operands supplied.

        We will omit operands which have been repeated in the arguments; this
        prevents us reporting R0 multiple times in AND r0, r0, r0 (for example).
        """
        accumulator = []
        seen = set()
        for operand in operands:
            if operand.type == self._const.ARM_OP_REG:
                if operand.reg not in seen:
                    accumulator.extend(self._operand_registers(operand, maybe_presentable=maybe_presentable))
                    seen.add(operand.reg)
            else:
                accumulator.extend(self._operand_registers(operand, shift=shift, maybe_presentable=maybe_presentable))

        return accumulator

    def _operand_registers(self, operand, shift=None, maybe_presentable=False):
        """
        Return a list of register values related to the operand supplied

        @param operand:             The Capstone operand to display
        @param shift:               Operand for shifting
        @param maybe_presentable:   True to describe addresses and pointers.
        """
        accumulator = []
        if operand.type == self._const.ARM_OP_REG:
            regnum = self.inv_reg_map.get(operand.reg, None)
            if regnum is not None:
                accumulator.append('R%i = &%08x' % (regnum, self.get_reg(regnum)))
        if operand.type == self._const.ARM_OP_MEM:
            # Base
            base = None
            regnum = self.inv_reg_map.get(operand.mem.base, None)
            if regnum is not None:
                base = self.get_reg(regnum)
                accumulator.append('R%i = &%08x' % (regnum, base))

            # Index
            regnum = self.inv_reg_map.get(operand.mem.index, None)
            if regnum is not None:
                accumulator.append('R%i = &%08x' % (regnum, self.get_reg(regnum)))
            else:
                # There's no index, so we'll check if there's a presentable value string at that position
                if base is not None and maybe_presentable and self.config.show_referenced_pointers:
                    desc = self.access.describe_address(base)
                    if desc:
                        # The description may have multiple elements, so comma separate them
                        desc = ', '.join(desc)
                        accumulator[-1] += ' ({})'.format(desc)

            # FIXME: Is lshift also a register here?

        if operand.shift.type != self._const.ARM_SFT_INVALID:
            if operand.shift.type in (self._const.ARM_SFT_LSL_REG,
                                      self._const.ARM_SFT_LSR_REG,
                                      self._const.ARM_SFT_ASR_REG,
                                      self._const.ARM_SFT_ROR_REG):
                # This is a shift by a register, so we can include its value in the result
                regnum = self.inv_reg_map.get(operand.shift.value, None)
                if regnum is not None:
                    accumulator.append('R%i = &%08x' % (regnum, self.get_reg(regnum)))

        return accumulator

    def _tidy_shifts(self, instr):
        """
        Replace the lower case shifts with upper case ones to match the mnemonics.
        """
        if 'r ' in instr:
            instr = instr.replace('lsr', 'LSR')
            instr = instr.replace('asr', 'ASR')
            instr = instr.replace('ror', 'ROR')
        else:
            instr = instr.replace('lsl', 'LSL')
            instr = instr.replace('rrx', 'RRX')
        return instr

    def disassemble_fpa_instruction(self, i, mnemonic, op_str):
        word = struct.unpack('<L', i.bytes)[0]
        if False:
            # For debugging the FPA instructions.
            print("dir:")
            for n in dir(i):
                if n[0] != '_':
                    v = getattr(i, n)
                    if callable(v):
                        try:
                            s = v()
                        except Exception as exc:
                            s = '<not callable: %s>' % (exc,)
                        v = "%r: %s" % (v, s)
                    print("  %s: %s" % (n, v))

            print("bytes: %r" % (i.bytes,))
            print("word: &%08x" % (word,))

        opcode = (word>>24) & 15

        def operand_fm(word):
            immediate = (word & 8)
            value = (word & 7)

            fp_immediates = [
                    "0", "1", "2", "3", "4", "5", "0.5", "10"
                ]

            if immediate:
                operand = "#{}".format(fp_immediates[value])
            else:
                operand = "F{}".format(value)
            return operand

        if opcode in (12, 13) and (word>>8) & 15 == 1:
            # LDF/STF
            # format is        cccc 110p uywl nnnn xddd 0001 iiii iiii
            #
            # <LDF|STF>{cond}<S|D|E|P> Fd,[Rn,#imm]{!}
            # <LDF|STF>{cond}<S|D|E|P> Fd,[Rn],#imm
            #
            # where cccc = condition
            #          p = Pre-indexing/~Post-indexing
            #          u = Up/~Down
            #         yx = transfer length (S,D,E or P)
            #          w = Writeback
            #          l = Load/~Store
            #       nnnn = Rn
            #        ddd = Fd
            #   iiiiiiii = 8-bit immediate offset
            cc = self.cc_values[word>>28]
            if cc == 'AL':
                cc = ''
            mnemonic = 'LDF' if word & (1<<20) else 'STF'
            # Length bits are not contiguous
            length = 'SDEP'[((word >> 21) & 2) + ((word >> 15) & 1)]
            preindex = word & (1<<24)
            up = word & (1<<23)
            armreg = (word>>16) & 15
            fpreg = (word>>12) & 7
            offset = (word & 255) * 4
            if not up:
                offset = -offset
            writeback = word & (1<<21)
            mnemonic = "{}{}{}".format(mnemonic, cc, length)
            if preindex:
                if armreg == 15:
                    access = "&{:08x}".format(i.address + 8 + offset)
                else:
                    if offset == 0:
                        access = "[R{}]{}".format(armreg, "!" if writeback else "")
                    else:
                        access = "[R{}, #{}]{}".format(armreg, offset, "!" if writeback else "")
            else:
                access = "[R{}], #{}".format(armreg, offset)
            op_str = "F{}, {}".format(fpreg, access)

        elif opcode in (12, 13) and (word>>8) & 15 == 2:
            # LFM/SFM
            # format is        cccc 110p uywl nnnn xddd 0010 iiii iiii
            #
            # <LFM|SFM>{cond} Fd,count,[Rn, #imm]{!}
            # <LFM|SFM>{cond} Fd,count,[Rn],#imm
            #
            # where cccc = condition
            #          p = Pre-indexed/~Post-indexed
            #          u = Up/~Down
            #         yx = register count (4,1,2 or 3)
            #          w = Writeback
            #          l = Load/~Store
            #       nnnn = Rn
            #        ddd = Fd
            #   iiiiiiii = immediate offset
            cc = self.cc_values[word>>28]
            if cc == 'AL':
                cc = ''
            mnemonic = 'LFM' if word & (1<<20) else 'SFM'
            # Count bits are not contiguous
            count = (((word >> 21) & 2) + ((word >> 15) & 1))
            preindex = word & (1<<24)
            up = word & (1<<23)
            armreg = (word>>16) & 15
            fpreg = (word>>12) & 7
            offset = (word & 255) * 4
            if not up:
                offset = -offset
            writeback = word & (1<<21)
            mnemonic = "{}{}".format(mnemonic, cc)
            if preindex:
                if armreg == 15:
                    access = "&{:08x}".format(i.address + 8 + offset)
                else:
                    if offset == 0:
                        access = "[R{}]{}".format(armreg, "!" if writeback else "")
                    else:
                        access = "[R{}, #{}]{}".format(armreg, offset, "!" if writeback else "")
            else:
                access = "[R{}], #{}".format(armreg, offset)
            op_str = "F{}, {}, {}".format(fpreg, count, access)

        elif opcode == 14 and (word>>8) & 15 == 1 and (word>>4) & 1 == 0:
            # format is        cccc 1110 abcd ennn jddd 0001 fgh0 immm
            #
            # <Dyadic op>{cond}<S|D|E>{P|M|Z} Fd,Fn,<Fm|#constant>
            # <Monadic op>{cond}<S|D|E>{P|M|Z} Fd,<Fm|#constant>
            #
            # where cccc = condition
            #       abcd = opcode
            #         ef = destination size
            #         gh = rounding mode
            #       immm = Fm/constant
            #        nnn = Fn
            #        ddd = Fd
            #          j = Monadic/~Dyadic
            opcode = (word >> 20) & 15
            length = "SDEx"[((word>>18) & 2) + ((word>>7) & 1)]
            # length 3 is invalid
            rounding = " PMZ"[(word>>5) & 3]
            # rounding 0 has no symbol?
            fpregn = (word >> 16) & 7
            fpregd = (word >> 12) & 7
            monadic = (word>>15) & 1

            fpdo_mnemonic = {
                    0: "ADF",   #... binary ops
                    1: "MUF",
                    2: "SUF",
                    3: "RSF",
                    4: "DVF",
                    5: "RDF",
                    6: "POW",
                    7: "RPW",
                    8: "RMF",
                    9: "FML",
                    10: "FDV",
                    11: "FRD",
                    12: "POL",
                    13: "F0D",  # ... undefined binary ops
                    14: "F0E",
                    15: "F0F",

                    16: "MVF",  # ... unary ops
                    17: "MNF",
                    18: "ABS",
                    19: "RND",
                    20: "SQT",
                    21: "LOG",
                    22: "LGN",
                    23: "EXP",
                    24: "SIN",
                    25: "COS",
                    26: "TAN",
                    27: "ASN",
                    28: "ACS",
                    29: "ATN",
                    30: "URD",
                    31: "NRM",
                }

            cc = self.cc_values[word>>28]
            if cc == 'AL':
                cc = ''
            mnemonic = fpdo_mnemonic[opcode | (monadic<<4)]

            mnemonic = "{}{}{}{}".format(mnemonic, cc, length, rounding)

            operand = operand_fm(word)
            if monadic:
                op_str = "F{}, {}".format(fpregd, operand)
            else:
                op_str = "F{}, F{}, {}".format(fpregd, fpregn, operand)

        elif opcode == 14 and (word>>8) & 15 == 1 & (word>>4) & 1 == 1:
            opcode = (word >> 20) & 7
            status = (word & (9<<20)) == (9<<20)
            invalid = (word & (9<<20)) == (8<<20)
            if status:
                # format is        cccc 1110 1en1 0nnn 1111 0001 0001 immm
                #
                # <CMF|CNF>{E}{cond} Fn,Fm
                # <CMF|CNF>{E}{cond} Fn,#constant
                #
                # where cccc = condition
                #          e = Exception
                #          n = CNF/~CMF
                #        nnn = Fn
                #       immm = Fm/constant
                excepting = word & (1<<22)
                negated = word & (1<<21)

                fpregn = (word>>16) & 7

                cc = self.cc_values[word>>28]
                if cc == 'AL':
                    cc = ''
                mnemonic = "{}{}{}".format('CNF' if negated else 'CMF',
                                           'E' if excepting else '',
                                           cc)
                operand = operand_fm(word)
                op_str = "F{}, {}".format(fpregn, operand)
            elif invalid:
                pass

            else:
                # format is        cccc 1110 abcl ennn dddd 0001 fgh1 0mmm
                #
                # FLT{cond}<S|D|E>{P|M|Z} Fn,Rd
                # FIX{cond}{P|M|Z}        Rd,Fm
                # <WFS|RFS|WFC|RFC>{cond} Rd
                #
                # where cccc = condition
                #          l = Load/~Store
                #        abc = operation            abcl         abcl
                #                                   0000 FLT     0001 FIX
                #                                   0010 WFS     0011 RFS
                #                                   0100 WFC     0101 RFC
                #                                                1xx1 may be compare
                #         ef = destination size (FLT only)
                #         gh = rounding mode (FLT and FIX only)
                #        nnn = Fn (FLT only)
                #        mmm = Fm (FIX only)
                #       dddd = Rd
                length = "SDEx"[((word>>18) & 2) + ((word>>7) & 1)]
                # length 3 is invalid
                rounding = " PMZ"[(word>>5) & 3]

                if opcode == 0:
                    mnemonic = 'FLT'
                elif opcode == 1:
                    mnemonic = 'FIX'
                    length = ''
                elif opcode > 5:
                    mnemonic = 'xx{}'.format(opcode)
                else:
                    mnemonic = '{}F{}'.format('R' if opcode & 1 else 'W',
                                              'C' if opcode & 4 else 'S')
                    length = ''
                    rounding = ''

                cc = self.cc_values[word>>28]
                if cc == 'AL':
                    cc = ''
                mnemonic = "{}{}{}{}".format(mnemonic, cc, length, rounding)

                armreg = (word>>12) & 15

                if opcode == 0:
                    fpregn = (word>>16) & 7
                    op_str = 'F{}, R{}'.format(fpregn, armreg)
                elif opcode == 1:
                    fpregm = (word>>0) & 7
                    op_str = 'R{}, F{}'.format(armreg, fpregm)
                elif opcode < 6:
                    op_str = 'R{}'.format(armreg)
                else:
                    op_str = ''

        return (mnemonic, op_str, None)

    def disassemble_instruction(self, address, inst,
                                live_registers=False, live_memory=False,
                                thumb=False):
        """
        Disassemble an instruction into broken down values.

        @param address:         Address the instruction comes from
        @param inst:            32bit/16bit instruction word
        @param live_registers:  Whether registers may be used to provide more information
        @param live_memory:     Whether memory reads may be used to provide more information
        @param thumb:           True to disassemble as a Thumb instruction

        @return: Tuple of (bytes-consumed, mnemonic string, operands string, comment string)
                 Mnemonic string, operands string and comment string will be None if no
                 disassembly was available.
        """
        if not self.capstone:
            return (2 if thumb else 4, None, None, None)

        if live_memory:
            # Check if this is has a data description
            content = self.access.describe_content(address)
            if content:
                return (2 if thumb else 4, None, None, content)

        self.md.mode = self._capstone.CS_MODE_THUMB if thumb else self._capstone.CS_MODE_ARM
        for i in self.md.disasm(inst, address):
            mnemonic = i.mnemonic.upper()
            op_str = i.op_str

            if self._capstone_version_major == 5:
                # In Capstone 5, r13 is returned as `r13`
                # (and r14 as `lr`)
                if self.config.rename_r13_to_sp:
                    op_str = op_str.replace('r13', 'sp')
                if self.config.rename_r14_to_lr:
                    op_str = op_str.replace('r14', 'lr')
            else:
                # In Capstone 4 and below, r13 is returned as `sp` (so we need to undo that)
                # (and r14 as `lr`)
                if not self.config.rename_r13_to_sp:
                    op_str = op_str.replace('sp', 'r13')
                if not self.config.rename_r14_to_lr:
                    op_str = op_str.replace('lr', 'r14')

            if self.config.format == 'capstone':
                return (2 if thumb else 4, mnemonic, op_str, '')

            op_str = op_str.replace('0x', '&')
            comment = None
            if mnemonic[0:3] == 'SVC':
                # Manually replace the mnemonic, due to bug in earlier capstone
                mnemonic = 'SWI' + mnemonic[3:]
                # Look up the SWI number, if we can.
                swi = i.operands[0].imm
                op_str = self.access.decode_swi(swi)
                if op_str is None:
                    op_str = '&%06X' % (swi,)

                # Special cases for CallASWI / CallASWIR12
                swic = swi & ~0x20000
                if swic in (0x6f, 0x71):
                    rn = 10 if swi & 255 == 0x6f else 12
                    if live_registers:
                        real_swi = self.get_reg(rn)
                        comment = 'R%s = &%x' % (rn, real_swi)
                        callaswi_name = self.access.decode_swi(real_swi)
                        if callaswi_name:
                            comment += '  (%s)' % (callaswi_name,)
                    else:
                        comment = 'SWI number in R%s' % (rn,)

                elif swic == 1:
                    # OS_WriteS
                    if live_memory:
                        # FIXME: Maybe this should be just safe_string, and we replace control characters with escapes?
                        # FIXME: Truncate this string if it's long?
                        string = self.access.get_memory_string(address + 4)
                        if string:
                            string = "\"%s\"" % (self.access.decode_string(string),)
                            comment = 'R15+4 = {}'.format(string)

                # See if we can find this as a named entry point
                if live_memory:
                    region = self.access.describe_region(address)
                    if region:
                        region2 = self.access.describe_region(address + 1)
                        if region2 and region2[2] != region[2] and region[2].startswith(region2[2]):
                            desc = region[2][len(region2[2]):].lstrip(' ,:')
                            if comment:
                                comment += ' ; {}'.format(desc)
                            else:
                                comment = desc

            elif mnemonic[0:3] in ('MVN', 'CMN'):

                if mnemonic[0:3] != 'MVN':
                    # This could be a 'P' operation but to find out we need to extract the word
                    word = struct.unpack('<L', i.bytes)[0]
                    armregd = (word>>12) & 15
                    if armregd == 15:
                        # This is a TEQ/CMP/TSTP
                        mnemonic += 'P'

                accumulator = []
                accumulator.extend(self._operand_constant(i.operands[1], negated=True))
                if accumulator:
                    comment = ', '.join(accumulator)

                op_str = self._tidy_shifts(op_str)

            elif mnemonic[0:3] == 'ADR' and \
                 i.operands[1].type == self._const.ARM_OP_IMM:
                # Thumb ADR instruction
                imm = address + i.operands[1].imm + 4
                op_prefix, _ = op_str.split(',', 1)
                op_suffix = '&%08x' % (imm & 0xFFFFFFFF,)
                op_str = '%s, %s' % (op_prefix, op_suffix)

                if live_memory:
                    desc = self.access.describe_address(imm)
                    if desc:
                        comment = '-> %s' % ('; '.join(desc),)

            elif mnemonic[0:3] in ('ADD', 'SUB', 'ADC', 'SBC', 'RSB', 'RSC'):
                if i.operands[1].type == self._const.ARM_OP_REG and \
                   i.operands[1].reg == self._const.ARM_REG_R15 and \
                   i.operands[2].type == self._const.ARM_OP_IMM and \
                   mnemonic[2] != 'C':
                    # ADR replacement
                    imm = i.operands[2].imm
                    if len(i.operands) == 4 and i.operands[3].type == self._const.ARM_OP_IMM:
                        # Has an explicit rotate
                        imm = (imm << (32 - i.operands[3].imm)) | (imm >> i.operands[3].imm)
                        imm = imm & 0xFFFFFFFF
                    if mnemonic[0:3] == 'ADD':
                        imm = address + imm + 8
                    else:
                        imm = address - imm + 8
                    op_prefix, _ = op_str.split(',', 1)
                    op_suffix = '&%08x' % (imm & 0xFFFFFFFF,)
                    op_str = '%s, %s' % (op_prefix, op_suffix)
                    mnemonic = 'ADR%s' % (mnemonic[3:],)

                    if live_memory:
                        desc = self.access.describe_address(imm)
                        if desc:
                            comment = '-> %s' % ('; '.join(desc),)

                elif mnemonic[0:3] == 'ADD' and \
                     i.operands[0].type == self._const.ARM_OP_REG and \
                     i.operands[0].reg == self._const.ARM_REG_R15 and \
                     len(i.operands) == 3 and \
                     i.operands[2].type == self._const.ARM_OP_REG and \
                     i.operands[2].shift.type == self.capstone.arm_const.ARM_SFT_LSL and \
                     i.operands[2].shift.value == 2:
                    # Dispatch table!
                    regnum = self.inv_reg_map.get(i.operands[2].reg, None)
                    if regnum is not None:
                        if live_registers:
                            comment = 'Table dispatch index #%s' % (self.get_reg(regnum),)
                        else:
                            comment = 'Table dispatch index R%s' % (regnum,)
                else:
                    accumulator = []
                    if live_registers and self.config.show_referenced_registers:
                        accumulator.extend(self._operand_multiple_registers([i.operands[1],
                                                                             i.operands[2]]))

                    if thumb and len(i.operands) == 2:
                        accumulator.extend(self._operand_constant(i.operands[1]))
                    elif len(i.operands) > 2:
                        accumulator.extend(self._operand_constant(i.operands[2],
                                                                  shift=i.operands[3] if len(i.operands) == 4 else None))

                    if accumulator:
                        comment = ', '.join(accumulator)

                op_str = self._tidy_shifts(op_str)

            elif mnemonic[0:3] in ('ORR', 'BIC', 'AND', 'EOR', 'MUL', 'MLA'):
                accumulator = []
                if live_registers and self.config.show_referenced_registers:
                    accumulator.extend(self._operand_multiple_registers([i.operands[1],
                                                                         i.operands[2]]))

                if len(i.operands) > 2:
                    accumulator.extend(self._operand_constant(i.operands[2],
                                                              shift=i.operands[3] if len(i.operands) == 4 else None))

                if accumulator:
                    comment = ', '.join(accumulator)

                op_str = self._tidy_shifts(op_str)

            elif mnemonic[0:3] in ('LDR', 'STR'):
                if len(i.operands) > 1 and \
                   i.operands[1].type == self._const.ARM_OP_MEM and \
                   i.operands[1].reg == self._const.ARM_REG_R15 and \
                   i.operands[1].mem.index == 0:
                   # Length of operands is broken in Capstone 5.0.1 (only includes a
                   # single operand).
                    mem = i.operands[1].mem
                    if thumb:
                        addr = address + mem.disp + 4
                        # Thumb address is rounded down if this is a word operation
                        if 'B' not in mnemonic and 'H' not in mnemonic:
                            addr = addr & ~3
                    else:
                        addr = address + mem.disp + 8
                    op_prefix, _ = op_str.split(',', 1)
                    op_suffix = '&%08x' % (addr,)
                    op_str = '%s, %s' % (op_prefix, op_suffix)

                    # If we can work out what the address is, do so - don't if it's
                    # a low address though.
                    if live_memory and mnemonic[0:3] == 'LDR' and addr > 0x8000:
                        if 'B' in mnemonic:
                            byte = self.access.get_memory_byte(addr)
                            if byte is not None:
                                comment = '= &%02x' % (byte,)
                        else:
                            word = self.access.get_memory_word(addr)
                            if word is not None:
                                comment = '= &%08x' % (word,)

                if live_registers and self.config.show_referenced_registers:
                    if mnemonic[0:3] == 'STR':
                        accumulator = self._operand_registers(i.operands[0])
                        if i.operands[1].reg != self._const.ARM_REG_R15:
                            accumulator.extend(self._operand_registers(i.operands[1]))
                        more = ', '.join(accumulator)
                        comment = '%s; %s' % (comment, more) if comment else more

                    elif mnemonic[0:3] == 'LDR' and \
                         i.operands[1].reg != self._const.ARM_REG_R15:
                        # Show the values of the referenced registers
                        maybe_string = 'B' in mnemonic
                        accumulator = self._operand_registers(i.operands[1], maybe_presentable=maybe_string)
                        more = ', '.join(accumulator)
                        comment = '%s; %s' % (comment, more) if comment else more

                op_str = self._tidy_shifts(op_str)

            elif mnemonic[0:3] in ('MOV', 'CMP', 'TEQ', 'TST'):

                if not thumb and mnemonic[0:3] != 'MOV':
                    # This could be a 'P' operation but to find out we need to extract the word
                    word = struct.unpack('<L', i.bytes)[0]
                    armregd = (word>>12) & 15
                    if armregd == 15:
                        # This is a TEQ/CMP/TSTP
                        mnemonic += 'P'

                accumulator = []
                if live_registers and self.config.show_referenced_registers:
                    if mnemonic[0:3] != 'MOV':
                        accumulator = self._operand_registers(i.operands[0])
                    accumulator.extend(self._operand_registers(i.operands[1]))

                accumulator.extend(self._operand_constant(i.operands[1]))

                if accumulator:
                    comment = ', '.join(accumulator)

                op_str = self._tidy_shifts(op_str)

            elif mnemonic[0:3] == 'MSR':

                accumulator = []

                # Capstone doesn't report the operand properly (https://github.com/capstone-engine/capstone/issues/2684)
                imm_index = None
                if len(i.operands) > 1 and i.operands[1].type == self._const.ARM_OP_IMM:
                    imm_index = 1
                elif len(i.operands) == 1 and i.operands[0].type == self._const.ARM_OP_IMM:
                    imm_index = 0

                if live_registers and self.config.show_referenced_registers:
                    accumulator.extend(self._operand_registers(i.operands[imm_index]))

                if imm_index is not None:
                    imm = i.operands[imm_index].imm
                    (psr, _) = op_str.split(',', 1)
                    if '_' in psr:
                        (_, mask) = psr.split('_', 1)
                    else:
                        mask = None
                    accumulator.append("#%s" % (self.psr_name(imm, mask=mask),))
                if accumulator:
                    comment = ', '.join(accumulator)

            elif mnemonic[0:3] in ('LSL', 'LSR', 'ASR', 'ROR'):
                # Capstone treats the shifting operations on MOV as separate instructions, which
                # is confusing for us poor RISC OS users.
                shift = mnemonic[0:3]
                mnemonic = 'MOV%s' % (mnemonic[3:],)
                op_list = op_str.split(', ')
                if i.operands[1].shift.type in (self.capstone.arm_const.ARM_SFT_LSL,
                                                self.capstone.arm_const.ARM_SFT_LSR,
                                                self.capstone.arm_const.ARM_SFT_ASR,
                                                self.capstone.arm_const.ARM_SFT_ROR):
                    # Use a decimal number for constant shifts, as hex shifts are really not that helpful
                    op_list[-1] = "%s #%s" % (shift, i.operands[1].shift.value)
                else:
                    op_list[-1] = "%s %s" % (shift, op_list[-1])
                op_str = ', '.join(op_list)

                # Annotate the registers
                if live_registers and self.config.show_referenced_registers:
                    accumulator = self._operand_registers(i.operands[1])
                    if len(i.operands) == 3:
                        accumulator.extend(self._operand_registers(i.operands[2]))
                    comment = ', '.join(accumulator)

            elif mnemonic[0:3] in ('LDM', 'STM'):

                if live_registers and self.config.show_referenced_registers:
                    accumulator = self._operand_registers(i.operands[0])
                    comment = ', '.join(accumulator)

            elif mnemonic in ('B', 'BL') or (len(mnemonic) > 2) and mnemonic[:-2] in ('B', 'BL'):
                if op_str[0:2] == '#&':
                    op_str = '&%08x' % (int(op_str[2:], 16),)
                if live_memory:
                    # We can allow this to be omitted in cases if the memory that's being debugged
                    # is not actually live memory (could be relocated, synthetic, etc).
                    addr = i.operands[0].imm
                    func = self.access.describe_code(addr)
                    if func:
                        comment = '-> Function: %s' % (func,)

            elif mnemonic[0:3] in ('LDC', 'STC', 'CDP', 'MCR', 'MRC') and \
                 self.config.support_fpa:
                (mnemonic, op_str, comment) = self.disassemble_fpa_instruction(i, mnemonic, op_str)

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

            # Apply any fixups for the mnemonic name which are easily translatable
            mnemonic = self.mnemonic_replacements.get(mnemonic, mnemonic)

            return (2 if thumb else 4, mnemonic, op_str, comment)

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

        return (2 if thumb else 4, self.undefined, None, comment)

    def disassemble(self, address, inst,
                    live_registers=False, live_memory=False,
                    thumb=False):
        """
        Disassemble an instruction into a formatted string.

        @param address:         Address the instruction comes from
        @param inst:            32bit/16bit instruction word
        @param live_registers:  Whether registers may be used to provide more information
        @param live_memory:     Whether memory reads may be used to provide more information
        @param thumb:           True to disassemble as a Thumb instruction

        @return:         Tuple of (consumed, string describing the instruction or None if not disassembly)
        """
        (consumed, mnemonic, op_str, comment) = self.disassemble_instruction(address, inst,
                                                                             live_registers=live_registers,
                                                                             live_memory=live_memory,
                                                                             thumb=thumb)
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


@base.register_disassembler
class DisassembleThumb(DisassembleARM):
    # Architecture name
    arch = "thumb"

    # Minimum width in bytes of instructions
    inst_width_min = 2

    # Maximum width in bytes of instructions
    inst_width_max = 2

    # The default class to use if no configuration is supplied
    default_config = DisassembleARMConfig

    def disassemble(self, address, inst,
                    live_registers=False, live_memory=False):
        return super(DisassembleThumb, self).disassemble(address, inst, live_registers, live_memory, thumb=True)
