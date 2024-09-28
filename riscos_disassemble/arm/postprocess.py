"""
Post-processing of the Disassembly output, following the style used by Darren Salt's DebuggerPlus.

The DebuggerARMFlags class provides the interface to manipulate disassembly text, from that produced
by the Disassemble clases, using the flags supplied. Not all the flags provided by the original
DebuggerPlus are supported here. The object declares which flags are supported and the default flags
in prpoerties on the class.

The flags are provided using a bitfield, with set bits indicating the the flag (and transformation
feature) is enabled.

The following class (and object) properties are available:

* `Flag_*`: Bits indicating the flag is active.
* `supported_flags`:    A logical combination of the flags that are able to be changed by the user.
* `forced_flags`:       Flags that must always be on.
* `default_flags`:      The approximate flags for the default Disassemble object.
* `flag_description`:   A dictionary mapping the flag name (readable) to its description.
* `flag_name_mapping`:  A mapping of the upper case flag name to a tuple of
                        (readable flag, bit value, description)

The object has the following properties (in addition to the above):

* `flags`:              Read only property indicating the currently selected flags

The following methods can be used:

* `update(bic, eor)`:   Change the state of the flags
* `transform(instruction_word, text)`:  Perform a transformation of the text using the currently
                        configured flags.
"""

import re
import struct


class DebuggerARMFlags(object):
    """
    Class to manage the transformation of the ARM assembler using the Flags.
    """
    Flag_FDwithR13 = (1<<0)
    Flag_APCS = (1<<1)
    Flag_LFMstack = (1<<2)
    Flag_LFS = (1<<3)
    Flag_QuoteSWIs = (1<<4)
    Flag_UseDCD = (1<<5)
    Flag_UseVDU = (1<<6)
    Flag_ANDEQasDCD = (1<<7)
    Flag_UseADRL = (1<<8)
    Flag_UseADRW = (1<<9)
    Flag_LongMul = (1<<10)
    Flag_UseLDRL = (1<<11)
    Flag_UseNOP = (1<<12)
    Flag_OldPSR = (1<<13)
    Flag_Wide = (1<<14)
    Flag_HSLO = (1<<15)
    Flag_Shift = (1<<16)
    Flag_Lower = (1<<17)
    Flag_ConstShift = (1<<18)
    Flag_ConstShiftAll = (1<<19)
    # Bits 20-23 = Reserved, must be 0
    # Bits 24-31 = CPU type

    # The flags that we support changing
    supported_flags = Flag_APCS | Flag_Lower | Flag_UseDCD | Flag_ANDEQasDCD | Flag_UseNOP | Flag_QuoteSWIs | Flag_UseVDU

    # The flags that we don't support, but are always on (because they're always done)
    forced_flags = Flag_Shift

    # The flags that we will start with
    default_flags = Flag_Lower | forced_flags

    flag_description = {
            'FDwithR13':    "Use FD with R13, eg. STMDB R13 -> STMFD R13.",
            'APCS':         "Use APCS-R register set and recognise C function entry.",
            'LFMstack':     "Use stack notation with LFM & SFM where possible.",
            'LFS':          "Use LFS and SFS in preference to LFM & SFM.",
            'QuoteSWIs':    "Put quotes around SWI names.",
            'UseDCD':       "Use DCD instead of 'Undefined instruction', and BRK where " \
                            "DCD &x6000010 would be used.",
            'UseVDU':       "Use VDU x instead of SWI OS_WriteI+x.",
            'ANDEQasDCD':   "Use DCD instead of ANDEQ, MOV Rn,Rn (same register) etc.",
            'UseADRL':      "Use ADRL/ADRX instead of ADR then ADD/SUB on same reg.",
            'UseADRW':      "Use ADRW instead of ADD/SUB Rn,R12,#m and LDRW, STRW, " \
                            "LDRBW, STRBW instead of xxxx Rn,[R12,#m].",
            'LongMul':      "Append L to UMUL, UMLA, SMUL, SMLA (thus using the " \
                            "'official' forms).",
            'UseLDRL':      "Use LDRL instead of ADD/SUB Rn,Rm,#o + LDR Rn,[Rn,#p] and " \
                            "ADD/SUB Rm,Ra,#o + LDR Rn,[Ra,#p]! and STR instead of " \
                            "equivalent STRs. " \
                            "(The LDRWL form is enabled by this *and* UseADRW)",
            'UseNOP':       "Use NOP instead of MOV R0,R0.",
            'OldPSR':       "Use the old PSR suffixes _ctl, _flg, _all.",
            'Wide':         "Disassemble for wide display.",
            'HSLO':         "Use HS and LO instead of CS and CC.",
            'Shift':        "Use x<<y comments where possible for numbers >= 8192." \
                            "This affects arithmetic and logic instructions. y is " \
                            "restricted to multiples of 4 if possible, unless x=1.",
            'Lower':        "Force all register names to lower case.",
            'ConstShift':   "Display non-standard constant (x ROR y) as #x,y. " \
                            "This flag affects certain instructions in which the " \
                            "constant is not stored in the standard way, possibly " \
                            "having unexpected effects if you try to reassemble the " \
                            "code. " \
                            "Affects: ANDS, ORRS, EORS, BICS, TEQ, TST " \
                            "(CMP and CMN are also affected). " \
                            "16 encoded as 64>>2 will be displayed as '#64,2'.",
            'ConstShiftAll': "Display non-standard constant (x ROR y) as #x,y.",
        }

    # Flag names
    flag_name_mapping = {}
    for name, value in list(locals().items()):
        if name.startswith('Flag_'):
            flag_name_mapping[name[5:].upper()] = (name[5:], locals()[name], flag_description[name[5:]])

    # APCS register transformation in form (matching regex, replacement upper, replacement lower)
    apcs_transform = [
            (re.compile(r'R15|PC', re.I), 'PC', 'pc'),
            (re.compile(r'R14|LR', re.I), 'LR', 'lr'),
            (re.compile(r'R13|SP\b', re.I), 'SP', 'sp'),
            (re.compile(r'R12', re.I), 'IP', 'ip'),
            (re.compile(r'R11', re.I), 'FP', 'fp'),
            (re.compile(r'R10', re.I), 'SL', 'sl'),
            (re.compile(r'R9', re.I), 'V6', 'v6'),
            (re.compile(r'R8', re.I), 'V5', 'v5'),
            (re.compile(r'R7', re.I), 'V4', 'v4'),
            (re.compile(r'R6', re.I), 'V3', 'v3'),
            (re.compile(r'R5', re.I), 'V2', 'v2'),
            (re.compile(r'R4', re.I), 'V1', 'v1'),
            (re.compile(r'R3', re.I), 'A4', 'a4'),
            (re.compile(r'R2', re.I), 'A3', 'a3'),
            (re.compile(r'R1', re.I), 'A2', 'a2'),
            (re.compile(r'R0', re.I), 'A1', 'a1'),
        ]
    register_re = re.compile(r'\b(R[0-9]|R1[0-5]|SP|LR|PC|C[0-7]|P[0-9]|P1[0-5]|F[0-7])\b', re.I)
    psr_re = re.compile(r'\b([asc]psr(?:_[a-z]+))\b', re.I)
    undef_re = re.compile(r'^Undefined instruction', re.I)
    breakdown_re = re.compile(r'^([^ ]+)( +)(.*?)(?:( +)(;.*))?$')

    default_comment_column = 26

    def __init__(self, flags=None):
        if flags is None:
            flags = self.default_flags
        self.flags = (flags & self.supported_flags) | self.forced_flags

    def update(self, bic=0, eor=0):
        bic = bic & self.supported_flags
        eor = eor & self.supported_flags

        self.flags &= ~bic
        self.flags ^= eor

    def transform(self, word, dis):
        """
        Transform a disassembly into the form requested by the flags.
        """
        if self.flags == self.default_flags:
            # Nothing to change, so return as-is
            return dis

        if isinstance(word, bytes):
            (wordvalue,) = struct.unpack("<L", word)
        else:
            wordvalue = word

        # Use DCD
        if self.flags & self.Flag_UseDCD:
            match = self.undef_re.search(dis)
            if match:
                dis = "DCD     &{:08x}                 ; {}".format(wordvalue, dis)

        # ANDEQasDCD
        if self.flags & self.Flag_ANDEQasDCD:
            if dis.startswith('ANDEQ'):
                dis = "DCD     &{:08x}                 ; {}".format(wordvalue, dis)

        # Break down the disassembly into components
        match = self.breakdown_re.search(dis)
        if match:
            (mnemonic, spc1, operands) = (match.group(1), match.group(2), match.group(3))
            spc2 = match.group(4) if match.group(4) else ''
            comment = match.group(5) if match.group(5) else ''

            operands_column = len(mnemonic) + len(spc1)
            comment_column = (len(operands) + len(spc2)) if comment else self.default_comment_column

            # APCS + Lower
            if self.flags & self.Flag_APCS:
                use_lower = (self.flags & self.Flag_Lower)
                for (regex, upper, lower) in self.apcs_transform:
                    operands = regex.sub(lower if use_lower else upper, operands)
            else:
                if self.flags & self.Flag_Lower:
                    operands = self.register_re.sub(lambda match: match.group(0).lower(), operands)
                    # FIXME: Check whether we include the CPSR, etc in the lower/upper?
                    #operands = self.psr_re.sub(lambda match: match.group(0).lower(), operands)
                else:
                    operands = self.register_re.sub(lambda match: match.group(0).upper(), operands)
                    # FIXME: Check whether we include the CPSR, etc in the lower/upper?
                    #operands = self.psr_re.sub(lambda match: match.group(0).upper(), operands)

            # UseNOP
            if self.flags & self.Flag_UseNOP:
                if mnemonic == 'MOV' and operands.upper() == 'R0, R0':
                    mnemonic = 'NOP'
                    operands = ''

            # UseVDU
            if self.flags & self.Flag_UseVDU:
                if mnemonic == 'SWI' and operands.startswith("OS_WriteI+"):
                    mnemonic = 'VDU'
                    comment = "; SWI {}".format(operands)
                    arg = operands[10:]
                    if arg[0] == '"':
                        # ASCII string, so we can make this a simple value
                        operands = str(ord(arg[1]))
                    else:
                        operands = arg

            # QuoteSWIs
            if self.flags & self.Flag_QuoteSWIs:
                if mnemonic.startswith('SWI'):
                    if not operands.startswith(("OS_WriteI+", "&")):
                        operands = '"{}"'.format(operands)

            # Fix up the spaces to line up to operands
            if len(mnemonic) + len(spc1) != operands_column:
                spc1 = ' ' * (operands_column - len(mnemonic))

            # Fix up the spaces to line up to comment
            if comment:
                if len(operands) + len(spc2) != comment_column:
                    spc2 = ' ' * (comment_column - len(operands))
            else:
                spc2 = ''

            # Rebuild disassembly string
            dis = ''.join([mnemonic, spc1, operands, spc2, comment])

        return dis
