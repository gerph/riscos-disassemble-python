"""
Disassembly interface for the system.

This module provides interfaces to different disassembly systems, so that
the disassembly can access the functions in the same way.

The DisassemblerBase class should be subclassed to create an instance which
can be used by the system. The class should provide the following attributes:

* `arch`:           The architecture name for this disassembler
* `inst_width_min`: The shortest number of bytes required for an instruction
* `inst_width_max`: The longest number of bytes required for an instruction

The following methods should be provided:

* `disassemble_instruction`: Should provide a set of values describing the
            interpretation of the instruction - the number of bytes it
            spans, the mnemonic, the operands and a comment.
* `disassemble`: Should provide a textual disassembly of the instruction
            provided, and the number of bytes decoded. If no disassembly
            is known, the value None should be returned as the string.
            (if no method is provided, the base class with provide a
            simple representation)
* `colour_disassembly`: Should provide a colourised version of the text
            supplied.

Access to the file or memory data, and its interpretation is through
the `access` property of the DisassembleBase object (or its derivatives)
See the access.py module for details.

To look up the disassembler for a particular architecture, use code like:

    from riscos_disassemble import get_disassembler

    dis_cls = get_disassembler(arch)
    if dis_cls:
        dis = dis_cls(config=config)
"""

import re

from .access import DisassembleAccess

registrations = {}


class DisassembleBase(object):
    # Architecture name
    arch = "unknown"

    # Minimum width in bytes of instructions
    inst_width_min = 1

    # Maximum width in bytes of instructions
    inst_width_max = 1

    # The default class to use if no configuration is supplied
    default_config = object

    # How we write an undefined instruction
    undefined = 'Undefined instruction'

    # Colouring parameters
    inst_re = re.compile('([A-Za-z][A-Za-z0-9]+|B)(\s*)')
    comment_re = re.compile('(^|\s+)(;.*)$')

    operand_categories = [
            (re.compile(r'\s+'), 'space'),
            (re.compile(r'[#!\^\-,.]'), 'punctuation'),
            (re.compile(r'[\[\]]'), 'brackets'),
            (re.compile(r'[\{}]'), 'braces'),
        ]

    inst_category = {}
    inst_category_prefix2 = {}
    inst_category_prefix3 = {}

    def __init__(self, config=None, access=None):
        if not config:
            config = self.default_config()
        self.config = config
        if not access:
            access = DisassembleAccess()
        self.access = access

    def disassemble_instruction(self, address, inst,
                                live_registers=False, live_memory=False):
        """
        Disassemble an instruction into broken down values.

        @param address:         Address the instruction comes from
        @param inst:            32bit/16bit instruction word
        @param live_registers:  Whether registers may be used to provide more information
        @param live_memory:     Whether memory reads may be used to provide more information

        @return: Tuple of (bytes-consumed, mnemonic string, operands string, comment string)
                 Mnemonic string, operands string and comment string will be None if no
                 disassembly was available.
        """
        return (self.inst_width_min, None, None, None)

    def disassemble(self, address, inst,
                    live_registers=False, live_memory=False,
                    *args, **kwargs):
        """
        Disassemble an instruction into a formatted string.

        @param address:         Address the instruction comes from
        @param inst:            32bit/16bit instruction word
        @param live_registers:  Whether registers may be used to provide more information
        @param live_memory:     Whether memory reads may be used to provide more information
        @param thumb:           True to disassemble as a Thumb instruction

        @return:         Tuple of (consumed, string describing the instruction or None if not disassembly)
        """
        try:
            (consumed, mnemonic) = super(DisassembleBase, self).disassemble(address, inst, *args,
                                                                            live_registers=live_registers,
                                                                            live_memory=live_memory,
                                                                            **kwargs)
            return (consumed, mnemonic)
        except AttributeError:
            pass

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

    def colour_disassembly(self, text):
        """
        Transform text from a disassembly into a list of sequences with colours.

        @param text: Contains the disassembled text

        @return: List of either tuples of (colour, text) or just plain text string.
        """
        return [text]


def register_disassembler(cls):
    """
    Decorator to register a class as a disassembler.
    """
    arch = cls.arch
    registrations[arch] = cls
    return cls
