"""
File offset annotations.
"""

Module_Start = 0x0
Module_Init = 0x4
Module_Die = 0x8
Module_Service = 0xc
Module_Title = 0x10
Module_HelpStr = 0x14
Module_HC_Table = 0x18    #  help and command table.
Module_SWIChunk = 0x1c
Module_SWIEntry = 0x20
Module_NameTable = 0x24
Module_NameCode = 0x28
Module_MsgFile = 0x2c
Module_Extension = 0x30
Module_ServiceMagic = 0xe1a00000

Util_Magic1 = 0x79766748
Util_Magic2 = 0x216c6776


class DisassembleAccessAnnotate(object):
    """
    Mixin for the Disassemble classes, which adds in SWI decoding.
    """

    annotations = {}
    code_comments = {}

    # The lowest address we'll append function descriptions
    minimum_funcname_offset = 0x40

    def annotate_aif(self):
        if self.get_memory_word(self.baseaddr + 0x10) != 0xef000011:
            # No SWI OS_Exit, so it's not an AIF file
            return
        self.annotations = {
                20: "AIF: Size of read only data",
                24: "AIF: Size of read-write data",
                28: "AIF: Size of debug data",
                32: "AIF: Size of zero-init data",
                36: "AIF: Debug type",
                40: "AIF: Linkage base",
                44: "AIF: Workspace size",
                48: "AIF: Flags and bitness",
                52: "AIF: Data base",
                56: "AIF: Reserved (1)",
                60: "AIF: Reserved (2)",
            }

        self.code_comments = {
                0: "AIF: Decompression branch",
                4: "AIF: Self relocation branch",
                8: "AIF: Zero init branch",
                12: "AIF: Entry point branch",
                16: "AIF: OS_Exit",
            }

        bitness = self.get_memory_word(self.baseaddr + 48) & 0xFF
        if bitness in (0, 26):
            self.annotations[48] += ' (26 bit)'
        elif bitness == 32:
            self.annotations[48] += ' (32 bit)'
        elif bitness == 64:
            self.annotations[48] += ' (64 bit)'
            # If it's 64bit, then we need to annotate the code as being 32bit
            for bl_offset in (0, 4, 8, 12, 16):
                self.code_comments[bl_offset] += ' (ARM32)'

        for bl_offset in (0, 4, 8, 12):
            bl = self.get_memory_word(self.baseaddr + bl_offset)
            if (bl & 0xFF000000) == 0xeb000000:
                # This is a BL instruction
                dest = bl_offset + (bl & 0x00FFFFFF) * 4 + 8
                self.code_comments[dest] = self.code_comments[bl_offset][5:].replace('branch', 'code')

        if bitness == 64:
            self.code_comments[0x100 + 0] = "AIF: Decompression branch"
            self.code_comments[0x100 + 4] = "AIF: Zero init branch"
            self.code_comments[0x100 + 8] = "AIF: Entry point branch"

            for bl_offset in (0, 4, 8):
                bl = self.get_memory_word(self.baseaddr + 0x100 + bl_offset)
                if (bl & 0xFF000000) == 0x94000000:
                    # This is a BL instruction (in AArch64)
                    dest = 0x100 + bl_offset + (bl & 0x00FFFFFF) * 4
                    self.code_comments[dest] = self.code_comments[0x100 + bl_offset][5:].replace('branch', 'code')

    def annotate_module(self):
        self.annotations = {
                Module_Start:       "Module: Start offset",
                Module_Init:        "Module: Initialisation code offset",
                Module_Die:         "Module: Finalisation code offset",
                Module_Service:     "Module: Service handler offset",
                Module_Title:       "Module: Title string offset",
                Module_HelpStr:     "Module: Help string offset",
                Module_HC_Table:    "Module: Command table offset",
                Module_SWIChunk:    "Module: SWI chunk",
                Module_SWIEntry:    "Module: SWI handler code offset",
                Module_NameTable:   "Module: SWI names table offset",
                Module_NameCode:    "Module: SWI decoding code offset",
                Module_MsgFile:     "Module: Messages filename offset",
                Module_Extension:   "Module: Extension flags offset",
            }

        for mod_offset in range(0, Module_Extension + 4, 4):
            if mod_offset == Module_SWIChunk:
                value = self.get_memory_word(self.baseaddr + mod_offset)
                # Check if it's value
                if value & 0x3F != 0:
                    break
                if value & 0xFFF00000 != 0:
                    break
                continue
            code_offset = self.get_memory_word(self.baseaddr + mod_offset)
            if code_offset != 0:
                if mod_offset > Module_SWIChunk:
                    # Need to check if it's valid before using it
                    if mod_offset not in (Module_NameTable, Module_MsgFile):
                        # Code entry points
                        if code_offset & 3:
                            # Not a word, so not valid
                            break
                    if code_offset & 0xFFF00000:
                        # Far too big to be sensible
                        break

                if mod_offset in (Module_Start,
                                  Module_Init,
                                  Module_Die,
                                  Module_Service,
                                  Module_SWIEntry,
                                  Module_NameCode):
                    # This is code
                    self.code_comments[code_offset] = self.annotations[mod_offset][8:].replace(' offset', '')
                else:
                    # This is data
                    self.annotations[code_offset] = self.annotations[mod_offset][8:].replace(' offset', '')

                if mod_offset == Module_Service:
                    code_data = self.get_memory_word(self.baseaddr + code_offset)
                    if code_data == Module_ServiceMagic:
                        # Ursula service block exists
                        self.annotations[code_offset - 4] = "Fast service call table offset"
                        table_offset = self.get_memory_word(self.baseaddr + code_offset - 4)
                        self.annotations[table_offset] = "Fast service call table (flags)"
                        self.annotations[table_offset + 4] = "Fast service call code offset"
                        fast_offset = self.get_memory_word(self.baseaddr + table_offset + 4)
                        if fast_offset != 0:
                            self.code_comments[fast_offset] = "Fast service call entry"

    def annotate_utility(self):
        if self.get_memory_word(self.baseaddr + 4) != Util_Magic1 or \
           self.get_memory_word(self.baseaddr + 8) != Util_Magic2:
            return

        self.annotations = {
                4: "Util: Magic signature 1",
                8: "Util: Magic signature 2",
                12: "Util: Read only size",
                16: "Util: Read-write size",
                20: "Util: Flags and bitness",
            }
        self.code_comments = {
                0: "Util: Entry branch",
            }
        bitness = self.get_memory_word(self.baseaddr + 20) & 0xFF
        if bitness in (0, 26):
            self.annotations[20] += ' (26 bit)'
        elif bitness == 32:
            self.annotations[20] += ' (32 bit)'
        elif bitness == 64:
            self.annotations[20] += ' (64 bit)'
            # If it's 64bit, then we need to annotate the code as being 32bit
            for bl_offset in (0,):
                self.code_comments[bl_offset] += ' (ARM32)'

        for bl_offset in (0,):
            bl = self.get_memory_word(self.baseaddr + bl_offset)
            if (bl & 0xFF000000) == 0xea000000:
                # This is a B instruction
                dest = bl_offset + (bl & 0x00FFFFFF) * 4 + 8
                self.code_comments[dest] = self.code_comments[bl_offset][6:].replace('branch', 'code')

        if bitness == 64:
            self.annotations[24] = "Util: Entry point offset (64 bit)"

            offset = self.get_memory_word(self.baseaddr + 24)
            self.code_comments[offset] = "Entry point code"

    def describe_code_comment(self, addr):
        """
        Describe the code at a given address.

        @param addr:    Address to describe (which might not be mapped)

        @return: Name of the function (or function + offset)
                 None if code is not known
        """
        base = super(DisassembleAccessAnnotate, self).describe_code_comment(addr)
        comment = self.code_comments.get(addr - self.baseaddr)
        if comment:
            if base:
                comment = "{}  ; {}".format(comment, base)
            return comment
        return base

    def describe_content(self, addr):
        """
        Describe the content at a given address data values

        @param addr:    Address to describe (which might not be mapped)

        @return: Description of the content (eg 'header offset')
                 None if code is not known
        """
        content = self.annotations.get(addr - self.baseaddr)
        return content
