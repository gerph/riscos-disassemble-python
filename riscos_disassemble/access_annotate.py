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


class DisassembleAccessAnnotate(object):
    """
    Mixin for the Disassemble classes, which adds in SWI decoding.
    """

    annotations = {}

    def annotate_aif(self):
        if self.get_memory_word(0x8010) != 0xef000011:
            # No SWI OS_Exit, so it's not an AIF file
            return
        self.annotations = {
                0x8000 + 0: "AIF: Decompression branch",
                0x8000 + 4: "AIF: Self relocation branch",
                0x8000 + 8: "AIF: Zero init branch",
                0x8000 + 12: "AIF: Entry point branch",
                0x8000 + 16: "AIF: OS_Exit",
                0x8000 + 20: "AIF: Size of read only data",
                0x8000 + 24: "AIF: Size of read-write data",
                0x8000 + 28: "AIF: Size of debug data",
                0x8000 + 32: "AIF: Size of zero-init data",
                0x8000 + 36: "AIF: Debug type",
                0x8000 + 40: "AIF: Linkage base",
                0x8000 + 44: "AIF: Workspace size",
                0x8000 + 48: "AIF: Flags and bitness",
                0x8000 + 52: "AIF: Data base",
                0x8000 + 56: "AIF: Reserved (1)",
                0x8000 + 60: "AIF: Reserved (2)",
            }

        bitness = self.get_memory_word(0x8000 + 48) & 0xFF
        if bitness in (0, 26):
            self.annotations[0x8000 + 48] += ' (26 bit)'
        elif bitness == 32:
            self.annotations[0x8000 + 48] += ' (32 bit)'
        elif bitness == 64:
            self.annotations[0x8000 + 48] += ' (64 bit)'
            # If it's 64bit, then we need to annotate the code as being 32bit
            for bl_offset in (0, 4, 8, 12, 16):
                self.annotations[0x8000 + bl_offset] += ' (ARM32)'

        for bl_offset in (0, 4, 8, 12):
            bl = self.get_memory_word(0x8000 + bl_offset)
            if (bl & 0xFF000000) == 0xeb000000:
                # This is a BL instruction
                dest = 0x8000 + bl_offset + (bl & 0x00FFFFFF) * 4 + 8
                self.annotations[dest] = self.annotations[0x8000 + bl_offset][5:].replace('branch', 'code')

        if bitness == 64:
            self.annotations[0x8100 + 0] = "AIF: Decompression branch"
            self.annotations[0x8100 + 4] = "AIF: Zero init branch"
            self.annotations[0x8100 + 8] = "AIF: Entry point branch"

            for bl_offset in (0, 4, 8):
                bl = self.get_memory_word(0x8100 + bl_offset)
                if (bl & 0xFF000000) == 0x94000000:
                    # This is a BL instruction (in AArch64)
                    dest = 0x8100 + bl_offset + (bl & 0x00FFFFFF) * 4
                    self.annotations[dest] = self.annotations[0x8100 + bl_offset][5:].replace('branch', 'code')

    def annotate_module(self):
        self.annotations = {
                Module_Start: "Module: Start offset",
                Module_Init: "Module: Initialisation code offset",
                Module_Die: "Module: Finalisation code offset",
                Module_Service: "Module: Service handler offset",
                Module_Title: "Module: Title string offset",
                Module_HelpStr: "Module: Help string offset",
                Module_HC_Table: "Module: Command table offset",
                Module_SWIChunk: "Module: SWI chunk",
                Module_SWIEntry: "Module: SWI handler code offset",
                Module_NameTable: "Module: SWI names table offset",
                Module_NameCode: "Module: SWI decoding code offset",
                Module_MsgFile: "Module: Messages filename offset",
                Module_Extension: "Module: Extension flags offset",
            }

        for mod_offset in range(0, Module_Extension + 4, 4):
            if mod_offset == Module_SWIChunk:
                value = self.get_memory_word(mod_offset)
                # Check if it's value
                if value & 0x3F != 0:
                    break
                if value & 0xFFF00000 != 0:
                    break
                continue
            code_offset = self.get_memory_word(mod_offset)
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

                self.annotations[code_offset] = self.annotations[mod_offset][8:].replace(' offset', '')

                if mod_offset == Module_Service:
                    code_data = self.get_memory_word(code_offset)
                    if code_data == Module_ServiceMagic:
                        # Ursula service block exists
                        table_offset = self.get_memory_word(code_offset - 4)
                        self.annotations[table_offset] = "Fast service call table"
                        fast_offset = self.get_memory_word(table_offset + 4)
                        if fast_offset != 0:
                            self.annotations[fast_offset] = "Fast service call entry"

    def describe_content(self, addr):
        """
        Describe the content at a given address (data values, or references)

        @param addr:    Address to describe (which might not be mapped)

        @return: Description of the content (eg 'header offset')
                 None if code is not known
        """
        content = self.annotations.get(addr)
        return content
