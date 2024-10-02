"""
File offset annotations.
"""


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

    def describe_content(self, addr):
        """
        Describe the content at a given address (data values, or references)

        @param addr:    Address to describe (which might not be mapped)

        @return: Description of the content (eg 'header offset')
                 None if code is not known
        """
        content = self.annotations.get(addr)
        return content
