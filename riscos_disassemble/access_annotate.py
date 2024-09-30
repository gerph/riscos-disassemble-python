"""
File offset annotations.
"""


class DisassembleAccessAnnotate(object):
    """
    Mixin for the Disassemble classes, which adds in SWI decoding.
    """

    annotations = {}

    def annotate_aif(self, access):
        self.annotations = {
                0x8000 + 0: "AIF: Decompression branch",
                0x8000 + 4: "AIF: Self relocation branch",
                0x8000 + 8: "AIF: Zero init branch",
                0x8000 + 12: "AIF: Entry point",
                0x8000 + 16: "AIF: OS_Exit",
                0x8000 + 20: "AIF: Size of read only data",
                0x8000 + 24: "AIF: Size of read-write data",
                0x8000 + 28: "AIF: Size of debug data",
                0x8000 + 32: "AIF: Size of zero-init data",
                0x8000 + 36: "AIF: Debug type",
                0x8000 + 40: "AIF: Linkage base",
                0x8000 + 44: "AIF: Workspace size",
                0x8000 + 48: "AIF: Flags (and bitness)",
                0x8000 + 52: "AIF: Data base",
                0x8000 + 56: "AIF: Reserved (1)",
                0x8000 + 60: "AIF: Reserved (2)",
            }

    def describe_content(self, addr):
        """
        Describe the content at a given address (data values, or references)

        @param addr:    Address to describe (which might not be mapped)

        @return: Description of the content (eg 'header offset')
                 None if code is not known
        """
        content = self.annotations.get(addr)
        return content
