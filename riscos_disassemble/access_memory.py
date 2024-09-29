"""
Memory access helper functions.

* `DisassembleAccessFile` allows a filehandle to be used as the source for
  reading the file as the memory source.
"""

import struct


class DisassembleAccessFile(object):
    """
    Mixin for the Disassemble classes, which adds in memory decoding by seeking.
    """

    # Initialise with the base address of the file
    baseaddr = 0

    # Initialise with the file handle for the file
    fh = None

    # Set to True when seek is needed to reset the file pointer
    fh_seek_needed = False
    fh_seek_pos = None

    # File extent, or None if not known
    _fh_extent = None

    # How close to the end we'll do the fast get_memory_string call
    fast_memory_string = 128

    @property
    def fh_extent(self):
        if self._fh_extent is None:
            if not self.fh_seek_needed:
                self.fh_seek_pos = self.fh.tell()
                self.fh_seek_needed = True
            self.fh.seek(0, 2)  # Seek to end
            self._fh_extent = self.fh.tell()
        return self._fh_extent

    def fh_reset(self):
        """
        Seek back to where the caller might have expected us to be.
        """
        if self.fh_seek_needed:
            self.fh.seek(self.fh_seek_pos)
            self.fh_seek_needed = False

    def get_memory_byte(self, addr):
        """
        Read the current value of a byte from memory (only used when live_memory is True).

        @param addr:    Address to read the value of

        @return:    Byte value from memory (unsigned)
                    None if no memory is present
        """
        if addr < self.baseaddr:
            return None
        if addr + 1 > self.baseaddr + self.fh_extent:
            return None

        if not self.fh_seek_needed:
            self.fh_seek_pos = self.fh.tell()
            self.fh_seek_needed = True
        self.fh.seek(addr - self.baseaddr)
        b = bytearray(self.fh.read(1))[0]
        return b

    def get_memory_word(self, addr):
        """
        Read the current value of a word from memory (only used when live_memory is True).

        @param addr:    Address to read the value of

        @return:    Word value from memory (unsigned 4 bytes, little endian)
                    None if no memory is present
        """
        if addr < self.baseaddr:
            return None
        if addr + 4 > self.baseaddr + self.fh_extent:
            return None

        if not self.fh_seek_needed:
            self.fh_seek_pos = self.fh.tell()
            self.fh_seek_needed = True
        self.fh.seek(addr - self.baseaddr)
        w = struct.unpack("<L", self.fh.read(4))[0]
        return w

    def get_memory_string(self, addr):
        """
        Read the current value of a control terminated string from memory
        (only used when live_memory is True).

        @param addr:    Address to read the value of

        @return:    String read (as a bytes sequence)
                    None if no memory is present
        """

        # Whether it can even be a string
        if addr < self.baseaddr:
            return None
        if addr + 1 > self.baseaddr + self.fh_extent:
            return None

        blist = []

        if addr + self.fast_memory_string < self.baseaddr + self.fh_extent:
            # There's at least 128 bytes, so we'll just try reading them
            if not self.fh_seek_needed:
                self.fh_seek_pos = self.fh.tell()
                self.fh_seek_needed = True
            self.fh.seek(addr - self.baseaddr)

            data = bytearray(self.fh.read(self.fast_memory_string))
            for b in data:
                if b < 32:
                    break
                blist.append(b)
            addr += len(blist)

        # This is near to the end of the file or we didn't find a terminator, so we'll try reading individual bytes
        while True:
            b = self.get_memory_byte(addr)
            if b is None:
                return None
            if b < 32:
                break
            blist.append(b)
            addr += 1
        bstr = bytes(bytearray(blist))
        return bstr.decode('latin-1').encode('ascii', 'backslashreplace')
