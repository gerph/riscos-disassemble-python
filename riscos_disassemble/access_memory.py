"""
Memory access helper functions.

* `DisassembleAccessFile` allows a filehandle to be used as the source for
  reading the file as the memory source.
"""

import struct


class DisassembleAccessFile(object):
    """
    Mixin for the DisassembleAccess classes, which adds in memory decoding by seeking.
    """

    # Initialise with the base address of the file
    baseaddr = 0

    # Initialise with the file handle for the file
    fh = None

    # Set to True when seek is needed to reset the file pointer
    fh_seek_pos = 0 # We start at the start of the file

    # File extent, or None if not known
    _fh_extent = None

    # How close to the end we'll do the fast get_memory_string call
    fast_memory_string = 128

    # Recent words we have read, to improve performance.
    fh_word_cache = {}
    fh_word_cache_limit = 200

    @property
    def fh_extent(self):
        if self._fh_extent is None:
            self.fh_seek_pos = self.fh.tell()
            self.fh.seek(0, 2)  # Seek to end
            self._fh_extent = self.fh.tell()
            self.fh.seek(self.fh_seek_pos, 0)  # Seek back to old position
        return self._fh_extent

    def fh_seek(self, addr):
        """
        Seek to a specific address.

        @param addr:    This is the address we want
        """
        want_pos = addr - self.baseaddr
        if self.fh_seek_pos != want_pos:
            #print("seek &%x, at &%x" % (self.fh_seek_pos, want_pos))
            self.fh.seek(want_pos, 0)
            self.fh_seek_pos = want_pos

    def fh_read(self, nbytes, addr=None):
        if addr is None:
            addr = self.fh_seek_pos + self.baseaddr
        if nbytes == 4:
            w = self.fh_word_cache.get(addr)
            if w is not None:
                return struct.pack("<L", w)
        #print("Plain read at &%x" % (addr,))
        self.fh_seek(addr)
        got = self.fh.read(nbytes)
        if len(got) == 4:
            self.fh_word_cache[addr] = struct.unpack("<L", got)[0]
        self.fh_seek_pos += len(got)
        return got

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

        self.fh_seek(addr)
        b = bytearray(self.fh.read(1))[0]
        self.fh_seek_pos += 1
        return b

    def get_memory_word(self, addr):
        """
        Read the current value of a word from memory (only used when live_memory is True).

        @param addr:    Address to read the value of

        @return:    Word value from memory (unsigned 4 bytes, little endian)
                    None if no memory is present
        """
        w = self.fh_word_cache.get(addr)
        if w is not None:
            #print("Cache hit at &%x" % (addr,))
            return w

        if addr < self.baseaddr:
            return None
        if addr + 4 > self.baseaddr + self.fh_extent:
            return None

        self.fh_seek(addr)
        w = struct.unpack("<L", self.fh.read(4))[0]
        if len(self.fh_word_cache) > self.fh_word_cache_limit:
            self.fh_word_cache = {}
        self.fh_word_cache[addr] = w
        self.fh_seek_pos += 4
        return w

    def get_memory_string(self, addr, zeroterm=False):
        """
        Read the current value of a control terminated string from memory
        (only used when live_memory is True).

        @param addr:        Address to read the value of
        @param zeroterm:    True to terminiate only on 0

        @return:    String read (as a bytes sequence)
                    None if no memory is present
        """

        # Whether it can even be a string
        if addr < self.baseaddr:
            return None
        if addr + 1 > self.baseaddr + self.fh_extent:
            return None

        blist = []

        done = False
        if addr + self.fast_memory_string < self.baseaddr + self.fh_extent:
            # There's at least 128 bytes, so we'll just try reading them
            self.fh_seek(addr)

            data = bytearray(self.fh.read(self.fast_memory_string))
            self.fh_seek_pos += self.fast_memory_string
            for b in data:
                if (zeroterm and b == 0) or (not zeroterm and b < 32):
                    done = True
                    break
                blist.append(b)
            addr += len(blist)

        # This is near to the end of the file or we didn't find a terminator, so we'll try reading individual bytes
        while not done:
            b = self.get_memory_byte(addr)
            if b is None:
                return None
            if (zeroterm and b == 0) or (not zeroterm and b < 32):
                break
            blist.append(b)
            addr += 1
        bstr = bytes(bytearray(blist))
        return bstr.decode('latin-1').encode('ascii', 'backslashreplace')
