"""
Mixin classes for information about SWIs and address descriptions.

* `DisassembleAccessSWIs` provides name lookup for SWIs.
* `DisassembleAccessServices` provides name lookup for Services.
* `DisassembleAccessDescriptions` provices descriptions for code.
"""

class DisassembleAccessSWIs(object):
    """
    Mixin for the DisassembleAccess classes, which adds in SWI decoding.
    """

    swi_cache = None

    def decode_swi(self, swi):
        """
        Decode a SWI number into a SWI name.

        @param swi: SWI number to decode

        @return:    SWI name, eg "OS_WriteC", "OS_WriteI+'B'", "XIIC_Control", or &XXXXX
        """
        if self.swi_cache is None:
            from . import swis
            swi_cache = {}
            for name in dir(swis):
                if name[0] != '_' and '_' in name:
                    number = getattr(swis, name)
                    swi_cache[number] = name
            # Populate OS_WriteI
            for vdu in range(256):
                swi_cache[0x100 + vdu] = 'OS_WriteI+' + ('"%c"' % (vdu,) if 0x20 <= vdu < 0x7f else str(vdu))
            self.swi_cache = swi_cache

        xbit = swi & 0x20000
        name = self.swi_cache.get(swi & ~0x20000, None)
        if name:
            if xbit:
                name = 'X' + name
            return name
        return '&{:x}'.format(swi)


class DisassembleAccessServices(object):
    """
    Mixin for the DisassembleAccess classes, which adds in Service decoding.
    """
    service_cache = None

    def decode_service(self, service):
        """
        Decode a service number into a service name.

        @param service: Service number to decode

        @return:        Service name, eg "Service_Error"
                        Service number, eg "&XXXXXX"
        """
        if self.service_cache is None:
            from . import services
            service_cache = {}
            for name in dir(services):
                if name[0:8] == 'Service_':
                    number = getattr(services, name)
                    service_cache[number] = name
            self.service_cache = service_cache

        name = self.service_cache.get(service, None)
        if name:
            return name
        return '&{:x}'.format(service)


class DisassembleAccessDescriptions(object):

    def describe_address(self, addr, description=None):
        """
        Return a list of descriptions about the contents of an address.

        @param addr:        Address to describe the content of.
        @param description: Any additional information which is known, such as:
                                'pointer to string'
                                'pointer to code'
                                'pointer to error'
                                'corrupted'

        @return:    list of strings describing what's at that address
                    None if nothing known
        """
        if addr in (0, 0xFFFFFFFF):
            return []
        is_string = False
        not_string = False
        value_str = None
        words = None

        if description:
            if description.startswith('pointer to string'):
                # We know it's a string, so we try to fetch it
                value_str = self.get_memory_string(addr)
                if value_str is not None:
                    is_string = True

            if not value_str and (addr & 3) == 0:
                if description.startswith('pointer to code'):
                    # We know it's code, so we try to describe that
                    region = self.describe_code(addr)
                    if region:
                        return ['Function: %s' % (function,)]

                if description.startswith('pointer to error'):
                    errnum = self.get_memory_word(addr)
                    value_str = self.get_memory_string(addr + 1)
                    if value_str is not None and errnum is not None:
                        return ["Error &{:x}: \"{}\"".format(errnum,
                                                             value_str.decode('latin-1').encode('ascii', 'backslashreplace'))]

        if not value_str:
            # Let's have a guess at the string
            if not description or description.startswith('pointer to '):
                value_str = self.get_memory_string(addr)
                limit = 6
                if value_str and len(value_str) >= limit:
                    is_string = True
                else:
                    not_string = True

        if not not_string and not is_string:
            # We don't know if it's a string yet, so let's have a see whether
            # it looks like a string
            words = self.get_memory_words(addr, 4 * 4)
            word = words[0] if words else None
            if word is None:
                # It's not in mapped memory, so give up now.
                return []
            if 32 <= (word & 255) < 127 and \
               32 <= ((word>>8) & 255) < 127 and \
               32 <= ((word>>16) & 255) < 127 and \
               32 <= ((word>>24) & 255) < 127:
                # Looks like a plausible string; let's use it
                value_str = self.get_memory_string(addr)
                if len(value_str) < 250:
                    # So long as it's not too long, we'll say it's a string
                    is_string = True
                    not_string = False

        if is_string:
            return ["\"%s\"" % (self.decode_string(value_str),)]

        if (addr & 3) == 0:
            # It's aligned, so it might be a pointer to some words
            if not words:
                # If we've not already read the words, try now.
                words = self.get_memory_words(addr, 4 * 4)
            if words:
                words_str = ", ".join("&%08x" % (word,) for word in words)
                desc = ["[%s]" % (words_str,)]
                if not description or description.startswith('pointer to code'):
                    function = self.describe_code(addr)
                    if function:
                        #desc.insert(0, function)
                        desc = ['Function: %s' % (function,)]
                return desc

        return []
