"""
Disassembly functions.

The functions provided here make for a simpler disassembly.
"""

from . import base

initialised = False


def get_disassembler(arch):
    """
    Retrieve the class which performs disassembly for a given architecture.
    """

    if not initialised:
        import riscos_disassemble.arm.disassemble
        import riscos_disassemble.arm64.disassemble

    dis_cls = base.registrations.get(arch)
    return dis_cls


def disassemble_instruction(arch, address, inst,
                            live_registers=False, live_memory=False,
                            access=None):
    """
    Disassemble an instruction into broken down values.

    @param arch:            Disassembly architecture
    @param address:         Address the instruction comes from
    @param inst:            32bit/16bit instruction word
    @param live_registers:  Whether registers may be used to provide more information
    @param live_memory:     Whether memory reads may be used to provide more information

    @return: Tuple of (bytes-consumed, mnemonic string, operands string, comment string)
             Mnemonic string, operands string and comment string will be None if no
             disassembly was available.
    """
    dis_cls = get_disassembler(arch)
    if not dis_cls:
        return (0, None, None, None)
    dis = dis_cls(access=access)
    return dis.disassemble_instruction(address, inst,
                                       live_registers=live_registers,
                                       live_memory=live_memory)


def disassemble(arch, address, inst,
                live_registers=False, live_memory=False,
                *args, **kwargs):
    """
    Disassemble an instruction into a formatted string.

    @param arch:            Disassembly architecture
    @param address:         Address the instruction comes from
    @param inst:            32bit/16bit instruction word
    @param live_registers:  Whether registers may be used to provide more information
    @param live_memory:     Whether memory reads may be used to provide more information
    @param thumb:           True to disassemble as a Thumb instruction

    @return:         Tuple of (consumed, string describing the instruction or None if not disassembly)
    """
    dis_cls = get_disassembler(arch)
    if not dis_cls:
        return (0, None)

    dis = dis_cls(access=access)
    return dis.disassemble(address, inst,
                           live_registers=live_registers,
                           live_memory=live_memory)
