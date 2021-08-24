"""
emulate_helper.py

Helper functions for emualtion.

"""

import re
import struct

import speakeasy.winenv.arch as e_arch

fpu_instructions = ['fld1', 'fldl2t', 'fldl2e', 'fldpi', 'fldlg2', 'fldln2',
                    'fldz', 'fld', 'fxch', 'fcmovb', 'fcmove', 'fcmovbe', 'fcmovu',
                    'fcmovnb', 'fcmovne', 'fcmovnbe', 'fcmovnu', 'ffree', 'fnop',
                    'fabs', 'fdecstp', 'fincstp', 'fxam']
fpu_addr = 0


def fixups_unicorn(emu, begin, end, mnem, op, arch):
    global fpu_addr

    """
    Implements some hacks to fix/workoaround some issues in unicorn emulation

    Args:
        emu: emulation instance
        begin: begin address
        end: end address
        mnem: mnemonic codes
        op: opcodes
        arch: architecture

    Returns:
        None
    """

    #
    # Fixup #1
    # Unicorn issue #1092 (XOR instruction executed twice)
    # https://github.com/unicorn-engine/unicorn/issues/1092
    #               #820 (Incorrect memory view after running self-modifying code)
    # https://github.com/unicorn-engine/unicorn/issues/820
    # Issue: self modfying code in the same Translated Block (16 bytes?)
    # Yes, I know...this is a huge kludge... :-/
    #

    TB = 16

    if mnem == 'xor':
        p = re.compile(
            '(.*) ptr \[(.*?)([\+\-\*\/])(.*?)\], (.*)', re.IGNORECASE)
        try:
            r = p.match(op)
            if r:
                n1 = extract_addr(emu, r.group(2))
                n2 = extract_addr(emu, r.group(4))
                addr = arit_addr(n1, n2, r.group(3))

                if (addr - begin) <= TB:
                    xorval = extract_addr(emu, r.group(5))
                    manual_xor(emu, r.group(1), addr, xorval)
                    # Skip instruction
                    emu.reg_write(e_arch.X86_REG_EIP if arch == 'x86' else e_arch.AMD64_REG_RIP,
                                  begin + end)
                    print('[!] Fixup #1 applied (self-mod code)')
        except:
            pass

        return

    #
    # Fixup #2
    # The "fpu" related instructions (FPU/FNSTENV), used to recover EIP, sometimes
    # returns the wrong addresses.
    # In this case, I need to track the first FPU instruction and then place
    # its address in STACK when FNSTENV is called
    #
    if mnem in fpu_instructions:
        # Rgister the location of the FPU instruction
        fpu_addr = begin

        return
    if mnem == 'fnstenv' and fpu_addr != 0:

        if emu.get_stack_ptr() == emu.stack_base:
            # If the stack pointer is at its base, I bring it back a little bit
            # to avoid an "unmapped write".
            # This happens in presence of recursive encoding for shikata_ga_nai
            if arch == 'x86':
                emu.reg_write(e_arch.X86_REG_ESP, emu.get_stack_ptr() - 4)
            else:
                emu.reg_write(e_arch.AMD64_REG_RSP, emu.get_stack_ptr() - 8)
        # Now it's time to write the location in the stack (overwriting)
        if arch == 'x86':
            emu.mem_write(emu.reg_read(e_arch.X86_REG_ESP),
                          struct.pack("<I", fpu_addr))
            # Skip instruction
            emu.reg_write(e_arch.X86_REG_EIP, begin + 4)
        else:
            emu.mem_write(emu.reg_read(e_arch.AMD64_REG_RSP),
                          struct.pack("<I", fpu_addr))
            # Skip instruction
            emu.reg_write(e_arch.AMD64_REG_RIP, begin + 4)

        fpu_addr = 0

        print('[!] Fixup #2 applied (FPU opcodes)')
        return

    #
    # Fixup #3
    # Trap Flag evasion technique
    # https://unit42.paloaltonetworks.com/single-bit-trap-flag-intel-cpu/
    #
    # The call of the RDTSC with the trap flag enabled, cause an unhandled
    # interrupt. Example code:
    #        pushf
    #        or dword [esp], 0x100
    #        popf
    #        rdtsc
    #
    # Any call to RDTSC with Trap Flag set will be intercepted and TF will
    # be cleared
    #
    if mnem == 'rdtsc':

        # Read the Trap Flag
        TF = emu.reg_read(e_arch.X86_REG_EFLAGS) >> 8
        if TF == 1:
            cleared = emu.reg_read(e_arch.X86_REG_EFLAGS) & ~(1 << 8)
            emu.reg_write(e_arch.X86_REG_EFLAGS, cleared)

            if arch == 'x86':
                # Skip instruction
                emu.reg_write(e_arch.X86_REG_EIP, begin + 2)
            else:
                # Skip instruction
                emu.reg_write(e_arch.AMD64_REG_RIP, begin + 2)

            print('[!] Fixup #3 applied (Trap Flag evasion)')


def extract_addr(emu, ref):
    """
    Convert the parameter to the address:
    if it's an int, we have direct conversion otherwise we read the register

    Args:
        emu: emulation instance
        ref: this may contain an address or a register (from which an 
             address will be extracted)

    Returns:
        The memory address
    """

    # Check if int or register
    try:
        addr = int(ref, 16)
    except:
        addr = None

    try:
        if addr == None:
            addr = emu.reg_read(ref.replace(' ', ''))
    except:
        addr = None

    return addr


def arit_addr(addr1, addr2, operation):
    """
    Perform the arithmetic operation on the two addresses

    Args:
        addr1: address 1 for arithmetic operation
        addr2: address 2 for arithmetic operation
        operation: string with the operation (+,-,* or /)

    Returns:
        Result of the operation
    """

    if operation == '+':
        res = addr1 + addr2
    elif operation == '-':
        res = addr1 - addr2
    elif operation == '*':
        res = addr1 * addr2
    else:
        res = addr1 // addr2

    return res


def manual_xor(emu, plen, addr, xorval):
    """
    Manually apply the XOR operation in memory

    Args:
        emu: emulation instance
        plen: length of the pointer (ex. dword)
        addr: memory address of the bytes to be xored
        xorval: XOR value

    Returns:
        None
    """

    if plen == 'dword':
        nbytes = 4

    buff = emu.mem_read(addr, nbytes)
    buff = struct.pack("<I", struct.unpack("<I", buff)[0] ^ xorval)
    emu.mem_write(addr, buff)
