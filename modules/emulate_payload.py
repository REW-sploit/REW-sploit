"""
REW-sploit

emulate_payload

Functions to emulate code (EXE, DLL or shellcode) and inspect it.

"""

import os
import sys
import tempfile
import argparse
import logging
import json
import struct
import hexdump
import yara
import re
import collections
from colorama import Fore, Back, Style
from colorama import init
from socket import inet_ntoa, ntohs
from os import access, R_OK
from os.path import isfile

import speakeasy
import speakeasy.winenv.arch as e_arch
import speakeasy.winenv.defs.winsock.ws2_32 as wstypes

import modules.emulate_config as cfg
#from modules.emulate_config import *
from modules.emulate_rules import *
from modules.emulate_fixups import *
from modules.pe_helper import *
from modules.emulate_helper import *

#
# Globals
#

# colorama init
init(autoreset=True)

debug = 0
enable_fixups = True
donut_stub = False
enable_unhook = None
mem_chunk = {}

rc4_key = b''

#
# The YARA matching buffer handle 'maxlen' instructions.
# Keep this into consideration when creating rules
#
opcodes_buffer = collections.deque(maxlen=5)


def get_logger():
    """
    Get the default logger for speakeasy

    Args:
        None

    Returns:
        Logger object
    """
    logger = logging.getLogger('rew-sploit')
    if not logger.handlers:
        sh = logging.StreamHandler(sys.stdout)
        logger.addHandler(sh)
    logger.setLevel(logging.INFO)

    return logger


def hook_CreateThread(emu, api_name, func, params):
    """
    Hook for CreateThread and CreateRemoteThreadAPI.
    Used to dump the content of the memory mapped on the 
    thread.

    Args:
        Derived from Speakeasy implementation

    Returns:
        Result of the called API
    """

    if len(params) == 6:
        # This is for CreateRemoteThread
        _, _, ep, _, _, _ = params
    else:
        # This is for CreateThread
        _, _, _, ep, _, _, _ = params

    # Try to access all the memory from the entry_point
    # until an error is triggered
    i = 0
    while 1 == 1:
        try:
            _ = emu.mem_read(ep + i, 1)
            i += 1
        except:
            break

    path = os.path.join(tempfile.mkdtemp(), hex(ep) + '.bin')
    with open(path, 'wb') as outfile:
        outfile.write(emu.mem_read(ep, i))

    print(Fore.MAGENTA + '[+] Dumping ''CreateThread'' ( complete dump saved in ' + path + ' )'
                         + Style.RESET_ALL)
    # Call the function
    rv = func(params)

    return rv


def hook_WriteFile(emu, api_name, func, params):
    """
    Hook for WriteFile API.
    Used to dump the content of the buffer

    Args:
        Derived from Speakeasy implementation

    Returns:
        Result of the called API
    """

    _, lpbuffer, numbytes, _, _ = params

    path = os.path.join(tempfile.mkdtemp(), hex(lpbuffer) + '.bin')
    with open(path, 'wb') as outfile:
        outfile.write(emu.mem_read(lpbuffer, numbytes))

    print(Fore.MAGENTA + '[+] Dumping ''WriteFile'' ( complete dump saved in ' + path + ' )'
                         + Style.RESET_ALL)
    # Call the function
    rv = func(params)

    return rv


def hook_VirtualAlloc(emu, api_name, func, params):
    """
    Hook for VirutalAlloc API.
    Used to dump the buffer when accessed

    Args:
        Derived from Speakeasy implementation

    Returns:
        Result of the called API
    """

    global mem_chunk

    lpaddr, dwsize, _, _ = params

    # Call the function
    rv = func(params)

    emu.add_mem_read_hook(hook_dump_mem, begin=rv, end=rv + dwsize)
    emu.add_dyn_code_hook(hook_dump_dyn)

    mem_chunk[rv] = rv + dwsize

    return rv


def hook_dump_mem(emu, access, addr, size, value, ctx):
    """
    Memory hook.
    Dump the content of allocated memory if accessed to be read.
    Used by hook_VirtualAlloc
    """

    global mem_chunk

    for begin in mem_chunk:
        if addr >= begin and addr < mem_chunk[begin]:
            path = os.path.join(tempfile.mkdtemp(), hex(begin) + '.bin')
            with open(path, 'wb') as outfile:
                outfile.write(emu.mem_read(begin, mem_chunk[begin] - begin))

            print(Fore.MAGENTA + '[+] Dumping ''VirtualAlloc'' on read ( complete dump saved in ' +
                  path + ' )' + Style.RESET_ALL)
            del(mem_chunk[begin])
            break

    return


def hook_dump_dyn(ctx):
    """
    Dynamic code hook.
    Dump the memory area allocated by VirtuaAlloc and then executed
    Used by hook_VirtualAlloc
    """

    global mem_chunk

    addr = ctx.get_base()
    for begin in mem_chunk:
        if addr >= begin and addr < mem_chunk[begin]:
            path = os.path.join(tempfile.mkdtemp(), hex(begin) + '.bin')
            with open(path, 'wb') as outfile:
                outfile.write(ctx.process.emu.mem_read(
                    begin, mem_chunk[begin] - begin))

            print(Fore.MAGENTA + '[+] Dumping ''VirtualAlloc'' on exec ( complete dump saved in ' +
                  path + ' )' + Style.RESET_ALL)
            del(mem_chunk[begin])
            break

    return


def hook_VirtualFree(emu, api_name, func, params):
    """
    Hook for VirutalFree API.
    Used to dump the buffer if released

    Args:
        Derived from Speakeasy implementation

    Returns:
        Result of the called API
    """

    global mem_chunk

    lpaddr, dwsize, _ = params

    path = os.path.join(tempfile.mkdtemp(), hex(lpaddr) + '.bin')
    with open(path, 'wb') as outfile:
        outfile.write(emu.mem_read(lpaddr, mem_chunk[lpaddr] - lpaddr))

    print(Fore.MAGENTA + '[+] Dumping ''VirtualAlloc'' on free ( complete dump saved in ' +
          path + ' )' + Style.RESET_ALL)
    del(mem_chunk[lpaddr])

    # Call the function
    rv = func(params)

    return rv


def hook_recv(emu, api_name, func, params):
    """
    Hook for recv. Just a placeholder for the time being

    Args:
        Derived from Speakeasy implementation

    Returns:
        Result of the called API
    """

    socket, buf, length, flags = params
    # Call the function
    rv = func(params)

    return rv


def hook_send(emu, api_name, func, params):
    """
    Hook for send. Just a placeholder for the time being

    Args:
        Derived from Speakeasy implementation

    Returns:
        Result of the called API
    """

    socket, buf, length, flags = params
    # Call the function
    rv = func(params)

    return rv


def hook_connect(emu, api_name, func, params):
    """
    Hook for connect. Just a placeholder for the time being

    Args:
        Derived from Speakeasy implementation

    Returns:
        Result of the called API
    """

    socket, jpname, namelen = params

    # Extract the LHOST and LPORT
    # sockaddr = wstypes.sockaddr_in(emu.get_ptr_size())
    # sa = emu.mem_cast(sockaddr, pname)
    # raddr = inet_ntoa(sa.sin_addr.to_bytes(4, 'little'))
    # rport = ntohs(sa.sin_port)

    # Call the function
    rv = func(params)

    return rv


def hook_readmem(emu, access, addr, size, value, ctx):
    """
    Hook for readmem. Just a placeholder for the time being

    Args:
        Derived from Speakeasy implementation

    Returns:
        Result of the called API
    """

    return


def hook_mapviewofsection(emu, api_name, func, params):
    """
    Hook for ZwMapViewOfSection
    This one is needed for Donut EXE emulation.
    The very first call of this API is done with protection
    PAGE_READWRITE (0x04). After a while unicorn drops an read access
    violation. This does not happen if I patch the protection to 
    PAGE_EXECUTE_READWRITE (0x40)
    """

    if params[9] == 0x04:
        params[9] = 0x40

    # Call the function
    rv = func(params)

    return rv


def hook_code_32(emu, begin, end, ctx):
    """
    32 bit hooking function. This is executed for each instruction

    Args:
        Derived from Speakeasy implementation

    Returns:
        None
    """

    # As a first thing, to avoid delays, check UnHook
    global enable_unhook

    if enable_unhook != None:
        if enable_unhook == 0:
            return
        elif enable_unhook == begin:
            enable_unhook = None
            print(Fore.GREEN + '[+] Hook Enabled' + Style.RESET_ALL)
            # Set entry-point when hoos starts, needed for fixups
            cfg.entry_point = begin
        else:
            return

    global rc4_key
    global enable_fixups
    global donut_stub

    # Get cmd2 obj for poutput
    cmd2 = ctx['cmd2']

    mnem, op, instr = emu.get_disasm(emu.reg_read(e_arch.X86_REG_EIP), end)

    opcodes = int(emu.mem_read(begin, end).hex(), 16)
    opcodes_buffer.append(emu.mem_read(begin, end))
    opcodes_data = b''.join(opcodes_buffer)

    if enable_fixups == True:
        fixups_unicorn(emu, begin, end, mnem, op, 'x86', cfg.entry_point)

    #########################################################
    # 32 BIT YARA RULES/CUSTOM RULES MATCHING SECTION START #
    #                                                       #
    # Here you can add also your custom code.               #
    # Variable "begin" contains the current Instruction     #
    # Pointer. Example:                                     #
    #                                                       #
    #    if begin == 0x10002321:                            #
    #         ...do something...                            #
    #                                                       #
    #########################################################

    # Look for "xor esi,0x<const>"
    if rule_reverse_tcp_rc4_xor_32.match(data=opcodes_data):

        try:
            # Replace the value to read just 8 bytes
            xorconst = opcodes & 0xFFFFFFFF
            xorval = struct.unpack("<I", struct.pack(">I", xorconst))[0] ^ 8
            emu.reg_write(e_arch.X86_REG_ESI, xorval)
            cmd2.poutput(Fore.MAGENTA + '[+] XOR constant for payload length: %s - 0x%x' % (struct.pack("<I", xorconst),
                                                                                            struct.unpack("<I", struct.pack(">I", xorconst))[0]) +
                         Style.RESET_ALL)
        except:
            cmd2.poutput(
                Red.MAGENTA + '[!] Error decoding XOR constant' + Style.RESET_ALL)

        opcodes_buffer.clear()

    # Look for "add bl, byte ptr [esi+edx]"
    # This should contain the RC4 password
    elif rule_reverse_tcp_rc4_key.match(data=opcodes_data):
        try:
            password = emu.mem_read(emu.reg_read(e_arch.X86_REG_ESI), 16)
            hex_password = ''.join('{:02x}'.format(x) for x in password)
            cmd2.poutput(Fore.MAGENTA + '[+] Recovered RC4 key: %s - 0x%s' % (password, hex_password)
                         + Style.RESET_ALL)
            rc4_key = password
        except:
            cmd2.poutput(
                Red.MAGENTA + '[!] Error extracting RC4 key' + Style.RESET_ALL)

        opcodes_buffer.clear()
        emu.exit_process()

    # Identification of chacha key and nonce
    elif rule_encrypted_shell_reverse_tcp_32.match(data=opcodes_data):
        try:
            chachakey = emu.mem_read(
                emu.reg_read(e_arch.X86_REG_ESP) + 0x6F, 32)
            # Write the last portion of the nonce
            emu.mem_write(emu.reg_read(e_arch.X86_REG_ESP) + 0x6A,
                          struct.pack(">I", opcodes & 0x00000000FFFFFFFF))
            chachanonce = emu.mem_read(
                emu.reg_read(e_arch.X86_REG_ESP) + 0x62, 12)
            cmd2.poutput(
                Fore.MAGENTA + '[+] Recovered Chacha key %s' % (chachakey) + Style.RESET_ALL)
            cmd2.poutput(
                Fore.MAGENTA + '[+] Recovered Chacha nonce %s' % (chachanonce) + Style.RESET_ALL)
        except:
            cmd2.poutput(
                Red.MAGENTA + '[!] Error extracting ChaCha key/nonce' + Style.RESET_ALL)

        opcodes_buffer.clear()
        emu.exit_process()

    # Shortcut for Donut code
    elif rule_donut_hash_shortcut_32.match(data=opcodes_data):

        if donut_stub == False:
            cmd2.poutput(
                Fore.YELLOW + '[*] Donut stub detected (you may want to'
                              ' add DLLs in decoy folder. See README.md)' + Style.RESET_ALL)
            donut_stub = True

        emu.add_api_hook(hook_mapviewofsection, 'ntdll', 'ZwMapViewOfSection')
        enable_unhook = 0
        opcodes_buffer.clear()

    ##########################################
    # 32 bit YARA RULES MATCHING SECTION END #
    ##########################################

    # Print debug infos
    if debug >= 1:

        print()
        print('   EAX=0x%x' % emu.reg_read(e_arch.X86_REG_EAX))
        print('   EBX=0x%x' % emu.reg_read(e_arch.X86_REG_EBX))
        print('   ECX=0x%x' % emu.reg_read(e_arch.X86_REG_ECX))
        print('   EDX=0x%x' % emu.reg_read(e_arch.X86_REG_EDX))
        print('   ESI=0x%x' % emu.reg_read(e_arch.X86_REG_ESI))
        print('   EDI=0x%x' % emu.reg_read(e_arch.X86_REG_EDI))
        print('   ESP=0x%x' % emu.reg_read(e_arch.X86_REG_ESP))
        print('   EBP=0x%x' % emu.reg_read(e_arch.X86_REG_EBP))
        print('%s: 0x%s %s' % (hex(begin), emu.mem_read(begin, end).hex(), instr))

        if debug >= 2:
            input('Press ENTER to proceed')

    return


def hook_code_64(emu, begin, end, ctx):
    """
    64 bit hooking function. This is executed for each instruction

    Args:
        Derived from Speakeasy implementation

    Returns:
        None
    """

    # As a first thing, to avoid delays, check UnHook
    global enable_unhook

    if enable_unhook != None:
        if enable_unhook == 0:
            return
        elif enable_unhook == begin:
            enable_unhook = None
            print(Fore.GREEN + '[+] Hook Enabled' + Style.RESET_ALL)
            # Set entry-point when hoos starts, needed for fixups
            cfg.entry_point = begin
        else:
            return

    global rc4_key
    global enable_fixups
    global donut_stub

    # Get cmd2 obj for poutput
    cmd2 = ctx['cmd2']

    mnem, op, instr = emu.get_disasm(emu.reg_read(e_arch.AMD64_REG_RIP), end)

    opcodes = int(emu.mem_read(begin, end).hex(), 16)
    opcodes_buffer.append(emu.mem_read(begin, end))
    opcodes_data = b''.join(opcodes_buffer)

    if enable_fixups == True:
        fixups_unicorn(emu, begin, end, mnem, op, 'x64', cfg.entry_point)

    #########################################################
    # 64 BIT YARA RULES/CUSTOM RULES MATCHING SECTION START #
    #                                                       #
    # Here you can add also your custom code.               #
    # Variable "begin" contains the current Instruction     #
    # Pointer. Example:                                     #
    #                                                       #
    #    if begin == 0x10002321:                            #
    #         ...do something...                            #
    #                                                       #
    #########################################################

    # Look for "xor esi,0x<const>"
    if rule_reverse_tcp_rc4_xor_64.match(data=opcodes_data):
        try:
            # Replace the value to read just 8 bytes
            xorconst = opcodes & 0xFFFFFFFF
            xorval = struct.unpack("<I", struct.pack(">I", xorconst))[0] ^ 8
            emu.reg_write(e_arch.AMD64_REG_RSI, xorval)
            cmd2.poutput(Fore.MAGENTA + '[+] XOR constant for payload length: %s - 0x%x' % (struct.pack("<I", xorconst),
                                                                                            struct.unpack("<I", struct.pack(">I", xorconst))[0]) +
                         Style.RESET_ALL)
        except:
            cmd2.poutput(
                Red.MAGENTA + '[!] Error decoding XOR constant' + Style.RESET_ALL)

        opcodes_buffer.clear()

    # Look for "add bl, byte ptr [esi+edx]"
    # This should contain the RC4 password
    elif rule_reverse_tcp_rc4_key.match(data=opcodes_data):
        try:
            password = emu.mem_read(emu.reg_read(e_arch.AMD64_REG_RSI), 16)
            hex_password = ''.join('{:02x}'.format(x) for x in password)
            cmd2.poutput(Fore.MAGENTA + '[+] Recovered RC4 key: %s - 0x%s' % (password, hex_password)
                         + Style.RESET_ALL)
            rc4_key = password
        except:
            cmd2.poutput(
                Red.MAGENTA + '[!] Error extracting RC4 key' + Style.RESET_ALL)

        opcodes_buffer.clear()
        emu.exit_process()

    # Identification of chacha key and nonce
    elif rule_encrypted_shell_reverse_tcp_64.match(data=opcodes_data):
        try:
            chachakey = emu.mem_read(emu.reg_read(
                e_arch.AMD64_REG_RSP) + 0xa0, 32)
            chachanonce = emu.mem_read(
                emu.reg_read(e_arch.AMD64_REG_RSP) + 0x93, 12)
            cmd2.poutput(
                Fore.MAGENTA + '[+] Recovered Chacha key %s' % (chachakey) + Style.RESET_ALL)
            cmd2.poutput(
                Fore.MAGENTA + '[+] Recovered Chacha nonce %s' % (chachanonce) + Style.RESET_ALL)
        except:
            cmd2.poutput(
                Red.MAGENTA + '[!] Error extracting ChaCha key/nonce' + Style.RESET_ALL)

        opcodes_buffer.clear()
        emu.exit_process()

    # Shortcut for Donut code
    elif rule_donut_hash_shortcut_64.match(data=opcodes_data):

        if donut_stub == False:
            cmd2.poutput(
                Fore.YELLOW + '[*] Donut stub detected (you may want to'
                              ' add DLLs in decoy folder. See README.md)' + Style.RESET_ALL)
            donut_stub = True

        emu.add_api_hook(hook_mapviewofsection, 'ntdll', 'ZwMapViewOfSection')
        enable_unhook = 0
        opcodes_buffer.clear()

    ###################################
    # YARA RULES MATCHING SECTION END #
    ###################################

    # Print debug infos
    if debug >= 1:

        print()
        print('   RAX=0x%x' % emu.reg_read(e_arch.AMD64_REG_RAX))
        print('   RBX=0x%x' % emu.reg_read(e_arch.AMD64_REG_RBX))
        print('   RCX=0x%x' % emu.reg_read(e_arch.AMD64_REG_RCX))
        print('   RDX=0x%x' % emu.reg_read(e_arch.AMD64_REG_RDX))
        print('   RSI=0x%x' % emu.reg_read(e_arch.AMD64_REG_RSI))
        print('   RDI=0x%x' % emu.reg_read(e_arch.AMD64_REG_RDI))
        print('   RSP=0x%x' % emu.reg_read(e_arch.AMD64_REG_RSP))
        print('   RBP=0x%x' % emu.reg_read(e_arch.AMD64_REG_RBP))
        print('%s: 0x%s %s' % (hex(begin), emu.mem_read(begin, end).hex(), instr))

        if debug >= 2:
            input('Press ENTER to proceed')

    return


def start_speakeasy(self, kwargs, cfg):
    """
    Prepare the harness and starts the emulation session.

    Args:
        self: cmd2 object used for output
        kwargs: arguments coming from the CLI
        cfg: the Speakeasy configuration file

    Returns:
        None
    """

    global debug
    global enable_fixups
    global enable_unhook
    global donut_stub

    ip = kwargs['ip'].replace('\'', '')
    port = kwargs['port']
    payload = kwargs['payload'].replace('\'', '')
    file = kwargs['file'].replace('\'', '')
    arch = kwargs['arch'].replace('\'', '')  # 'x86'
    dbg = kwargs['debug']
    fixups = kwargs['fixups']
    unhook = kwargs['unhook']
    thread = kwargs['thread']
    writefile = kwargs['writefile']
    writemem = kwargs['writemem']
    exportname = kwargs['exportname']

    debug = dbg
    enable_fixups = fixups

    if not access(payload, R_OK):
        self.poutput(
            Fore.RED + '[!] Payload file not existing or not readable ' + Style.RESET_ALL)
        return
    if unhook != None:
        try:
            enable_unhook = int(unhook.replace('\'', ''), base=16)
        except:
            self.poutput(
                Fore.RED + '[!] Invalid address (must be Hex)' + Style.RESET_ALL)
            return

    logger = get_logger()
    se = speakeasy.Speakeasy(config=cfg, logger=logger)
    arch = arch.lower()

    # Automatically detects arch for EXE and DLL
    detected_arch = pe_arch(payload)
    if detected_arch:
        arch = detected_arch
        self.poutput(
            Fore.YELLOW + '[*] Architecture set to ' + arch + Style.RESET_ALL)

    if arch == 'x86':
        arch = e_arch.ARCH_X86
        # Set hooks
        se.add_code_hook(hook_code_32, ctx={'cmd2': self})
    elif arch in ('x64', 'amd64'):
        arch = e_arch.ARCH_AMD64
        # Set hooks
        se.add_code_hook(hook_code_64, ctx={'cmd2': self})
    else:
        self.poutput(
            Fore.RED + '[!] Unsupported architecture' + Style.RESET_ALL)
        return

    opcodes_buffer.clear()
    # se.add_mem_write_hook(hook_readmem)
    # se.add_mem_read_hook(hook_readmem)

    # Hook some API
    #se.add_api_hook(hook_recv, 'ws2_32', 'recv')
    #se.add_api_hook(hook_send, 'ws2_32', 'send')
    #se.add_api_hook(hook_connect, 'ws2_32', 'connect')
    if thread == True:
        se.add_api_hook(hook_CreateThread, 'kernel32', 'CreateThread')
        se.add_api_hook(hook_CreateThread, 'kernel32', 'CreateRemoteThread')
    if writefile == True:
        se.add_api_hook(hook_WriteFile, 'kernel32', 'WriteFile')
    if writemem == True:
        se.add_api_hook(hook_VirtualAlloc, 'kernel32', 'VirtualAlloc')
        se.add_api_hook(hook_VirtualFree, 'kernel32', 'VirtualFree')

    # Detect file type and start proper emulation
    code_type = pe_format(payload)
    if code_type == 3:
        start_shellcode(self, payload, se, arch)
    elif code_type == 2:
        start_dll(self, payload, se, arch, exportname)
    elif code_type == 1:
        start_exe(self, payload, se, arch)

    # Clean up logger handlers to avoid conflicts
    for hndl in logger.handlers:
        logger.removeHandler(hndl)

    # Reset flags and vars for next emulation
    enable_unhook = None
    donut_stub = False
    debug = 0
    mem_chunk = {}

    if ip != '0.0.0.0':
        self.poutput(
            Fore.GREEN + '\n[+] Getting payload from PCAP' + Style.RESET_ALL)

        buf = extract_payload(self, file, ip, port, rc4_key)

        if buf:
            path = os.path.join(tempfile.mkdtemp(), 'payload')
            self.poutput(Fore.MAGENTA + '[+] Payload sample ( complete dump saved in ' + path + ' )'
                         + Style.RESET_ALL)
            hexdump(buf[:48])
            with open(path, 'wb') as outfile:
                outfile.write(buf)


def module_main(self, *args, **kwargs):
    """
    Main module entry point
    """

    # Load Speakeasy configuration
    config_path = './speakeasy_default.json'
    with open(config_path, 'r') as f:
        cfg = json.load(f)

    start_speakeasy(self, kwargs, cfg)
