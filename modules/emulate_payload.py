"""
REW-sploit

emulate_payload

This module is able to identify if a specific flow, identified by
IP and PORT (intended as IP of the Meterpreter C2) is a Meterpreter session
and it tries to decrypt it if possible

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
from Crypto.Cipher import ARC4
from os import access, R_OK
from os.path import isfile

import speakeasy
import speakeasy.winenv.arch as e_arch
import speakeasy.winenv.defs.winsock.ws2_32 as wstypes

from modules.pcap_helper import *
from modules.emulate_rules import *
from modules.emulate_fixups import *
from modules.pe_helper import *
from modules.donut import *

#
# Parse also extras folder for additional packages
#

# Try https://github.com/Sentinel-One/CobaltStrikeParser.git
cbparser = True
try:
    sys.path.append(r'extras/CobaltStrikeParser')
    from extras.CobaltStrikeParser.parse_beacon_config import *
except:
    cbparser = False

#
# Globals
#

# colorama init
init(autoreset=True)

debug = 0
enable_fixups = True
donut_stub = False
enable_unhook = None
entry_point = 0

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
    Hook for CreateThread API.
    Used to dump the content of the memory mapped on the 
    thread.

    Args:
        Derived from Speakeasy implementation

    Returns:
        Result of the called API
    """

    _, _, entry_point, _, _, _ = params

    # Try to access all the memory from the entry_point
    # until an error is triggered
    i = 0
    while 1 == 1:
        try:
            _ = emu.mem_read(entry_point + i, 1)
            i += 1
        except:
            break

    path = os.path.join(tempfile.mkdtemp(), hex(entry_point) + '.bin')
    with open(path, 'wb') as outfile:
        outfile.write(emu.mem_read(entry_point, i))

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


def hook_code_32(emu, begin, end, ctx):
    """
    32 bit hooking function. This is executed for each instruction

    Args:
        Derived from Speakeasy implementation

    Returns:
        None
    """
    global entry_point

    # As a first thing, to avoid delays, check UnHook
    global enable_unhook

    if enable_unhook != None:
        if enable_unhook == 0:
            return
        elif enable_unhook == begin:
            enable_unhook = None
            print(Fore.GREEN + '[+] Hook Enabled' + Style.RESET_ALL)
            # Set entry-point when hoos starts, needed for fixups
            entry_point = begin
        else:
            return

    global rc4_key
    global enable_fixups
    global donut_stub

    logger = get_logger()
    # Get cmd2 obj for poutput
    cmd2 = ctx['cmd2']

    mnem, op, instr = emu.get_disasm(emu.reg_read(e_arch.X86_REG_EIP), end)

    opcodes = int(emu.mem_read(begin, end).hex(), 16)
    opcodes_buffer.append(emu.mem_read(begin, end))
    opcodes_data = b''.join(opcodes_buffer)

    if enable_fixups == True:
        fixups_unicorn(emu, begin, end, mnem, op, 'x86', entry_point)

    #####################################
    # YARA RULES MATCHING SECTION START #
    #####################################

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

    # Shortcut for Donut PIC code
    elif rule_donut_hash_shortcut_32.match(data=opcodes_data):

        if donut_stub == False:
            cmd2.poutput(
                Fore.YELLOW + '[*] Donut stub detected' + Style.RESET_ALL)
            donut_stub = True

        apiname = emu.mem_read(emu.reg_read(
            e_arch.X86_REG_ECX), 30).split(b'\x00')[0]

        if apiname not in donut_api_imports:
            # Skip the slow export hash name computation
            emu.reg_write(e_arch.X86_REG_EIP, begin + 5)

        opcodes_buffer.clear()

    ###################################
    # YARA RULES MATCHING SECTION END #
    ###################################

    # Print debug infos
    if debug >= 1:
        print('%s: 0x%s %s' % (hex(begin), emu.mem_read(begin, end).hex(), instr))
        print('   EAX=0x%x' % emu.reg_read(e_arch.X86_REG_EAX))
        print('   EBX=0x%x' % emu.reg_read(e_arch.X86_REG_EBX))
        print('   ECX=0x%x' % emu.reg_read(e_arch.X86_REG_ECX))
        print('   EDX=0x%x' % emu.reg_read(e_arch.X86_REG_EDX))
        print('   ESI=0x%x' % emu.reg_read(e_arch.X86_REG_ESI))
        print('   EDI=0x%x' % emu.reg_read(e_arch.X86_REG_EDI))
        print('   ESP=0x%x' % emu.reg_read(e_arch.X86_REG_ESP))
        print('   EBP=0x%x' % emu.reg_read(e_arch.X86_REG_EBP))

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
    global entry_point

    # As a first thing, to avoid delays, check UnHook
    global enable_unhook

    if enable_unhook != None:
        if enable_unhook == 0:
            return
        elif enable_unhook == begin:
            enable_unhook = None
            print(Fore.GREEN + '[+] Hook Enabled' + Style.RESET_ALL)
            # Set entry-point when hoos starts, needed for fixups
            entry_point = begin
        else:
            return

    global rc4_key
    global donut_stub

    logger = get_logger()
    # Get cmd2 obj for poutput
    cmd2 = ctx['cmd2']

    mnem, op, instr = emu.get_disasm(emu.reg_read(e_arch.AMD64_REG_RIP), end)

    opcodes = int(emu.mem_read(begin, end).hex(), 16)
    opcodes_buffer.append(emu.mem_read(begin, end))
    opcodes_data = b''.join(opcodes_buffer)

    if enable_fixups == True:
        fixups_unicorn(emu, begin, end, mnem, op, 'x64', entry_point)

    #####################################
    # YARA RULES MATCHING SECTION START #
    #####################################

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

    # Shortcut for Donut PIC code
    elif rule_donut_hash_shortcut_64.match(data=opcodes_data):

        if donut_stub == False:
            cmd2.poutput(
                Fore.YELLOW + '[*] Donut stub detected' + Style.RESET_ALL)
            donut_stub = True

        apiname = emu.mem_read(emu.reg_read(
            e_arch.AMD64_REG_RAX), 30).split(b'\x00')[0]

        if apiname not in donut_api_imports:
            # Skip the slow export hash name computation
            emu.reg_write(e_arch.AMD64_REG_RIP, begin + 29)

        opcodes_buffer.clear()

    ###################################
    # YARA RULES MATCHING SECTION END #
    ###################################

    # Print debug infos
    if debug >= 1:
        print('%s: 0x%s %s' % (hex(begin), emu.mem_read(begin, end).hex(), instr))
        print('   RAX=0x%x' % emu.reg_read(e_arch.AMD64_REG_RAX))
        print('   RBX=0x%x' % emu.reg_read(e_arch.AMD64_REG_RBX))
        print('   RCX=0x%x' % emu.reg_read(e_arch.AMD64_REG_RCX))
        print('   RDX=0x%x' % emu.reg_read(e_arch.AMD64_REG_RDX))
        print('   RSI=0x%x' % emu.reg_read(e_arch.AMD64_REG_RSI))
        print('   RDI=0x%x' % emu.reg_read(e_arch.AMD64_REG_RDI))
        print('   RSP=0x%x' % emu.reg_read(e_arch.AMD64_REG_RSP))
        print('   RBP=0x%x' % emu.reg_read(e_arch.AMD64_REG_RBP))

        if debug >= 2:
            input('Press ENTER to proceed')

    return


def extract_payload(self, filename, ip, port, key):
    """
    Extract the payload from the PCAP file

    Args:
        self: cmd2 object used for output
        filename: PCAP filename
        ip: C2 IP
        port: C2 port
        key: decryption key

    Returns:
        Buffer of the payload sent by Metasploit 
    """
    buffer = pcap_extract(filename, ip, port, 1)

    if key:
        self.poutput(Fore.MAGENTA +
                     '[+] Decrypting RC4 Payload' + Style.RESET_ALL)
        cipher = ARC4.new(key)
        buffer = cipher.decrypt(buffer[4:])

    return buffer


def load_init_registers(se, arch, sc_addr):
    """
    Init registers with the EIP...just in case...

    Args:
        se: Speakeasy object
        arch: architecture
        sc_addr: the shellcode address (entry point)

    Returns:
        None
    """

    if arch == e_arch.ARCH_X86:
        se.reg_write(e_arch.X86_REG_EAX, sc_addr)
        se.reg_write(e_arch.X86_REG_EBX, sc_addr)
        se.reg_write(e_arch.X86_REG_EDI, sc_addr)
        se.reg_write(e_arch.X86_REG_ESI, sc_addr)
    else:
        se.reg_write(e_arch.AMD64_REG_RAX, sc_addr)
        se.reg_write(e_arch.AMD64_REG_RBX, sc_addr)
        se.reg_write(e_arch.AMD64_REG_RDI, sc_addr)
        se.reg_write(e_arch.AMD64_REG_RSI, sc_addr)


def is_cobaltstrike(shellcode):
    """
    Detect if the payload is a CobaltStrike Beacon.

    Args:
        shellcode: buffer containing the shellcode

    Returns:
        Boolean stating if it is CobaltStrike
    """

    pos = shellcode.find(b'\xff\xff\xff') + 3
    if pos != -1:
        key = struct.unpack_from('<I', shellcode, pos)[0]
        magic_enc = struct.unpack_from('<I', shellcode, pos + 8)[0] ^ key
        magic = magic_enc & 0xFFFF

        if magic == 0x5a4d or magic == 0x9090:
            return True
    else:
        return False


def decode_cobaltstrike(self, payload):
    """
    Decode CobalStrike config if parser is installed.

    Args:
        self: cmd2 object used for output
        payload: buffer with the shellcode

    Returns:
        None (prints out the configuration)
    """

    config = cobaltstrikeConfig(payload).parse_encrypted_config_non_pe()
    self.poutput(
        Fore.YELLOW + '  [*] Parser detected, printing config:' + Style.RESET_ALL)

    for key in config:
        print('    ', key, '->', config[key])


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

    se = speakeasy.Speakeasy(config=cfg, logger=get_logger())
    arch = arch.lower()
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
    if writefile == True:
        se.add_api_hook(hook_WriteFile, 'kernel32', 'WriteFile')

    # Detect file type and start proper emulation
    code_type = pe_format(payload)
    if code_type == 3:
        start_shellcode(self, payload, se, arch)
    elif code_type == 2:
        start_dll(self, payload, se, arch, exportname)
    elif code_type == 1:
        start_exe(self, payload, se, arch)

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


def start_shellcode(self, payload, se, arch):
    """
    Loads and emulates shellcode

    Args:
        self: cmd2 object used for output
        payload: filename containing shellcode
        se: SpeakEasy object
        arch: architecture
    Returns:
        None
    """
    global entry_point

    sc_addr = se.load_shellcode(payload, arch)
    entry_point = sc_addr

    # Check for CobaltStrike
    if is_cobaltstrike(se.mem_read(sc_addr, 0x500)) == True:
        self.poutput(
            Fore.YELLOW + '[*] CobaltStrike beacon config detected' + Style.RESET_ALL)
        if cbparser == True:
            decode_cobaltstrike(self, payload)

    # Initialize the registers with EIP
    load_init_registers(se, arch, sc_addr)

    # Map some additional memory accessed by the shellcode
    se.emu.mem_map(sc_addr - 0x100, 0x100)
    # Start emulation
    self.poutput(Fore.GREEN + '[+] Starting emulation' + Style.RESET_ALL)
    se.run_shellcode(sc_addr, offset=0x0)
    self.poutput(Fore.GREEN + '[+] Emulation ended' + Style.RESET_ALL)

    return


def start_exe(self, payload, se, arch):
    """
    Loads and emulates EXE file

    Args:
        self: cmd2 object used for output
        payload: filename containing shellcode
        se: SpeakEasy object
        arch: architecture
    Returns:
        None
    """
    global entry_point

    module = se.load_module(payload)
    entry_point = module.base + module.ep

    # Start emulation
    self.poutput(Fore.GREEN + '[+] Starting emulation' + Style.RESET_ALL)
    se.run_module(module)
    self.poutput(Fore.GREEN + '[+] Emulation ended' + Style.RESET_ALL)

    return


def start_dll(self, payload, se, arch, exportname):
    """
    Loads and emulates DLL

    Args:
        self: cmd2 object used for output
        payload: filename containing shellcode
        se: SpeakEasy object
        arch: architecture
    Returns:
        None
    """
    global entry_point

    module = se.load_module(payload)

    # Start emulation
    self.poutput(Fore.GREEN + '[+] Starting emulation' + Style.RESET_ALL)

    # Fake args
    arg0 = 0x0
    arg1 = 0x1
    if exportname == None:
        # Enumerate the DLL exports
        for exp in module.get_exports():
            self.poutput(
                Fore.GREEN + '[+] DLL Export: ' + exp.name + Style.RESET_ALL)
        self.poutput(
            Fore.GREEN + '[+]     Specify -E option to execute an export' + Style.RESET_ALL)
    else:
        # Execute the given function
        se.run_module(module, all_entrypoints=False)
        for exp in module.get_exports():
            if exp.name == exportname.strip('\''):
                self.poutput(
                    Fore.GREEN + '[+] DLL Export: ' + exp.name + Style.RESET_ALL)
                entry_point = exp.address
                se.call(exp.address, [arg0, arg1])

    self.poutput(Fore.GREEN + '[+] Emulation ended' + Style.RESET_ALL)

    return


def module_main(self, *args, **kwargs):
    """
    Main module entry point
    """

    # Load Speakeasy configuration
    config_path = './speakeasy_default.json'
    with open(config_path, 'r') as f:
        cfg = json.load(f)

    start_speakeasy(self, kwargs, cfg)
