"""
REW-sploit

emulate_helper

Common functions used for the "emulate" modules

"""

import re
import os
import struct
from Crypto.Cipher import ARC4
from colorama import Fore, Back, Style
from colorama import init

import speakeasy
import speakeasy.winenv.arch as e_arch
import speakeasy.winenv.defs.winsock.ws2_32 as wstypes

import modules.emulate_config as cfg
#from modules.emulate_config import *
from modules.pcap_helper import *


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

    sc_addr = se.load_shellcode(payload, arch)
    sc_size = os.path.getsize(payload)
    cfg.entry_point = sc_addr

    # Check for CobaltStrike
    if is_cobaltstrike(se.mem_read(sc_addr, sc_size)) == True:
        self.poutput(
            Fore.YELLOW + '[*] CobaltStrike beacon config detected' + Style.RESET_ALL)
        if cfg.cbparser == True:
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

    module = se.load_module(payload)
    cfg.entry_point = module.base + module.ep

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
                cfg.entry_point = exp.address
                se.call(exp.address, [arg0, arg1])

    self.poutput(Fore.GREEN + '[+] Emulation ended' + Style.RESET_ALL)

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

    MAGIC_CFG = [
        b'\x69\x68\x69\x68\x69\x6b..\x69\x6b\x69\x68\x69\x6b..\x69\x6a',
        b'\x2e\x2f\x2e\x2f\x2e\x2c..\x2e\x2c\x2e\x2f\x2e\x2c..\x2e',
        b'\x00\x01\x00\x01\x00\x02..\x00\x02\x00\x01\x00\x02..\x00'
    ]

    # Check for encrypted config
    pos = shellcode.find(b'\xff\xff\xff') + 3
    if pos != -1:
        key = struct.unpack_from('<I', shellcode, pos)[0]
        magic_enc = struct.unpack_from('<I', shellcode, pos + 8)[0] ^ key
        magic = magic_enc & 0xFFFF

        if magic == 0x5a4d or magic == 0x9090:
            return True
    
    # Check for plain/encoded config
    for pattern in MAGIC_CFG:
        match = re.search(pattern, shellcode)
        if match:
             return True

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

    try:
        config = cfg.cobaltstrikeConfig(payload).parse_config()
    except:
        pass
    if not config:
        try:
            config = cfg.cobaltstrikeConfig(payload).parse_encrypted_config_non_pe()
        except:
            pass

    self.poutput(
        Fore.YELLOW + '  [*] Parser detected, printing config:' + Style.RESET_ALL)
    if config:
        for key in config:
            print('    ', key, '->', config[key])
