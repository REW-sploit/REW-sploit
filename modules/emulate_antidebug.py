"""
REW-sploit

emulate_antidebug

Functions to emulate code (EXE, DLL or shellcode) and identify antidebug.
See https://anti-debug.checkpoint.com/
"""

import os
import sys
import tempfile
import argparse
import logging
import json
import struct
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
current_process = 0

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
    logger.setLevel(logging.ERROR)

    return logger

def hook_isdebuggerpresent(emu, api_name, func, params):
    """
    Hook IsDebuggerPresent

    Args:
        Derived from Speakeasy implementation

    Returns:
        Result of the called API
    """

    print(Fore.YELLOW + '[#] IsDebuggerPresent() at ' + hex(emu.get_ret_address()) +
          Style.RESET_ALL)
    # Call the function
    rv = func(params)

    return rv

def hook_getcurrentprocess(emu, api_name, func, params):
    """
    Hook GetCurrentProcess

    Args:
        Derived from Speakeasy implementation

    Returns:
        Result of the called API
    """

    global current_process

    # Call the function
    rv = func(params)

    current_process = rv
    return rv

def hook_checkremotedebuggerpresent(emu, api_name, func, params):
    """
    Hook CheckRemoteDebuggerPresnet()

    Args:
        Derived from Speakeasy implementation

    Returns:
        Result of the called API
    """

    print(Fore.YELLOW + '[#] CheckRemoteDebuggerPresent() at ' + hex(emu.get_ret_address()) +
          Style.RESET_ALL)
    # Call the function
    rv = func(params)

    return rv

def hook_ntqueryinformationprocess(emu, api_name, func, params):
    """
    Hook NtQueryInformationProcess(
        HANDLE           ProcessHandle,
        PROCESSINFOCLASS ProcessInformationClass,
        PVOID            ProcessInformation,
        ULONG            ProcessInformationLength,
        PULONG           ReturnLength)

    If ProcessHandle is current process and ProcessInformationClass is 
    equal to 0x07 (ProcessDebugPort) or 0x1f (ProcessDebugFlags), can be 
    used to detect debugger

    Args:
        Derived from Speakeasy implementation

    Returns:
        Result of the called API
    """

    global current_process

    handle, infoclass, _, _, _ = params

    if handle == current_process and (infoclass == 0x07 or infoclass == 0x1f):
        print(Fore.YELLOW + '[#] Suspect NtQueryInformationProcess() at ' + 
              hex(emu.get_ret_address()) + Style.RESET_ALL)

    # Call the function
    rv = func(params)

    return rv

def hook_ntquerysysteminformation(emu, api_name, func, params):
    """
    Hook NtQuerySystemInformation(
        SYSTEM_INFORMATION_CLASS SystemInformationClass,
        PVOID                    SystemInformation,
        ULONG                    SystemInformationLength,
        PULONG                   ReturnLength)

    If SystemInformationClass is set to 0x23, can be 
    used to detect debugger

    Args:
        Derived from Speakeasy implementation

    Returns:
        Result of the called API
    """

    infoclass, _, _, _ = params

    if infoclass == 0x23:
        print(Fore.YELLOW + '[#] Suspect NtQuerySystemInformation() at ' + 
              hex(emu.get_ret_address()) + Style.RESET_ALL)

    # Call the function
    rv = func(params)

    return rv

def hook_peb_beingdebugged(emu, access, addr, size, value, ctx):
    """
    Memory hook.
    Detects direct access to PEB!BeingDebugged     
    """

    print(Fore.YELLOW + '[#] Direct access to PEB!BeingDebugged at ' + 
              hex(emu.get_pc()) + Style.RESET_ALL)

    return

def hook_peb_ntglobalflag(emu, access, addr, size, value, ctx):
    """
    Memory hook.
    Detects direct access to PEB!NtGlobalFlag     
    """

    print(Fore.YELLOW + '[#] Direct access to PEB!NtGlobalFlag at ' + 
              hex(emu.get_pc()) + Style.RESET_ALL)

    return

def hook_peb_heapbase(emu, access, addr, size, value, ctx):
    """
    Memory hook.
    Detects direct access to HeapBase. Used to access Flags and ForceFlags.
    """

    print(Fore.YELLOW + '[#] Suspect access to HeapBase (may be used to access Flags'
          ' and ForceFlags) at ' + hex(emu.get_pc()) + Style.RESET_ALL)

    return

def hook_getprocaddress(emu, api_name, func, params):
    """
    Hooks FARPROC GetProcAddress(
        HMODULE hModule,
        LPCSTR  lpProcName
    );

    Detects access to CsrGetProcessID (CRSS.EXE).
    If a process is able to open CRSS.exe process, it means 
    that the process has SeDebugPrivilege enabled

    Args:
        Derived from Speakeasy implementation

    Returns:
        Result of the called API

    """

    module, procname = params

    if emu.read_mem_string(procname).lower() == 'CsrGetProcessId'.lower():
        print(Fore.YELLOW + '[#] GetProcAddress() of CRSS.EXE at ' + 
              hex(emu.get_ret_address()) + Style.RESET_ALL)

    # Call the function
    rv = func(params)

    return rv

def hook_createfilea(emu, api_name, func, params):
    """
    HANDLE CreateFileA(
        PCSTR                 lpFileName,
        DWORD                 dwDesiredAccess,
        DWORD                 dwShareMode,
        LPSECURITY_ATTRIBUTES lpSecurityAttributes,
        DWORD                 dwCreationDisposition,
        DWORD                 dwFlagsAndAttributes,
        HANDLE                hTemplateFile
    );

    Tries to open the image of the current process in exclusive mode;
    if it fails it is probably under debugger.

    Args:
        Derived from Speakeasy implementation

    Returns:
        Result of the called API

    """

    filename, access, sharemode, _, _, _, _ = params

    if (
        emu.read_mem_string(filename).split('\\')[-1] == emu.get_current_module().path.split('/')[-1] and 
        access == 0x80000000 and 
        sharemode == 0
       ):
        print(Fore.YELLOW + '[#] Exclusive CreateFileA() on current process at ' + 
              hex(emu.get_ret_address()) + Style.RESET_ALL)

    # Call the function
    rv = func(params)

    return rv

def hook_getlocaltime(emu, api_name, func, params):
    """
    HANDLE GetLocalTime(
        LPSYSTEMTIME lpSystemTime
    );

    Gets local time. If called multiple times could be sign of 
    timing checks

    Args:
        Derived from Speakeasy implementation

    Returns:
        Result of the called API

    """

    print(Fore.YELLOW + '[#] Call to GetLocalTime() at ' + 
              hex(emu.get_ret_address()) + Style.RESET_ALL)

    # Call the function
    rv = func(params)

    return rv

def hook_getsystemtime(emu, api_name, func, params):
    """
    void GetSystemTime(
        LPSYSTEMTIME lpSystemTime
    );

    Gets system time. If called multiple times could be sign of 
    timing checks

    Args:
        Derived from Speakeasy implementation

    Returns:
        Result of the called API

    """

    print(Fore.YELLOW + '[#] Call to GetSystemTime() at ' + 
              hex(emu.get_ret_address()) + Style.RESET_ALL)

    # Call the function
    rv = func(params)

    return rv

def hook_gettickcount(emu, api_name, func, params):
    """
    DWORD GetTickCount();

    The return value is the number of milliseconds that have elapsed since the system was started.
    If called multiple times could be sign of 
    timing checks

    Args:
        Derived from Speakeasy implementation

    Returns:
        Result of the called API

    """

    print(Fore.YELLOW + '[#] Call to GetTickCount() at ' + 
              hex(emu.get_ret_address()) + Style.RESET_ALL)

    # Call the function
    rv = func(params)

    return rv

def hook_queryperformancecounter(emu, api_name, func, params):
    """
    BOOL QueryPerformanceCounter(
        LARGE_INTEGER *lpPerformanceCount
    );

    Retrieves the current value of the performance counter

    Args:
        Derived from Speakeasy implementation

    Returns:
        Result of the called API

    """

    print(Fore.YELLOW + '[#] Call to QueryPerformanceCounter() at ' + 
              hex(emu.get_ret_address()) + Style.RESET_ALL)

    # Call the function
    rv = func(params)

    return rv

def hook_timegettime(emu, api_name, func, params):
    """
    DWORD timeGetTime();

    Retrieves the system time, in milliseconds. 
    The system time is the time elapsed since Windows was started.

    Args:
        Derived from Speakeasy implementation

    Returns:
        Result of the called API

    """

    print(Fore.YELLOW + '[#] Call to timeGetTime() at ' + 
              hex(emu.get_ret_address()) + Style.RESET_ALL)

    # Call the function
    rv = func(params)

    return rv

def hook_virtualprotect(emu, api_name, func, params):
    """
    BOOL VirtualProtect(
        LPVOID lpAddress,
        SIZE_T dwSize,
        DWORD  flNewProtect,
        PDWORD lpflOldProtect
    );

    Check if VirtualAlloc is called on a return address (from stack). It is used
    to discover the stepping over of a function done in debuggers. It is usually
    done if the returning address is equal to 0xCC (INT3).

    Args:
        Derived from Speakeasy implementation

    Returns:
        Result of the called API

    """

    address, _, _, _ = params
    haddress = hex(address)[2:]

    for addr in emu.get_stack_trace():
        if haddress in addr:

            print(Fore.YELLOW + '[#] Call to VirtualProtect() on "Return Address" at ' +
                hex(emu.get_ret_address()) + Style.RESET_ALL)
            break

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

    global enable_fixups
    global donut_stub

    # Get cmd2 obj for poutput
    cmd2 = ctx['cmd2']

    mnem, op, instr = emu.get_disasm(emu.reg_read(e_arch.X86_REG_EIP), end)

    opcodes = int(emu.mem_read(begin, end).hex(), 16)
    opcodes_buffer.append(emu.mem_read(begin, end))
    opcodes_data = b''.join(opcodes_buffer)

    #
    # Set up memory hooks for antidebug detection, just done once
    #
    if begin == cfg.entry_point:

        peb_addr = struct.unpack("<Q",emu.mem_read(emu.peb_addr,8))[0]
        emu.add_mem_read_hook(hook_peb_beingdebugged, begin=peb_addr + 0x02, end=peb_addr + 0x03)
        emu.add_mem_read_hook(hook_peb_ntglobalflag, begin=peb_addr + 0x68, end=peb_addr + 0x69)

        emu.add_mem_read_hook(hook_peb_heapbase, begin=peb_addr + 0x18, end=peb_addr + 0x19)
        emu.add_mem_read_hook(hook_peb_heapbase, begin=peb_addr + 0x1030, end=peb_addr + 0x1031)

    if enable_fixups == True:
        fixups_unicorn(emu, begin, end, mnem, op, 'x86', cfg.entry_point)

    #####################################
    # YARA RULES MATCHING SECTION START #
    #####################################

    # Shortcut for Donut code
    if rule_donut_hash_shortcut_32.match(data=opcodes_data):

        if donut_stub == False:
            cmd2.poutput(
                Fore.YELLOW + '[*] Donut stub detected (you may want to'
                              ' add DLLs in decoy folder. See README.md)' + Style.RESET_ALL)
            donut_stub = True

        # FIXME
        # emu.add_api_hook(hook_mapviewofsection, 'ntdll', 'ZwMapViewOfSection')
        enable_unhook = 0
        opcodes_buffer.clear()

    ###################################
    # YARA RULES MATCHING SECTION END #
    ###################################

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

    global enable_fixups
    global donut_stub

    # Get cmd2 obj for poutput
    cmd2 = ctx['cmd2']

    mnem, op, instr = emu.get_disasm(emu.reg_read(e_arch.AMD64_REG_RIP), end)

    opcodes = int(emu.mem_read(begin, end).hex(), 16)
    opcodes_buffer.append(emu.mem_read(begin, end))
    opcodes_data = b''.join(opcodes_buffer)

    #
    # Set up memory hooks for antidebug detection, just done once
    #
    if begin == cfg.entry_point:
        peb_addr = struct.unpack("<Q",emu.mem_read(emu.peb_addr,8))[0]
        emu.add_mem_read_hook(hook_peb_beingdebugged, begin=peb_addr + 2, end=peb_addr + 3)
        emu.add_mem_read_hook(hook_peb_ntglobalflag, begin=peb_addr + 0xbc, end=peb_addr + 0xbd)

        emu.add_mem_read_hook(hook_peb_heapbase, begin=peb_addr + 0x30, end=peb_addr + 0x31)


    if enable_fixups == True:
        fixups_unicorn(emu, begin, end, mnem, op, 'x64', cfg.entry_point)

    #####################################
    # YARA RULES MATCHING SECTION START #
    #####################################

    # Shortcut for Donut code
    if rule_donut_hash_shortcut_64.match(data=opcodes_data):

        if donut_stub == False:
            cmd2.poutput(
                Fore.YELLOW + '[*] Donut stub detected (you may want to'
                              ' add DLLs in decoy folder. See README.md)' + Style.RESET_ALL)
            donut_stub = True

        # FIXME
        #emu.add_api_hook(hook_mapviewofsection, 'ntdll', 'ZwMapViewOfSection')
        enable_unhook = 0
        opcodes_buffer.clear()

    ###################################
    # YARA RULES MATCHING SECTION END #
    ###################################

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

    fixups = kwargs['fixups']
    payload = kwargs['payload'].replace('\'', '')
    arch = kwargs['arch'].replace('\'', '')  # 'x86'
    unhook = kwargs['unhook']
    exportname = kwargs['exportname']

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

    # Place hooks for antidebug
    se.add_api_hook(hook_isdebuggerpresent, 'kernel32', 'IsDebuggerPresent')
    se.add_api_hook(hook_getcurrentprocess, 'kernel32', 'GetCurrentProcess')
    se.add_api_hook(hook_checkremotedebuggerpresent, 'kernel32', 'CheckRemoteDebuggerPresent')
    se.add_api_hook(hook_ntqueryinformationprocess, 'ntdll', 'NtQueryInformationProcess')
    se.add_api_hook(hook_ntquerysysteminformation, 'ntdll', 'NtQuerySystemInformation')
    se.add_api_hook(hook_getprocaddress, 'kernel32', 'GetProcAddress')
    se.add_api_hook(hook_createfilea, 'kernel32', 'CreateFileA')
    se.add_api_hook(hook_getlocaltime, 'kernel32', 'GetLocalTime')
    se.add_api_hook(hook_getsystemtime, 'kernel32', 'GetSystemTime')
    se.add_api_hook(hook_gettickcount, 'kernel32', 'GetTickCount')
    se.add_api_hook(hook_queryperformancecounter, 'kernel32', 'QueryPerformanceCounter')
    se.add_api_hook(hook_timegettime, 'winmm', 'timeGetTime')
    se.add_api_hook(hook_virtualprotect, 'kernel32', 'VirtualProtect')

    # Detect file type and start proper emulation
    code_type = pe_format(payload)
    if code_type == 3:
        start_shellcode(self, payload, se, arch)
    elif code_type == 2:
        start_dll(self, payload, se, arch, exportname)
    elif code_type == 1:
        start_exe(self, payload, se, arch)

def module_main(self, *args, **kwargs):
    """
    Main module entry point
    """

    # Load Speakeasy configuration
    config_path = './speakeasy_default.json'
    with open(config_path, 'r') as f:
        cfg = json.load(f)

    start_speakeasy(self, kwargs, cfg)
