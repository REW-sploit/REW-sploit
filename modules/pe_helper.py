"""
REW-sploit

pe_helper.py

Utils funtctions to manage PE files
"""

import pefile
from pefile import *


def pe_format(filename):
    """
    Returns the format of the executable

    Args:
        filename: filename to check
    Returns:
       -2: File Not Found
       -1: Generic error
        1: EXE
        2: DLL
        3: Shellcode
    """

    try:
        pe = pefile.PE(filename)
        if pe.is_dll():
            res = 2
        elif pe.is_exe():
            res = 1
    except PEFormatError:
        res = 3
    except FileNotFoundError:
        res = -2
    except:
        res = -1

    return res

def pe_arch(filename):
    """
    Automatically detect architecture for EXE and DLL

    Args:
        filename: filename to check

    Returns:
        None:    no arch detected
        x86:     x86 architecture 
        amd64:   amd64 architecture

    """
    
    res = None

    fmt = pe_format(filename)

    if fmt == 1 or fmt == 2:
        # Check architecure for EXE and DLL
        pe = pefile.PE(filename)

        machine = pe.FILE_HEADER.Machine

        if machine == 0x8664:
            res = 'amd64'
        if machine == 0x014c:
            res = 'x86'

    return res