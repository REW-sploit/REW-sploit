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
