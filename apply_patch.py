#!/usr/bin/env python

"""
Applies needed patches to the speakeasy-emulator

usage: apply_patch.py [-h] [-f] [-r]

optional arguments:
  -h, --help    show this help message and exit
  -f, --force   No prompts before applying
  -r, --revert  Revert patching
"""

import patch
import speakeasy
import os
import argparse

def apply_all(folder, revert):
    #
    # Files to patch: objman.py
    #
    destination = folder + '/windows/objman.py'
    patchfile = 'patches/objman.diff'
    try:
        pset = patch.fromfile(patchfile)
        if revert == True:
            pset.revert(root=folder)
        else:
            pset.apply(root=folder)
        
        print('OK: %s patched successfully' % (destination))
    except:
        print('KO: Error patching %s' % (destination))

if __name__ == '__main__':

    ap = argparse.ArgumentParser()
    ap.add_argument('-f', '--force', action='store_true', help='No prompts before applying',
                     default=False)
    ap.add_argument('-r', '--revert', action='store_true', help='Revert patching',
                     default=False)
    args = ap.parse_args()

    location = speakeasy.__file__
    folder = os.path.dirname(location)

    print('You are going to apply patch to:')
    print(folder)
    if args.force == False:
        input('Press ENTER to continue')
    print()

    apply_all(folder,args.revert)
