"""
REW-sploit

emulate_config

Common variables for emulation

"""

import sys

# Used to track EP and apply Fixups when needed
entry_point = 0

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
