#!/usr/bin/env python
# coding=utf-8

import argparse
import random
import sys

import cmd2
from cmd2 import style, fg, bg
from colorama import Fore, Back, Style

version = '0.3.5'


class RewSploit(cmd2.Cmd):
    """ REW-sploit """

    # Setting this true makes it run a shell command if a cmd2/cmd command doesn't exist
    # default_to_shell = True
    REWSPLOIT_CATEGORY = 'REW-sploit Commands'

    def __init__(self):
        hist_file = '~/.rew-sploit_history'
        shortcuts = cmd2.DEFAULT_SHORTCUTS
        shortcuts.update({'&': 'speak'})
        super().__init__(multiline_commands=['orate'], shortcuts=shortcuts,
                         persistent_history_file=hist_file, persistent_history_length=100)

        self.intro = style('\n\n    __ __     ____  ____  __     __  __  ____ \n   / // /___ / ___)(  _ \(  )   /  \(  )(_  _)\n  ( (( ((___)\___ \ ) __// (_/\(  O ))(   )(\n   \_\\_\     (____/(__)  \____/ \__/(__) (__)\n\n                                 \n                                 Version: ' + version + '\n\n',
                           fg=fg.blue, bg=bg.black, bold=True)
        self.prompt = style('(REW-sploit)<< ', fg=fg.magenta)
        self.default_category = 'Utility Commands'

    #######################################
    # Module meterpreter_reverse_tcp
    #######################################
    met_rev_tcp_parser = argparse.ArgumentParser()
    met_rev_tcp_parser.add_argument('-f', '--file', type=ascii, help='PCAP file name',
                                    required=True)
    met_rev_tcp_parser.add_argument('-i', '--ip', type=ascii, help='Meterpreter C2 IP',
                                    required=True)
    met_rev_tcp_parser.add_argument('-p', '--port', type=int, help='Meterpreter C2 Port (default: 4444)',
                                    default=4444)

    @cmd2.with_category(REWSPLOIT_CATEGORY)
    @cmd2.with_argparser(met_rev_tcp_parser)
    def do_meterpreter_reverse_tcp(self, args):
        """
        Identify and try to decrypt the Meterpreter TCP session (AES encrypted)
        """

        plugin = __import__('modules.meterpreter_reverse_tcp')
        plugin.meterpreter_reverse_tcp.module_main(self=self, ip=args.ip,
                                                   port=args.port, file=args.file)

        return

    #######################################
    # Module meterpreter_reverse_http
    #######################################
    @cmd2.with_category(REWSPLOIT_CATEGORY)
    def do_meterpreter_reverse_http(self, args):
        """
        Identify and try to decrypt the Meterpreter HTTP session (AES encrypted)
        """

        self.poutput(Fore.RED + '[+] Not implemented yet' + Style.RESET_ALL)
        return

    #######################################
    # Module meterpreter_reverse_https
    #######################################
    @cmd2.with_category(REWSPLOIT_CATEGORY)
    def do_meterpreter_reverse_https(self, args):
        """
        Identify and try to decrypt the Meterpreter HTTPS session (AES encrypted)
        """

        self.poutput(Fore.RED + '[+] Not implemented yet' + Style.RESET_ALL)
        return

    #######################################
    # Module emulate_payload
    #######################################
    emulate_payload_parser = argparse.ArgumentParser()
    emulate_payload_parser.add_argument('-P', '--payload', type=ascii, help='Payload binary file',
                                        required=True, metavar='<Filename>')
    emulate_payload_parser.add_argument('-f', '--file', type=ascii, help='PCAP file name',
                                        default='', metavar='<Filename>')
    emulate_payload_parser.add_argument('-i', '--ip', type=ascii, help='Meterpreter C2 IP',
                                        default='0.0.0.0')
    emulate_payload_parser.add_argument('-p', '--port', type=int, help='Meterpreter C2 Port (default: 4444)',
                                        default=4444)
    emulate_payload_parser.add_argument('-a', '--arch', type=ascii, help='Architecture (x86 or x64)',
                                        default='x86')
    emulate_payload_parser.add_argument('-d', '--debug', action='count', help='Enable debug (more d, more infos)',
                                        default=0)
    emulate_payload_parser.add_argument('-F', '--fixups', action='store_true', help='Enable Unicorn Fixups',
                                        default=False)
    emulate_payload_parser.add_argument('-U', '--unhook', type=ascii, help='UnHook single step function forever (0) or until <Address> (in hex). Speeds up emulation',
                                        default=None, metavar='0x<Address>')
    emulate_payload_parser.add_argument('-T', '--thread', action='store_true', help='Dump CreateThread API content from lpStartAddress',
                                        default=False)
    emulate_payload_parser.add_argument('-W', '--writefile', action='store_true', help='Dump WriteFile API content',
                                        default=False)
    emulate_payload_parser.add_argument('-E', '--exportname', type=ascii, help='DLL Export to emulate',
                                        default=None, metavar='<DLLExportame>')

    @cmd2.with_category(REWSPLOIT_CATEGORY)
    @cmd2.with_argparser(emulate_payload_parser)
    def do_emulate_payload(self, args):
        """
        Emulate payload to decode encryption keys and decode the payload from PCAP
        """

        plugin = __import__('modules.emulate_payload')
        plugin.emulate_payload.module_main(self=self, ip=args.ip, port=args.port,
                                           payload=args.payload, file=args.file, arch=args.arch,
                                           debug=args.debug, fixups=args.fixups,
                                           unhook=args.unhook, thread=args.thread,
                                           writefile=args.writefile, exportname=args.exportname)
        return


if __name__ == '__main__':
    c = RewSploit()
    sys.exit(c.cmdloop())
