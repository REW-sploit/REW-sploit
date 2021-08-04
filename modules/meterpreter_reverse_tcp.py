"""
REW-sploit

meterpreter_reverse_tcp

This module is able to identify if a specific flow, identified by
IP and PORT (intended as IP of the Meterpreter C2) is a Meterpreter session
and it tries to decrypt it if possible

"""

import struct
from Crypto.Cipher import ARC4
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from colorama import Fore, Back, Style
from colorama import init

import modules.msf
from modules.msf import *
from modules.pcap_helper import *

# Processing MSF variable section and load a dict
msf_tlvid = {getattr(modules.msf, item): item
             for item in dir(modules.msf) if item.startswith("TLV_TYPE_")}
msf_cmdid = {getattr(modules.msf, item): item
             for item in dir(modules.msf) if item.startswith("COMMAND_ID_")}

# colorama init
init(autoreset=True)


def dec_meterpreter_xor(pkt):
    """
    Remove the XOR encryption of a meterpreter packet.
    Returns the decrypted packet

    Args:
        pkt: network buffer containing the packet

    Returns:
        The decrypted buffer
    """

    rv = []
    # Extract the XOR key (first 4 bytes)
    xor_key = pkt[0:4]

    for i in range(len(pkt)):
        rv.append(pkt[i] ^ xor_key[i % 4])

    rv = bytearray(rv)

    return rv


def extract_tlv(pkt, offset=-1):
    """
    Parse and extract all the fields in the packet
    Returns a dictionary list with TLV (type,length,values)

    Args:
        pkt: network buffer containing the packet
        offset: set as parameter because some packets (the handshake)
                have different positioning. It is set to 0 for usual traffic 
                packets.

    Returns: 
        list of TLV
    """

    tlv = []

    if offset == -1:
        offset = HEADER_SIZE + START_OFFSET

    while offset < len(pkt) - 1:

        tlv_value = None

        # Get length and type
        tlv_len, tlv_type = struct.unpack(
            ">II", pkt[offset:offset + HEADER_SIZE])

        # Extract values
        # String
        if tlv_type & TLV_META_TYPE_STRING == TLV_META_TYPE_STRING:
            tlv_value = pkt[offset + HEADER_SIZE:offset + tlv_len]
        # UINT
        elif tlv_type & TLV_META_TYPE_UINT == TLV_META_TYPE_UINT:
            tlv_value = struct.unpack(
                ">I", pkt[offset + HEADER_SIZE:offset + HEADER_SIZE + 4])[0]
        # QWORD
        elif tlv_type & TLV_META_TYPE_QWORD == TLV_META_TYPE_QWORD:
            # FIXME
            tlv_value = struct.unpack(
                ">Q", pkt[offset + HEADER_SIZE:offset + HEADER_SIZE + 8])[0]
        # Bool
        elif tlv_type & TLV_META_TYPE_BOOL == TLV_META_TYPE_BOOL:
            # FIXME
            tlv_value = -1
        else:
            # Raw
            tlv_value = pkt[offset + HEADER_SIZE:offset + tlv_len]

        tlv.append({'type': tlv_type, 'len': tlv_len, 'value': tlv_value})
        offset += tlv_len

    return tlv


def is_meterpreter(self, filename, ip, port):
    """
    Report if a connection on the given IP/PORT is a meterpreter connection

    Args:
        self: cmd2 object used for output
        filename: PCAP filename
        ip: C2 IP
        port: C2 port

    Returns:
        Boolean stating if is a meterpreter session
    """

    # Extracts 1st msf -> victim
    buff = pcap_extract_meterpreter(filename, ip, port, 1)
    buff = dec_meterpreter_xor(buff)
    data_sent = extract_tlv(buff)

    # Look for RSA Public key
    for tlv in data_sent:
        if tlv['type'] == TLV_TYPE_RSA_PUB_KEY:
            try:
                key = RSA.importKey(bytes(tlv['value']))
                pubkey = key.publickey().exportKey("PEM")
                self.poutput(pubkey.decode('utf-8'))
            except:
                return False
            return True
    return False


def get_sym_key(filename, ip, port):
    """
    Get the symmetric unencrypted AES key from the meterpreter conversation.

    Args:
        filename: PCAP filename
        ip: C2 IP
        port: C2 port

    Returns: 
        key or None if not available
    """

    # Extracts 2nd victim -> msf
    buff = pcap_extract_meterpreter(filename, ip, port, 2)
    buff = dec_meterpreter_xor(buff)
    data_sent = extract_tlv(buff)

    # Look for unencrypted AES key
    for tlv in data_sent:
        if tlv['type'] == TLV_TYPE_SYM_KEY:
            return tlv['value']

    return None


def dec_meterpreter_traffic(self, key, filename, ip, port):
    """
    Decrypt the meterpreter traffic with the given key

    Args:
        self: cmd2 object used for output
        key: decryption key
        filename: PCAP filename
        ip: C2 IP
        port: C2 port

    Returns:
        None (prints TLV)
    """

    start_pkt = 3
    buff = b''
    oldbuff = b'1'

    buff = pcap_extract_meterpreter(filename, ip, port, start_pkt)

    while buff != oldbuff:
        # FIXME: this is an horrible hack to stop...may be need to be changed
        oldbuff = buff
        buff = dec_meterpreter_xor(buff)

        iv = buff[32:48]
        try:
            cipher = AES.new(key=bytes(key), mode=AES.MODE_CBC, IV=bytes(iv))
            buff = cipher.decrypt(bytes(buff[48:]))
            # Remove padding bytes
            # FIXME: improve this with more robust check
            padding_bytes = buff[-1]
            buff = buff[:-padding_bytes]
        except:
            self.poutput('[!] Packet decryption failed')

        tlv = extract_tlv(buff, offset=0)
        print_tlv(self, tlv)

        start_pkt += 1
        buff = pcap_extract_meterpreter(filename, ip, port, start_pkt)


def print_tlv(self, tlv):
    """
    Print TLV values formatted

    Args:
        self: cmd2 object used for output
        tlv: TLV value

    Returns:
        None (prints TLV)
    """

    self.poutput(Fore.CYAN + '\n\n>>>>>>>>>>>>>>>' + Style.RESET_ALL)
    for t in tlv:
        self.poutput('')
        try:
            self.poutput('Type:   %s (0x%X)' %
                         (msf_tlvid[t['type']], t['type']))
        except KeyError:
            self.poutput('Type:   %s (0x%X)' % ('TLV_TYPE_UNK', t['type']))
        self.poutput('Length: %d' % t['len'])
        if t['type'] == TLV_TYPE_COMMAND_ID:
            try:
                self.poutput('Value:  %s (0x%X)' %
                             (msf_cmdid[t['value']], t['value']))
            except KeyError:
                self.poutput('Value:  %s (0x%X)' %
                             ('COMMAND_ID_UNK', t['value']))
        else:
            self.poutput('Value:  %s' % t['value'])


def module_main(self, *args, **kwargs):
    """
    Main module entry point
    """

    ip = kwargs['ip'].replace('\'', '')
    port = kwargs['port']
    file = kwargs['file'].replace('\'', '')

    if is_meterpreter(self, file, ip, port) == True:
        self.poutput(
            Fore.GREEN + '\n[+] Meterpreter session identified' + Style.RESET_ALL)
    else:
        self.poutput(
            Fore.RED + '\n[!] No Meterpreter session ' + Style.RESET_ALL)
        return False

    key = get_sym_key(file, ip, port)
    if key:
        hexkey = ''.join('{:02x}'.format(x) for x in key)
        self.poutput(
            Fore.GREEN + '\n[+] Meterpreter AES key found: ' + hexkey + Style.RESET_ALL)
    else:
        self.poutput(
            Fore.RED + '\n[!] Meterpreter AES key not available' + Style.RESET_ALL)
        return False

    dec_meterpreter_traffic(self, key, file, ip, port)
