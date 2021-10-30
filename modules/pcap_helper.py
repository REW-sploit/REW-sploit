"""
REW-sploit

pcap_helper.py

Utils functions to manage pcap files
"""

from scapy.all import *


def pcap_extract(filename, ip, port, session):
    """
    Returns the payload of a given communication, based on ip/port
    (dst port).

    Args:
        filename: PCAP filename
        ip: C2 IP
        port: C2 port
        session: identify specific session (order)
    Returns:
        Buffer with the network payload
    """

    pcapfilter = 'port %d and src %s' % (port, ip)
    curr_session = 0
    buffer = b''

    try:
        for sess in sniff(offline=filename, session=IPSession,
                          filter=pcapfilter).sessions().values():
            curr_session += 1
            if curr_session == session:
                for packet in sess:
                    if Raw in packet:
                        buffer += bytes(packet[Raw])
            else:
                continue
    except Exception as e:
        print('Error processing %s: %s' % (filename, e))
        print('If using PCAPNG file, try PCAP instead')

    return buffer


def pcap_extract_meterpreter(filename, ip, port, comnum):
    """
    Returns the payload of a given communication, based on ip/port
    (dst port).
    The 'comnum' identifies the # of the communication exchange
    in the filtered data.

    Args:
        filename: PCAP filename
        ip: C2 IP
        port: C2 port
        comnum: # of exchange in the session

    Returns:
        Buffer with the network payload 
    """

    pcapfilter = 'port %d and host %s' % (port, ip)
    try:
        cap = sniff(offline=filename, filter=pcapfilter)
    except Exception as e:
        print('Error processing %s: %s' % (filename, e))
        print('If using PCAPNG file, try PCAP instead')

    current_comnum = 1
    recv_port = port
    payload = b''

    for p in cap:
        try:
            # get data for selected communication
            buffer = bytes(p[Raw])
            if recv_port != int(p[TCP].dport):
                payload += buffer
            else:
                recv_port = int(p[TCP].sport)
                current_comnum += 1
                if current_comnum > comnum:
                    break
                else:
                    payload = buffer

        except (AttributeError, IndexError):  # Skip the ACKs.
            pass

    return payload
