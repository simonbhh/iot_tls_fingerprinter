"""
    This file contains the methods to collects TLS client hello messages
    from a .pcap file to create TLSClientHello objects and fingerprint them

    The Scapy library is used to retrieve the information of the pcap file
"""

__author__  = "Simon"
__date__    = "19/06/2019"

import sys
import os
import re

#from scapy.layers.ssl_tls import *
from scapy.all import *

from classes.TLSClientHello import TLSClientHello
from classes.Packet import Packet
from classes.Trace import Trace

# Creating the logger
import logging

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

formatter = logging.Formatter('%(name)s - %(levelname)s: %(message)s')

file_handler = logging.FileHandler('run.log')
file_handler.setFormatter(formatter)
logger.addHandler(file_handler)

#load_layer('tls')

def extract_client_hello(packets):
    """ Return packets corresponding to a client_hello """
    res = []
    for pkt in packets:
        if 'TLS Client Hello' in pkt:
            res.append(pkt)
    return res

def ip_parsing(packet):
    """ Method that parses the IP info of a packet """
    src = packet['IP'].src
    dst = packet['IP'].dst
    sport = packet['TCP'].sport
    dport = packet['TCP'].dport

    return (src, dst, sport, dport)

def tls_parsing(packet):
    """ Method that parses TLS info of a packet """
    version = check_field(packet, 'TLS Client Hello', 'version')
    cipher_suites_length = check_field(packet,
        'TLS Client Hello', 'cipher_suites_length')
    cipher_suites = check_field(packet, 'TLS Client Hello', 'cipher_suites')
    compression_methods_length = check_field(packet,
        'TLS Client Hello', 'compression_methods_length')
    compression_methods = check_field(packet,
        'TLS Client Hello', 'compression_methods')
    extensions_length = check_field(packet,
        'TLS Client Hello', 'extensions_length')
    extensions = extensions_parsing(packet['TLS Client Hello'])
    sign_algs = check_field(packet,
        'TLS Extension Signature Algorithms', 'algs')
    ec_point_format = None
    ec_point_formats = None
    extention_type = None
    random = None
    random_bytes = check_field(packet, 'TLS Client Hello', 'random_bytes')

    return (version, cipher_suites_length, cipher_suites,
            compression_methods_length, compression_methods,
            extensions_length, extensions, sign_algs, ec_point_format,
            ec_point_formats, extention_type, random, random_bytes)

def check_field(packet, attr, field):
    """
        Method that checks if the field exist in the packet
        and return its value or None
    """
    result = None
    try:
        result = getattr(packet[attr], field)
    except IndexError:
        logger.exception('Attribute error on %s', field)
    return result

def extensions_parsing(client_hello):
    """ Method that parses the extensions info of a packet """
    return client_hello['TLS Extension'].type

def create_trace(file_path):
    """ Method that creates the traces objects and stores them in a list """
    # Reading pcap file with pyshark
    logger.info('File: %s', file_path)

    packets = rdpcap(file_path)

    # Extracting client_hello packets
    client_hellos = extract_client_hello(packets)
    logger.debug('# of client hellos = %s', len(client_hellos))

    tls_packets = []

    # Iterating through all the client_hello packets
    for pkt in client_hellos:
        # Getting IP info
        (src, dst, sport, dport) = ip_parsing(pkt)
        logger.debug((src, dst, sport, dport))

        # Getting TLS info
        (version, csuites_len, csuites, comp_meth_len,
            comp_meth, ext_len, ext, sign_algs, ec_point_format,
            ec_point_formats, extention_type,
            random, random_bytes) = tls_parsing(pkt)
        logger.debug((version, csuites_len, csuites, comp_meth_len, comp_meth,
            ext_len, ext, sign_algs, ec_point_format, ec_point_formats,
            extention_type, random, random_bytes))

        # Creating the Packet and TLSClientHello objects and storing them
        tls_client_hello = TLSClientHello(version, csuites_len, csuites,
            comp_meth_len, comp_meth, ext_len, ext, sign_algs, ec_point_format,
            ec_point_formats, extention_type, random, random_bytes)
        ip_packet = Packet(src, dst, sport, dport, tls_client_hello)
        tls_packets.append(ip_packet)

        logger.debug('Packet: %s', ip_packet)

    # Formatting the name of the device using RegEx
    name = re.sub('.*/', '', file_path)
    name = re.sub('.pcap', '', name)
    logger.debug('Name is %s', name)

    # Creating and returning the Trace object
    return Trace(name, file_path, tls_packets)
