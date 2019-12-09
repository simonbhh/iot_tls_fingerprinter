"""
    This file contains the methods to collects TLS client hello messages
    from a .pcap file to create TLSClientHello objects and fingerprint them

    The PyShark library is used to retrieve the information of the pcap file
"""

__author__  = "Simon"
__date__    = "25/06/2019"

import sys
import os
import re

import pyshark

from classes.TLSClientHello import TLSClientHello
from classes.TLSServerHello import TLSServerHello
from classes.TLSCertificate import TLSCertificate
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

def extract_client_hello(packets):
    """
    Return packets corresponding to a client_hello

    :param packets: a list of packets

    :returns: the client hello part of the certificate
    """
    res = []
    for pkt in packets:
        if 'SSL' == pkt.highest_layer:
            try:
                if 'Handshake Protocol: Client Hello' in pkt.ssl.handshake:
                    res.append(pkt)
            except AttributeError as error:
                pass#logger.exception(error)
    return res

def extract_server_hello(packets):
    """
    Return packets corresponding to a client_hello

    :param packets: a list of packets

    :returns: the server hello part of the certificate
    """
    res = []
    for pkt in packets:
        if 'SSL' == pkt.highest_layer:
            try:
                if 'Handshake Protocol: Server Hello' in pkt.ssl.handshake:
                    res.append(pkt)
            except AttributeError as error:
                pass#logger.exception(error)
    return res

def extract_certificate(packets):
    """
    Return packets corresponding to a client_hello

    :param packets: a list of packets

    :returns: the certificate part of the packet
    """
    res = []
    for pkt in packets:
        if 'SSL' == pkt.highest_layer:
            try:
                if 'Handshake Protocol: Certificate' in str(pkt):
                    res.append(pkt)
            except AttributeError as error:
                pass#logger.exception(error)
    return res

def ip_parsing(packet):
    """
    Method that parses the IP info of a packet

    :param packet: a packet

    :returns: a tuple with the relevant fields
    """
    src = packet.ip.src
    dst = packet.ip.dst
    sport = packet.tcp.srcport
    dport = packet.tcp.dstport

    return (src, dst, sport, dport)

def client_hello_parsing(packet):
    """
    Method that parses TLS client hello info of a packet

    :param packet: a packet

    :returns: a tuple with the relevant fields
    """
    version = check_field(packet, 'handshake_version')
    cipher_suites_length = check_field(packet, 'handshake_cipher_suites_length')
    cipher_suites = check_field(packet, 'handshake_ciphersuite')
    compression_methods_length = check_field(packet,
        'handshake_comp_methods_length')
    compression_methods = check_field(packet, 'handshake_comp_method')
    extensions_length = check_field(packet, 'handshake_extensions_length')
    extensions = check_field(packet, 'handshake_extensions_supported_group')
    sign_algs = check_field(packet, 'handshake_sig_hash_alg')
    ec_point_format = check_field(packet,
        'handshake_extensions_ec_point_format')
    ec_point_formats = check_field(packet,
        'handshake_extensions_ec_point_formats')
    extension_type = check_field(packet, 'handshake_extension_type')
    random = check_field(packet, 'handshake_random')
    random_bytes = check_field(packet, 'handshake_random_bytes')

    return (version, cipher_suites_length, cipher_suites,
            compression_methods_length, compression_methods,
            extensions_length, extensions, sign_algs, ec_point_format,
            ec_point_formats, extension_type, random, random_bytes)


def server_hello_parsing(packet):
    """
    Method that parses TLS server hello info of a packet

    :param packet: a packet

    :returns: a tuple with the relevant fields
    """
    version = check_field(packet, 'handshake_version')
    cipher_suite = check_field(packet, 'handshake_ciphersuite')

    return (version, cipher_suite)

def certificate_parsing(packet):
    """
    Method that parses TLS certificate info of a packet

    :param packet: a packet

    :returns: the certificate raw information
    """

    return (str(packet.ssl))


def check_field(packet, field):
    """
    Method that checks if the field exist in the packet
    and return its value or None

    :param packet: a packet
    :param field: the field to extract

    :returns: the field information
    """
    result = None
    try:
        result = getattr(packet.ssl, field)
    except AttributeError:
        logger.exception('Attribute error on %s', field)
    return result

def create_trace(file_path):
    """
    Method that creates the traces objects and stores them in a list

    :param file_path: the path to the file

    :returns: the trace object created
    """
    # Reading pcap file with pyshark
    logger.info('File: %s', file_path)

    packets = pyshark.FileCapture(file_path)

    # Extracting client_hello packets
    client_hellos = extract_client_hello(packets)
    logger.debug('# of client hellos = %s', len(client_hellos))

    # Lists that will contain the objects corresponding to tls packets
    tls_client_hellos = []
    tls_server_hellos = []
    tls_certificates = []

    # Iterating through all the client_hello packets
    for pkt in client_hellos:
        # Getting IP info
        (src, dst, sport, dport) = ip_parsing(pkt)
        logger.debug((src, dst, sport, dport))

        # Getting TLS info
        (version, csuites_len, csuites, comp_meth_len,
            comp_meth, ext_len, ext, sign_algs, ec_point_format,
            ec_point_formats, extension_type,
            random, random_bytes) = client_hello_parsing(pkt)
        logger.debug((version, csuites_len, csuites, comp_meth_len, comp_meth,
            ext_len, ext, sign_algs, ec_point_format, ec_point_formats,
            extension_type, random, random_bytes))

        # Creating the Packet and TLSClientHello objects and storing them
        tls_client_hello = TLSClientHello(version, csuites_len, csuites,
            comp_meth_len, comp_meth, ext_len, ext, sign_algs, ec_point_format,
            ec_point_formats, extension_type, random, random_bytes)
        ip_packet = Packet(src, dst, sport, dport, tls_client_hello, str(pkt),
                True)
        tls_client_hellos.append(ip_packet)

        logger.debug('Packet: %s', ip_packet)

    # Extracting server_hello packets
    server_hellos = extract_server_hello(packets)
    logger.debug('# of server hellos = %s', len(server_hellos))

    for pkt in server_hellos:
        # Getting IP info
        (src, dst, sport, dport) = ip_parsing(pkt)
        logger.debug((src, dst, sport, dport))

        # Getting TLS info
        (version, cipher_suite) = server_hello_parsing(pkt)
        logger.debug((version, cipher_suite))

        # Creating the Packet and TLSClientHello objects and storing them
        tls_server_hello = TLSServerHello(version, cipher_suite)
        ip_packet = Packet(src, dst, sport, dport, tls_server_hello, str(pkt),
                True)
        tls_server_hellos.append(ip_packet)

        logger.debug('Packet: %s', ip_packet)

    # Extracting certificate packets
    certificates = extract_certificate(packets)
    logger.debug('# of certificates = %s', len(certificates))

    # Extracting certificate packets
    for pkt in certificates:
        # Getting IP info
        (src, dst, sport, dport) = ip_parsing(pkt)
        logger.debug((src, dst, sport, dport))

        # Getting TLS info
        raw_ssl = certificate_parsing(pkt)
        #logger.debug(raw_ssl)

        # Creating the Packet and TLSCertificate objects and storing them
        tls_certificate = TLSCertificate(raw_ssl)
        ip_packet = Packet(src, dst, sport, dport, tls_certificate, str(pkt))
        tls_certificates.append(ip_packet)

        #logger.debug('Packet: %s', ip_packet)

    # Formatting the name of the device using RegEx
    name = re.sub('.*/', '', file_path)
    name = re.sub('.pcap', '', name)
    logger.debug('Name is %s', name)

    # Creating and returning the Trace object
    return Trace(name, file_path, tls_client_hellos, tls_server_hellos,
            tls_certificates)
