""" Class that represents an IP packet """

__author__  = "Simon"
__date__    = "19/06/2019"

import urllib.request
import json

# Creating the logger
import logging

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

formatter = logging.Formatter('%(name)s - %(levelname)s: %(message)s')

file_handler = logging.FileHandler('run.log')
file_handler.setFormatter(formatter)
logger.addHandler(file_handler)

class Packet:
    """ Class that represents an IP packet  """

    modern_csuites = [
        "TLS_ECDHE_ECDSA_AES256_GCM_SHA384",
        "TLS_ECDHE_RSA_AES256_GCM_SHA384",
        "TLS_ECDHE_ECDSA_CHACHA20_POLY1305",
        "TLS_ECDHE_RSA_CHACHA20_POLY1305",
        "TLS_ECDHE_ECDSA_AES128_GCM_SHA256",
        "TLS_ECDHE_RSA_AES128_GCM_SHA256",
        "TLS_ECDHE_ECDSA_AES256_SHA384",
        "TLS_ECDHE_RSA_AES256_SHA384",
        "TLS_ECDHE_ECDSA_AES128_SHA256",
        "TLS_ECDHE_RSA_AES128_SHA256"
    ]

    def __init__(self, src, dst, sport, dport, tls_info, raw, isCsuite=False):
        """
        Constructor

        :param src: the source ip address
        :param dst: the destination ip address
        :param sport: the source port
        :param dport: the destination port
        :param tls_info: the tls object with the tls information of the packet
        :param raw: the raw content of the packet
        """
        self.src = src
        self.dst = dst
        self.sport = sport
        self.dport = dport
        self.tls_info = tls_info
        self.raw = raw
        if (isCsuite):
            self.tls_info.extract_csuite(self.raw)

    def get_org_name(self):
        """
        Methods that returns the organization's name who owns the src IP

        :returns: the organization's name
        """
        # We call an API to get the info of the destination IP
        content = urllib.request.urlopen(
            "http://ip-api.com/json/" + self.dst).read()
        data = json.loads(content.decode('utf-8'))
        org_name = None
        try:
            org_name = data['org']
        except KeyError:
            logger.exception('No org_name on IP %s', self.dst)
        return org_name

    def compare_random_bytes(self, pkt):
        """
        Method that compares 2 random bytes fields

        :param pkt: the packet to compare to

        :returns: the percentage of difference between 2 random bytes fields
        """
        random_len = len(self.tls_info.random_bytes)
        matches = 0
        for i in range(0, random_len):
            if (self.tls_info.random_bytes[i] ==
                    pkt.tls_info.random_bytes[i]):
                matches += 1
        return round((matches / random_len * 100), 2)

    def __str__(self):
        """
        Redefined to_string method

        :returns: a string that represents a packet
        """
        return ('src: ' + str(self.src) + '\n' +
                'dst: ' + str(self.dst) + '\n' +
                'sport: ' + str(self.sport) + '\n' +
                'dport: ' + str(self.dport) + '\n')
