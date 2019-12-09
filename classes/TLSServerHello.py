""" Class that represents a Server Hello TLS message """

__author__  = "Simon"
__date__    = "11/07/2019"

import re

class TLSServerHello:
    """ Class that represents a TLS server hello """

    def __init__(self, version, cipher_suite, csuite=None):
        """
        Constructor

        :param version: the tls version
        :param cipher_suite: the number of the cipher suite used
        :param csuite: the cipher suite choosed by the server
        """
        self.version = version
        self.cipher_suite = cipher_suite

    def extract_csuite(self, raw):
        """
        Method that extracts the cipher suites of the raw attribute

        :param raw: the raw content of the packet
        """
        raw = raw.splitlines()
        result = []
        for line in raw:
            if 'Cipher Suite:' in line:
                line = re.sub(r'.*: ', '', line)
                line = re.sub(r' .*', '', line)
                result.append(line)
        self.csuite = result

    def __str__(self):
        """
        Redefined to_string method

        :returns: a string that represents a server hello
        """
        return ('version: ' + str(self.version) + '\n\t' +
                'cipher_suite: ' + str(self.cipher_suite) + '\n')
