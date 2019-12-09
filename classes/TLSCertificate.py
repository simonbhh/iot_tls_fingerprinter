""" Class that represents a TLS Certificate """

__author__  = "Simon"
__date__    = "18/07/2019"

import re
import subprocess

class TLSCertificate:
    """ Class that represents a TLS Certificate """

    def __init__(self, raw):
        """
        Constructor

        :param raw: the raw data of the tls message
        :param issuer_sequence: the issuer sequence of the certificate
        :param not_before: the not before time of a certificate
        :param not_after: the not after time of a certificate
        """
        self.raw = raw
        self.issuer_sequence = self.extract_issuer_sequence()
        self.not_before = None
        self.not_after = None
        self.subject = None
        self.issuer = None

    def extract_issuer_sequence(self):
        """
        Method that extracts the issuer sequence
        """
        raw = self.raw.splitlines()
        sequence = []
        search = ['RDNSequence', 'commonName=']
        for line in raw:
            if all(x in line for x in search):
                line = re.sub(r'.*=', '', line)
                line = line.replace(')', '')
                sequence.append(line)
        return sequence

    def extract_info(self, port, ip):
        """
        Method that extracts relevant info of a certificate
        """
        nmap = subprocess.Popen(
            ['nmap','--script','ssl-cert','-p', port, ip],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, err = nmap.communicate()
        out = out.decode('utf-8').splitlines()
        for line in out:
            if 'Subject:' in line:
                line = re.sub(r'.*commonName=', '', line)
                line = re.sub(r'/.*', '', line)
                self.subject = line
            if 'Issuer:' in line:
                line = re.sub(r'.*commonName=', '', line)
                line = re.sub(r'/.*', '', line)
                self.issuer = line
            if 'before:' in line:
                line = re.sub(r'.*before:', '', line)
                line = re.sub(r'T.*', '', line)
                self.not_before = line
            if 'after:' in line:
                line = re.sub(r'.*after:', '', line)
                line = re.sub(r'T.*', '', line)
                self.not_after = line

    def __str__(self):
        """
        Redefined to_string method

        :returns: a string that represents a certificate
        """
        return ('raw: ' + str(self.raw) + '\n')
