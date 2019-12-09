""" Class that represents a CLient Hello TLS message """

__author__  = "Simon"
__date__    = "19/06/2019"

import hashlib
import re

class TLSClientHello:
    """ Class that represents a TLS client hello """

    # Class variable for the fingerprint combinations
    attr_for_fpt = ['version', 'cipher_suites_length', 'cipher_suites',
        'compression_methods_length', 'compression_methods',
        'extensions_length', 'extensions', 'sign_algs', 'ec_point_format',
        'ec_point_formats', 'extension_type', 'random', 'random_bytes']

    def __init__(self, version, cipher_suites_length, cipher_suites,
                compression_methods_length, compression_methods,
                extensions_length, extensions, sign_algs, ec_point_format,
                ec_point_formats, extension_type, random, random_bytes,
                fingerprint=None, csuites=None):
        """
        Constructor

        :param version: the tls version
        :param cipher_suites_length: the number of cipher suites
        :param cipher_suites: a number identifying the list of ciper suites
        :param compression_methods_length: the number of comp methods
        :param compression_methods: a number identifying the comp methods
        :param extensions_length: the number of extensions
        :param extensions: a number identifying the extensions
        :param extension_type: a number identifying the extension type
        :param random: the random field
        :param random_bytes: the random bytes field
        :param fingerprint: the hash of the fields of the client hello
        :param csuites: the list of the cipher suites offered
        """
        self.version = version
        self.cipher_suites_length = cipher_suites_length
        self.cipher_suites = cipher_suites
        self.compression_methods_length = compression_methods_length
        self.compression_methods = compression_methods
        self.extensions_length = extensions_length
        self.extensions = extensions
        self.sign_algs = sign_algs
        self.ec_point_format = ec_point_format
        self.ec_point_formats = ec_point_formats
        self.extension_type = extension_type
        self.random = random
        self.random_bytes = random_bytes

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
        self.csuites = result

    def check_cipher_suites(self):
        """
        Method that checks for vulnerable cipher suites in the packet

        :returns: a list of tuples (cipher suite, potential vulnerability)
        """
        result = []
        for csuite in self.csuites:
            vulnerabilities = []
            if 'CBC' in csuite:
                vulnerabilities.append('CBC')
            if 'RC4' in csuite:
                vulnerabilities.append('RC4')
            if 'DES' in csuite:
                vulnerabilities.append('DES')
            if 'anon' in csuite:
                vulnerabilities.append('anon')
            if 'EXPORT' in csuite:
                vulnerabilities.append('EXPORT')
            if len(vulnerabilities) > 0:
                result.append((csuite, vulnerabilities))
        return result

    def inter_csuites(self, tls_info):
        """
        Method that makes an intersection between 2 csuites lists
        and returns the matches and the lists length

        :param tls_info: the tls content of the packet

        :returns: tuples of the intersection of 2 cipher suites
        """
        return (set(self.csuites).intersection(tls_info.csuites),
                len(self.csuites), len(tls_info.csuites))

    def basic_sign(self):
        """
        Method that fingerprints the TLS record "with all the fields
        """
        sign = hashlib.sha1()
        sign.update((str(self.version)).encode('utf-8'))
        sign.update((str(self.cipher_suites_length)).encode('utf-8'))
        sign.update((str(self.cipher_suites)).encode('utf-8'))
        sign.update((str(self.compression_methods_length)).encode('utf-8'))
        sign.update((str(self.compression_methods)).encode('utf-8'))
        sign.update((str(self.extensions_length)).encode('utf-8'))
        sign.update((str(self.extensions)).encode('utf-8'))
        sign.update((str(self.sign_algs)).encode('utf-8'))
        self.fingerprint = sign.hexdigest()

    def csuites_sign(self):
        """
        Method that fingerprints the TLS record with the cipher suites
        """
        sign = hashlib.sha1()
        sign.update((str(self.version)).encode('utf-8'))
        sign.update((str(self.cipher_suites)).encode('utf-8'))
        self.fingerprint = sign.hexdigest()

    def comp_sign(self):
        """
        Method that fingerprints the TLS record with the comp methods
        """
        sign = hashlib.sha1()
        sign.update((str(self.version)).encode('utf-8'))
        sign.update((str(self.compression_methods_length)).encode('utf-8'))
        sign.update((str(self.compression_methods)).encode('utf-8'))
        self.fingerprint = sign.hexdigest()

    def comp_ext_sign(self):
        """
        Method that fingerprints the TLS record with the comp methods
        and the extensions
        """
        sign = hashlib.sha1()
        sign.update((str(self.version)).encode('utf-8'))
        sign.update((str(self.compression_methods_length)).encode('utf-8'))
        sign.update((str(self.compression_methods)).encode('utf-8'))
        sign.update((str(self.ec_point_format)).encode('utf-8'))
        sign.update((str(self.ec_point_formats)).encode('utf-8'))
        sign.update((str(self.extension_type)).encode('utf-8'))
        self.fingerprint = sign.hexdigest()

    def signalgs_sign(self):
        """
        Method that fingerprints the TLS record with the sign algs
        """
        sign = hashlib.sha1()
        sign.update((str(self.version)).encode('utf-8'))
        sign.update((str(self.sign_algs)).encode('utf-8'))
        self.fingerprint = sign.hexdigest()

    def comp_ext_signalgs_sign(self):
        """
        Method that fingerprints the TLS record with the comp methods,
        the extensions and the sign algs
        """
        sign = hashlib.sha1()
        sign.update((str(self.version)).encode('utf-8'))
        sign.update((str(self.compression_methods_length)).encode('utf-8'))
        sign.update((str(self.compression_methods)).encode('utf-8'))
        sign.update((str(self.ec_point_format)).encode('utf-8'))
        sign.update((str(self.ec_point_formats)).encode('utf-8'))
        sign.update((str(self.extension_type)).encode('utf-8'))
        sign.update((str(self.sign_algs)).encode('utf-8'))
        self.fingerprint = sign.hexdigest()

    def random_sign(self):
        """
        Method that fingerprints the TLS record with the random field
        """
        sign = hashlib.sha1()
        sign.update((str(self.random)).encode('utf-8'))
        self.fingerprint = sign.hexdigest()

    def random_bytes_sign(self):
        """
        Method that fingerprints the TLS record with the random bytes field
        """
        sign = hashlib.sha1()
        sign.update((str(self.random_bytes)).encode('utf-8'))
        self.fingerprint = sign.hexdigest()

    def fingerprint_combination(self, attributes):
        """
        Method that fingerprints the TLS record with the fields contained in
        the attributes argument

        :param attributes: a list of attributes of the class

        :returns: the fingerprint
        """
        sign = hashlib.sha1()
        for attr in attributes:
            sign.update((str(getattr(self, attr))).encode('utf-8'))
        self.fingerprint = sign.hexdigest()
        return self.fingerprint

    def __str__(self):
        """
        Redefined to_string method

        :returns: a string that represents a client hello
        """
        return ('version: ' + str(self.version) + '\n\t' +
                'cipher_suites_length: ' +
                    str(self.cipher_suites_length) + '\n\t' +
                'cipher_suites: ' + str(self.cipher_suites) + '\n\t' +
                'compression_methods_length: ' +
                    str(self.compression_methods_length) + '\n\t' +
                'compression_methods: ' +
                    str(self.compression_methods) + '\n\t' +
                'extensions_length: ' + str(self.extensions_length) + '\n\t' +
                'extensions: ' + str(self.extensions) + '\n\t' +
                'sign_algs: ' + str(self.sign_algs) + '\n\t' +
                'sign_algs: ' + str(self.ec_point_format) + '\n\t' +
                'sign_algs: ' + str(self.ec_point_formats) + '\n\t' +
                'sign_algs: ' + str(self.extension_type) + '\n\t' +
                'sign_algs: ' + str(self.random) + '\n\t' +
                'sign_algs: ' + str(self.random_bytes) + '\n')
