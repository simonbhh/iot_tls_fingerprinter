""" Class that represents a Wireshark trace file """

__author__  = "Simon"
__date__    = "19/06/2019"

from texttable import Texttable

class Trace:
    """ Class that represents a Wireshark trace file """

    def __init__(self, name, file_path, client_hellos, server_hellos,
            certificates):
        """
        Constructor

        :param name: the name of the trace
        :param file_path: the path of the trace file (as specified in the args)
        :param client_hellos: the list of packets corresponding to client hello
        :param server_hellos: the list of packets corresponding to server hello
        :param certificates: the list of certificates sent by the server
        """
        self.name = name
        self.file_path = file_path
        self.client_hellos = client_hellos
        self.server_hellos = server_hellos
        self.certificates = certificates

    def fingerprints_compare(self, trace, all):
        """
        Method that compares 2 traces using the fingerprint attributes

        :param trace: the trace to compare to
        :param all: if true all fingerprinting methods are used

        :returns: the matches between the fingerprints of the client hello pkts
        """
        checked_signature = []
        matches = []
        # We compare each signature of each packet in both traces
        for pkt1 in self.client_hellos:
            for pkt2 in trace.client_hellos:
                sign1 = pkt1.tls_info.fingerprint
                sign2 = pkt2.tls_info.fingerprint
                # If there is a match we add the element to the result
                if (sign1 == sign2 and sign1 not in checked_signature):
                    checked_signature.append(sign1)
                    # If all is true don't put the hash in the resulting tuple
                    if all:
                        matches.append((self.name, trace.name))
                    else:
                        matches.append((self.name, sign1, trace.name))
        return matches

    def csuites_compare(self, trace):
        """
        Method that compares 2 traces using the csuites lists

        :param trace: the trace to compare to

        :returns: the result of the intersections between csuites of the packets
        """
        result = []
        # We intersect each csuites list of each packet in both traces
        for pkt1 in self.client_hellos:
            for pkt2 in trace.client_hellos:
                inter = pkt1.tls_info.inter_csuites(pkt2.tls_info)
                result.append((self.name, trace.name,
                        inter[0], inter[1], inter[2]))
        return result

    def random_compare(self, trace):
        """
        Method that compares 2 traces using the random bytes field

        :param trace: the trace to compare to

        :returns: the result of the random comprisons between packets
        """
        result = []
        for pkt1 in self.client_hellos:
            for pkt2 in trace.client_hellos:
                result.append((self.name, trace.name,
                        pkt1.compare_random_bytes(pkt2)))
        return result

    def display_signature(self):
        """
        Method that displays the signatures of all packets of the trace
        """
        table = Texttable()
        table.set_cols_width([20,50])
        table.header(['Source IP', 'Signature'])
        for pkt in self.client_hellos:
            table.add_row([pkt.src, pkt.tls_info.fingerprint])
        print(self.name + ':')
        print(table.draw())

    def display_org_name(self):
        """
        Method that displays the org name of all packets
        destination IP of the trace
        """
        table = Texttable()
        table.set_cols_width([20,50])
        table.header(['Destination IP', 'Cloud Server Organization'])
        for pkt in self.client_hellos:
            table.add_row([pkt.dst, pkt.get_org_name()])
        print(table.draw())
