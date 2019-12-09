#!/usr/bin/env python3

"""
    Main script for loading the wireshark captures and storing them in order
    to compare the fingerprints of the different client_hello messages

    This project is using an argument parser and a logger
"""

__author__  = "Simon"
__date__    = "20/06/2019"

import sys
import subprocess
import argparse
import logging
import time
import itertools
from itertools import combinations
import networkx as nx
import numpy as np
import matplotlib
import matplotlib.pyplot as plt
import seaborn as sns
import collections
from collections import Counter
import math

from texttable import Texttable
from tqdm import tqdm

from common.pyshark_parser import *
#from common.scapy_parser import *

# List of allowed arguments as analysis method
analysis_methods = [
    'basic_sign',
    'csuites_sign',
    'comp_sign',
    'comp_ext_sign',
    'signalgs_sign',
    'comp_ext_signalgs_sign',
    'random_sign',
    'random_bytes_sign',
    'all',
    'combinations',
    'libs_compare',
    'csuites_check',
    'cert_check',
    'version_check'
    ]

# List of signature methods available
relevant_sign_methods = [
    'basic_sign',
    'csuites_sign',
    'comp_ext_sign',
    'signalgs_sign',
    'comp_ext_signalgs_sign',
    'random_sign',
    'random_bytes_sign'
    ]

class bcolors:
    """
    Colors and styles to display to the terminal
    """
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def create_argparse():
    """
    Method that creates the argument parser
    """
    parser = argparse.ArgumentParser(
        description="Fingerprinting TLS implementations")
    parser.add_argument("pcap_directory", type=str,
        help="the directory that contains the wireshark captures")
    parser.add_argument("analysis_method", type=str,
        help=str(analysis_methods))
    return parser

def make_traces(pcap_dir, pcap_file_num):
    """
    Method that creates the traces objects

    :param pcap_dir: the directory containing the pcap files
    :param pcap_file_num: the number of pcap file in the directory

    :return: a list of created traces
    """
    result = []
    # We iterate through every file in the specified directory
    for filename in tqdm(os.listdir(pcap_dir), total = pcap_file_num,
        unit = 'file', ncols = 75):
        # We look for Wireshark capture files
        if filename.endswith(".pcap"):
            file_path = os.path.join(pcap_dir, filename)
            result.append(create_trace(file_path))
    return result

def fingerprint(traces, analysis_method):
    """
    Method that fingerprints packets of traces with the specified method

    :param traces: a list of trace objects
    :param analysis_method: a fingerprint method to use
    """
    for trace in traces:
        # Fingerprinting the TLS Client Hello records
        for pkt in trace.client_hellos:
            getattr(pkt.tls_info, analysis_method)()
            #print(pkt.tls_info)
            logger.debug('Fingerprint: %s', pkt.tls_info.fingerprint)

def fingerprint_for_combinations(traces, attr_sublist):
    """
    Method that fingerprints packets of traces according to the attribute
    sublist

    :param traces: a list of trace objects
    :param attr_sublist: a list of attributes to use for the fingerprint
    """
    for trace in traces:
        for pkt in trace.client_hellos:
            pkt.tls_info.fingerprint_combination(attr_sublist)

def compare_traces(traces, all=False):
    """
    Method that compares all the traces in the traces list
    thanks to the fingerprints

    :param traces: a list of trace objects
    :param all: the analysis_method argument from the command line

    :return: a list of tuples (device1, device2)
    """
    res = []
    for i in range(len(traces)):
        for j in range(i+1, len(traces)):
            cmp = traces[i].fingerprints_compare(traces[j], all)
            if cmp != []:
                res.append(cmp)
    return res

def compare_devices_to_libs(devices, libs):
    """
    Method that compares all the traces between the devices and the libs
    thanks to the fingerprints

    :param devices: a list of device trace objects
    :param libs: a list of library trace objects

    :returns: a matrix
    """
    matrix = np.zeros(shape=(len(devices), len(libs)))
    comp_num = 0
    comp_list = []
    # Iterating through all the devices and libs
    for i in range(0, len(devices)):
        for j in range(0, len(libs)):
            cmp = devices[i].fingerprints_compare(libs[j], True)
            if cmp != []:
                matrix[i][j] += 1
                comp_num += 1
                comp_list.append((cmp, i, j))
    return (matrix, comp_num)

def display_similarities(comparisons):
    """
    Method that display the matches in the comparisons

    :param comparisons: a list of triples (device1, device2, sign)
    """
    table = Texttable()
    table.set_cols_width([30,30,30])
    table.header(['Device 1', 'Device 2', 'Signature'])
    for triple in comparisons:
        table.add_row([triple[0], triple[2], triple[1]])
    print(bcolors.HEADER + 'Similarities: ' + bcolors.ENDC)
    print(table.draw())

def display_info(traces):
    """
    Method that displays some info about the traces

    :param traces: a list of trace objects
    """
    # We display the signature of each client_hello and their src IP
    for trace in traces:
        trace.display_signature()
        trace.display_org_name()
        print('\n')

def assemble_similarities(all_sign_traces):
    """
    Method that assemble the similarities between all the comparisons

    :param all_sign_traces: a list of tuples (device1, device2)

    :return: a list of cliques in a graph
    """
    # We use a graph to look for maximal cliques in it
    G = nx.Graph()
    for clique in all_sign_traces:
        for vertices in combinations(clique, r=2):
            G.add_edge(*vertices)
    pos = nx.spring_layout(G)
    nx.draw(G, pos, font_size=12, with_labels=False)
    for p in pos:  # raise text positions
        pos[p][1] += 0.05
    nx.draw_networkx_labels(G, pos)
    plt.show()
    return list(nx.find_cliques(G))

def display_assembled_similarities(list):
    """
    Method that displays the assembled similarities

    :param list: a list of sublist (cliques in a graph here)
    """
    table = Texttable()
    table.set_cols_width([80])
    for sublist in list:
        table.add_row([sublist])
    print(bcolors.HEADER + 'Assembled similarities:' + bcolors.ENDC)
    print(table.draw())

def display_links_strength(traces):
    """
    Method that displays the strength of the tuples

    :param traces: a list of trace objects
    """
    # We count similar tuples by sorting them first
    result = Counter(tuple(t) for t in map(sorted, traces))
    # We can then display it in a table
    table = Texttable()
    table.set_cols_width([50,30])
    table.header(['Similarities', 'Nb of occurences'])
    # We iterate through the dict by sorting the pairs
    for key in sorted(result, key=result.get, reverse=True):
        table.add_row([key, result[key]])
    print(bcolors.HEADER + 'Links strength:' + bcolors.ENDC)
    print(table.draw())

def display_csuites_inter(traces):
    """
    Method that displays the result of the intersection of csuites lists

    :param traces: a list of trace objects
    """
    # Intersecting cipher suites
    table = Texttable()
    table.set_cols_width([30,30,10,10,10,10])
    table.header(['Device 1', 'Device 2', 'Length',
            'Percent1', 'Percent2', 'Mean'])
    result = []
    # We fill up the result list with all the tuples corresponding
    # to an intersection of cipher suites lists
    for i in range(len(traces)):
        for j in range(i+1, len(traces)):
            inter = traces[i].csuites_compare(traces[j])
            # We iterate through the tuples in the inter list
            for tup in inter:
                # We compute the percentage of matching csuites in the lists
                # and compute the mean of that
                percent1 = round((len(tup[2]) / tup[3] * 100), 2)
                percent2 = round((len(tup[2]) / tup[4] * 100), 2)
                mean = round(((percent1 + percent2) / 2), 2)
                result.append((tup[0], tup[1], len(tup[2]),
                        percent1, percent2, mean))
    # We sort the list
    result.sort(key=lambda tup: tup[5], reverse=True)
    # We add the tuples to the table to display them
    for tup in result:
        table.add_row([tup[0], tup[1], tup[2], tup[3], tup[4], tup[5]])
    print(bcolors.HEADER + 'Cipher Suites intersections:' + bcolors.ENDC)
    print(table.draw())

def display_random_similarities(traces):
    """
    Method that displays the percentage of random bytes similarities

    :param traces: a list of trace objects
    """
    result = []
    for i in range(len(traces)):
        for j in range(i+1, len(traces)):
            sim = traces[i].random_compare(traces[j])
            for tup in sim:
                result.append(tup)
    result.sort(key=lambda tup: tup[2], reverse=True)
    # Creating the table to display
    table = Texttable()
    table.set_cols_width([30,30,10])
    table.header(['Device 1', 'Device 2', 'Percentage'])
    # We add the tuples to the table to display them
    for tup in result:
        table.add_row([tup[0], tup[1], tup[2]])
    print(bcolors.HEADER + 'Random bytes comparison :' + bcolors.ENDC)
    print(table.draw())

def display_vulnerabilities(device, vulnerabilities, choosed_csuites):
    """
    Method that displays the potential points of vulnerabilities

    :param device: the name of the device
    :param vulnerabilities: a list of tuples (csuite, vulnerable_algo)
    :param choosed_csuites: a list of choosed csuites by the server
    """
    print(bcolors.HEADER + 'Potential vulnerabilities (' +
            device + ') :' + bcolors.ENDC)
    table = Texttable()
    table.set_cols_width([40,20])
    table.header(['Cipher Suite', 'Weaknesses'])
    for vuln in vulnerabilities:
        table.add_row([vuln[0], vuln[1]])
    print(table.draw())
    print('Choosed cipher suites: ', choosed_csuites, '\n')

def display_issuer_sequence(traces):
    """
    Method that displays the issuer sequence

    :param traces: a list of trace objects
    """
    print(bcolors.HEADER + 'RDN Sequences :' + bcolors.ENDC)
    for trace in traces:
        i = 1
        print('\n' + trace.name + ' :')
        for pkt in trace.certificates:
            print('Packet ' + str(i) + ' : ')
            table = Texttable()
            table.set_cols_width([50])
            for step in pkt.tls_info.issuer_sequence:
                table.add_row([step])
            print(table.draw())
            i += 1

def display_certificate_dates(traces):
    """
    Method that displays the certificate dates

    :param traces: a list of trace objects
    """
    print(bcolors.HEADER + 'Certificate dates :' + bcolors.ENDC)
    for trace in traces:
        i = 1
        print('\n' + trace.name + ' :')
        for pkt in trace.certificates:
            print('Packet ' + str(i) + ' : ')
            table = Texttable()
            table.set_cols_width([20,20])
            table.header(['Not before', 'Not after'])
            table.add_row([pkt.tls_info.not_before, pkt.tls_info.not_after])
            print(table.draw())
            i += 1

def display_nmap_result(traces):
    """
    Method that displays the result of the nmap command

    :param traces: a list of trace objects
    """
    print(bcolors.HEADER + 'Nmap :' + bcolors.ENDC)
    for trace in traces:
        i = 1
        print('\n' + trace.name + ' :')
        for pkt in trace.certificates:
            pkt.tls_info.extract_info(pkt.sport, pkt.src)
            print('Packet ' + str(i) + ' : ')
            table = Texttable()
            table.set_cols_width([15,25,25,15,15])
            table.header(['IP', 'Subject', 'Issuer', 'Not before', 'Not after'])
            table.add_row([pkt.src, pkt.tls_info.subject, pkt.tls_info.issuer,
                    pkt.tls_info.not_before, pkt.tls_info.not_after])
            print(table.draw())
            i += 1

def display_version(traces):
    """
    Method that displays the version of the TLS protocol used

    :param traces: a list of trace objects
    """
    print(bcolors.HEADER + 'TLS Version :' + bcolors.ENDC)
    for trace in traces:
        i = 1
        print('\n' + trace.name + ' :')
        for pkt in trace.client_hellos:
            print('Packet ' + str(i) + ' : ')
            table = Texttable()
            table.set_cols_width([10])
            table.header(['TLS Version'])
            table.add_row([pkt.tls_info.version])
            print(table.draw())
            i += 1

def compute_files_dir(directory):
    """
    Method that computes the number of files in a directory

    :param directory: the concerned directory

    :return: the number of file
    """
    return len([file for file in os.listdir(directory)
        if file.endswith('.pcap') and os.path.isfile(
        os.path.join(directory, file))])

def create_heatmap(matrix, devices, libs):
    """
    Method that creates a heatmap with the comparisons of the devices and
    the libraries

    :param matrix: a matrix with the links strength
    :param devices: a list of device trace objects
    :param libs: a list of library trace objects
    """
    # Creating the heatmap
    #ax = sns.heatmap(matrix, annot=True, fmt='.2f', linewidths=.5,
    #                cmap="YlGnBu", xticklabels=True, yticklabels=True)
    ax = sns.heatmap(matrix, cmap="YlGnBu", xticklabels=True, yticklabels=True)
    # Adding percentage symbol after the numbers manually (the '.1%' format is
    # having issues here)
    #for t in ax.texts: t.set_text(t.get_text() + " %")
    ax.set_xticklabels(libs)
    ax.set_yticklabels(devices)
    # Rotate the tick labels and set their alignment.
    plt.setp(ax.get_yticklabels(), rotation=0, ha="right",
             rotation_mode="anchor", fontsize=8)
    #plt.setp(ax.get_xticklabels(), fontsize=8)
    plt.setp(ax.get_xticklabels(), rotation=40, ha="right",
             rotation_mode="anchor", fontsize=8)
    plt.show()

def main():
    """
    Creates the traces and computes the differences
    """

    # Creating the parser
    parser = create_argparse()
    args = parser.parse_args()

    analysis_method = args.analysis_method

    if analysis_method not in analysis_methods:
        print('Error: The fingerprint method is incorrect,' +
            'choose one of the following: ' + str(analysis_methods))
        exit(0)

    # Creating and configuring the logger
    logger = logging.getLogger(__name__)
    logger.setLevel(logging.DEBUG)

    formatter = logging.Formatter('%(name)s - %(levelname)s: %(message)s')

    file_handler = logging.FileHandler('run.log')
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)

    logger.info('=============================================================')
    logger.info('Starting')

    pcap_dir = args.pcap_directory

    # We compute the number of pcap files in the directory
    pcap_file_num = compute_files_dir(pcap_dir)
    print('Number of pcap files: ' + str(pcap_file_num))

    # List that will contains the traces objects
    traces = make_traces(pcap_dir, pcap_file_num)

    logger.debug('# of trace file = %s', len(traces))

    # We perform the fingerprint and comparisons according to the argument
    if analysis_method == 'all':
        all_sign_traces = []
        # We perform all the relevant sign methods to then compare the results
        for sign_meth in relevant_sign_methods:
            fingerprint(traces, sign_meth)
            comparisons = compare_traces(traces, True)
            all_sign_traces.append(comparisons)
        # We flatten the list completely (twice the op is necessary to do so)
        all_sign_traces = [i for sublist in all_sign_traces for i in sublist]
        all_sign_traces = [i for sublist in all_sign_traces for i in sublist]
        assembled_sim = assemble_similarities(all_sign_traces)
        #display_info(traces)
        display_assembled_similarities(assembled_sim)
        print('\n')
        display_links_strength(all_sign_traces)
        print('\n')
        display_csuites_inter(traces)
        print('\n')
        #display_random_similarities(traces)

    elif analysis_method == 'combinations':
        # We perform fingerprinting of all combinations of the attributes
        # Computing nCr to get the result of 2 amongst pcap_file_num
        f = math.factorial
        nCr = f(pcap_file_num) / f(2) / f(pcap_file_num - 2)
        print('nCr =', nCr)
        # Try out several percentages
        percentage_down = 0
        percentage_up = 0
        down = (nCr * percentage_down / 100)
        up = nCr - (nCr * percentage_up / 100)
        print('down =', down)
        print('up =', up)

        # Creating the combinations and fingerprinting them
        attr_list = TLSClientHello.attr_for_fpt
        all_sign_traces = []
        combinations = []
        total_combinations = 0
        # Iterating through all combinations of client hello attributes
        for L in range(0, len(attr_list)+1):
            for attr_sublist in itertools.combinations(attr_list, L):
                fingerprint_for_combinations(traces, attr_sublist)
                comparisons = compare_traces(traces, True)
                # Adding only relevant information by checking on the size
                comp_size = len(comparisons)
                if (comp_size >= down and comp_size <= up):
                    all_sign_traces.append(comparisons)
                    combinations.append(attr_sublist)
                # Counting the total number of combinations
                total_combinations += 1

        # Displaying the "winning" combinations of attributes
        #print(combinations)
        print('number of winning combinations =', len(combinations),
            'out of', total_combinations)

        # We flatten the list completely (twice the op is necessary to do so)
        all_sign_traces = [i for sublist in all_sign_traces for i in sublist]
        all_sign_traces = [i for sublist in all_sign_traces for i in sublist]
        print('all_sign_traces size :', len(all_sign_traces))
        print('\n')
        assembled_sim = assemble_similarities(all_sign_traces)
        #display_info(traces)
        display_assembled_similarities(assembled_sim)
        print('\n')
        display_links_strength(all_sign_traces)
        """
        print('\n')
        display_csuites_inter(traces)
        """

    elif analysis_method == 'libs_compare':
        # Here we only compare the iot devices with the tls libraries
        # We produce a heatmap in the end to show which devices in closest to
        # which tls library
        libs_directory = '../captures/ssl_libs' # Hard coded value to change
        libs_file_num = compute_files_dir(libs_directory)
        libs_traces = make_traces(libs_directory, libs_file_num)
        # Computing nCr to get the result of 2 amongst pcap_file_num
        f = math.factorial
        nCr = f(pcap_file_num) / f(2) / f(pcap_file_num - 2)
        print('nCr =', nCr)
        # Try out several percentages
        percentage_down = 0
        percentage_up = 0
        down = (nCr * percentage_down / 100)
        up = nCr - (nCr * percentage_up / 100)
        print('down =', down)
        print('up =', up)

        # Creating the combinations and fingerprinting them
        attr_list = TLSClientHello.attr_for_fpt
        combinations = []
        total_combinations = 0
        final_matrix = np.zeros(shape=(len(traces), len(libs_traces)))
        # Iterating through all combinations of client hello attributes
        for L in range(0, len(attr_list)+1):
            for attr_sublist in itertools.combinations(attr_list, L):
                fingerprint_for_combinations(traces, attr_sublist)
                fingerprint_for_combinations(libs_traces, attr_sublist)
                (matrix, comp_num) = compare_devices_to_libs(traces,
                                                                libs_traces)
                # Adding only relevant information to the final_matrix
                # by checking on the size
                if (comp_num > down and comp_num < up):
                    final_matrix += matrix
                    combinations.append(attr_sublist)
                # Counting the total number of combinations
                total_combinations += 1

        print('total_combinations =', total_combinations)
        print('number of fingerprint method used =', len(combinations))
        print(final_matrix)

        """
        final_matrix = np.zeros(shape=(len(traces), len(libs_traces)))
        for sign_meth in relevant_sign_methods:
            fingerprint(traces, sign_meth)
            fingerprint(libs_traces, sign_meth)
            (matrix, comp_num) = compare_devices_to_libs(traces,
                                                            libs_traces)
            final_matrix += matrix

        print(final_matrix)
        """

        to_delete = []
        for i in range(0, final_matrix.shape[0]):
            cmpt = 0
            for j in range(0, final_matrix.shape[1]):
                final_matrix[i][j] = (final_matrix[i][j] /
                                    len(combinations) * 100)
                if final_matrix[i][j] == 0:
                    cmpt += 1
                if cmpt == len(libs_traces):
                    # Adding the right index to delete (minus the number of
                    # already added index because on the removal the length of
                    # the list will decrease)
                    to_delete.append(i - len(to_delete))

        heatmap_devices = []
        heatmap_libs = []
        for trace in traces:
            heatmap_devices.append(trace.name)
        for lib in libs_traces:
            heatmap_libs.append(lib.name)

        print('to_delete =', to_delete)

        # Deleting selected rows in the matrix
        for i in to_delete:
            final_matrix = np.delete(final_matrix, (i), axis=0)
            del heatmap_devices[i]

        print(final_matrix)

        # Creating the heatmap
        create_heatmap(final_matrix, heatmap_devices, heatmap_libs)

        print('heatmap_devices size =', len(heatmap_devices))

    elif analysis_method == 'csuites_check':
        # Looking for outdated cipher suites in the client hellos
        vulnerable_csuites = []
        for trace in traces:
            for pkt in trace.client_hellos:
                vulnerable_csuites = pkt.tls_info.check_cipher_suites()

            choosed_csuites = []
            for pkt in trace.server_hellos:
                choosed_csuites.append(pkt.tls_info.csuite)
            display_vulnerabilities(trace.name, vulnerable_csuites, choosed_csuites)
            print('Number of TLSClientHello: ', len(trace.client_hellos))

    elif analysis_method == 'cert_check':
        # Displaying the issuer sequence of the certificates
        display_issuer_sequence(traces)

        # Displaying the result of the nmap command on the servers
        display_nmap_result(traces)

    elif analysis_method == 'version_check':
        # Displaying versions of the TLS protocol used
        display_version(traces)

    else:
        # We perform the fingerprinting method specified in the arguments
        fingerprint(traces, analysis_method)
        # We compute and display the similarities
        comparisons = compare_traces(traces)
        # We flatten the list and sort it to then display it
        comparisons = [item for sublist in comparisons for item in sublist]
        comparisons.sort(key=lambda triple: triple[2])
        display_info(traces)
        display_similarities(comparisons)


    logger.info('Finished\n\n\n\n\n')

if __name__ == '__main__':
    start_time = time.time()
    main()
    print('Execution time: %s seconds' %(time.time() - start_time))
