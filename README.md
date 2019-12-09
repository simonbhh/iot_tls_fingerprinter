# TLS Librairies Fingerprinter

## Description

The aim of this project is to fingerprint TLSClientHello messages from IoT devices to their servers in the Cloud as well as analysing more in depth the the TLS Handshake.

PyShark is used in this project in order to extract the relevant packets from wireshark capture files.

The project only runs with Python 3.

## How to use

### On Linux platforms

First of all the required librairies need to be installed :

```bash
pip install -r requirements.txt
```

Then simply run the following command by specifying the path of the directory containting the pcap files and which analysis method you want to use :

```bash
./run.py [pcap_directory] [analysis_method]
```

To check the different option available you can run :

```bash
./run.py -h
```

## How it works

### The parser

Here's the different steps of how the program works :

 - Iterating through the pcap files in the specified directory
 - Iterating through the packets present in the pcap files in order to find client_hello and server_hello messages
 - Parsing those packets to store the important TLS fields in the corresponding TLS class, either TLSClientHello, TLSServerHello or TLSCertificate

### Analysis methods

#### Basic fingerprinting methods

Once we created our objects containting all the fields we need, we can perform fingerprinting methods on those. To do so, we take the fields we want and we hash them altogether using the SHA-1 algorithm. Different fingerprint methods using different fields are implemented in the TLSClientHello class :
 - basic_sign : version, cipher suites, compression methods, extentions and sign algorithms
 - csuites_sign : version, cipher suites
 - comp_sign : version, compression methods
 - comp_ext_sign : version, compression methods, extentions, ec point format
 - signalgs_sign : version, sign algorithms
 - comp_ext_signalgs_sign : version, compression methods, extentions, sign algorithms, ec point format
 - random_sign : random
 - random_bytes_sign : random bytes

#### Advanced fingerprinting methods

Two more advanced fingerprinting methods have been implemented as well :
 - combinations : performs fingerprint with all combinations of the list of all the attributes of the TLSClientHello class
 - libs_compare : compares all the fingerprints of all combinations of the fields like the *combinations* method right above but by comparing devices to ssl libraries only, it produces a heatmap of the result

#### Other methods

Other methods have been implemented to analyze more in depth the TLS Handshake :
 - csuites_check : check for outdated advertised cipher suites in each trace
 - cert_check : check for the issuer sequence of each trace, also perform a nmap command on each of them to get more information (unable to recover any info for devices which connect to a server with a port different than 443 usually)
 - version_check : check for the version of the TLS protocol used
