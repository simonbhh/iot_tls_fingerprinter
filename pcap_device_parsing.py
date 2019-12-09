#!/usr/bin/env python3

"""
    Script used to create one pcap file per device from the
    https://yourthings.info/data/ study

    The directory of the wireshark traces was located at the root
    of the project
"""

__author__  = "Simon"
__date__    = "02/08/2019"

import os
import sys
import subprocess

# The devices with their corresponding IP adress
device_mapping = {'Google OnHub': '192.168.0.2',
    'Samsung SmartThings Hub': '192.168.0.4',
    'Insteon Hub': '192.168.0.6',
    'Sonos': '192.168.0.7',
    'Securifi Almond': '192.168.0.8',
    'Nest Camera': '192.168.0.10',
    'Belkin WeMo Motion Sensor': '192.168.0.12',
    'LIFX Virtual Bulb': '192.168.0.13',
    'Belkin WeMo Switch': '192.168.0.14',
    'Amazon Echo': '192.168.0.15',
    'Wink Hub': '192.168.0.16',
    'Belkin Netcam': '192.168.0.18',
    'Ring Doorbell': '192.168.0.19',
    'Roku TV': '192.168.0.21',
    'Roku 4': '192.168.0.22',
    'Amazon Fire TV': '192.168.0.23',
    'nVidia Shield': '192.168.0.24',
    'Apple TV (4th Gen)': '192.168.0.25',
    'Belkin WeMo Link': '192.168.0.26',
    'Netgear Arlo Camera': '192.168.0.27',
    'D-Link DCS-5009L Camera': '192.168.0.28',
    'Logitech Logi Circle': '192.168.0.29',
    'Canary': '192.168.0.30',
    'Piper NV': '192.168.0.31',
    'Withings Home': '192.168.0.32',
    'WeMo Crockpot': '192.168.0.33',
    'MiCasaVerde VeraLite': '192.168.0.34',
    'Chinese Webcam': '192.168.0.35',
    'August Doorbell Cam': '192.168.0.36',
    'TP-Link WiFi Plug': '192.168.0.37',
    'Chamberlain myQ Garage Opener': '192.168.0.38',
    'Logitech Harmony Hub': '192.168.0.39',
    'Caseta Wireless Hub': '192.168.0.41',
    'Google Home Mini': '192.168.0.42',
    'Google Home': '192.168.0.43',
    'Bose SoundTouch 10': '192.168.0.44',
    'Harmon Kardon Invoke': '192.168.0.45',
    'Apple HomePod': '192.168.0.47',
    'Roomba': '192.168.0.48',
    'Samsung SmartTV': '192.168.0.49',
    'Koogeek Lightbulb': '192.168.0.50',
    'TP-Link Smart WiFi LED Bulb': '192.168.0.51',
    'Wink 2 Hub': '192.168.0.52',
    'Nest Cam IQ': '192.168.0.53',
    'Nest Guard': '192.168.0.54',
    'Ubuntu Desktop': '192.168.0.113',
    'Android Tablet': '192.168.0.138',
    'iPhone': '192.168.0.151',
    'iPad': '192.168.0.159'}

if __name__ == '__main__':

    # List of devices that have a created pcap file
    known_devices = []

    # The directory containing the pcap files
    pcap_dir = sys.argv[1]

    # Temporary pcap files
    tmpfile = './tshark/tmp.pcap'
    renamed_file = './tshark/renamed.pcap'

    # We iterate through every file in the specified directory
    for filename in os.listdir(pcap_dir):
        file_path = os.path.join(pcap_dir, filename)
        print('Current file:', file_path)
        i = 1
        # We iterate through the devices
        for device in list(device_mapping):
            # Example : tshark -r ../captures/yourthings_data/10/
            # eth1-20180410.0000.1523336400 -Y 'ssl.record.content_type == 22
            # && (ip.src == 192.168.0.2 || ip.dst == 192.168.0.2)'
            # -w test_output.pcap
            ip = str(device_mapping[device])
            filter = ('ssl.record.content_type == 22 && (ip.src == ' + ip +
                ' || ip.dst == ' + ip + ')')
            outfile = './tshark/' + device + '.pcap'
            # Checking if the file already exist
            if True:#device in known_devices:
                # If yes we cancat the result of tshark with the existing file
                file_size = os.path.getsize(outfile)
                # We check if the size of the file is less than 10 Kb
                if file_size < 10000:
                    subprocess.run([
                        'tshark', '-r', file_path, '-Y', filter, '-w', tmpfile
                    ])
                    subprocess.run([
                        'mv', outfile, renamed_file
                    ])
                    subprocess.run([
                        'mergecap', '-a', '-w', outfile, renamed_file, tmpfile
                    ])
                    print(str(i) + '. ' + device + ' file updated')

                    # We check if the file has a size of more than 10 Kb
                    if os.path.getsize(outfile) > 10000:
                        # If so, we remove the concerned device from the dict
                        del device_mapping[device]
                        print('Removing ' + device)
            else:
                # If no we add the device to the list and create a new file
                known_devices.append(device)
                subprocess.run([
                    'tshark', '-r', file_path, '-Y', filter, '-w', outfile
                ])
                print(str(i) + '. ' + device + ' file created')

                # We check if the file has a size of more than 10 Kb
                if os.path.getsize(outfile) > 10000:
                    # If so, we remove the concerned device from the dict
                    del device_mapping[device]
                    print('Removing ' + device)
            i += 1

    # Removing temporary files
    subprocess.run([
        'rm', tmpfile, renamed_file
    ])
