import argparse
import re
from scapy.all import *
from colorama import init, Fore, Style

init()  # Initialize colorama

def process_packet(packet):
    if packet.haslayer(Raw):
        payload = packet[Raw].load.decode('utf-8', errors='ignore')
        if 'Host:' in payload:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            website = re.search(r'Host: ([\w\.]+)', payload).group(1)
            print(f'{Fore.GREEN}[Source]{Style.RESET_ALL} {src_ip}\t{Fore.GREEN}[Dest]{Style.RESET_ALL} {dst_ip}\t{Fore.GREEN}[Website]{Style.RESET_ALL} {website}')

def extract_website(pcap_file):
    sniff(offline=pcap_file, filter="tcp and port 80", prn=process_packet, store=False)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='PCAP Analysis')
    parser.add_argument('-f', '--file', help='Path to the pcap file', required=True)
    args = parser.parse_args()

    extract_website(args.file)
