import argparse

parser = argparse.ArgumentParser()
parser.add_argument('-t', '--sniffing-time', dest='time', type=int, default=0, 
                    help='For how much to sniff (in milliseconds). Setting this will disable sniffing until keyboard interruption')
parser.add_argument('-s', '--size', dest='size', type=int, default=65535, help='Max size of the packets to be saved')
# parser.add_argument('-p', '--sigfig', dest='sigfig', type=int, default=0, help='Amount of significant figures in timestamps')
# parser.add_argument('-v', '--verbose', dest='verbose', action='store_true', help='Verbose  mode')
parser.add_argument('-f', '--folder', dest="folder", type=str, default=None,
                    help='Folder, where .pcap file will be created. Default: [working_directory]/sniffed')
parser.add_argument('filename', help="Name of the .pcap file")