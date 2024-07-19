from sys import platform
from argparser import parser
from Sniffer import Sniffer
from PcapHandler import PcapHandler


def check_admin():
    if platform.startswith("win"):
        import ctypes
        return ctypes.windll.shell32.IsUserAnAdmin() == 1
    elif platform.startswith("linux"):
        import os
        return os.geteuid() == 0
    else:
        raise SystemError("Unsupported OS.")


def main():
    args = parser.parse_args()
    pcap_handler = PcapHandler(
        folder=args.folder, filename=args.filename, 
        significant_figures=0, max_packet_size=args.size) # sigfig set to 0 bc handler doesn't do anything with it anyways
    sniffer = Sniffer(pcap_handler) # interface set to any bc sniffer doesn't differentiate between them

    if args.time:
        sniffer.sniff(for_milliseconds=args.time)
    else:
        sniffer.sniff(until_keyboard_interrupt=True)

if __name__ == "__main__":
    if not check_admin():
        print("In order to capture traffic, this srcipt requires admin privileges.")
    else:
        main()
