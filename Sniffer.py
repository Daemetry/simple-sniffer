import socket
import datetime
import sys

from PcapHandler import PcapHandler

class Sniffer:
    def __init__(self, pcap_handler: PcapHandler, interface: str = ""):
        if sys.platform.startswith("win"):
            self._socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
            self._socket.bind(('0.0.0.0', 0))
            self._socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            self._socket.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
            pcap_handler.network_type = 101

        elif sys.platform.startswith("linux"):
            self._socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
            if interface:
                self._socket.bind((interface, 0))
                pcap_handler.network_type = 1 if interface == "eth0" else 105

        else:
            raise SystemError("Unsupported OS.")
        
        self._pcap_stream = pcap_handler
        self.captured_packets = 0
        self._done = False

    def sniff(self, until_keyboard_interrupt = False, for_milliseconds = 0):
        if self._done:
            raise ValueError("One instance of sniffer only supports one sniffing session.")
        
        if until_keyboard_interrupt and not for_milliseconds:
            print("Starting sniffing...")
            self._sniff_until_keyboard_interrupt()
        elif not until_keyboard_interrupt and for_milliseconds:
            print("Starting sniffing...")
            self._sniff_for_milliseconds(for_milliseconds)
        else:
            raise ValueError("You must choose one of the sniffing modes.")


    def _sniff_single_packet(self):
        packet, _ = self._socket.recvfrom(65535)
        timestamp = datetime.datetime.now().timestamp()
        ts_sec = int(timestamp)
        ts_usec = int((timestamp - ts_sec) * 1000000)

        self._pcap_stream.write_packet(packet, ts_sec, ts_usec)
        self.captured_packets += 1
        print(f"\rCaptured packets: {self.captured_packets}", end="")


    def _sniff_until_keyboard_interrupt(self):
        try:
            while True:
                self._sniff_single_packet()
        except KeyboardInterrupt:
            self._stop()


    def _sniff_for_milliseconds(self, milliseconds: int):
        start = datetime.datetime.now().timestamp()
        while True:
            self._sniff_single_packet()
            cur_time = datetime.datetime.now().timestamp()
            diff = int((cur_time - start) * 1000)
            if diff >= milliseconds:
                break
        self._stop()

    def _stop(self):
        if self._done:
            return
        self._done = True
        self._pcap_stream.close()
        self._socket.close()
        print("\nDone!")
