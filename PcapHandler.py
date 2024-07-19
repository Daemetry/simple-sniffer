import datetime
import struct
import os

class PcapHandler:
    _magic_number = 0xA1B2C3D4
    _version_major = 2
    _version_minor = 4

    # Pcap-supported network-types:
    # Ethernet (IEEE 802.3) - 1
    # IEEE 802.11 (Wi-Fi) - 105
    # PPP (Point-to-Point Protocol) - 9
    # Raw IP packets - 101
    def __init__(self, folder: os.PathLike | str = None, filename: str = None, significant_figures = 0, max_packet_size = 65535, network_type: int = 1):
        if network_type not in [1, 9, 101, 105]:
            raise ValueError("Network type does not correlate to any compatible with the format.")
        
        self.filename = filename
        self.max_size = max_packet_size
        self.sigfig = significant_figures
        self.network_type = network_type
        self.folder = folder
        self.filename = filename
        
        timezone_offset_seconds = datetime.datetime.now().astimezone().tzinfo \
            .utcoffset(datetime.datetime.now()).total_seconds()
        self._timezone = int(timezone_offset_seconds / 3600)

        self._stream = None
        self._closed = False
        

    def _stream_init(self):
        if self._stream:
            return
        
        self._global_header = struct.pack(
            '<IHHiIII', PcapHandler._magic_number, 
            PcapHandler._version_major, PcapHandler._version_minor, 
            self._timezone, self.sigfig, self.max_size, self.network_type
            )
        
        self.folder = self.folder if self.folder else os.getcwd() + "/sniffed"
        self.filename = self.filename if self.filename else f"Sniff at {datetime.datetime.now()}"
        self.filename += ".pcap" if not self.filename.endswith(".pcap") else ""
        self.file_path = os.path.join(
            self.folder, 
            self.filename
        )

        os.makedirs(self.folder, exist_ok=True)
        self._stream = open(self.file_path, 'wb')
        self._stream.write(self._global_header)


    def write_packet(self, packet: bytes, timestamp_sec, timestamp_usec):
        if self._closed:
            raise ValueError("I/O operation on closed file")
        self._stream_init()

        original_len = len(packet)
        captured_len = min(original_len, self.max_size)
        pcap_packet_header = struct.pack("<IIII", timestamp_sec, timestamp_usec, captured_len, original_len)
        self._stream.write(pcap_packet_header)
        self._stream.write(packet[:captured_len])
        

    def close(self):
        if self._closed:
            return
        if self._stream:
            self._stream.close()
        self._closed = True

    def __enter__(self):
        self._stream_init()
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()
