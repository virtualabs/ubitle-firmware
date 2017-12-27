"""
Quick'n'dirty Pcap module

This module only provides a specific class able to write
PCAP files with Bluetooth Low Energy Link Layer.
"""
from io import BytesIO
from struct import pack

class PcapBleWriter(object):
    """
    PCAP BLE Link-layer writer.
    """

    DLT_BLUETOOTH_LE_LL = 251

    def __init__(self, output=None):
        # open stream
        if output is None:
            self.output = BytesIO()
        else:
            self.output = open(output,'wb')

        # write headers
        self.write_header()

    def write_header(self):
        """
        Write PCAP header.
        """
        header = pack(
            '<IHHIIII',
            0xa1b2c3d4,
            2,
            4,
            0,
            0,
            65535,
            self.DLT_BLUETOOTH_LE_LL
        )
        self.output.write(header)

    def write_packet(self, ts_sec, ts_usec, aa, packet):
        """
        Add packet to PCAP output.
        """
        pkt_header = pack(
            '<IIII',
            ts_sec,
            ts_usec,
            len(packet) + 7,
            len(packet) + 7
        )
        self.output.write(pkt_header)
        self.output.write(pack('<I', aa))
        self.output.write(packet)
        self.output.write(pack('<BBB', 0, 0, 0)) # fake CRC

    def close(self):
        """
        Close PCAP.
        """
        if not isinstance(self.output, BytesIO):
            self.output.close()
