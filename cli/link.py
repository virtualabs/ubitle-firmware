"""
Link module.
"""

from serial import Serial
from struct import pack, unpack
from packets import Packet, PacketRegistry, ResetCommand, VersionCommand, \
    ScanConnectionsCommand, RecoverConnectionCommand, ResetResponse, VersionResponse, ScanConnectionsResponse, AccessAddressNotification, RecoverConnectionResponse

class Link(object):
    """
    Serial link with the BBC Micro:Bit
    """

    def __init__(self, interface, baudrate=115200):
        self.interface = Serial(interface, baudrate)

    def write(self, packet):
        """
        Send a packet
        """
        raw_pkt = packet.toBytes()
        return self.interface.write(raw_pkt)

    def read(self):
        """
        Read packet from serial.
        """
        pkt_buffer = bytes()

        # first, wait for our magic
        magic = self.interface.read(1)
        while magic != b'\xbc':
            #print('...')
            magic = self.interface.read(1)
        pkt_buffer += bytes(magic)

        # get operation and flags
        opflags = self.interface.read(1)
        pkt_buffer += bytes(opflags)

        # get packet size
        pkt_size = self.interface.read(2)
        pkt_buffer += pkt_size
        _pkt_size = unpack('<H', pkt_size)[0]

        # read packet size (data)
        data = self.interface.read(_pkt_size)
        pkt_buffer = pkt_buffer + data

        # read checksum
        checksum = self.interface.read(1)
        pkt_buffer += bytes(checksum)

        # Create packet from data
        packet = Packet.fromBytes(pkt_buffer)
        return packet

    def wait_packet(self, clazz):
        """
        Wait for a specific packet type.
        """
        while True:
            pkt = PacketRegistry.decode(self.read())
            if isinstance(pkt, clazz):
                return pkt

    def reset(self):
        """
        Reset sniffer.
        """
        pkt = ResetCommand()
        self.write(pkt)
        self.wait_packet(ResetResponse)

    def get_version(self):
        """
        Get sniffer version.
        """
        self.write(VersionCommand())
        pkt = self.wait_packet(VersionResponse)
        return (pkt.major, pkt.minor)


    def scan_access_addresses(self):
        self.write(ScanConnectionsCommand())
        self.wait_packet(ScanConnectionsResponse)
        # loop on access address notifications
        while True:
            pkt = PacketRegistry.decode(self.read())
            if isinstance(pkt, AccessAddressNotification):
                yield pkt
                """
                print('[-%03d dBM] %08x (channel: %d)' %
                    (
                        pkt.rssi,
                        pkt.access_address,
                        pkt.channel
                    )
                )
                """

    def recover_connection(self, access_address, channel_map=None):
        """
        Recover an existing connection.
        """
        self.write(RecoverConnectionCommand(access_address, channel_map))
        self.wait_packet(RecoverConnectionResponse)
        while True:
            # get packet
            pkt = PacketRegistry.decode(self.read())
            yield pkt
