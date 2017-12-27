"""
Packets module

This module provides the `PacketRegistry` packet decoder, along with all the
required packet classes.
"""

from struct import pack, unpack

class register_packet(object):
    """
    Decorator used to register packet classes with the corresponding operations
    and types.
    """
    def __init__(self, packet_op, packet_type):
        self.packet_op = packet_op
        self.packet_type = packet_type


    def __call__(self, clazz):
        """
        Register our class along with the corresponding packet operation and
        type.
        """
        PacketRegistry.register(
            self.packet_op,
            self.packet_type,
            clazz
        )
        return clazz

class PacketRegistry(object):
    """
    Packet registry.

    This class acts as a registry and provide a static method to decode raw
    packets into the corresponding classes.
    """

    registry = {}

    @staticmethod
    def register(packet_op, packet_type, packet_class):
        """
        Associate a packet class with its characteristics.
        """
        pkt_characs = packet_op | ((packet_type&0x0f) << 4)
        if pkt_characs not in PacketRegistry.registry:
            PacketRegistry.registry[pkt_characs] = packet_class

    @staticmethod
    def decode(packet):
        """
        Decode packet into corresponding class instance.
        """
        pkt_characs = packet.operation | ((packet.flags&0x0F) << 4)
        if pkt_characs in PacketRegistry.registry:
            return PacketRegistry.registry[pkt_characs].from_raw(packet)
        else:
            return packet


class Packet(object):
    """
    Serial packet representation.
    """

    OP_VERSION = 0x01
    OP_RESET = 0x02
    OP_SCAN_AA = 0x03
    OP_RECOVER_AA = 0x04
    OP_RECOVER_AA_CHM = 0x05
    OP_DEBUG = 0x0E
    OP_VERBOSE = 0x0F

    F_CMD = 0x01
    F_RESP = 0x02
    F_NOTIFICATION = 0x04

    N_ACCESS_ADDRESS = 0x00
    N_CRC = 0x01
    N_CHANNEL_MAP = 0x02
    N_HOP_INTERVAL = 0x03
    N_HOP_INCREMENT = 0x04
    N_PACKET = 0x05


    def __init__(self, operation, data, flags):
        """
        Constructor
        """
        self.operation = operation
        self.data = data
        self.flags = flags

    @staticmethod
    def crc(data, previous=0xff):
        """
        Compute 8-bit CRC
        """
        c = previous
        for i in list(data):
            c ^= i
        return c

    @staticmethod
    def fromBytes(data):
        """
        Extract packet from bytes.
        """
        # check magic
        if data[0] != 0xbc:
            return None

        # check crc
        _crc = Packet.crc(data[:-1])
        if _crc == data[-1]:
            # parse operation and flags
            op = data[1] & 0x0F
            flags = (data[1]>>4)&0x0F

            # get packet size
            pkt_size = unpack('<H', data[2:4])[0]

            # check size
            if pkt_size == len(data) - 5:
                return Packet(op, data[4:4+pkt_size], flags)
            else:
                return None
        else:
            return None

    def toBytes(self):
        """
        Serialize packet to bytes
        """
        # generate header
        length_l = len(self.data) & 0xFF
        length_h = (len(self.data)>>8) & 0xFF
        buffer = [
            0xBC,
            (self.operation & 0x0F) | ((self.flags&0x0F) << 4),
            length_l,
            length_h
        ]
        for i in self.data:
            buffer.append(i)
        _crc = Packet.crc(buffer)
        buffer.append(_crc)
        return bytes(buffer)

    def __str__(self):
        """
        String representation.
        """
        hex_payload = ' '.join(['%02x' % c for c in self.data])
        return "<Packet op=%02x flags=%02x data='%s'>" % (
            self.operation,
            self.flags,
            #self.data
            hex_payload
        )

    def __repr__(self):
        """
        Representation string
        """
        return str(self)

###################################
# Commands and responses
###################################


@register_packet(Packet.OP_DEBUG, Packet.F_RESP)
class DebugPacket(Packet):
    """
    Debug message packet
    """

    def __init__(self, message):
        """
        Constructor.
        """
        self.message = message
        super().__init__(Packet.OP_DEBUG, message, Packet.F_RESP)

    def __repr__(self):
        return '<pkt> DEBUG: %s' % self.message

    @staticmethod
    def from_raw(packet):
        """
        Decode a raw packet.
        """
        return DebugPacket(packet.data)


class ResetCommand(Packet):
    """
    Reset command.
    """
    def __init__(self):
        super().__init__(Packet.OP_RESET, bytes([]), Packet.F_CMD)

@register_packet(Packet.OP_RESET, Packet.F_RESP | Packet.F_CMD)
class ResetResponse(Packet):
    """
    Reset response packet.
    """
    def __init__(self):
        super().__init__(Packet.OP_RESET, bytes([]), Packet.F_RESP)


    def __str__(self):
        """
        String conversion.
        """
        return '<pkt> Reset response'

    def __repr__(self):
        return str(self)

    @staticmethod
    def from_raw(packet):
        return ResetResponse()


class VersionCommand(Packet):
    """
    Version command.
    """
    def __init__(self):
        super().__init__(Packet.OP_VERSION, bytes([]), Packet.F_CMD)

@register_packet(Packet.OP_VERSION, Packet.F_RESP)
class VersionResponse(Packet):
    """
    Version response.
    """
    def __init__(self, major=0, minor=0):
        self.major, self.minor = major, minor
        super().__init__(Packet.OP_VERSION, bytes([major, minor]), Packet.F_CMD | Packet.F_RESP)

    def __str__(self):
        return '<pkt> Version: %d %d' % (self.major, self.minor)

    def __repr__(self):
        return str(self)


    @staticmethod
    def from_raw(packet):
        """
        Parse major and minor versions.
        """
        return VersionResponse(packet.data[0],packet.data[1])


class ScanConnectionsCommand(Packet):
    """
    Version command.
    """
    def __init__(self):
        super().__init__(Packet.OP_SCAN_AA, bytes([]), Packet.F_CMD)

@register_packet(Packet.OP_SCAN_AA, Packet.F_CMD | Packet.F_RESP)
class ScanConnectionsResponse(Packet):
    """
    Scan connection response.
    """
    def __init__(self):
        super().__init__(Packet.OP_SCAN_AA, bytes([]), Packet.F_CMD)

    def __str__(self):
        return '<pkt> ScanConnectionsResponse'

    @staticmethod
    def from_raw(packet):
        """
        Convert raw packet into ScanConnectionsResponse.
        """
        return ScanConnectionsResponse()

@register_packet(Packet.N_ACCESS_ADDRESS, Packet.F_NOTIFICATION)
class AccessAddressNotification(Packet):
    """
    Access Address notification sent while discovering existing
    AA.
    """
    def __init__(self, channel=0, rssi=0, access_address=None):
        """
        Constructor.
        """
        self.channel = channel
        self.rssi = rssi
        self.access_address = access_address
        payload = pack('<BBI', self.channel, self.rssi, self.access_address)
        super().__init__(
            Packet.N_ACCESS_ADDRESS,
            bytes(payload),
            Packet.F_NOTIFICATION
        )

    def __str__(self):
        return "<AccessAddressNotification channel='%d' rssi='%s' address='%02x:%02x:%02x:%02x'>" % (
            self.channel,
            str(-self.rssi),
            (self.access_address & 0xff000000) >> 24,
            (self.access_address & 0xff0000) >> 16,
            (self.access_address & 0xff00) >> 8,
            self.access_address & 0xff,

        )

    @staticmethod
    def from_raw(packet):
        """
        Convert raw packet to AccessAddressNotification.
        """
        channel = packet.data[0]
        rssi = packet.data[1]
        access_address = unpack('<I', packet.data[2:6])[0]
        return AccessAddressNotification(channel, rssi, access_address)


class RecoverConnectionCommand(Packet):
    """
    Recover connection parameters command.
    """
    def __init__(self, access_address, chm=None):
        if chm is None:
            payload = pack('<I', access_address)
            super().__init__(Packet.OP_RECOVER_AA, payload, Packet.F_CMD)
        else:
            chm = bytes([
                chm&0xff,
                (chm&0xff00) >> 8,
                (chm&0xff0000) >> 16,
                (chm&0xff000000) >> 24,
                (chm&0xff00000000) >> 32,
            ])
            payload = pack('<I', access_address) + chm
            super().__init__(Packet.OP_RECOVER_AA_CHM, payload, Packet.F_CMD)

@register_packet(Packet.OP_RECOVER_AA, Packet.F_CMD | Packet.F_RESP)
@register_packet(Packet.OP_RECOVER_AA_CHM, Packet.F_CMD | Packet.F_RESP)
class RecoverConnectionResponse(Packet):
    """
    Recover connection response.
    """
    def __init__(self, operation, access_address=0):
        if operation == Packet.OP_RECOVER_AA:
            super().__init__(Packet.OP_RECOVER_AA, pack('<I', access_address), Packet.F_CMD | Packet.F_RESP)
        elif operation == Packet.OP_RECOVER_AA_CHM:
            super().__init__(Packet.OP_RECOVER_AA_CHM, pack('<I', access_address), Packet.F_CMD | Packet.F_RESP)
        else:
            pass

    @staticmethod
    def from_raw(packet):
        return RecoverConnectionResponse(packet.operation)


@register_packet(Packet.N_CRC, Packet.F_NOTIFICATION)
class CrcNotification(Packet):
    """
    Crc notification
    """
    def __init__(self, access_address, crc):
        """
        Constructor
        """
        self.access_address = access_address
        self.crc = crc
        payload = pack('<II', access_address, crc)
        super().__init__(Packet.N_CRC, payload, Packet.F_NOTIFICATION)

    @staticmethod
    def from_raw(packet):
        access_address, crc = unpack('<II', packet.data[:8])
        return CrcNotification(access_address, crc)

@register_packet(Packet.N_CHANNEL_MAP, Packet.F_NOTIFICATION)
class ChannelMapNotification(Packet):
    """
    Channel map notification.
    """
    def __init__(self, access_address, channel_map):
        """
        Constructor
        """
        self.access_address = access_address
        self.channel_map = channel_map
        #print(hex(self.channel_map))
        payload = pack('<IIB', self.access_address, self.channel_map&0xffffffff, (self.channel_map & 0xff00000000)>>32)
        super().__init__(Packet.N_CHANNEL_MAP, payload, Packet.F_NOTIFICATION)

    @staticmethod
    def from_raw(packet):
        access_address, chm_l, chm_h = unpack('<IIB', packet.data[:9])
        return ChannelMapNotification(access_address, chm_l | (chm_h << 32))


@register_packet(Packet.N_HOP_INTERVAL, Packet.F_NOTIFICATION)
class HopIntervalNotification(Packet):
    """
    Hop interval notification.
    """
    def __init__(self, access_address, interval):
        self.access_address = access_address
        self.interval = interval
        payload = pack('<IH', access_address, interval)
        super().__init__(Packet.N_HOP_INTERVAL, payload, Packet.F_NOTIFICATION)

    @staticmethod
    def from_raw(packet):
        access_address, interval = unpack('<IH', packet.data[:6])
        return HopIntervalNotification(access_address, interval)

@register_packet(Packet.N_HOP_INCREMENT, Packet.F_NOTIFICATION)
class HopIncrementNotification(Packet):
    def __init__(self, access_address, increment):
        self.access_address = access_address
        self.increment = increment
        payload = pack('<IB', access_address, increment)
        super().__init__(Packet.N_HOP_INCREMENT, payload, Packet.F_NOTIFICATION)

    @staticmethod
    def from_raw(packet):
        access_address, increment = unpack('<IB', packet.data[:6])
        return HopIncrementNotification(access_address, increment)

@register_packet(Packet.N_PACKET, Packet.F_NOTIFICATION)
class BlePacketNotification(Packet):
    def __init__(self, data):
        self.data = data
        return super().__init__(Packet.N_PACKET, self.data, Packet.F_NOTIFICATION)

    @staticmethod
    def from_raw(packet):
        return BlePacketNotification(packet.data)
