import sys
from argparse import ArgumentParser
from link import Link
from packets import *
from pcap import PcapBleWriter
from time import time


parser = ArgumentParser('uBit LE sniffer')
parser.add_argument(
    '-d',
    '--device',
    dest='device',
    type=str,
    default='/dev/ttyACM0',
    help='Micro:Bit device serial port'
)

parser.add_argument(
    '-s',
    '--scan-connections',
    dest='scan_aa',
    action='store_true',
    default=False,
    help='Scan available BLE connections'
)

parser.add_argument(
    '-f',
    '--follow',
    dest='follow',
    type=str,
    help='Follow an existing connection'
)

parser.add_argument(
    '-m',
    '--channel-map',
    dest='chm',
    type=str,
    default=None,
    help='Set channel map'
)

parser.add_argument(
    '-i',
    '--hop-interval',
    dest='hop',
    type=int,
    default=None,
    help='Set hop interval'
)

parser.add_argument(
    '-v',
    '--verbose',
    dest='verbose',
    action='store_true',
    default=False,
    help='Enable verbose mode'
)

parser.add_argument(
    '-o',
    '--output',
    dest='output',
    default=None,
    help='PCAP output file'
)

args = parser.parse_args()

try:
    output = PcapBleWriter(args.output)
    l = Link(args.device, 115200)
    l.reset()
    major,minor = l.get_version()
    print('uBitle v1.0 [firmware version %d.%d]' % (major, minor))
    print('')

    if args.scan_aa:
        aad = {}
        print('[i] Listing available access addresses ...')
        for aa in l.scan_access_addresses():
            if aa.access_address not in aad:
                aad[aa.access_address] = 1
            else:
                aad[aa.access_address] += 1

            print(
                '[ -%3d dBm] 0x%08x | pkts: %d' % (
                    aa.rssi,
                    aa.access_address,
                    aad[aa.access_address]
                )
            )
    elif args.follow is not None:
        # convert target into integer
        aa = int(args.follow, 16)
        if args.chm is not None:
            chm = int(args.chm, 16)
        else:
            chm = None
        print('[i] Following connection 0x%08x ...' % aa)
        for pkt in l.recover_connection(aa, chm):
            if isinstance(pkt, CrcNotification):
                print('[i] Recovered initial CRC value: 0x%06x' % pkt.crc)
                if args.chm is not None:
                    print('[i] Forced channel map: 0x%010x' % chm)
                    print('[i] Recovering hop interval ...')
                elif (args.hop is not None) and (args.chm is not None):
                    print('[i] Forced channel map: 0x%010x' % chm)
                    print('[i] Forced hop interval: %d' % args.hop)
                    print('[i] Recovering hop increment ...')
                else:
                    print('[i] Recovering channel map (may take some time) ...')
            elif isinstance(pkt, ChannelMapNotification):
                print('[i] Recovered channel map: 0x%010x' % pkt.channel_map)
                print('[i] Recovering hop interval ...')
            elif isinstance(pkt, HopIntervalNotification):
                print(pkt.toBytes())
                print('[i] Recovered hop interval: %d' % pkt.interval)
                print('[i] Recovering hop increment ...')
            elif isinstance(pkt, HopIncrementNotification):
                if pkt.increment != 0:
                    print('[i] Recovered hop increment: %d' % pkt.increment)
                    print('[i] All parameters successfully recovered, following BLE connection ...')
                else:
                    if args.chm is not None or args.hop is not None:
                        print('/!\\ Bad increment value, check channel map and/or hop interval.')
                    else:
                        print('/!\\ Something went wrong, please try again.')
            elif isinstance(pkt, BlePacketNotification):
                timestamp = time()
                ts_sec = int(timestamp)
                ts_usec = int((timestamp - ts_sec)*1000000)
                output.write_packet(ts_sec, ts_usec, aa, pkt.data)
                pkt_hex = ' '.join(['%02x' % c for c in pkt.data])
                print('LL Data: ' + pkt_hex)
            elif args.verbose:
                print(pkt)
except KeyboardInterrupt as exc:
    print('[i] Stopping capture process ...')
    output.close()
except IOError as io_exc:
    print(io_exc)
    if '/dev/' in io_exc.strerror and io_exc.errno == 2:
        print('[!] Device %s not found' % args.device)
    else:
        print('[!] Capture file cannot be created')
except PermissionError as perm_exc:
    print('[!] You do not have sufficient privileges to perform this operation.')
except Exception as unexpected_exc:
    print('[!] An unexpected error occured:')
    print(unexpected_exc)
