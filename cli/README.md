micro:bit BTLE sniffer CLI
==========================

Use Python3 to execute the ubit-sniffer.py application:

```
$ python3 ubit-sniffer.py -h
```

Use the `-s` option to search for active BTLE connections (you have to specify
  the serial port corresponding to your Micro:Bit plugged into your computer,
  here */dev/ttyACM0*):

```
$ python3 ubit-sniffer.py -d /dev/ttyACM0 -s
```

It will list a bunch of access addresses along with signal strength and the number of packets captured for each address.
You can then try to recover a connection BTLE parameters (CRCInit value, channel map, hop interval and hop increment) with this command:

```
$ python3 ubit-sniffer.py -d /dev/ttyACM0 -f 0x1337b33f
```

The tool will try to recover all the required values and then start to follow the specified connection. It may not be able to
recover the hop interval or hop increment if the channel map is not correctly recovered. This may happen if a master device
regularly updates the channel map used for this connection, and is a known limitation of this proof of concept.

If you are lucky enough to follow an existing connection, you may want to save your packets to a PCAP file with the `-o` option:

```
$python3 ubit-sniffer.py -d /dev/ttyACM0 -f 0x1337b33f -o btle-capture.pcap
```
