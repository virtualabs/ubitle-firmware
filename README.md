Micro:Bit BTLE Sniffer PoC
==========================

This project is composed of a firmware to install in a micro:bit and a Python3 command-line
application. Follow the firmware's README to compile and the cli's README to use the application.

Basically, you should be able:

- to detect active BTLE connections with the -s option
- to follow an existing connection (i.e. recover the corresponding BTLE parameters) with the -f option
- to dump packets to a PCAP file with the -o option

It's a proof of concept and therefore does not support yet some BTLE features such as channel mapping
updates and hop interval updates.
