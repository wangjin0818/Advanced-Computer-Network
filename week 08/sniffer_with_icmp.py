import socket

import os
import struct
from ctypes import *

#host to listen on 
host = "192.168.146.130"

# our IP header
class IP(Structure):
    _fields_ = [
        ("ihl",     c_ubyte, 4),
        ("version", c_ubyte, 4),
        ("tos",     c_ubyte, 8),
        ("len",     c_ushort, 16),
        ("id",      c_ushort, 16),
        ("offset",  c_ushort, 16),
        ("ttl",     c_ubyte, 8),
        ("protocol_num", c_ubyte, 8),
        ("sum",     c_ushort, 8),
        ("src",     c_uint32, 32),
        ("dst",     c_uint32, 32)
    ]

    def __new__(self, socket_buffer=None):
        return self.from_buffer_copy(socket_buffer)

    def __init__(self, socket_buffer=None):
        # map protocol constants to their names
        self.protocol_map = {1:"ICMP", 6:"TCP", 17:"UDP"}

        # human readable IP addresses
        self.src_address = socket.inet_ntoa(struct.pack("<L", self.src))
        self.dst_address = socket.inet_ntoa(struct.pack("<L", self.dst))

        # human readable protocol
        try:
            self.protocol = self.protocol_map[self.protocol_num]
        except:
            self.protocol = str(self.protocol_num)

class ICMP(Structure):
    _fields_ = [
        ("type", c_ubyte),
        ("code", c_ubyte),
        ("checksum", c_ushort),
        ("unused", c_ushort),
        ("next_hop_mtu", c_ushort)
    ]

    def __new__(self, socket_buffer):
        return self.from_buffer_copy(socket_buffer)

    def __init__(self, socket_buffer):
        pass

# this should look familiar from the previous example
if os.name == "nt":
    socket_protocol = socket.IPPROTO_IP
else:
    socket_protocol = socket.IPPROTO_ICMP

sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket_protocol)

sniffer.bind((host, 0))
sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

if os.name == "nt":
    sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

try:
    while True:
        # read in a packet
        raw_buffer = sniffer.recvfrom(65565)[0]

        print raw_buffer
        # create an IP header from the first 20 bytes of the buffer
        ip_header = IP(raw_buffer)

        # print out the protocol that was detected and the hosts
        print "Protocol: %s %s -> %s" % (ip_header.protocol, ip_header.src_address, ip_header.dst_address)

        # if it's ICMP, we want it
        if ip_header.protocol == "ICMP":

            # calculate where our ICMP packet starts
            offset = ip_header.ihl * 4

            buf = raw_buffer[offset:offset + sizeof(ICMP)]

            # create our ICMP structure
            icmp_header = ICMP(buf)

            print "ICMP -> Type: %d Code: %d" % (icmp_header.type, icmp_header.code)
            

except KeyboardInterrupt:

    # if we're using Windows, turn off promiscuous mode
    if os.name == "nt":
        sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)