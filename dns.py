import struct
import socket
import argparse
import socket
import random

class DNSHeader:
    DNS_QUERY = 0
    DNS_RESPONSE = 1
    
    OP_QUERY = 0
    OP_INVQUERY = 1
    OP_STATUS = 2
    
    R_OK = 0
    R_FMTERR = 1
    R_SERVER_FAILURE = 2
    R_NAME_ERROR = 3
    R_NOT_IMPLEMENTED = 4
    R_REFUSED = 5

    TYPE_A = 1
    TYPE_NS = 2
    TYPE_MX = 15
    TYPE_AAAA = 28

    QCLASS_IN = 1
    
    def __init__(self):
        self.ID = 0
        self.QR = DNSHeader.DNS_QUERY
        self.OpCode = DNSHeader.OP_QUERY
        self.AA = 0
        self.TC = 0
        self.RD = 0
        self.RA = 0
        self.RCode = 0
        self.QDCount = 0
        self.ANCount = 0
        self.NSCount = 0
        self.ARCount = 0

    def parse(self, buffer):
        self.ID, b1, b2, self.QDCount, self.ANCount, self.NSCount, self.ARCount = struct.unpack("!HBBHHHH", buffer)
        self.QR     = (b1 & 0b10000000) >> 7
        self.OpCode = (b1 & 0b01111000) >> 3
        self.AA     = (b1 & 0b00000100) >> 2
        self.TC     = (b1 & 0b00000010) >> 1
        self.RD     = b1 & 0b1
        self.RA     = (b2 & 0b10000000) >> 7
        self.RCode  = (b2 & 0b1111)
        

    def unparse(self):
        b1 = self.QR << 7 | self.OpCode << 3 | self.AA << 2 | self.TC << 1 | self.RD
        b2 = self.RA << 7 | self.RCode
        return struct.pack('!HBBHHHH', self.ID, b1, b2, self.QDCount, self.ANCount, self.NSCount, self.ARCount)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", type=str, required=True, help="Host whose IP you want to resolve")
    parser.add_argument("--dns_server", type=str, default="8.8.8.8", help="Path to DNS server")
    parser.add_argument("--save_path", type=str, default="out.html", help="Path to which to save index page at this host")
    parser.add_argument('--recursive', default=True, action=argparse.BooleanOptionalAction, help="If True, do a recursive query, which will return the IP address right away. If False, do an iterative query")
    opt = parser.parse_args()
    host = opt.host
    dns_server = opt.dns_server
    dns_port = 53
    save_path = opt.save_path
    recursive = opt.recursive

    ## TODO: Fill this in