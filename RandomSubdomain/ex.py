from scapy.all import *
import string
from os import urandom
from randomSubdomain import *

def main():
    dom = 'hola.chao.cl'
    ip_dst = '2.7.4.7'
    src_port = 33865
    t = 0
    packet =[]

    id_IP = int(RandShort())
    id_DNS = int(RandShort())
    r = randomSubBuilder(dom, ip_dst, src_port, t)
    a = answerRandSub(r, 0)
    a.show2()
    packet.append(r)
    packet.append(a)
    wrpcap("file.pcap", packet)

if __name__ == '__main__':
    main()
