from scapy.all import *
import sys
from os import urandom
from random import randint
from randFloats import *

def amplificationBuilder(ip_src,ip_dst, src_port, q_name, t):
    """
    Amplification attack packet builder
    Param: ip_src -> Source ip (target)
           ip_dst -> Destination ip
           src_port -> Source port
           q_name -> Domain name
           t: Arrival time
           return: A packet with EDNS0 extension
    """
    id_IP = int(RandShort())
    id_DNS = int(RandShort())
    p = Ether()/IP(dst=ip_dst, src=ip_src, id = id_IP)/UDP(sport=src_port)/DNS(rd=0, id= id_DNS, qd=DNSQR(qname=str(q_name), qtype = "ALL"),ar=DNSRROPT(rclass=4096))
    p.time = t
    return p

def answerAmplification(p, t):
    """
    Gives an amplified response to the packet p
    Param: p -> request
           t -> Response delay time
           return: A response that has the EDNS0 extension and the answer section is set up
           - Type: TXT -> Contains a large string
    """
    id_IP = int(RandShort())
    #Create the answer with EDNS0 extension
    ans = Ether()/IP(dst = p[IP].src, src = p[IP].dst, id = id_IP)/UDP(dport = p[UDP].sport)/DNS(id = p[DNS].id, qr = 1, rd = 0, cd = 1, qd = p[DNS].qd, ar = DNSRROPT(rclass=4096))

    #Create and set the answer
    n = randint(3800, 3900) #r_data string number of bytes
    r_data = urandom(n)
    ans[DNS].an = DNSRR(type='TXT', rclass=0x8001, rdata = r_data)

    #Set the response time
    ans.time = p.time + t
    return ans

def main():
    """
    sys.argv[1]: pcap file
    sys.argv[2]: Target ip
    sys.argv[3]: Attack extension (seconds)
    sys.argv[4]: Amount of packages per second
    sys.argv[5]: Start date TODO: ver en que se medirá (Con respecto al paquete)
    sys.argv[6]: Delay time of each response
    """

    ip = str(sys.argv[2])
    duracion = int(sys.argv[3])
    c = int(sys.argv[4])
    inicio = float(sys.argv[5])
    dt = float(sys.argv[6])

    p0 = sniff(offline = str(sys.argv[1]), count = 1)
    t0 = p0[0].time
    ti = t0 + inicio
    tf = ti + duracion
    serv = '200.7.4.7'
    srcport = 33865 #Any port
    qname = 'hola.chao.cl'

    new_packages = []
    seed = 20 #Seed for randomize
    time = genInter(seed, ti, tf, c)
    for t in time:
        p = amplificationBuilder(ip, serv, srcport, qname, t)
        a = answerAmplification(p, dt)
        new_packages.append(p)
        new_packages.append(a)

    wrpcap("file.pcap", new_packages)
if __name__ == '__main__':
    main()
