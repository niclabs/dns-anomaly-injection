from scapy.all import *
import sys
from os import urandom
from random import randint
from randFloats import *
import time as Time
import string
from PacketInserter import *

def amplificationBuilder(ip_src,ip_dst, src_port, q_name, t):
    """
    Amplification attack packet builder
    Param: ip_src: Source ip (target)
           ip_dst: Destination ip
           src_port: Source port
           q_name: Domain name
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
    Param: p: request
           t: Response delay time
    return: A response packet that has the EDNS0 extension and the answer section is set up
           - Type: TXT: Contains a large string
    """
    id_IP = int(RandShort())
    #Create the answer with EDNS0 extension
    ans = Ether()/IP(dst = p[IP].src, src = p[IP].dst, id = id_IP)/UDP(dport = p[UDP].sport, sport = p[UDP].dport)/DNS(id = p[DNS].id, qr = 1, rd = 0, cd = 1, qd = p[DNS].qd, ar = DNSRROPT(rclass=4096))

    #Create and set the answer
    n = randint(3800, 3900) #r_data string number of bytes
    r_data = urandom(n)
    ans[DNS].an = DNSRR(type='TXT', rclass=0x8001, rdata = r_data)

    #Set the response time
    ans.time = p.time + t
    return ans

def amplificationAttack(serv: string, ip:string, srcport: int, duracion: int, c: int, ti: float, dt: float, qname : string):
    """
    Param: serv: Server ip
           ip: Target ip
           srcport: Source port
           duracion: Attack extension (seconds)
           c: Amount of packages per second
           ti: Start date TODO: ver en que se medirá (Con respecto al paquete)
           dt: Delay time of each response
           qname: Domain asked
    return: Array of tuples (request, response) of the attack
    tiempo promedio 0.006673997294210002
    """

    tf = ti + duracion
    new_packages = []
    seed = Time.time() #Seed for randomize
    time = genInter(seed, ti, tf, c)
    for t in time:
        p = amplificationBuilder(ip, serv, srcport, qname, t)
        a = answerAmplification(p, dt)
        tuple = []
        tuple.append(p)
        tuple.append(a)
        new_packages.append(tuple)
    return new_packages

def main(args):
    """
    Param: args: list of arguments
           args[1]: Name of the source pcap file with extension
           args[2]: Name of the new pcap file with extension
           args[3]: Relative path to the input file, it finishes with '/'
           args[4]: Relative path to the output file
           args[5]: Server ip
           agrs[6]: Target ip
           args[7]: Source port
           args[8]: Attack extension (seconds)
           args[9]: Amount of packages per second
           args[10]: Start date
           args[11]: Delay time of each response
           args[12]: Domain asked
    """
    p0 = sniff(offline = args[3] + args[1], count = 1)
    t0 = p0[0].time

    new_packages = amplificationAttack(args[5], args[6], int(args[7]), int(args[8]), int(args[9]), float(args[10]) + t0, float(args[11]), args[12])
    inserter = PacketInserter()\
               .withPackets(new_packages)\
               .withPcapInput(args[1])\
               .withPcapOutput(args[2])\
               .withInputDir(args[3])\
               .withOutputDir(args[4])\
               .insert()

if __name__ == '__main__':
    if(len(sys.argv) == 13):
        main(sys.argv)
    else:
        print("Argumentos no válidos")
