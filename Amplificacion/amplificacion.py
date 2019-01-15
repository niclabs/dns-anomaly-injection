from scapy.all import *
import sys
sys.path.append("..")
import os
import random
from randFloats import *
import time as Time
import string
from PacketInserter import *


def checkArgs(args):
    """
    Check if the arguments are correct
    Param: args: list of arguments
           +args[1]: Name of the source pcap file with extension
           +args[2]: Name of the new pcap file with extension
           +args[3]: Relative path to the input file, it finishes with '/'
           +args[4]: Relative path to the output file
           args[5]: Server ip
           agrs[6]: Target ip
           +args[7]: Source port
           +args[8]: Attack extension (seconds)
           +args[9]: Amount of packets per second
           +args[10]: Start date
           args[11]: Domain asked
    """
    try:
        assert(os.path.exists(str(args[3]) + str(args[1])))
    except:
        raise Exception("Invalid source path")
    try:
        assert(os.path.exists(str(args[4])))
    except:
        raise Exception("Invalid output file path")
    try:
        f = args[2].split(".")
        assert(len(f) == 2)
        assert(f[1] == "pcap")
    except:
        raise Exception("Wrong output file extension")
    try:
        assert(int(args[7]) >= 0)
        assert(int(args[7]) <= 65535)
    except:
        raise Exception("Source port must be between 0 and 65535")
    try:
        assert(float(args[8]) > 0)
    except:
        raise Exception("Extension of the attack must be greater than 0")
    try:
        assert(int(args[9]) > 0)
    except:
        raise Exception("Amount of packets per second must be greater than 0")
    try:
        assert(float(args[10])>= 0)
    except:
        raise Exception("Start date must be greater than or equal to 0")



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
    n = random.randint(3800, 3900) #r_data string number of bytes
    r_data = os.urandom(n)
    ans[DNS].an = DNSRR(type='TXT', rclass=0x8001, rdata = r_data)

    #Set the response time
    ans.time = p.time + t
    return ans

def amplificationAttack(serv: string, ip:string, srcport: int, duracion: int, c: int, ti: float, qname : string):
    """
    Param: serv: Server ip
           ip: Target ip
           srcport: Source port
           duracion: Attack extension (seconds)
           c: Amount of packets per second
           ti: Start date TODO: ver en que se medirá (Con respecto al paquete)
           qname: Domain asked
    return: Array of tuples (request, response) of the attack
    """

    tf = ti + duracion
    new_packets = []
    seed = Time.time() #Seed for randomize
    time = genInter(seed, ti, tf, c)
    for t in time:
        dt = abs(random.gauss(0.00427404912058, 0.00807278328296))
        p = amplificationBuilder(ip, serv, srcport, qname, t)
        a = answerAmplification(p, dt)
        tuple = []
        tuple.append(p)
        tuple.append(a)
        new_packets.append(tuple)
    return new_packets

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
           args[9]: Amount of packets per second
           args[10]: Start date
           args[11]: Domain asked
    """
    p0 = sniff(offline = args[3] + args[1], count = 1)
    t0 = p0[0].time

    new_packets = amplificationAttack(args[5], args[6], int(args[7]), int(args[8]), int(args[9]), float(args[10]) + t0, args[11])
    inserter = PacketInserter()\
               .withPackets(new_packets)\
               .withPcapInput(args[1])\
               .withPcapOutput(args[2])\
               .withInputDir(args[3])\
               .withOutputDir(args[4])\
               .insert()

if __name__ == '__main__':
    if(len(sys.argv) == 12):
        checkArgs(sys.argv)
        main(sys.argv)
    else:
        print("Invalid arguments")
        print("input_file output_file input_path output_path server_ip target_ip source_port attack_extension packets start_date domain")
