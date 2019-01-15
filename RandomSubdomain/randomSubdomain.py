from scapy.all import *
import random
import string
import sys
import os
sys.path.append("..")
import time as Time
from randFloats import *
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
           args[6]: Target domain
           +args[7]: Attack extension (seconds)
           +args[8]:  Amount of packets per second
           +args[9]: Start date
           +args[10]: Source port
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
        raise Exception("Invalid output file extension")
    try:
        assert(int(args[7]) > 0)
    except:
        raise Exception("Attack extension must be greater than 0")
    try:
        assert(int(args[8]) > 0)
    except:
        raise Exception("Amoount of packets per second must be greater than 0")
    try:
        assert(float(args[9]) >= 0)
    except:
        raise Exception("Start date must be greater than or equal to 0")
    try:
        assert(int(args[10]) >= 0)
        assert(int(args[10]) <= 65535)
    except:
        raise Exception("Source port must be between 0 and 65535")

def randomSub():
    """
    Creates a random string that contains numbers and letters. The size is a random number between 10 and 30
    return: A random subdomain
    """
    crc = str(string.ascii_letters + string.digits)
    n = random.randint(10,30)
    return "".join(random.sample(crc, n))

def genIp():
    """
    Gives a random ip
    """
    ip = ".".join(str(random.randint(0, 255)) for _ in range(4))
    return ip

def randomSubBuilder(dom, ip_dst, src_port, t):
    """
    Random Subdomain attack packet builder
    Param: dom: Domain that you want to attack
           ip_dest: Destination ip
           src_port: Source port
           t: Arrival time
    return: A packet that has a random string as a subdomain
    """
    id_IP = int(RandShort())
    id_DNS = int(RandShort())
    sub = randomSub()
    q_name = sub + '.' + dom
    ans = Ether()/IP(dst = ip_dst, id = id_IP)/UDP(sport = src_port)/DNS(rd = 0, id= id_DNS, qd=DNSQR(qname=str(q_name)))
    ans.time = t
    return ans

def answerRandSub(p, dom, ip_dom, ip_srv,  t):
    """
    Gives a regular response to packet "p"
    Param: p: request
           dom: Domain asked
           ip_dom: ip of the domain that was asked
           ip_srv: Domain asked server ip
           t: Response delay time
    return : A response packet that has the EDNS0 extension and an additional record with the answer
    """
    id_IP = int(RandShort())
    ar_ans = DNSRR(rrname = dom, rdata = ip_dom)
    ar_ext = DNSRROPT(rclass=4096)
    an_ans = DNSRR(rrname = dom, rdata = ip_srv)
    ns_ans = DNSRR(rrname = dom, type = 2, rdata = dom)
    ans = Ether()/IP(dst = p[IP].src, src = p[IP].dst, id = id_IP)/UDP(dport = p[UDP].sport, sport = p[UDP].dport)/DNS(id = p[DNS].id, qr = 1, rd = 0, cd = 1, qd = p[DNS].qd, ns = ns_ans, an = an_ans,ar= ar_ans/ar_ext)
    ans.time = p.time + t
    return ans

def randomSubAttack(serv: string, dom : string, dom_ip: string, snd_ip: string, duracion: int, c: int, ti: float, srcport : int):
    """
    Gives an array of tuples that contains request and response
    Param: serv: Server ip
           dom: Target domain
           dom_ip: Domain ip
           snd_ip: Domain server ip
           duracion: Attack extension (seconds)
           c: Amount of packets per second
           ti: Start date TODO: ver en que se medirá (Con respecto al paquete)
           srcport: Source port
    return: Array of tuples (request, response) of the attack
    """
    tf = ti + duracion
    new_packets = []
    seed = Time.time() #Seed for randomize
    time = genInter(seed, ti, tf, c)
    for t in time:
        dt = abs(random.gauss(0.00427404912058, 0.00807278328296))
        p = randomSubBuilder(dom, serv, srcport, t)
        a = answerRandSub(p, dom, dom_ip, snd_ip, dt)
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
           args[6]: Target domain
           args[7]: Attack extension (seconds)
           args[8]:  Amount of packets per second
           args[9]: Start date
           args[10]: Source port
    """
    p0 = sniff(offline = args[3] + args[1], count = 1)
    t0 = p0[0].time

    new_packets = randomSubAttack(args[5], args[6] + ".", genIp(), genIp(), int(args[7]), int(args[8]), float(args[9]) + t0, int(args[10]))
    inserter =PacketInserter()\
              .withPackets(new_packets)\
              .withPcapInput(args[1])\
              .withPcapOutput(args[2])\
              .withInputDir(args[3])\
              .withOutputDir(args[4])\
              .insert()

if __name__ == '__main__':
    if(len(sys.argv) == 11):
        checkArgs(sys.argv)
        main(sys.argv)
    else:
        print("Invalid arguments")
        print("input_file output_file input_path output_path server_ip target_domain domain_ip attack_extension packets start_date source_port")
