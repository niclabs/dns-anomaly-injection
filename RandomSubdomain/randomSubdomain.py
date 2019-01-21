from scapy.all import *
import random
import string
import sys
import os
sys.path.append("..")
import time as Time
from randFloats import *
from PacketInserter import *

def checkValidIp(ip : string):
    """
    Check if an ip is valid
    Param: ip: String
    return: Boolean
    """
    values = ip.split(".")
    if(len(values) != 4):
        return False
    else:
        for v in values:
            if(int(v) < 0 or int(v) > 255):
                return False
    return True

def checkArgs(src_file, dst_file, src_path, dst_path, src_ip, srv_ip, dom, ext, packets, ti, src_port):
    """
    Check if the arguments are correct
    Param: +src_file: Name of the source pcap file with extension
           +dst_file: Name of the new pcap file with extension
           +src_path: Relative path to the input file, it finishes with '/'
           +dst_path: Relative path to the output file, it finishes with '/'
           +src_ip: Source ip
           +srv_ip: Server ip
           dom: Target domain
           +ext: Attack extension (seconds)
           +packets:  Amount of packets per second
           +ti: Start date
           +src_port: Source port
    """
    try:
        assert(src_path[len(src_path) - 1] == "/")
    except:
        raise Exception("Relative path to the input file, it finishes with '/'")
    try:
        assert(os.path.exists(str(src_path) + str(src_file)))
    except:
        raise Exception("Invalid source path")
    try:
        assert(dst_path[len(dst_path) - 1] == "/")
    except:
        raise Exception("Relative path to the output file, it finishes with '/'")
    try:
        assert(os.path.exists(str(dst_path)))
    except:
        raise Exception("Invalid output file path")
    try:
        f = dst_file.split(".")
        assert(len(f) == 2)
        assert(f[1] == "pcap")
    except:
        raise Exception("Invalid output file extension")
    try:
        assert(checkValidIp(src_ip))
    except:
        raise Exception("Invalid source ip")
    try:
        assert(checkValidIp(srv_ip))
    except:
        raise Exception("Invalid server ip")
    try:
        assert(int(ext) > 0)
    except:
        raise Exception("Attack extension must be greater than 0")
    try:
        assert(int(packets) > 0)
    except:
        raise Exception("Amoount of packets per second must be greater than 0")
    try:
        assert(float(ti) >= 0)
    except:
        raise Exception("Start date must be greater than or equal to 0")
    try:
        assert(int(src_port) >= 0)
        assert(int(src_port) <= 65535)
    except:
        raise Exception("Source port must be between 0 and 65535")

def randomSub(seed: float):
    """
    Creates a random string that contains numbers and letters. The size is a random number between 10 and 30
    Param: seed: Seed for randomize
    return: A random subdomain
    """
    crc = str(string.ascii_letters + string.digits)
    random.seed(seed)
    n = random.randint(10,30)
    return "".join(random.sample(crc, n))

def genIp():
    """
    Gives a random ip
    """
    ip = ".".join(str(random.randint(0, 255)) for _ in range(4))
    return ip

def randomSubBuilder(dom: string, src_ip: string, dst_ip: string, src_port: int, t: float, seed: float):
    """
    Random Subdomain attack packet builder
    Param: dom: Domain that you want to attack
           src_ip: Source ip
           dst_ip: Destination ip
           src_port: Source port
           t: Arrival time
           seed: Seed for randomize
    return: A packet that has a random string as a subdomain
    """
    id_IP = int(RandShort())
    id_DNS = int(RandShort())
    sub = randomSub(seed)
    q_name = sub + '.' + dom
    ans = Ether()/IP(src = src_ip, dst = dst_ip, id = id_IP)/UDP(sport = src_port)/DNS(rd = 0, id= id_DNS, qd=DNSQR(qname=str(q_name)))
    ans.time = t
    return ans

def regularResponse(p, dom: string, ip_dom: string, ip_srv: string,  dt: float):
    """
    Gives a regular response to packet "p"
    Param: p: request
           dom: Domain asked
           ip_dom: ip of the domain that was asked
           ip_srv: Domain asked server ip
           dt: Response delay time
    return : A response packet that has the EDNS0 extension and an additional record with the answer
    """
    id_IP = int(RandShort())
    ar_ans = DNSRR(rrname = dom, rdata = ip_dom)
    ar_ext = DNSRROPT(rclass=4096)
    an_ans = DNSRR(rrname = dom, rdata = ip_srv)
    ns_ans = DNSRR(rrname = dom, type = 2, rdata = dom)
    ans = Ether()/IP(dst = p[IP].src, src = p[IP].dst, id = id_IP)/UDP(dport = p[UDP].sport, sport = p[UDP].dport)/DNS(id = p[DNS].id, qr = 1, rd = 0, cd = 1, qd = p[DNS].qd, ns = ns_ans, an = an_ans,ar= ar_ans/ar_ext)
    ans.time = p.time + dt
    return ans

def randomSubAttack(src_ip: string, serv: string, dom : string, dom_ip: string, snd_ip: string, duracion: int, c: int, ti: float, srcport : int):
    """
    Gives an array of tuples that contains request and response
    Param: src_ip: Source ip
           serv: Server ip
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
        dt = abs(random.gauss(0.0001868, 0.0000297912738902))
        p = randomSubBuilder(dom, src_ip, serv, srcport, t, Time.time())
        a = regularResponse(p, dom, dom_ip, snd_ip, dt)
        tuple = []
        tuple.append(p)
        tuple.append(a)
        new_packets.append(tuple)

    return new_packets
