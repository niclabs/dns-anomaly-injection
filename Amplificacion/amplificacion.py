from scapy.all import *
import sys
sys.path.append("..")
import os
import random
from randFloats import *
import time as Time
import string
from PacketInserter import *
sys.path.append("../RandomSubdomain")
from randomSubdomain import checkValidIp
from randomSubdomain import genIp
from randomSubdomain import regularResponse


def checkArgs(src_file, dst_file, src_path, dst_path, srv_ip, target_ip, src_port, ext, packets, ti, domain, dom_ip, snd_ip, number_botnets, server_tolerance):
    """
    Check if the arguments are correct
    Param: +src_file: Name of the source pcap file with extension
           +dst_file: Name of the new pcap file with extension
           +src_path: Relative path to the input file, it finishes with '/'
           +dst_path: Relative path to the output file it finishes with '/'
           +srv_ip: Server ip
           +target_ip: Target ip
           +src_port: Source port
           +ext: Attack extension (seconds)
           +packets: Amount of packets per second
           +ti: Start date
           domain: Asked domain
           +dom_ip: Asked domain ip
           +snd_ip: Asked domain server ip
           +number_botnets: Number of botnets
           +server_tolerance: Amount of packets that the server can answer in 0.1 sec
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
        assert(dst_path[len(dst_path) -1] == "/")
    except:
        raise Exception("Relative path to the output file it finishes with '/'")
    try:
        assert(os.path.exists(str(dst_path)))
    except:
        raise Exception("Invalid output file path")
    try:
        f = dst_file.split(".")
        assert(len(f) == 2)
        assert(f[1] == "pcap")
    except:
        raise Exception("Wrong output file extension")
    try:
        assert(checkValidIp(srv_ip))
    except:
        raise Exception("Invalid server ip")
    try:
        assert(checkValidIp(target_ip))
    except:
        raise Exception("Invalid target ip")
    try:
        assert(int(src_port) >= 0)
        assert(int(src_port) <= 65535)
    except:
        raise Exception("Source port must be between 0 and 65535")
    try:
        assert(float(ext) > 0)
    except:
        raise Exception("Extension of the attack must be greater than 0")
    try:
        assert(int(packets) > 0)
    except:
        raise Exception("Amount of packets per second must be greater than 0")
    try:
        assert(float(ti)>= 0)
    except:
        raise Exception("Start date must be greater than or equal to 0")
    try:
        assert(checkValidIp(dom_ip))
    except:
        raise Exception("Invalid domain ip")
    try:
        assert(checkValidIp(snd_ip))
    except:
        raise Exception("Invalid domain server ip")
    try:
        assert(number_botnets > 0)
    except:
        raise Exception("Number of botnets must be greater than 0")
    try:
        assert(server_tolerance > 0)
    except:
        raise Exception("Server tolerance must be greater than 0")


def amplificationBuilder(ip_src: string,ip_dst: string, src_port: int, q_name: string, t: float):
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

def amplificationResponse(p, dt: float):
    """
    Gives an amplified response to the packet p
    Param: p: request
           dt: Response delay time
    return: A response packet that has the EDNS0 extension and the answer section is set up
           - Type: TXT: Contains a large string
    """
    id_IP = int(RandShort())
    #Create the answer with EDNS0 extension
    ans = Ether()/IP(dst = p[IP].src, src = p[IP].dst, id = id_IP)/UDP(dport = p[UDP].sport, sport = p[UDP].dport)/DNS(id = p[DNS].id, qr = 1, rd = 0, cd = 1, qd = p[DNS].qd, ar = DNSRROPT(rclass=4096))

    #Create and set the answer
    n = random.randint(38, 40) #Amplification factor
    r_data = os.urandom(n*len(p))
    ans[DNS].an = DNSRR(type='TXT', rclass=0x8001, rdata = r_data)

    #Set the response time
    ans.time = p.time + dt
    return ans

def amplificationAttack(serv: string, ip:string, srcport: int, duracion: int, c: int, ti: float, qname : string, ans_type: int, dom_ip = genIp(), dom_srv_ip = genIp()):
    """
    Assuming that the server is giving an amplified response
    Param: serv: Server ip
           ip: Target ip
           srcport: Source port
           duracion: Attack extension (seconds)
           c: Amount of packets per second
           ti: Start date TODO: ver en que se medirá (Con respecto al paquete)
           qname: Domain asked
           ans_type: int that specified if the response is amplified
                    - 1: the response is amplified
                    - 0: the response isn't amplified
           dom_ip: Domain ip
           dom_srv_ip: Domain server ip
    return: Array of tuples (request, response) of the attack
    """

    tf = ti + duracion
    new_packets = []
    seed = Time.time() #Seed for randomize
    time = genInter(seed, ti, tf, c)
    for t in time:
        dt = abs(random.gauss(0.0001868, 0.0000297912738902))
        p = amplificationBuilder(ip, serv, srcport, qname, t)
        if(ans_type == 1):
            a = amplificationResponse(p, dt)
        else:
            a = regularResponse(p, qname, dom_ip, dom_srv_ip, dt)
        tuple = []
        tuple.append(p)
        tuple.append(a)
        new_packets.append(tuple)
    return new_packets
