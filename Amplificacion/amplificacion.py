from scapy.all import *
import sys
sys.path.append("..")
import os
import random
from randFloats import *
import time as Time
import string
sys.path.append("../RandomSubdomain")
from randomSubdomain import checkValidIp
from randomSubdomain import genIp
from randomSubdomain import regularResponse


def checkArgs(src_file, dst_file, src_path, dst_path, srv_ip, target_ip, src_port, ext, packets, ti, domain, dom_ip, snd_ip, number_botnets, server_tolerance, unit_time):
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
           +ti: Initial time of the attack
           domain: Asked domain
           +dom_ip: Asked domain ip
           +snd_ip: Asked domain server ip
           +number_botnets: Number of botnets
           +server_tolerance: Amount of packets per unit of time that the server can answer
           +unit_time: Fraction of time for server tolerance
    """
    try: #Check structure of the relative path to the input file
        assert(src_path[len(src_path) - 1] == "/")
    except:
        raise Exception("Wrong relative path to the input file, it finishes with '/'")
    try: #Check input file
        assert(os.path.exists(str(src_path) + str(src_file)))
    except:
        raise Exception("Invalid source path")
    try: #Check strucuture of the relative path to the output file
        assert(dst_path[len(dst_path) -1] == "/")
    except:
        raise Exception("Relative path to the output file it finishes with '/'")
    try: #Check relative path to the output file
        assert(os.path.exists(str(dst_path)))
    except:
        raise Exception("Invalid output file path")
    try: #Check extension of the output file
        f = dst_file.split(".")
        assert(len(f) == 2)
        assert(f[1] == "pcap")
    except:
        raise Exception("Wrong output file extension")
    try: #Check server ip
        assert(checkValidIp(srv_ip))
    except:
        raise Exception("Invalid server ip")
    try: #Check target ip
        assert(checkValidIp(target_ip))
    except:
        raise Exception("Invalid target ip")
    try: #Check valid port
        assert(int(src_port) >= 0)
        assert(int(src_port) <= 65535)
    except:
        raise Exception("Source port must be between 0 and 65535")
    try: #Check extension of the attack
        assert(float(ext) > 0)
    except:
        raise Exception("Extension of the attack must be greater than 0")
    try: #Check amount of packets
        assert(int(packets) > 0)
    except:
        raise Exception("Amount of packets per second must be greater than 0")
    try: #Chack initial time of the attack
        assert(float(ti)>= 0)
    except:
        raise Exception("Initial time of the attack must be greater than or equal to 0")
    try: #Check valid asked domain ip
        assert(checkValidIp(dom_ip))
    except:
        raise Exception("Invalid domain ip")
    try: #Check valid asked domain server ip
        assert(checkValidIp(snd_ip))
    except:
        raise Exception("Invalid domain server ip")
    try: #Check number of botnets
        assert(int(number_botnets) > 0)
    except:
        raise Exception("Number of botnets must be greater than 0")
    try: #Check server tolerance
        assert(int(server_tolerance) > 0)
    except:
        raise Exception("Server tolerance must be greater than 0")
    try: #Check fraction of time for server tolerance
        assert(float(unit_time) > 0)
    except:
        raise Exception("Fraction of time for server tolerance must be greater than 0")


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
    id_IP = int(RandShort()) #id for IP layer
    id_DNS = int(RandShort()) #id for DNS layer
    p = Ether()/IP(dst=ip_dst, src=ip_src, id = id_IP)/UDP(sport=src_port)/DNS(rd=0, id= id_DNS, qd=DNSQR(qname=str(q_name), qtype = "ALL"),ar=DNSRROPT(rclass=4096))
    p.time = t #Set arrival time
    return p

def amplificationResponse(p, dt: float):
    """
    Gives an amplified response to the packet p
    Param: p: request
           dt: Response delay time
    return: A response packet that has the EDNS0 extension and the answer section is set up
           - Type: TXT: Contains a large string
    """
    id_IP = int(RandShort()) #id for IP layer
    #Create the answer with EDNS0 extension
    ans = Ether()/IP(dst = p[IP].src, src = p[IP].dst, id = id_IP)/UDP(dport = p[UDP].sport, sport = p[UDP].dport)/DNS(id = p[DNS].id, qr = 1, rd = 0, cd = 1, qd = p[DNS].qd, ar = DNSRROPT(rclass=4096))

    #Create and set the answer
    n = random.randint(38, 40) #Amplification factor
    r_data = os.urandom(n*len(p)) #Random data to increase the size of the packet
    ans[DNS].an = DNSRR(type='TXT', rclass=0x8001, rdata = r_data) #Set the answer
    ans.time = p.time + dt #Set the response time
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

    tf = ti + duracion #End time of the attack
    new_packets = []
    seed = Time.time() #Seed for randomize
    time = genInter(seed, ti, tf, c) #Array with arrival times for requests
    for t in time:
        dt = abs(random.gauss(0.0001868, 0.0000297912738902)) #Delay time for response
        while(dt == 0): #Delay time can't be 0
            dt = abs(random.gauss(0.0001868, 0.0000297912738902))
        p = amplificationBuilder(ip, serv, srcport, qname, t) #Request
        if(ans_type == 1): #If the response is amplified
            a = amplificationResponse(p, dt)
        else: #Regular response
            a = regularResponse(p, qname, dom_ip, dom_srv_ip, dt)
        tuple = []
        tuple.append(p)
        tuple.append(a)
        new_packets.append(tuple)
    return new_packets
