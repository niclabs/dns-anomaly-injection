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
from randomSubdomain import check_new_tuple_args


def checkArgs(input_file, output_file, server_ip, target_ip, src_port, d, packets, it, domain, zombies, packets_per_window, window_size):
    """
    Check if the arguments are correct
    Param: +input_file: Path to the input file
           output_file: Path to the output file
           +server_ip: Server ip
           +target_ip: Target ip
           +src_port: Source port
           +d: Duration of the attack (seconds)
           +packets: Amount of packets per second
           +it: Initial time of the attack
           domain: Asked domain
           +zombies: Number of computers in the botnet
           +packets_per_window: Amount of packets per unit of time that the server can answer
           +window_size: Fraction of time for server tolerance
    """
    try: #Check input file
        assert(os.path.exists(str(input_file)))
    except:
        raise Exception("Invalid path to the input file")
    try: #Check server ip
        assert(checkValidIp(server_ip))
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
        assert(float(d) > 0)
    except:
        raise Exception("Extension of the attack must be greater than 0")
    try: #Check amount of packets
        assert(int(packets) > 0)
    except:
        raise Exception("Amount of packets per second must be greater than 0")
    try: #Chack initial time of the attack
        assert(float(it)>= 0)
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
        assert(int(zombies) > 0)
    except:
        raise Exception("Number of botnets must be greater than 0")
    try: #Check server tolerance
        assert(int(packets_per_window) > 0)
    except:
        raise Exception("Server tolerance must be greater than 0")
    try: #Check fraction of time for server tolerance
        assert(float(window_size) > 0)
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


def newTuple(l: list):
    """
    Gives an array that contains a request and response
    Param: l: List that contains the necessary arguments to create a tuple of request, response
           l[0]: Target ip
           l[1]: Server ip
           l[2]: Source port
           l[3]: Asked domain
           l[4]: Request arrival time
           l[5]: Delay time for response
           l[6]: Domain ip
           l[7]: Domain server ip
           l[8]: Answer type, boolean that specified if the response is amplified
                    -True: the response is amplified
                    -False: the response isn't amplified
    return: An array (request, response)
    """
    check_new_tuple_args(l)
    p = amplificationBuilder(l[0], l[1], l[2], l[3], l[4]) #Request
    if(l[8]): #If the response is amplified
        a = amplificationResponse(p, l[5])
    else: #Regular response
        a = regularResponse(p, l[3], l[6], l[7], l[5])
    return [p, a]


def argsBuilder(serv: string, ip:string, srcport: int, duration: int, c: int, ti: float, qname : string, ans_type: int, dom_ip = genIp(), dom_srv_ip = genIp()):
    """
    Gives an array of arguments to create packets
    Param: serv: Server ip
           ip: Target ip
           srcport: Source port
           duration: Duration of the attack (seconds)
           c: Amount of packets per second
           ti: Initial time of the attack
           qname: Asked domain
           ans_type: Boolean that specified if the response is amplified
                    -True: the response is amplified
                    -False: the response isn't amplified
           dom_ip: Domain ip
           dom_srv_ip: Domain server ip
    return: Array with the arguments of the packets for the attack
            Structure of each argument: [Target ip, server ip, source port, asked domain, request arrival time, response delay time, domain ip, domain server ip, answer type]
    """
    tf = ti + duration #End time of the attack
    new_packets_args = []
    seed = Time.time() #Seed for randomize
    time = genInter(seed, ti, tf, c) #Array with arrival times for requests
    for t in time:
        dt = abs(random.gauss(0.000322919547395, 0.018900697143)) #Delay time for response
        while(dt == 0): #Delay time can't be 0
            dt = abs(random.gauss(0.000322919547395, 0.018900697143))
        args = [ip, serv, srcport, qname, t, dt, dom_ip, dom_srv_ip, ans_type]
        new_packets_args.append(args)
    return new_packets_args

def genPackets(l :list):
    """
    Gives an array that contains tuples of requests and responses
    Param: l: List of arguments for each tuple
    """
    packets = []
    for arg in l:
        packets.append(newTuple(arg))
    return packets
