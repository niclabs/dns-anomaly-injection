from scapy.all import *
import sys
sys.path.append("..")
import random
from randFloats import *
from assertFunctions import check
import time as Time
import string
sys.path.append("../RandomSubdomain")
from randomSubdomain import genIp
from randomSubdomain import regularResponse

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
    n = random.randint(38, 48) #Amplification factor
    r_data = os.urandom(n*len(p)) #Random data to increase the size of the packet
    ans[DNS].an = DNSRR(type='TXT', rclass=0x8001, rdata = r_data) #Set the answer
    ans.time = p.time + dt #Set the response time
    return ans


def genPackets(l: list):
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

    check(len(l), lambda x: x== 9, "Wrong number of given arguments for genPackets(l), must be 9")
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
