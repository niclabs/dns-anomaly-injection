from scapy.all import *
import random
import string
import sys
import os
sys.path.append("..")
import time as Time
from randFloats import *
from PortsGenerator import randomSourcePorts
from ipGenerator import randomIP
from assertFunctions import check

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
    id_IP = int(RandShort()) #id for IP layer
    id_DNS = int(RandShort()) #id for DNS layer
    sub = randomSub(seed) #Random subdomain
    q_name = sub + '.' + dom #Complete domain request
    ans = Ether(src= '18:66:da:e6:36:56', dst= '18:66:da:4d:c0:08')/IP(src = src_ip, dst = dst_ip, id = id_IP)/UDP(sport = src_port)/DNS(rd = 0, id= id_DNS, qd=DNSQR(qname=str(q_name)))
    ans.time = t #Set time
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
    id_IP = int(RandShort()) #id for IP layer
    ar_ans = DNSRR(rrname = dom, rdata = ip_dom) #Domain answer
    ar_ext = DNSRROPT(rclass=4096) #Extension
    an_ans = DNSRR(rrname = dom, rdata = ip_srv) #Domain server answer
    ns_ans = DNSRR(rrname = dom, type = 2, rdata = dom) #Name server answer
    ans = Ether(dst= '18:66:da:e6:36:56', src= '18:66:da:4d:c0:08')/IP(dst = p[IP].src, src = p[IP].dst, id = id_IP)/UDP(dport = p[UDP].sport, sport = p[UDP].dport)/DNS(id = p[DNS].id, qr = 1, rd = 0, cd = 1, qd = p[DNS].qd, ns = ns_ans, an = an_ans,ar= ar_ans/ar_ext)
    ans.time = p.time + dt #Set arrival time
    return ans

def genPackets(l: list):
    """
    Gives an array that contains a request and response
    Param: l: List that contains the necessary arguments to create a tuple of request, response
           l[0]: Target domain
           l[1]: Source ip
           l[2]: Server ip
           l[3]: Source port
           l[4]: Request arrival time
           l[5]: Seed for randomize
           l[6]: Asked domain ip
           l[7]: Asked domain server ip
           l[8]: Response delay time
    return: An array (request, response)
    """
    check(len(l), lambda x: x== 9, "Wrong number of given arguments for genPackets(l), must be 9")
    req = randomSubBuilder(l[0], l[1], l[2], l[3], l[4], l[5])
    res = regularResponse(req, l[0], l[6], l[7], l[8])
    return [req, res]

def argsBuilder(target_dom:string, server_ip: string, domain_ip:string, server_dom_ip:string, ti:float, d:int, packets:int,  n_bot:int):
    """
    Gives an array of arguments to create packets
    Param: target_dom: Taget domain
           server_ip: Server ip
           domain_ip: Asked domain ip
           server_dom_ip: Asked domain server ip
           ti: Initial time of the attack
           d: Duration of the attack
           packets: Packets per second
           n_bot: Number of computers in the botnet for the DDoS attack
    return: Array with the arguments of the packets for the attack
            Structure of each argument: [target domain, source ip, server ip, source port, request arrival time, seed, domain ip, domain server ip, response delay time]
    """
    tf =  ti + d #End time of the attack
    new_packets_args = []
    if n_bot == 1: #If dos attack
        ips = randomIP(n_bot, Time.time(), False)
    else: #If ddos attack
        ips = randomIP(n_bot, Time.time(), True)
    ips = randomIP(n_bot, Time.time(), n_bot) #Array with source ip
    ports = randomSourcePorts(n_bot, Time.time()) #Array with source ports
    time = genInter(Time.time(), ti, tf, packets * n_bot) #Arrival time of the requests
    for t in time:
        n = random.randint(0, n_bot - 1)
        dt = abs(random.gauss(0.0001868, 0.0000297912738902)) #Delay time for the response
        while(dt == 0): #Delay time can't be 0
            dt = abs(random.gauss(0.0001868, 0.0000297912738902))
        args = [target_dom, ips[n], server_ip, ports[n], t, Time.time(), domain_ip, server_dom_ip, dt]
        new_packets_args.append(args)
    return new_packets_args
