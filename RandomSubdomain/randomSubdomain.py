from scapy.all import *
import random
import string
import sys
import time as Time
from randFloats import *
from PacketInserter import *


def randomSub():
    """
    Creates a random string. The size is a random number between [10, 30]
    The string doesn't contains "."
    return: A random subdomain
    """
    crc = str(string.ascii_letters + string.digits + string.punctuation).replace(".", "")
    n = random.randint(10,30)
    return "".join(random.sample(crc, n))
def getDom(s):
    """
    Gives a string that is the domain of the request "s"
    Param: s: Request, structure: b'text.domain.cl'
    return: structure string: domain.cl
    """
    s.replace("'", "")
    r = s.split(".")
    l = len(r)
    return r[l-2] + "." + r[l-1]

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

def answerRandSub(p, ip_dom, t):
    """
    Gives a regular response to packet "p"
    Param: p: request
           ip_dom: ip of the domain that was asked
           t: Response delay time
    return : A response packet that has the EDNS0 extension and an additional record with the answer
    """
    id_IP = int(RandShort())
    dom = getDom(str(p[DNSQR].qname))
    ar_ans = DNSRR(rrname = dom, rdata = ip_dom)
    ar_ext = DNSRROPT(rclass=4096)
    ans = Ether()/IP(dst = p[IP].src, src = p[IP].dst, id = id_IP)/UDP(dport = p[UDP].sport, sport = p[UDP].dport)/DNS(id = p[DNS].id, qr = 1, rd = 0, cd = 1, qd = p[DNS].qd, ar= ar_ans/ar_ext)
    ans.time = p.time + t
    return ans

def randomSubAttack(serv: string, dom : string, dom_ip: string, duracion: int, c: int, ti: float, dt: float, srcport : int):
    """
    Gives an array of tuples that contains request and response
    Param: serv: Server ip
           dom: Target domain
           dom_ip: Domain ip
           duracion: Attack extension (seconds)
           c: Amount of packages per second
           ti: Start date TODO: ver en que se medirá (Con respecto al paquete)
           dt: Delay time of each response
           srcport: Source port
    return: Array of tuples (request, response) of the attack
    tiempo promedio 0.006673997294210002
    """
    tf = ti + duracion
    new_packages = []
    seed = Time.time() #Seed for randomize
    time = genInter(seed, ti, tf, c)
    for t in time:
        p = randomSubBuilder(dom, serv, srcport, t)
        a = answerRandSub(p, dom_ip, dt)
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
           args[6]: Target domain
           args[7]: Domain ip
           args[8]: Attack extension (seconds)
           args[9]:  Amount of packages per second
           args[10]: Start date
           args[11]: Delay time of each response
           args[12]: Source port
    """
    p0 = sniff(offline = args[3] + args[1], count = 1)
    t0 = p0[0].time

    new_packages = randomSubAttack(args[5], args[6], args[7], int(args[8]), int(args[9]), float(args[10]) + t0, float(args[11]), int(args[12]))
    inserter =PacketInserter()\
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
