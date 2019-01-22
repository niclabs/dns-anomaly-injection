import argparse
from randomSubdomain import *
from scapy.all import *
import sys
sys.path.append("..")
from PacketInserter import *

def mainDoS(src_file, src_path, src_ip, srv_ip, dom, dom_ip, snd_ip, ext, packets, ti, src_port):
    """
    Param: src_file: Name of the source pcap file with extension
           src_path: Relative path to the input file, it finishes with '/'
           src_ip: Source ip
           srv_ip: Server ip
           dom: Target domain
           dom_ip: Domain ip
           snd_ip: Domain server ip
           ext: Attack extension (seconds)
           packets:  Amount of packets per second
           ti: Start date
           src_port: Source port

    """
    p0 = sniff(offline = src_path + src_file, count = 1)
    t0 = p0[0].time

    return randomSubAttack(src_ip, srv_ip, dom + ".", dom_ip, snd_ip, ext, packets, ti + t0, src_port)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description = "DoS Random Subdomain attack")
    parser.add_argument("-servtol", "--server_tolerance", help="Server tolerance, packets that the server can answer in 0.1 sec", type=int)
    parser.add_argument("-sf", "--src_file", help = "Name of the source pcap file with extension")
    parser.add_argument("-df", "--dst_file", help = "Name of the new pcap file with extension")
    parser.add_argument("-sp", "--src_path", help = "Relative path to the input file, it finishes with '/'")
    parser.add_argument("-dp", "--dst_path", help = "Relative path to the output file")
    parser.add_argument("-srcip", "--source_ip", help = "Source ip")
    parser.add_argument("-srv", "--server_ip", help = "Server ip")
    parser.add_argument("-target", "--target_domain", help = "Target domain")
    parser.add_argument("-ext", "--attack_extension", help = "Attack extension (seconds)", type=float)
    parser.add_argument("-psec", "--packets", help ="Amount of packets per second", type=int)
    parser.add_argument("-ti", "--initial_time", help = "Initial time of the attack", type=float)
    parser.add_argument("-sport", "--source_port", help = "Source port", type = int)
    parser.add_argument("-nbot", "--number_botnets", help="Number of botnets", type=int, default = 1)
    parser.add_argument("-domip","--domain_ip", help= "Asked domain ip, default: random ip", default= genIp())
    parser.add_argument("-sndip", "--server_dom_ip", help= "Asked domain server ip, default: random ip", default=genIp())
    args = parser.parse_args()

    checkArgs(args.src_file, args.dst_file, args.src_path, args.dst_path, args.source_ip, args.server_ip, args.target_domain, args.attack_extension, args.packets, args.initial_time, args.source_port)

    tf = args.initial_time + args.attack_extension
    new_packets = []
    ips = gen_n_ip(args.number_botnets)
    time = genInter(Time.time(), args.initial_time, tf, c * args.number_botnets)
    for t in time:
        n_ip = random.randint(0, args.number_botnets - 1)
        #TODO: Source port
        dt = abs(random.gauss(0.0001868, 0.0000297912738902))
        tuple = newTuple(args.target_domain, ips[n_ip], args.server_ip, args.source_port, t, Time.time(), args.domain_ip, args.server_dom_ip, dt)
        new_packets.append(tuple)

    inserter =PacketInserter()\
              .withPackets(new_packets)\
              .withPcapInput(args.src_file)\
              .withPcapOutput(args.dst_file)\
              .withInputDir(args.src_path)\
              .withOutputDir(args.dst_path)\
              .withServerIp(args.server_ip)\
              .withTimestamp(0.1)\
              .withServerTolerance(args.server_tolerance)\
              .insert()
