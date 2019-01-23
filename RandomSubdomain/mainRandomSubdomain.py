import argparse
from randomSubdomain import *
import sys
sys.path.append("..")
from PacketInserter import *
from PortsGenerator import randomSourcePorts
from ipGenerator import randomIP

def main(target_dom:string, server_ip: string, domain_ip:string, server_dom_ip:string, ti:float, ext:int, packets:int,  n_bot:int, attack_type):
    """
    Gives an array of packets
    Param: target_dom: Taget domain
           server_ip: Server ip
           domain_ip: Asked domain ip
           server_dom_ip: Asked domain server ip
           ti: Initial time of the attack
           ext: Attack extension
           packets: Packets per second
           n_bot: Amount of botnets
           attack_type: Boolean, true: DDoS attack, false: DoS
    return: Array of tuples with the packets of the attack
    """
    tf =  ti + ext
    new_packets = []
    ips = randomIP(n_bot, Time.time(), attack_type)
    ports = randomSourcePorts(n_bot, Time.time())
    time = genInter(Time.time(), ti, tf, packets * n_bot)
    for t in time:
        n = random.randint(0, n_bot - 1)
        dt = abs(random.gauss(0.0001868, 0.0000297912738902))
        while(dt == 0):
            dt = abs(random.gauss(0.0001868, 0.0000297912738902))
        tuple = newTuple(target_dom, ips[n], server_ip, ports[n], t, Time.time(), domain_ip, server_dom_ip, dt)
        new_packets.append(tuple)
    return new_packets

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description = "DoS Random Subdomain attack")
    parser.add_argument("-servtol", "--server_tolerance", help="Server tolerance, packets per unit of time that the server can answer", type=int, default =42)
    parser.add_argument("-unitt", "--unit_time", help= "Fraction of time for server tolerance", type=float, default= 0.01)
    parser.add_argument("src_file", help = "Name of the source pcap file with extension, ex: blanco.pcap.gz")
    parser.add_argument("dst_file", help = "Name of the new pcap file with extension")
    parser.add_argument("src_path", help = "Relative path to the input file, it finishes with '/'")
    parser.add_argument("dst_path", help = "Relative path to the output file")
    parser.add_argument("-srv", "--server_ip", help = "Server ip")
    parser.add_argument("-target", "--target_domain", help = "Target domain")
    parser.add_argument("-ext", "--attack_extension", help = "Attack extension (seconds)", type=float)
    parser.add_argument("-psec", "--packets", help ="Amount of packets per second", type=int)
    parser.add_argument("-ti", "--initial_time", help = "Initial time of the attack", type=float)
    parser.add_argument("-at", "--attack_type", help = "Attack type, true: DDoS, false: DoS", action="store_true")
    parser.add_argument("-nbot", "--number_botnets", help="Number of botnets", type=int, default = 1)
    parser.add_argument("-domip","--domain_ip", help= "Asked domain ip, default: random ip", default= genIp())
    parser.add_argument("-sndip", "--server_dom_ip", help= "Asked domain server ip, default: random ip", default=genIp())
    args = parser.parse_args()

    checkArgs(args.src_file, args.dst_file, args.src_path, args.dst_path, args.server_ip, args.target_domain, args.attack_extension, args.packets, args.initial_time, args.number_botnets, args.server_tolerance, args.unit_time)

    p0 = sniff(offline = args.src_path + args.src_file, count = 1)
    t0 = p0[0].time
    new_packets = main(args.target_domain, args.server_ip, args.domain_ip, args.server_dom_ip, args.initial_time + t0, args.attack_extension, args.packets, args.number_botnets, args.attack_type)

    if(args.unit_time > 1):
        unit_time = 1
    else:
        unit_time = args.unit_time
    inserter =PacketInserter()\
              .withPackets(new_packets)\
              .withPcapInput(args.src_file)\
              .withPcapOutput(args.dst_file)\
              .withInputDir(args.src_path)\
              .withOutputDir(args.dst_path)\
              .withServerIp(args.server_ip)\
              .withTimestamp(unit_time)\
              .withServerTolerance(args.server_tolerance)\
              .insert()
