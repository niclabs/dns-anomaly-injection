import argparse
from amplificacion import *
from scapy.all import *
import sys
sys.path.append("..")
from PacketInserter import *

def mainDoS(src_file, src_path, srv_ip, target_ip, src_port, ext, packets, ti, dom, rtype, dom_ip, snd_ip):
    """
    Gives an array with packets for the DoS amplication attack
    Param: src_file: Name of the source pcap file with extension
           src_path: Relative path to the input file, it finishes with '/'
           srv_ip: Server ip
           target_ip: Target ip
           src_port: Source port
           ext: Attack extension (seconds)
           packets: Amount of packets per second
           ti: Initial time of the attack
           dom: Asked domain
           rtype: Response type
                    - True: the response is amplified
                    - False: the response isn't amplified (Regular response)
           dom_ip: Asked domain ip
           snd_ip: Asked domain server ip
    return: Array of new packets
    """
    p0 = sniff(offline = src_path + src_file, count = 1)
    t0 = p0[0].time
    if(rtype):
        return amplificationAttack(srv_ip, target_ip, src_port, ext, packets, ti + t0, dom, 1)
    else:
        return amplificationAttack(srv_ip, target_ip, src_port, ext, packets, ti + t0, dom, 0, dom_ip, snd_ip)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description = "Amplification attack")
    parser.add_argument("-sf", "--src_file", help="Name of the source pcap file with extension")
    parser.add_argument("-df", "--dst_file", help="Name of the new pcap file with extension")
    parser.add_argument("-sp", "--src_path", help="Relative path to the input file, it finishes with '/'")
    parser.add_argument("-dp", "--dst_path", help="Relative path to the output file,, it finishes with '/'")
    parser.add_argument("-srv", "--server_ip", help = "Server ip")
    parser.add_argument("-target", "--target_ip", help= "Target ip")
    parser.add_argument("-sport", "--src_port", help = "Source port", type= int)
    parser.add_argument("-ext", "--attack_extension", help = "Attack extension (seconds)", type=int)
    parser.add_argument("-psec", "--packets", help= "Amount of packets per second", type=int)
    parser.add_argument("-ti", "--initial_time", help = "Initial time of the attack", type=float)
    parser.add_argument("-dom","--domain", help= "Asked domain")
    parser.add_argument("-rtype", "--response_type", help="Response type, true:amplified response, false:normal response. Default: true", action="store_true")
    parser.add_argument("-domip","--domain_ip", help= "Asked domain ip, default: random ip", default= genIp())
    parser.add_argument("-sndip", "--server_dom_ip", help= "Asked domain server ip, default: random ip", default=genIp())
    parser.add_argument("-nbot", "--number_botnets", help="Number of botnets", type=int, default = 1)
    args = parser.parse_args()

    checkArgs(args.src_file, args.dst_file, args.src_path, args.dst_path, args.server_ip, args.target_ip, args.src_port, args.attack_extension, args.packets, args.initial_time, args.domain, args.domain_ip, args.server_dom_ip, args.number_botnets)

    new_packets = []
    packets = mainDoS(args.src_file, args.src_path, args.server_ip, args.target_ip, args.src_port, args.attack_extension, args.packets * args.number_botnets, args.initial_time, args.domain, args.response_type, args.domain_ip, args.server_dom_ip)
    new_packets.extend(packets)

    inserter = PacketInserter()\
            .withPackets(new_packets)\
            .withPcapInput(args.src_file)\
            .withPcapOutput(args.dst_file)\
            .withInputDir(args.src_path)\
            .withOutputDir(args.dst_path)\
            .withServerIp(args.server_ip)\
            .insert()
