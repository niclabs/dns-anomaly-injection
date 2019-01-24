import argparse
from amplificacion import *
import sys
sys.path.append("..")
from PacketInserter import *

def mainDoS(srv_ip:string, target_ip:string, src_port:int, ext:int, packets:int, n_bots: int, ti:float, dom:string, rtype, dom_ip:string, snd_ip:string):
    """
    Gives an array with packets for the DoS amplication attack
    Param: srv_ip: Server ip
           target_ip: Target ip
           src_port: Source port
           ext: Attack extension (seconds)
           packets: Amount of packets per second
           n_bots: Amount of botnets
           ti: Initial time of the attack
           dom: Asked domain
           rtype: Response type
                    - True: the response is amplified
                    - False: the response isn't amplified (Regular response)
           dom_ip: Asked domain ip
           snd_ip: Asked domain server ip
    return: Array of new packets
    """

    if(rtype): #Amplified response case
        return amplificationAttack(srv_ip, target_ip, src_port, ext, packets * n_bots, ti, dom, 1)
    else: #Regular response case
        return amplificationAttack(srv_ip, target_ip, src_port, ext, packets * n_bots, ti, dom, 0, dom_ip, snd_ip)


if __name__ == '__main__':

    parser = argparse.ArgumentParser(description = "Amplification attack")
    parser.add_argument('-servtol', '--server_tolerance', help='Server tolerance, packets per unit of time that the server can answer, default:42', type=int, default=42)
    parser.add_argument('-unitt', '--unit_time', help= 'Fraction of time for server tolerance, default: 0.01', type=float, default=0.01)
    parser.add_argument('-srv', '--server_ip', help = 'Server ip, default: 200.7.4.7', default='200.7.4.7')
    parser.add_argument('-sport', '--src_port', help = 'Source port, default:21517', type= int, default=21517)
    parser.add_argument('-ext', '--attack_extension', help = 'Attack extension (seconds), default: 300 sec.', type=int, default=300)
    parser.add_argument('-psec', '--packets', help= 'Amount of packets per second, default: 1200', type=int, default=1200)
    parser.add_argument('-ti', '--initial_time', help = 'Initial time of the attack, default:0', type=float, default=0)
    parser.add_argument('-rtype', '--response_type', help='Response type, true:amplified response, false:normal response. Default: true', action='store_true')
    parser.add_argument('-domip','--domain_ip', help= 'Asked domain ip, default: random ip', default= genIp())
    parser.add_argument('-sndip', '--server_dom_ip', help= 'Asked domain server ip, default: random ip', default=genIp())
    parser.add_argument('-nbot', '--number_botnets', help='Number of botnets, default: 1', type=int, default = 1)
    requiredNamed = parser.add_argument_group('Required arguments')
    requiredNamed.add_argument('-sf', '--src_file', help='Name of the source pcap file with extension, ex: file.pcap.gz', required=True)
    requiredNamed.add_argument('-df','--dst_file', help='Name of the new pcap file with extension',required=True)
    requiredNamed.add_argument('-sp','--src_path', help = "Relative path to the input file, it finishes with '/'",required=True)
    requiredNamed.add_argument('-dp', '--dst_path', help="Relative path to the output file,, it finishes with '/'",required=True)
    requiredNamed.add_argument('-target', '--target_ip', help= 'Target ip', required=True)
    requiredNamed.add_argument('-dom','--domain', help= 'Asked domain', required=True)
    args = parser.parse_args()

    checkArgs(args.src_file, args.dst_file, args.src_path, args.dst_path, args.server_ip, args.target_ip, args.src_port, args.attack_extension, args.packets, args.initial_time, args.domain, args.domain_ip, args.server_dom_ip, args.number_botnets, args.server_tolerance, args.unit_time)
    p0 = sniff(offline = args.src_path + args.src_file, count = 1) #Read the first packet of the input file
    t0 = p0[0].time #Arrival time of the first packet of the input file
    new_packets = mainDoS(args.server_ip, args.target_ip, args.src_port, args.attack_extension, args.packets , args.number_botnets, args.initial_time + t0, args.domain, args.response_type, args.domain_ip, args.server_dom_ip)

    if(args.unit_time > 1): #unit time is between 0 and 1
        print("Fraction of time for server tolerance can't be greater than 1, set to 1")
        unit_time = 1
    else:
        unit_time = args.unit_time

    #Insert packets
    inserter = PacketInserter()\
            .withPackets(new_packets)\
            .withPcapInput(args.src_file)\
            .withPcapOutput(args.dst_file)\
            .withInputDir(args.src_path)\
            .withOutputDir(args.dst_path)\
            .withServerIp(args.server_ip)\
            .withTimestamp(unit_time)\
            .withServerTolerance(args.server_tolerance)\
            .insert()
