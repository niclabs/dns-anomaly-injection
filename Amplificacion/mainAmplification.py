import argparse
import os
from amplification import *
import sys
sys.path.append("..")
from PacketInserter import *
from assertFunctions import check
from ipGenerator import checkValidIp

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description = "Amplification attack")
    parser.add_argument('-p', '--packets_per_window', help='Server tolerance, packets per unit of time that the server can answer, default:100', type=int, default=100)
    parser.add_argument('-w', '--window_size', help= 'Fraction of time for server tolerance, default: 0.01', type=float, default=0.01)
    parser.add_argument('-s', '--server_ip', help = 'Server ip, default: 200.7.4.7', default='200.7.4.7')
    parser.add_argument('-sp', '--source_port', help = 'Source port, default:21517', type= int, default=21517)
    parser.add_argument('-d', '--duration', help = ' Duration of the attack (seconds), default: 300 sec.', type=int, default=300)
    parser.add_argument('-n', '--num_packets', help= 'Amount of packets per second per zombie, default: 1200', type=int, default=1200)
    parser.add_argument('-it', '--initial_time', help = 'Initial time of the attack, default:0', type=float, default=0)
    parser.add_argument('-rtype', '--response_type', help='Response type, true:amplified response, false:normal response. Default: false', action='store_true')
    parser.add_argument('-z', '--zombies', help='Number of computers in the botnet for the DDoS attack, default:1', type=int, default = 1)
    requiredNamed = parser.add_argument_group('Required arguments')
    requiredNamed.add_argument('-i', '--input_file', help='Path to the input file.', required=True)
    requiredNamed.add_argument('-o','--output_file', help='Path to the output file.',required=True)
    requiredNamed.add_argument('-target', '--target_ip', help= 'Target ip', required=True)
    requiredNamed.add_argument('-dom','--domain', help= 'Asked domain', required=True)
    args = parser.parse_args()

    #Check arguments
    check(args.input_file, lambda x: os.path.exists(x), "Invalid path to the input file")
    check(args.server_ip, lambda x: checkValidIp(x), "Invalid server ip")
    check(args.target_ip, lambda x: checkValidIp(x), "Invalid target ip")
    check(args.source_port, lambda x: int(x) >= 0 and int(x) <= 65535, "Source port must be between 0 and 65535")
    check(args.duration, lambda x: x > 0, "Duration of the attack must be greater than 0")
    check(args.num_packets, lambda x: x > 0 and x%1 == 0, "Amount of packets per second must be greater than 0")
    check(args.initial_time, lambda x: x>=0, "Initial time of the attack must be greater than or equal to 0")
    check(args.zombies, lambda x: x>=1, "Number of botnets must be greater than or equal to 1")
    check(args.packets_per_window, lambda x: x>0 and x%1==0, "Packets per window must be greater than 0")
    check(args.window_size, lambda x: x>0, "Window size must be greater than 0")

    p0 = sniff(offline = args.input_file, count = 1) #Read the first packet of the input file
    t0 = p0[0].time #Arrival time of the first packet of the input file
    new_packets_args = argsBuilder(args.server_ip, args.target_ip, args.source_port, args.duration, args.num_packets * args.zombies, args.initial_time + t0, args.domain, args.response_type)
    if(args.window_size > 1): #unit time is between 0 and 1
        print("Window size can't be greater than 1, set to 1")
        window_size = 1
    else:
        window_size = args.window_size

    #Insert packets
    print("Inserting packets...")
    inserter = PacketInserter()\
            .withArgs(new_packets_args)\
            .withPcapInput(args.input_file)\
            .withPcapOutput(args.output_file)\
            .withServerIp(args.server_ip)\
            .withTimestamp(window_size)\
            .withServerTolerance(args.packets_per_window)\
            .insert(genPackets)
    print("Packets successfully inserted")
