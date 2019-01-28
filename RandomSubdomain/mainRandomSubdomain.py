import argparse
from randomSubdomain import *
import sys
sys.path.append("..")
from PacketInserter import *
from PortsGenerator import randomSourcePorts
from ipGenerator import randomIP



if __name__ == '__main__':
    parser = argparse.ArgumentParser(description = "DoS Random Subdomain attack")
    parser.add_argument('-p', '--packets_per_window', help='Server tolerance, packets per unit of time that the server can answer, default:100', type=int, default =100)
    parser.add_argument('-w', '--window-size', help= 'Fraction of time for server tolerance, default:0.01', type=float, default= 0.01)
    parser.add_argument('-s', '--server_ip', help = 'Server ip, default: 200.7.4.7', default='200.7.4.7')
    parser.add_argument('-d', '--duration', help = 'Duration of the attack (seconds), default: 300 sec.', type=float, default= 300)
    parser.add_argument('-n', '--num_packets', help ='Amount of packets per second default: 2500', type=int, default=2500)
    parser.add_argument('-it', '--initial_time', help = 'Initial time of the attack, default:0', type=float, default= 0)
    parser.add_argument('-z', '--zombies', help='Number of computers in the botnet for the DDoS attack, default:1', type=int, default = 1)
    requiredNamed = parser.add_argument_group('Required arguments')
    requiredNamed.add_argument('-i', '--input_file', help='Path to the input file.', required=True)
    requiredNamed.add_argument('-o','--output_file', help='Path to the output file.', required=True)
    requiredNamed.add_argument('-target', '--target_domain', help = 'Target domain', required=True)
    args = parser.parse_args()

    checkArgs(args.input_file, args.output_file, args.server_ip, args.target_domain, args.duration, args.num_packets, args.initial_time, args.zombies, args.packets_per_window, args.window_size)

    p0 = sniff(offline = args.input_file, count = 1) #Read the first packet of the input file
    t0 = p0[0].time #Arrival time of the first packet of the input file
    print("Creating packets...")
    new_packets_args = argsBuilder(args.target_domain, args.server_ip, genIp(), genIp(), args.initial_time + t0, args.duration, args.num_packets, args.number_botnets)

    if(args.window_size > 1): #unit time is between 0 and 1
        window_size = 1
    else:
        window_size = args.window_size
    #Insert packets
    print("Inserting packets...")
    inserter =PacketInserter()\
              .withArgs(new_packets_args)\
              .withPcapInput(args.input_file)\
              .withPcapOutput(args.output_file)\
              .withServerIp(args.server_ip)\
              .withTimestamp(window_size)\
              .withServerTolerance(args.packets_per_window)\
              .insert()
    print("Packets successfully inserted")
