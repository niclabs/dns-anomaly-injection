from randomSubdomain import *
from scapy.all import *
import sys
sys.path.append("..")
from PacketInserter import *

def mainDoS(args: list):
    """
    Param: args: list of arguments
           args[1]: Name of the source pcap file with extension
           args[2]: Name of the new pcap file with extension
           args[3]: Relative path to the input file, it finishes with '/'
           args[4]: Relative path to the output file
           args[5]: Source ip
           args[6]: Server ip
           args[7]: Target domain
           args[8]: Attack extension (seconds)
           args[9]:  Amount of packets per second
           args[10]: Start date
           args[11]: Source port
    """
    p0 = sniff(offline = args[3] + args[1], count = 1)
    t0 = p0[0].time

    return randomSubAttack(args[5], args[6], args[7] + ".", genIp(), genIp(), int(args[8]), int(args[9]), float(args[10]) + t0, int(args[11]))


if __name__ == '__main__':
    if(len(sys.argv) == 12):
        checkArgs(sys.argv)
        new_packets = mainDoS(sys.argv)
        inserter =PacketInserter()\
                  .withPackets(new_packets)\
                  .withPcapInput(args[1])\
                  .withPcapOutput(args[2])\
                  .withInputDir(args[3])\
                  .withOutputDir(args[4])\
                  .insert()
    else:
        print("Invalid arguments")
        print("input_file output_file input_path output_path source_ip server_ip target_domain attack_extension packets start_date source_port")
