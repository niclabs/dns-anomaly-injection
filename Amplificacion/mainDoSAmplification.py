from amplificacion import *
from scapy.all import *
import sys
sys.path.append("..")
from PacketInserter import *

def mainDoS(args: list):
    """
    Gives an array with packets for the DoS amplication attack
    Param: args: list of arguments
           args[1]: Name of the source pcap file with extension
           args[2]: Name of the new pcap file with extension
           args[3]: Relative path to the input file, it finishes with '/'
           args[4]: Relative path to the output file
           args[5]: Server ip
           agrs[6]: Target ip
           args[7]: Source port
           args[8]: Attack extension (seconds)
           args[9]: Amount of packets per second
           args[10]: Start date
           args[11]: Asked domain
           args[12]: Response type
                    - 1: the response is amplified
                    - 0: the response isn't amplified
           Only needed if args[12] == 0
           args[13]: Asked domain ip
           agrs[14]: Asked domain server ip
    return: Array of new packets
    """
    p0 = sniff(offline = args[3] + args[1], count = 1)
    t0 = p0[0].time
    if(int(args[12]) == 1):
        return amplificationAttack(args[5], args[6], int(args[7]), int(args[8]), int(args[9]), float(args[10]) + t0, args[11], 1)
    else:
        return amplificationAttack(args[5], args[6], int(args[7]), int(args[8]), int(args[9]), float(args[10]) + t0, args[11], 0, args[13], agrs[14])


if __name__ == '__main__':
    if(len(sys.argv) == 13 or len(sys.argv) == 15):
        checkArgs(sys.argv)
        new_packets = mainDoS(sys.argv)
        inserter = PacketInserter()\
                   .withPackets(new_packets)\
                   .withPcapInput(args[1])\
                   .withPcapOutput(args[2])\
                   .withInputDir(args[3])\
                   .withOutputDir(args[4])\
                   .withServerIp(args[5])\
                   .insert()
    else:
        print("Invalid arguments")
        print("input_file output_file input_path output_path server_ip target_ip source_port attack_extension packets start_date domain response_type *domain_ip, *domain_server_ip")
