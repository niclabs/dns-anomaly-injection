try:
    from scapy.all import *
    import random
    import time
    import sys
    from PacketBuilder import *
except:
    raise Exception("Install scapy")
def createPackets(pktList: PacketList,sip: str,dip: str,source_port: int,number: int):
    pktFactory = PacketBuilder()
    for i in range(number):
        npkt = pktFactory.withSrcIP(sip)\
                .withDestIP(dip)\
                .withSrcPort(source_port)\
                .withFlags('S')\
                .build()
        pktList.append(npkt)
def insertPacket(new_packet_list, packetsOfFile: PacketList):
    ##TODO insert a list of packets on the packets of the file, not just one
    ##TODO Refactor in time 
    """
        insert a list of packet into the packets of file list where it's belong
        :param new_packet_list: the list of packet to be added
        :param packetsOfFile: the packet of the original file
        :return: a new packet list of for the new file
    """
    pkts = PacketList()
    for i in range(len(packetsOfFile)):
        packate = packetsOfFile[i]
        packate.time = packetsOfFile[i].time
        pkts.extend(packate)
    for j in range(len(new_packet_list)):
        length=len(pkts)
        aPacket = new_packet_list[j]
        aPacket.time=pkts[length-1].time+20
        pkts.extend(aPacket)
    print(pkts.nsummary())
    return pkts


def main(args: list):
    """
    Main function of the program, generates the output file on the
    output folder. 
    :param args:list :  the arguments given by console.
    :return: 0 if everything goes ok!
    """
    try:
        fileName = args[1]
        originIP = args[2]
        destinyIP = "200.7.4.7" #Ip del servidor
        sport = random.randint(1024, 65535)
        direction = "input/"+fileName
        file_pkts = rdpcap(direction)
        lpkts = PacketList()
        ##TODO replace for a function to create a bunch of packets and not just one.
        createPackets(lpkts,originIP,destinyIP,sport,20)
        print(lpkts.nsummary())
        new_packets = insertPacket(lpkts, file_pkts)  # insert at the end
        outName = fileName.split(".pcap")
        output = outName[0]+"-modified.pcap"
        output_direction = "output/"+output
        wrpcap(output_direction, new_packets)
        return 0
    except FileNotFoundError:
        raise Exception("File does not exist or is not placed at input folder")


if __name__ == "__main__":
    args = sys.argv
    if len(args) < 2:
        print("Numero invalido de argumentos, son de la forma:\n archivo_pcap Ip_Origen")
    else:
        main(args)
