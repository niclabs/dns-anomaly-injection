try:
    from scapy.all import *
    import random
    import time
    import sys
    from PacketBuilder import *
except:
    raise Exception("Install scapy")

def insertPacket(aPacket, packetsOfFile):
    ##TODO insert a list of packets on the packets of the file, not just one
    """
        insert a packet into the packets of file list where it's belong
        :param aPacket: the packet to insert
        :param packetsOfFile: the packet of the original file
        :return: a new packet list of for the new file
    """
    pkts = PacketList()
    length = len(packetsOfFile)
    for i in range(length):
        packate = packetsOfFile[i]
        packate.time = packetsOfFile[i].time
        pkts.extend(packate)
    aPacket.time=packetsOfFile[length-1].time+20
    pkts.extend(aPacket)
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
        pktFactory = PacketBuilder()
        ##TODO replace for a function to create a bunch of packets and not just one.
        npkt = pktFactory.withSrcIP(originIP)\
                .withDestIP(destinyIP)\
                .withSrcPort(sport)\
                .withFlags('S')\
                .build()
        new_packets = insertPacket(npkt, file_pkts)  # insert at the end
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
