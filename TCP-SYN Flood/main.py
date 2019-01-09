try:
    from scapy.all import *
    import random
    import time
    import sys
    from PacketBuilder import *
except:
    raise Exception("Install scapy")
def createResponsePackets(pktList: PacketList,rspnsList: PacketList,sip: str):
    """
        Create the response SYN ACK packets for the given ACK packets of the PacketList.
        :param pktList:PacketList: The SYN packet list 
        :param rspnsList:PacketList: The response SYN ACK packet list
        :param sip:str: the attacker source IP 
    """
    pktFactory = PacketBuilder()
    for i in range(len(pktList)):
        pkt = pktList[i]
        port = int(pkt.sport)
        npkt = pktFactory.withSrcIP("200.7.4.7")\
                .withDestIP(sip)\
                .withSrcPort(53)\
                .withDestPort(port)\
                .withFlags("SA")\
                .build()
        rspnsList.extend(npkt)
def createPackets(pktList: PacketList,sip: str,dip: str,number: int):
    """
        Creates a series of packets of information that are going to be added to the pcap file
        :param pktList:PacketList: The packet that is going to be added
        :param sip:str: the source IP
        :param dip:str: the destiny IP
        :param number:int: the number of packets to creates
        :return: a list of the ports used on the packets
    """
    ##TODO refactoring of this, is not reallistic
    pktFactory = PacketBuilder()
    for i in range(number):
        sport = random.randint(1024, 65535)
        npkt = pktFactory.withSrcIP(sip)\
                .withDestIP(dip)\
                .withSrcPort(sport)\
                .withFlags('S')\
                .build()
        pktList.extend(npkt)
        

def insertPacket(new_packet_list: PacketList,new_packet_response: PacketList, packetsOfFile: PacketList):
    ##TODO Refactor in time of added
    """
        insert a list of packet into the packets of file list where it's belong
        :param new_packet_list: the list of packet to be added
        :param packetsOfFile: the packet of the original file
        :return: a new packet list of for the new file
    """
    responseTime=0.000015
    i=0
    j=0
    pkts = PacketList()
    while i<len(packetsOfFile):
        prob = random.uniform(0,1)
        if prob<0.4 and j<len(new_packet_list):
            aPacket = new_packet_list[j]
            responsePacket = new_packet_response[j]
            dt = random.uniform(0.00014,0.00016)
            aPacket.time = dt
            responsePacket.time=dt+responseTime
            if len(pkts)!=0:
                aPacket.time += packetsOfFile[i].time
                responsePacket.time +=packetsOfFile[i].time
            pkts.extend(aPacket)
            pkts.extend(responsePacket)
            j+=1
        else:
            packate = packetsOfFile[i]
            packate.time = packetsOfFile[i].time
            pkts.extend(packate)
            i+=1
    while j<len(new_packet_list):
        dt=random.random()
        length=len(pkts)
        aPacket = new_packet_list[j]
        responsePacket = new_packet_response[j]
        aPacket.time=pkts[length-1].time+dt
        responsePacket.time = aPacket.time + responseTime
        pkts.extend(aPacket)
        pkts.extend(responsePacket)
        j+=1
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
        destinyIP = "200.7.4.7" #Ip of the server
        direction = "input/"+fileName
        file_pkts = rdpcap(direction)
        number_packets = random.randint(500,1000)
        lpkts = PacketList()
        lrspns = PacketList()
        ##TODO replace for a function to create a bunch of packets and not just one.
        createPackets(lpkts,originIP,destinyIP,number_packets)
        createResponsePackets(lpkts,lrspns,originIP)
        new_packets = insertPacket(lpkts,lrspns, file_pkts)
        outName = fileName.split(".pcap")
        output = outName[0]+"-modified.pcap"
        output_direction = "output/"+output
        wrpcap(output_direction, new_packets)
        return 0
    except FileNotFoundError:
        raise Exception("El archivo no existe o bien no esta en la carpeta input")

##TODO en la tarde generar las respuestas del servidor
if __name__ == "__main__":
    args = sys.argv
    if len(args) < 2:
        print("Numero invalido de argumentos, son de la forma:\n archivo_pcap Ip_Origen")
    else:
        main(args)
