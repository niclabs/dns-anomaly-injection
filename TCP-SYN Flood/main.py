try:
    import sys
    sys.path.append('..')
    import randFloats as rnd
    from scapy.all import *
    import random
    import time
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
        

def insertPacket(new_packet_list: PacketList,new_packet_response: PacketList,direction: str,output_direction: str):
    ##TODO Refactor in time of added
    """
        insert a list of packet into the packets of file list where it's belong
        :param new_packet_list: the list of packet to be added
        :return: a new packet list of for the new file
    """
    numPktsIns = len(new_packet_list)
    reader = PcapReader(direction)
    writer = PcapWriter(output_direction,append=True,sync=True)
    buffer = []
    primero = reader.read_packet()
    buffer.append(primero)
    ti= primero.time
    times = rnd.gen(time.time(),ti,ti+5,numPktsIns)
    responseTime=0.000015
    waiting = False
    j=0
    while True:
        pktRead = reader.read_packet()
        if pktRead == None:
            if len(buffer)!=0:
                waiting = True
            break
        buffer.append(pktRead)
        if j< numPktsIns and buffer[0].time > times[j]:
            aPacket = new_packet_list[j]
            response = new_packet_response[j]
            aPacket.time = times[j]
            response.time = times[j]+responseTime
            writer.write(aPacket)
            writer.write(response)
            j+=1
        else:
            writer.write(buffer[0])
            buffer.pop(0)
    while waiting:
        writer.write(buffer[0])
        buffer.pop(0)
        waiting = len(buffer)!=0

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
        outName = fileName.split(".pcap")
        output = outName[0]+"-modified.pcap"
        output_direction = "output/"+output
        wrpcap(output_direction,PacketList()) #Limpio el archivo anterior
        number_packets = random.randint(500,1000)
        lpkts = PacketList()
        lrspns = PacketList()
        createPackets(lpkts,originIP,destinyIP,number_packets)
        createResponsePackets(lpkts,lrspns,originIP)
        insertPacket(lpkts,lrspns,direction,output_direction)
        return 0
    except FileNotFoundError:
        raise Exception("El archivo no existe o bien no esta en la carpeta input")

if __name__ == "__main__":
    args = sys.argv
    if len(args) < 2:
        print("Numero invalido de argumentos, son de la forma:\n archivo_pcap Ip_Origen")
    else:
        main(args)
