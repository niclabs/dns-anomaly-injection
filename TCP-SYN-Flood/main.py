try:
    import sys
    sys.path.append('..')
    import randFloats as rnd
    from PacketInserter import *
    from scapy.all import *
    import random
    import time
    from PacketBuilder import *
except:
    raise Exception("Get assure that every library is avalaible")
def createPackets(fileName: str,sip: str,dip: str,number: int):
    """
        Creates a series of packets of information that are going to be added to the pcap file
        :param: fileName it's the name of the file which is going to be modified
        :param sip:str: the source IP
        :param dip:str: the destiny IP
        :param number:int: the number of packets to creates
        :return: a list of the packets to insert
    """
    first = sniff(offline=fileName,count=1)
    ti = first[0].time
    times =times = rnd.gen(time.time(),ti,ti+5,number)
    responseTime=0.000015
    pktFactory = PacketBuilder()
    pkts = []
    for i in range(number):
        sport = random.randint(1024, 65535)
        packetTime = times[i]
        respTime = packetTime + responseTime
        npkt = pktFactory.withSrcIP(sip)\
                .withDestIP(dip)\
                .withSrcPort(sport)\
                .withDestPort(53)\
                .withFlags('S')\
                .withTime(packetTime)\
                .build()
        rpkt = pktFactory.withSrcIP(dip)\
                .withDestIP(sip)\
                .withSrcPort(53)\
                .withDestPort(sport)\
                .withTime(respTime)\
                .withFlags('SA')\
                .build()
        pkts.append((npkt,rpkt))
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
        outName = fileName.split(".pcap")
        output = outName[0]+"-modified.pcap"
        output_direction = "output/"+output
        wrpcap(output_direction,PacketList()) #Limpio el archivo anterior
        number_packets = random.randint(500,1000)
        pkts=createPackets(direction,originIP,destinyIP,number_packets)
        print("Paquetes creados: "+str(2*number_packets))
        print("Empezando a ingresar paquetes en pcap")
        ins = PacketInserter()
        operation = ins.withPackets(pkts)\
                    .withInputDir("input/")\
                    .withPcapInput(fileName)\
                    .withOutputDir("output/")\
                    .withPcapOutput(output)\
                    .insert()
        if operation:
            print("Packets Inserted")
            return 0
    except FileNotFoundError:
        raise Exception("El archivo no existe o bien no esta en la carpeta input")

if __name__ == "__main__":
    args = sys.argv
    if len(args) < 2:
        print("Numero invalido de argumentos, son de la forma:\n archivo_pcap Ip_Origen")
    else:
        main(args)
