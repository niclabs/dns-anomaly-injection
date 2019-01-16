try:
    import sys
    sys.path.append('..')
    import randFloats as rnd
    from PacketInserter import *
    from scapy.all import *
    import random
    import time
    from TCPPacketBuilder import *
except:
    raise Exception("Get assure that every library is avalaible")
def createPackets(fileName: str,sip: str,dip: str,number: int,initialTime=0,duration = 60):
    """
        Creates a series of packets of information that are going to be added to the pcap file
        :param: fileName it's the name of the file which is going to be modified
        :param sip:str: the source IP
        :param dip:str: the destiny IP
        :param number:int: the number per second to create
        :param duration: the duration of the attack on the file
        :return: a list of the packets to insert
    """
    first = sniff(offline=fileName,count=1)
    ti = first[0].time + initialTime
    times =rnd.genInter(time.time(),ti,ti+duration,number)
    responseTime=0.00015
    pktFactory = TCPPacketBuilder()
    pkts = []
    quantity = len(times)
    for i in range(quantity):
        qrIpId = int(RandShort())
        rspIpId = int(RandShort())
        sport = random.randint(1024, 65535)
        packetTime = times[i]
        respTime = packetTime + responseTime
        npkt = pktFactory.withSrcIP(sip)\
                .withDestIP(dip)\
                .withSrcPort(sport)\
                .withDestPort(53)\
                .withEtherSrc('18:66:da:4d:c0:08')\
                .withEtherResp('18:66:da:e6:36:56')\
                .withFlags('S')\
                .withTime(packetTime)\
                .withIpId(qrIpId)\
                .build()
        rpkt = pktFactory.withSrcIP(dip)\
                .withDestIP(sip)\
                .withSrcPort(53)\
                .withDestPort(sport)\
                .withEtherSrc('18:66:da:e6:36:56')\
                .withEtherResp('18:66:da:4d:c0:08')\
                .withTime(respTime)\
                .withFlags('SA')\
                .withIpId(rspIpId)\
                .build()
        pkts.append((npkt,rpkt))
    return pkts
def main(args: list,test=""):
    """
    Main function of the program, generates the output file on the
    output folder. 
    :param args:list :  the arguments given by console.
    :param: test: is an extension to the output file name for the test, do not use if
    not testing 
    :return: 0 if everything goes ok!, 1 otherwise
    """
    try:
        fileName = args[1]
        originIP = args[2]
        destinyIP = "200.7.4.7" #Ip of the server
        direction = "input/"+fileName
        outName = fileName.split(".pcap")
        output = outName[0]+"-modified"+test+".pcap"
        output_direction = "output/"+output
        wrpcap(output_direction,PacketList()) #Limpio el archivo anterior
        number_packets_second = random.randint(2000,5000)
        print("Generating attack of "+str(number_packets_second)+" per second")
        if len(args) >= 4:
            initialTime = int(args[3])
        else:
            initialTime = 0
        if len(args)>=5:
            duration = int(args[4])
        else:
            duration = 60
        pkts=createPackets(direction,originIP,destinyIP,number_packets_second,initialTime,duration)
        print("Paquetes creados: "+str(2*len(pkts)))
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
        return 1
    except FileNotFoundError:
        raise Exception("El archivo no existe o bien no esta en la carpeta input")
if __name__ == "__main__":
    args = sys.argv
    if len(args) < 3:
        print("Numero invalido de argumentos, son de la forma:\n<archivo_pcap> <Ip_Origen> <tiempo inicial>(opcional,s) <duracion> (opcional,s)")
    else:
        main(args)
