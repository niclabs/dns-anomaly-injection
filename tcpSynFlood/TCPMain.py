try:
    import sys
    import argparse
    sys.path.append('..')
    import randFloats as rnd
    import ipGenerator as ipg
    from PacketInserter import *
    from scapy.all import *
    import random
    import time
    from TCPPacketBuilder import *
except:
    raise Exception("Get assure that every library is avalaible")
def createPackets(fileName: str,dip: str,number: int,initialTime=0,duration = 60,numberIp = 1):
    """
        Creates a series of packets of information that are going to be added to the pcap file
        :param: fileName it's the name of the file which is going to be modified
        :param sip:str: the source IP
        :param dip:str: the destiny IP
        :param number:int: the number per second to create
        :param duration: the duration of the attack on the file
        :return: a list of the packets to insert
    """
    #### First we create a list of random times and the ip's
    first = sniff(offline=fileName,count=1)
    ti = first[0].time + initialTime
    times =rnd.genInter(time.time(),ti,ti+duration,number)
    responseTime=0.0006
    print("Creando Ip's del ataque")
    ips = ipg.randomIP(numberIp,time.time(),True)
    #### Then we start to build with our builder
    pktFactory = TCPPacketBuilder()
    pkts = []
    quantity = len(times)
    for i in range(quantity):
        #### Create the random parameters for the attack
        k = random.randint(0,len(ips)-1)
        sip = ips[k]
        qrIpId = int(RandShort())
        rspIpId = int(RandShort())
        sport = random.randint(1024, 65535)
        packetTime = times[i]
        respTime = packetTime + responseTime
        #### Generate the packages
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
        #### Append the packages of request and response on a tuple
        pkts.append((npkt,rpkt))
    return pkts
def main(args,test=""):
    """
    Main function of the program, generates the output file on the
    output folder. 
    :param args:list :  the arguments given by console.
    :param: test: is an extension to the output file name for the test, do not use if
    not testing 
    :return: 0 if everything goes ok!, 1 otherwise
    """
    ##### Reading the inputs from the user
    fileName = args.fileInput
    numberOfIp = args.numberIp
    initialTime = args.ti
    duration = args.duration
    
    ##### Generating the files of the output
    destinyIP = "200.7.4.7" #Ip of the server
    direction = "input/"+fileName
    outName = fileName.split(".pcap")
    output = outName[0]+"-modified"+test+".pcap"

    ##### Getting prepared for generating the attack
    number_packets_second = random.randint(2000,5000)
    print("Generating attack of "+str(number_packets_second)+" per second")
    pkts=createPackets(direction,destinyIP,number_packets_second,initialTime,duration,numberOfIp)
    print("Paquetes creados: "+str(2*len(pkts)))

    ##### Insertion of the packets generated
    print("Empezando a ingresar paquetes en pcap")
    ins = PacketInserter()
    operation = ins.withPackets(pkts)\
                .withInputDir("input/")\
                .withPcapInput(fileName)\
                .withOutputDir("output/")\
                .withPcapOutput(output)\
                .withServerIp("200.7.4.7")\
                .withResponseDt(0.0006)\
                .withTimestamp(0.01)\
                .withServerTolerance(10)\
                .insert()
    ##TODO agregar la estadistica al codigo de los DNS.
    ##### Seeing that everything is ok
    if operation:
        print("Packets Inserted")
        return 0
    return 1
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description = "Simulacion de ataque NXDOMAIN")
    parser.add_argument('--di','--directory_input',dest='inputDirectory',action='store',default='input/',help="Nombre del directorio donde esta el input con / de la ruta",type=str)
    parser.add_argument('--fi','--file_input',dest='fileInput',action='store',default='',help="Nombre del archivo pcap con su respesctivas extensiones",type=str)
    parser.add_argument('--ti','--initial_time',dest='ti',action='store',default=0,help='',type=int)
    parser.add_argument('--dt','--duration',dest='duration',action='store',default=60,help='',type=int)
    parser.add_argument('--ipn','--ip_number',dest='numberIp',action='store',default=1,help='',type=int)
    parser.add_argument('--do','--directory_output',dest='outputDirectory',action='store',default='output/',help='',type=str)
    
    parser.parse_args()
    main(parser.parse_args())
