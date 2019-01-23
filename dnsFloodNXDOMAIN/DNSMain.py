
##### Sys libraries import and adding the path of modules to use
import sys
import argparse
sys.path.append('..')
    
##### Libraries and module to use, created by us or scapy
    
from scapy.all import *
from PacketInserter import *
from DNSPacketBuilder import *

##### Python libraries used
import time
import randFloats as rnd
import RandomSubdomain.randomSubdomain as rndSb
import ipGenerator as ipgen


def createFalseDomains(number: int):
    """
        :param number:int: the number of fake domains to make
        :return: a list of false domain names based on the time executed
    """
    domainNames = []
    for i in range(number):
        falseName = rndSb.randomSub(time.time())
        falseDomain = falseName+".cl."
        domainNames.append(falseDomain)
    return domainNames


def createPackateNXDomain(numberOfIp: int,destIp:str,times: list,names: list):
    """
        Creates a list of tuples (request,response) to simulate an NXDOMAIN 
        attack to the DNS server
        :param srcIp:str: the source IP where the attack is generated
        :param destIp:str: the IP of the server
        :param times:list: the time when the attack is given
        :param names:list: the name of the non existant domain
        :return: a list (request,response) of fake queries to be append
    """
    builder = DNSPacketBuilder()
    pkts = []
    ips = ipgen.randomIP(numberOfIp,time.time(),True)
    for i in range(len(times)):
        idDNS = int(RandShort())
        idQrIp = int(RandShort())
        idRspIp = int(RandShort())
        sport = random.randint(1024,65535)
        k = random.randint(0,len(ips)-1)
        packetTime = times[i]
        domainName = names[i]
        srcIp = ips[k]
        z = builder.withSrcIP(srcIp)\
            .withDestIP(destIp)\
            .withSrcPort(sport)\
            .withDestPort(53)\
            .withTime(packetTime)\
            .withDomain(domainName)\
            .withQrIpId(idQrIp)\
            .withRspIpId(idRspIp)\
            .withIdDNS(idDNS)\
            .build()
        pkts.append(z)
    return pkts


def main(args,test=""):
    ##### Reading console input from the user
    inputFileName = args.fileInput
    numberIp = args.numberIp
    initialTime = args.ti
    atckDuration = args.duration
    outputDir = args.outputDirectory
    inputDir  = args.inputDirectory
    timestamp = args.timestamp
    tolerance = args.tolerance
    pps = args.pps
    despps = args.des
    ##### Creating the right names for the output file
    fileComponents = inputFileName.split('.pcap')
    outputFileName = fileComponents[0]+"-modified"+test+".pcap"

    ##### Starting the simulation, setting it's parameters
    rate = int(abs(random.gauss(pps,despps)))
    while rate == 0:
        rate = int(abs(random.gauss(pps,despps)))
    print("Generating attack of "+str(rate)+" packets per second")
    first = sniff(offline=inputDir+inputFileName,count=1)
    if len(first)== 0:
        ti = initialTime
    else:
        ti=first[0].time + initialTime
    timeOfInsertion = rnd.genInter(time.time(),ti,ti+atckDuration,rate)
    domainNames = createFalseDomains(len(timeOfInsertion))
    
    ##### Creating the packets and generation it's insertion
    print("Creating the packets")
    packets = createPackateNXDomain(numberIp,"200.7.4.7",timeOfInsertion,domainNames)
    print("Number of packets created: "+str(2*len(packets)))
    inserter = PacketInserter()
    print("Inserting packets on the modified pcap")
    operation = inserter.withPackets(packets)\
                .withInputDir(inputDir)\
                .withPcapInput(inputFileName)\
                .withOutputDir(outputDir)\
                .withPcapOutput(outputFileName)\
                .withResponseDt(0.006)\
                .withServerIp("200.7.4.7")\
                .withTimestamp(timestamp)\
                .withServerTolerance(tolerance)\
                .insert()
    ##### Checking if everything goes ok
    if operation:
        print("Packets Inserted")
        return 0
    return 1
#### Runner of the module
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description = "Simulacion de ataque NXDOMAIN Flood")
    parser.add_argument('-di','--directory_input',dest='inputDirectory',action='store',default='input/',help="Nombre del directorio donde esta el input con / de la ruta",type=str)
    parser.add_argument('-pps','--packetsPerSecond',dest='pps',default=1500,type=int,help="Packets per second of the attack")
    parser.add_argument('-dpps''--desv_packets_per_second',dest='des',default=500,type=int,help="Standard desviation of the packets per second of the attack")
    parser.add_argument('-fi','--file_input',dest='fileInput',action='store',default='',help="Nombre del archivo pcap con su respesctivas extensiones",type=str)
    parser.add_argument('-ti','--initial_time',dest='ti',action='store',default=0,help='tiempo de inicio del ataque desde el primer paquete del primer archivo',type=int)
    parser.add_argument('-dt','--duration',dest='duration',action='store',default=1,help='tiempo de duracion del ataque, medido en segundos',type=int)
    parser.add_argument('-ipn','--ip_number',dest='numberIp',action='store',default=1,help='cantidad de ips del DDOS, por default es 1',type=int)
    parser.add_argument('-do','--directory_output',dest='outputDirectory',action='store',default='output/',help='direccion del archivo modificado del output',type=str)
    parser.add_argument('-time','--timestamp',dest='timestamp',action='store',default=0.001,help='tiempo de la ventana de medicion, medido en segundos',type=float)
    parser.add_argument('-tol','--tolerance',dest='tolerance',action='store',default=42,help='tolerancia del servidor',type=int)
    arguments = parser.parse_args()
    if arguments.timestamp >= 1.00:
        arguments.timestamp = 1.00
        print("Warning! Changed the timestamp to one second!")
    main(arguments)