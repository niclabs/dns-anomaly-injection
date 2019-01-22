try:
    ##### Sys libraries import and adding the path of modules to use
    import sys
    import argparse
    sys.path.append('..')
    sys.path.append('../RandomSubdomain')
    
    ##### Libraries and module to use, created by us or scapy
    
    from scapy.all import *
    from PacketInserter import *
    from DNSPacketBuilder import *

    ##### Python libraries used
    import time
    import randFloats as rnd
    import randomSubdomain as rndSb
    import ipGenerator as ipgen
except:

    #### Librarie not found error
    raise Exception("Be sure to have all the libraries installed")


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
    inputFileName = 
    numberIp = args.numberIp
    if len(args)>=4:
        initialTime = int(args[3])
    else:
        initialTime = 0
    if len(args)>=5:
        atckDuration = int(args[4])
    else:
        atckDuration = 60
    
    ##### Creating the right names for the output file
    fileComponents = inputFileName.split('.pcap')
    outputFileName = fileComponents[0]+"-modified"+test+".pcap"

    ##### Starting the simulation, setting it's parameters
    rate = random.randint(1000,2000) 
    first = sniff(offline="input/"+inputFileName,count=1)
    if len(first)== 0:
        ti = initialTime
    else:
        ti=first[0].time + initialTime
    timeOfInsertion = rnd.genInter(time.time(),ti,ti+atckDuration,rate)
    domainNames = createFalseDomains(len(timeOfInsertion))
    
    ##### Creating the packages and generation it's insertion
    packages = createPackateNXDomain(numberIp,"200.7.4.7",timeOfInsertion,domainNames)
    inserter = PacketInserter()
    print("Empezando a ingresar "+str(len(packages)))
    operation = inserter.withPackets(packages)\
                .withInputDir("input/")\
                .withPcapInput(inputFileName)\
                .withOutputDir("output/")\
                .withPcapOutput(outputFileName)\
                .withResponseDt(0.006)\
                .insert()

    ##### Checking if everything goes ok
    if operation:
        print("Packets Inserted")
        return 0
    return 1
#### Runner of the module
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description = "Simulacion de ataque NXDOMAIN")
    parser.add_argument('--di','--directory_input',dest='inputDirectory',action='store',default='input/',help="Nombre del directorio donde esta el input con / de la ruta",type=str)
    parser.add_argument('--fi','--file_input',dest='fileInput',action='store',default='',help="Nombre del archivo pcap con su respesctivas extensiones",type=str)
    parser.add_argument('--ti','--initial_time',dest='ti',action='store',default=0,help='',type=int)
    parser.add_argument('--dt','--duration',dest='duration',action='store',default=1,help='',type=int)
    parser.add_argument('--ipn','--ip_number',dest='numberIp',action='store',default=1,help='',type=int)
    parser.add_argument('--do','--directory_output',dest='outputDirectory',action='store',default='output/',help='',type=str)
    
    parser.parse_args()
    main(parser.parse_args())