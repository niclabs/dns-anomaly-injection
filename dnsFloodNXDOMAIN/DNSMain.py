
##### Sys libraries import and adding the path of modules to use
import sys
import argparse
sys.path.append('..')

##### Libraries and module to use, created by us or scapy
from scapy.all import *
from PacketInserter import *
from DNSPacketBuilder import *
import random
##### Python libraries used
import time
import randFloats as rnd
import RandomSubdomain.randomSubdomain as rndSb
import ipGenerator as ipgen

ipsBot = []
def createInserterPackets(args: list):
    """
        Adapter to the arguments for creating packets on the inserter
        :param: args is a list of at least 6 parameters to create the packets of the nx domain
        args[0] is the number of ip of the botnet available
        args[1] is the destiny ip of the packet to create
        args[2] is the duration of the attack
        args[3] is the initial time of the attack
        args[4] is the mean of packet per second of the attack
        args[5] is the standard desviation of packet per second
        :return: a list of packets given the arguments
    """
    assert len(args) >= 6
    numberOfIp = args[0]
    destIp = args[1]
    duration = args[2]
    ti = args[3]
    pps = args[4]
    despps = args[5]
    return createPackateNXDomain(numberOfIp,destIp,duration,ti,pps,despps)
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


def createPackateNXDomain(numberOfIp: int,destIp:str,duration: int,ti:float,pps: float,despps: float):
    """
        Creates the attack packets tuple and give a list of the form (request,response). The number of packets are
        variable and depends of the pps and despps that is the mean of the packets per second of the attack and it's
        standard desviation.
        :param numberOfIp:int: is the number of spoofed ip's of the attack to generate, it will not necesarily choose
        every one.
        :param destIp:str: is the destiny ip which will be attacked
        :param duration:int: the duration of the attack
        :param ti:float: the initial time of the attack
        :param pps:float: the mean of the packets per second
        :param despps:float: the standard desviation of the packets per second
        :return: a list of tuples whith (request,response) packets
    """
    assert duration >=1
    ## Starting defining the variables that we will use to create and store the packages created
    builder = DNSPacketBuilder()
    pkts = []
    global ipsBot
    if len(ipsBot) == 0:
        print("Creating bots for the attack")
        ipsBot = ipgen.randomIP(numberOfIp,time.time(),True)
    ta = ti
    ## We defined by every second the number of packets to create
    for i in range(duration):
        ta +=1
        rate = int(abs(random.gauss(pps,despps)))
        while rate == 0:
            rate = int(abs(random.gauss(pps,despps)))
        times = rnd.genInter(time.time(),ti,ta,rate)
        names = createFalseDomains(len(times))
        ## For each time created we also create a packet that will be sent at that time
        for i in range(len(times)):
            ## Generates it's ids of query and response of the ip layer
            idDNS = int(RandShort())
            idQrIp = int(RandShort())
            idRspIp = int(RandShort())
            ## The port number
            sport = random.randint(1024,65535)
            ## a time and a domain with it's ip
            k = random.randint(0,len(ipsBot)-1)
            packetTime = times[i]
            domainName = names[i]
            srcIp = ipsBot[k]
            ## And randomly we generate the response delay of the server
            responseDt = abs(random.gauss(0.00023973491409910548,3.641262394861281e-05))
            z = builder.withSrcIP(srcIp)\
                .withDestIP(destIp)\
                .withSrcPort(sport)\
                .withDestPort(53)\
                .withTime(packetTime)\
                .withDomain(domainName)\
                .withQrIpId(idQrIp)\
                .withRspIpId(idRspIp)\
                .withIdDNS(idDNS)\
                .withResponseDt(responseDt)\
                .build()
            pkts.append(z)
    return pkts


def main(args):
    ##### Reading console input from the user, defining it's variables
    inputFileName = args.fileInput
    outputFileDir = args.outputDirectory
    numberIp = args.numberIp
    initialTime = args.ti
    atckDuration = args.duration
    timestamp = args.timestamp
    tolerance = args.tolerance
    pps = args.pps
    despps = 250
    destinyIp = args.serverIp
    ##### Creating the right names for the output file
    outputFileName = outputFileDir ## TODO modificar esto

    ##### Starting the simulation, setting it's parameters of the initial time
    first = sniff(offline=inputFileName,count=1)
    if len(first)== 0:
        ti = initialTime
    else:
        ti=first[0].time + initialTime
    ##### Creating the packets and generate it's insertion
    #print("Creating the packets")
    #packets = createPackateNXDomain(numberIp,destinyIp,atckDuration,ti,pps,despps)
    #print("Number of packets created: "+str(2*len(packets)))
    ## Creating the arguments
    i = 0
    arguments = []
    while i < atckDuration:
        anArgument = [numberIp,destinyIp,1,ti+i,pps,despps]
        arguments.append(anArgument)
        i+=1
    inserter = PacketInserter()
    operation = inserter.withArgs(arguments)\
                .withQuantity(1)\
                .withPcapInput(inputFileName)\
                .withPcapOutput(outputFileName)\
                .withResponseDt(0.0066541468651955095)\
                .withServerIp(destinyIp)\
                .withTimestamp(timestamp)\
                .withServerTolerance(tolerance)\
                .insert(createInserterPackets)
    ##### Checking if everything goes ok after the insertion operation.
    if operation:
        print("Packets Inserted")
        return 0
    return 1
#### Runner of the module
if __name__ == "__main__":
    ##
    parser = argparse.ArgumentParser(description = "NXDOMAIN flood attack simulation")
    parser.add_argument('-n','--num_packets',dest='pps',default=2500,type=int,help="Mean of the packets per second of the attack")
    parser.add_argument('-i','--input_file',dest='fileInput',action='store',default='',help="Input pcap file name with his extension",type=str)
    parser.add_argument('-it','--initial_time',dest='ti',action='store',default=0,help='Initial time of the attack, when the first attack packet will be introduced, measured in seconds and by default is 0',type=int)
    parser.add_argument('-d','--duration',dest='duration',action='store',default=60,help='The time duration of the attack, also measured in second and by default is 1',type=int)
    parser.add_argument('-z','--zombies',dest='numberIp',action='store',default=1,help="Number of ip's of the botnet, if it's 1 the type of attack is DOS. By default is 1.",type=int)
    parser.add_argument('-o','--output',dest='outputDirectory',action='store',default='output/',help='Path and name of the output file with the attack inserted',type=str)
    parser.add_argument('-w','--window_size',dest='timestamp',action='store',default=0.01,help='Time for the measure window when the server is going or not to be down, this time is on seconds, for default is 0.01',type=float)
    parser.add_argument('-p','--packets_per_window',dest='tolerance',action='store',default=42,help='Server number of packets per the time of measure window, by default is 42',type=int)
    parser.add_argument('-s','--server_ip',dest='serverIp',action='store',default="200.7.4.7",help="DNS server's ip, by default is 200.7.4.7",type=str)
    arguments = parser.parse_args()
    if arguments.timestamp >= 1.00:
        arguments.timestamp = 1.00
        print("Warning! Changed the timestamp to one second!")
    main(arguments)
