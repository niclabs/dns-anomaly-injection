### Imports 
### Of console and system configurations and parser, python main libraries
import sys
import argparse
sys.path.append('..')
import random
import time

### Modules of functions and objects made by us
import randFloats as rnd
import ipGenerator as ipg
from PacketInserter import *
from TCPPacketBuilder import *

### Scapy librarie
from scapy.all import *


def createPackets(fileDirectionName: str,dip: str,pps: float,despps: float,initialTime=0,duration = 1,numberIp = 1):
    """
        Create the attack packets array of tuples, with the tuples form being (request,response).
        :param fileDirectionName:str: its the file route and it's name string
        :param dip:str: the destiny ip of the attack packets created, it's the hostage ip
        :param pps:float: the mean packets per second of the attack, it will be used to make a gaussian probability
        :param despps:float: the standard desviation of the packets per second of the attacker
        :param initialTime:float: the initial time of the attack 
        :param duration:float: the attack duration to the server
        :param numberIp:int: the number of ip of the DDOS attack (botnet number), if it's a 1, the type of the attack is DOS
        :return: a list of tuple of representing the attack and the server response.
    """
    assert duration>=1
    #### First we create a list of random ip's
    first = sniff(offline=fileDirectionName,count=1)
    ti = first[0].time + initialTime
    pkts = []
    print("Creating Ip's of the attack")
    ips = ipg.randomIP(numberIp,time.time(),True)
    #### Then we start to build with our builder
    pktFactory = TCPPacketBuilder()
    ta = ti
    for i in range(duration):
        ta += 1
        number = int(abs(random.gauss(pps,despps)))
        while number == 0:
            number = int(abs(random.gauss(pps,despps)))
        times =rnd.genInter(time.time(),ti,ta,number)
        quantity = len(times)
        for i in range(quantity):
            #### Create the random parameters for the attack
            responseTime = abs(random.gauss(0.005931744402515722,0.15624380490520876))
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
    inputdir = args.inputDirectory
    outputdir = args.outputDirectory
    numberOfIp = args.numberIp
    initialTime = args.ti
    duration = args.duration
    timestamp = args.timestamp
    tolerance = args.tolerance
    pps = args.pps
    despps = args.des
    ##### Generating the files of the output
    destinyIP = args.serverIp
    direction = inputdir+fileName
    outName = fileName.split(".pcap")
    output = outName[0]+"-modified"+test+".pcap"

    ##### Getting prepared for generating the attack
    pkts=createPackets(direction,destinyIP,pps,despps,initialTime,duration,numberOfIp)
    print("Number of attack packets: "+str(len(pkts)))
    print("Number of packets created: "+str(2*len(pkts)))

    ##### Insertion of the packets generated
    print("Inserting packets on the modified pcap")
    ins = PacketInserter()
    operation = ins.withPackets(pkts)\
                .withInputDir(inputdir)\
                .withPcapInput(fileName)\
                .withOutputDir(outputdir)\
                .withPcapOutput(output)\
                .withServerIp(destinyIP)\
                .withResponseDt(0.0066541468651955095)\
                .withTimestamp(timestamp)\
                .withServerTolerance(tolerance)\
                .insert()
    ##### Seeing that everything is ok
    if operation:
        print("Packets Inserted")
        return 0
    return 1
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description = "TCP-SYN Flood attack simulation")
    parser.add_argument('-di','--directory_input',dest='inputDirectory',action='store',default='input/',help="Directory path to the input, must finish with /",type=str)
    parser.add_argument('-pps','--packetsPerSecond',dest='pps',default=1500,type=int,help="Mean of the packets per second of the attack")
    parser.add_argument('-dpps''--desv_packets_per_second',dest='des',default=500,type=int,help="Standard desviation of the packets per second of the attack")
    parser.add_argument('-fi','--file_input',dest='fileInput',action='store',default='',help="Input pcap file name with his extension",type=str)
    parser.add_argument('-ti','--initial_time',dest='ti',action='store',default=0,help='Initial time of the attack, when the first attack packet will be introduced, measured in seconds and by default is 0',type=int)
    parser.add_argument('-dt','--duration',dest='duration',action='store',default=1,help='The time duration of the attack, also measured in second and by default is 1',type=int)
    parser.add_argument('-ipn','--ip_number',dest='numberIp',action='store',default=1,help="Number of ip's of the botnet, if it's 1 the type of attack is DOS. By default is 1.",type=int)
    parser.add_argument('-do','--directory_output',dest='outputDirectory',action='store',default='output/',help='Path to the output directory of modified pcap file',type=str)
    parser.add_argument('-time','--timestamp',dest='timestamp',action='store',default=0.01,help='Time for the measure window when the server is going or not to be down, this time is on seconds, for default is 0.01',type=float)
    parser.add_argument('-tol','--tolerance',dest='tolerance',action='store',default=42,help='Server number of packets per the time of measure window, by default is 42',type=int)
    parser.add_argument('-sip','--server_ip',dest='serverIp',action='store',default="200.7.4.7",help="DNS server's ip, by default is 200.7.4.7",type=str)
    arguments = parser.parse_args()
    if arguments.timestamp >= 1.00:
        arguments.timestamp = 1.00
        print("Warning! Changed the timestamp to one second!")
    main(arguments)