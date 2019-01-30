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
## arreglo global con las ips
ipsBot =  []
def createInserterPackets(args: list):
    """
        Adapter for the inserter argument to create the packets of the tcp syn attack of one second
        args[0] is the file directory
        args[1] is the destination ip of the packet
        args[2] is the mean of the number of packets per second of the attack
        args[3] is the standard desviation of the packets per second
        args[4] is the initial time of the time window that the packets will be created
        args[5] is the window time size for the packets to create
        args[6] is the number of ip's to generate
        :param: args: list: the arguments to pass for the function to create the packets
    """
    assert len(args) >= 7
    fileDir = args[0]
    dip = args[1]
    pps = args[2]
    despps = args[3]
    ti = args[4]
    dt = args[5]
    nip = args[6]
    return createPackets(fileDir,dip,pps,despps,ti,dt,nip)

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
    global ipsBot
    print("Creating Packets")
    #### First we create a list of random ip's
    first = sniff(offline=fileDirectionName,count=1)
    ti = first[0].time + initialTime
    pkts = []
    if len(ipsBot) == 0:
        ipsBot = ipg.randomIP(numberIp,time.time(),True)
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
            k = random.randint(0,len(ipsBot)-1)
            sip = ipsBot[k]
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
def main(args):
    """
    Main function of the program, generates the output file on the
    output folder.
    :param args:list :  the arguments given by console.
    :return: 0 if everything goes ok!, 1 otherwise
    """
    ##### Reading the inputs from the user
    inputNameDir = args.fileInput
    outNameDir = args.fileOutput
    numberOfIp = args.numberIp
    initialTime = args.it
    duration = args.duration
    timestamp = args.timestamp
    tolerance = args.tolerance
    pps = args.pps
    despps = 250
    ##### Generating the files of the output
    destinyIP = args.serverIp
    direction = inputNameDir
    output = outNameDir

    ##### Getting prepared for generating the attack
    first = sniff(offline=inputNameDir,count=1)
    if len(first)== 0:
        ti = initialTime
    else:
        ti=first[0].time + initialTime #pkts=createPackets(direction,destinyIP,pps,despps,initialTime,duration,numberOfIp)
    #print("Number of attack packets: "+str(len(pkts)))
    #print("Number of packets created: "+str(2*len(pkts)))
    arguments = []
    i = 0
    while i < duration:
        anArgument = [direction,destinyIP,pps,despps,ti+i,1,numberOfIp]
        arguments.append(anArgument)
        i+=1
    ##### Insertion of the packets generated
    print("Inserting packets on the modified pcap")
    ins = PacketInserter()
    operation = ins.withArgs(arguments)\
                .withQuantity(1)\
                .withPcapInput(direction)\
                .withPcapOutput(output)\
                .withServerIp(destinyIP)\
                .withResponseDt(0.0066541468651955095)\
                .withTimestamp(timestamp)\
                .withServerTolerance(tolerance)\
                .insert(createInserterPackets)
    ####Seeing that everything is ok
    if operation:
        print("Packets Inserted")
        return 0
    return 1
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description = "TCP-SYN Flood attack simulation")
    parser.add_argument('-n','--num_packets',dest='pps',default=3500,type=int,help="Mean of the packets per second of the attack")
    parser.add_argument('-i','--input_file',dest='fileInput',action='store',default='',help="Input pcap file name with his extension",type=str)
    parser.add_argument('-it','--initial_time',dest='it',action='store',default=0,help='Initial time of the attack, when the first attack packet will be introduced, measured in seconds and by default is 0',type=int)
    parser.add_argument('-d','--duration',dest='duration',action='store',default=1,help='The time duration of the attack, also measured in second and by default is 1',type=int)
    parser.add_argument('-z','--zombies',dest='numberIp',action='store',default=1,help="Number of ip's of the botnet, if it's 1 the type of attack is DOS. By default is 1.",type=int)
    parser.add_argument('-o','--output',dest='fileOutput',action='store',default='output/',help='Path to the output directory of modified pcap file',type=str)
    parser.add_argument('-w','--window_size',dest='timestamp',action='store',default=0.01,help='Time for the measure window when the server is going or not to be down, this time is on seconds, for default is 0.01',type=float)
    parser.add_argument('-p','--packets_per_window',dest='tolerance',action='store',default=100,help='Server number of packets per the time of measure window, by default is 100',type=int)
    parser.add_argument('-s','--server_ip',dest='serverIp',action='store',default="200.7.4.7",help="DNS server's ip, by default is 200.7.4.7",type=str)
    arguments = parser.parse_args()
    if arguments.timestamp >= 1.00:
        arguments.timestamp = 1.00
        print("Warning! Changed the timestamp to one second!")
    main(arguments)
