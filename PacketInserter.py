from scapy.all import *
"""
Packet inserter, inserts packets for the attack simulation
and creates a new pcap file with the attacks given
@author: Joaquin Cruz
"""
class PacketInserter:
    def __init__(self):
        """
            Creates a default packet inserter.
            :param: packetsToAppend is the tuple (request,response) list for the packets that
            will be added to the pcap file
            :param: input is the name of the pcap file with it's extension
            :param: output is the of the output pcap file with it's extension
            :param: inputDir is the relative path to the input file, it finishes with /
            :param: outputDir is the relative path to the output file directory, it also finishes with /
            :param: delayResponse is the delays of the response time of the server 
        """   
        self.__packetsToAppend=[]
        self.__input=""
        self.__output=""
        self.__inputDir=""
        self.__outputDir=""
        self.__delayResponse=float(0)
    def getPacketsToAppend(self):
        """
            Getter for the packet list
        """   
        return self.__packetsToAppend
    def getInputName(self):
        """
            Getter for the input file name
        """   
        return self.__input
    def getOutputName(self):
        """
            Getter for the output file name field
        """   
        return self.__output
    def getInputDir(self):
        """
            Getter for the input file path
        """   
        return self.__inputDir
    def getOutputDir(self):
        """
            Getter for the output file path
        """   
        return self.__outputDir
    def getDelay(self):
        """
            Getter for delay of the response number
        """   
        return self.__delayResponse
    def withPackets(self,packets: list):
        """
            Sets the list to packets to be inserted in the pcap file,
            it has to be a list of tuples (request,response). 
            :param packets:list: the list of packets that will be inserted
            :return: a reference to the object
        """   
        self.__packetsToAppend = packets
        return self
    def withPcapInput(self,input: str):
        """ 
            Defines the input file that is going to be given
            :param input:str: the name with the extension of the input file
            :return: a reference to the inserter
        """   
        self.__input=input
        return self
    def withPcapOutput(self,output: str):
        """
            Establishes the output pcap file name, has to be with the .pcap extension
            :param output:str:
            :return: a reference to the inserter
        """   
        self.__output=output
        return self
    def withInputDir(self,inputDir: str):
        """ 
            Give the path where the input file is
            :param inputDir:str: the input file path
            :return: a reference to the inserter
        """   
        self.__inputDir = inputDir
        return self
    def withOutputDir(self,outputDir: str):
        """
            Defines the output file path where is going to be
            created
            :param outputDir:str: the output file path
            :return: the packet inserted used
        """   
        self.__outputDir=outputDir
        return self
    def withDelay(self,delay: float):
        """
            Gives a delay to the server responses, for now only to the
            packets created
            :param delay:float: the delay time of the server
            :return: the inserter 
        """   
        self.__delayResponse=delay
        return self
    def addDelay(self,ddelay: float):
        """
            add a finite number to the delay parameter to the server response for the queries
            :param ddelay:float: the amount to add to the delay
            :return: a packet inserter reference
        """   
        self.__delayResponse+=ddelay
        return self
    def _insertAttackPacket(self,writer: PcapWriter,attacksAdded: int, resetCount: int):
        """
        docstring here
            :param self: 
            :param writer:PcapWriter: 
            :param attacksAdded:int: 
            :param resetCount:int: 
            :return: 
        """   
        aPacket = self.__packetsToAppend[0][0]
        writer.write(aPacket)
        if len(self.__packetsToAppend[0]) == 2:
            response = self.__packetsToAppend[0][1]
            response.time+=self.__delayResponse
            writer.write(response)
        self.__packetsToAppend.pop(0)
        attacksAdded+=1
        resetCount+=1
        return (attacksAdded,resetCount)
    
    def insert(self):
        """
            Insert the packages given to the pcap file mentioned, (if the output
            file exists already, it will be overwritten)
            from the pcap original file. At the end, the list to append will be empty, so be careful.
            :return: True if the file was succesfully generated
        """
        try:
            numPktsIns = len(self.__packetsToAppend)
            inputDirection = self.__inputDir+self.__input
            outputDirection = self.__outputDir+self.__output
            count = 0 #Counter, resets the writer in order to not persue a memory failure of writing
            wrpcap(outputDirection,PacketList()) #Cleans the pcap output file.
            reader = PcapReader(inputDirection)
            writer = PcapWriter(outputDirection,append=True,sync=True)
            buffer = []
            first = reader.read_packet()
            buffer.append(first)
            j=0
            while True:
                pktRead = reader.read_packet()
                if count == 50000:
                    del writer
                    writer = PcapWriter(outputDirection,append=True,sync=True)
                    count = 0 
                if pktRead == None:
                    break
                buffer.append(pktRead)
                if j < numPktsIns and buffer[0].time>self.__packetsToAppend[0][0].time:
                    (j,count) = self._insertAttackPacket(writer,j,count) #writes the attack packets on the file
                else: #we write the file packet into the new file
                    writer.write(buffer[0])
                    buffer.pop(0)
                    count+=1
            while len(buffer)!= 0 and j<numPktsIns:
                if count == 50000:
                    del writer
                    writer = PcapWriter(outputDirection,append=True,sync=True)
                    count = 0
                if j < numPktsIns and buffer[0].time>self.__packetsToAppend[0][0].time:
                    (j,count) = self._insertAttackPacket(writer,j,count)
                else:
                    writer.write(buffer[0])
                    count+=1
                    buffer.pop(0)
            while j<numPktsIns:
                if count == 50000:
                    del writer
                    writer = PcapWriter(outputDirection,append=True,sync=True)
                    count = 0 
                (j,count) = self._insertAttackPacket(writer,j,count)
            while len(buffer)!=0:
                if count == 50000:
                    del writer
                    writer = PcapWriter(outputDirection,append=True,sync=True)
                    count = 0 
                writer.write(buffer[0])
                count+=1
                buffer.pop(0)
            return True
        except FileNotFoundError:
            raise Exception("Asegurese que el archivo de input exista")