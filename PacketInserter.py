from scapy.all import *
import math
import sys
import states.InserterState as state

  

"""
Packet inserter, inserts packets for the attack simulation
and creates a new pcap file with the attacks given.
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
            :param: timestamp is the time period where the buffer will be measuring
            :param: serverTolerance is the number of querie's by the timestamp defined that the server
                                    can handle
        """   
        self.__packetsToAppend=[]
        self.__input=""
        self.__output=""
        self.__inputDir=""
        self.__outputDir=""
        self.__serverIp = "200.7.4.7"
        self.__responseDt= 0.006
        self.__state = state.ReadOkState(self)
        self.__timestamp = 0.001
        self.__serverTolerance = 30
    def getTimestamp(self):
        """
            Getter for the timestamp field of the object
            :return: the timestamp defined on in an object instance
        """
        return self.__timestamp
    def getServerTolerance(self):
        """
            Getter for the server tolerance
            :return: the server tolerance
        """
        return self.__serverTolerance
    def changeState(self,anotherState):
        """
            Changes the state that the inserter currently have for 
            another new state.
            :param: anotherState is the new state of the inserter
        """
        self.__state = anotherState 
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
    def getResponseDt(self):
        """
            Getter for delay of the response number
        """   
        return self.__responseDt
    def getServerIp(self):
        """
            Get the server Ip to see what packets are response one's
            :return: the ip of the server set
        """
        return self.__serverIp
    def getState(self):
        """
            Getter for the currently state of the inserter.
            :return: the current state
        """ 
        return self.__state
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
    def withServerIp(self,ip: str):

        self.__serverIp = ip
        return self
    def withResponseDt(self,dt: float):
        """
            Setter for the request response dt, base it calculation for the delay time
        """
        self.__responseDt = dt
        return self
    def withTimestamp(self, timestamp: float):
        """
            Setter for the server timestamp, this is, the number of seconds that the medition for the 
            server tolerance will have. For example, if the timestamp is 0.01, the buffers on the inserter will
            get only packets of a time interval of timestamp seconds. It have to be measured in seconds
        """
        self.__timestamp = timestamp
        return self
    def withServerTolerance(self, tolerance: int):
        """
            Setter for the server tolerance, this is, given the timestamp of the medition, the server can
            receive a maximum number of tolerance queries in that timestamp.
            For example, if the timestamp is 0.01 seconds and the tolerance is 30, the server can't get more than
            30 queries in 0.01 seconds of data analisis.
            :param: tolerance: int: maximum number of queries that the server can get in the timestamp given
        """
        self.__serverTolerance = tolerance
        return self
    def _calculateDelay(self,pktsPerSecond: float):
        """
            Calculates the time to add for the delay given the response dt.
            :return: the time of delay of the packet
        """
        porcentage = 0
        if pktsPerSecond >= 1000:
            porcentage = 0.5
        if pktsPerSecond >= 2000:
            porcentage = 0.8
        if pktsPerSecond >= 3000:
            porcentage = 1.5
        if pktsPerSecond >= 4000:
            porcentage = 1.7
        if pktsPerSecond >= 5000:
            porcentage = 2.3
        delay = self.__responseDt * porcentage
        return delay 
    def insert(self):
        """
            Insert the packages given to the pcap file mentioned, (if the output
            file exists already, it will be overwritten)
            from the pcap original file. At the end, the list to append will be empty, so be careful.
            :return: True if the file was succesfully generated, False if a problem happened
        """
        try:
            #### Preparing the buffers for insertion
            buffer = [] # normal buffer for the reader of the file
            bufferResponse = [] # buffer for the responses
            bufferQueries = [] # buffer for the queries
            noResponse = {} # dictionary for the queries with no responses
            #### Preparing the delay variables
            ti = 0 #Number of second passed from the first querie readed
            ta = ti #Time of the last package received
            queries = 0 # number of queries without response
            
            #### Preparing variables to insert the packets  
            inputDirection = self.__inputDir+self.__input
            outputDirection = self.__outputDir+self.__output
            count = 0 #Counter, resets the writer in order to not persue a memory failure of writing
            wrpcap(outputDirection,PacketList()) #Cleans the pcap output file.
            reader = PcapReader(inputDirection)
            writer = PcapWriter(outputDirection,append=True,sync=True)
            first = reader.read_packet()
            ti = first.time
            ta = ti
            buffer.append(first)
            #### Loop for the slow reading and writing of the packet
            while True:
                #### Calculating the delay of the response
                dt = math.ceil(ta-ti)
                if dt == 0:
                    dt = 1
                pps = queries/dt
                delay = self._calculateDelay(pps)
                
                #### Reading one packet from the original file
                pktRead = reader.read_packet()
                #### Checking the condition to reset the writer for overflow bug or
                #### ending the loop
                if pktRead == None:
                    break

                #### Processing the data readed and their value.
                buffer.append(pktRead)
                (count,queries,ta,writer) = self.__state.processData(buffer,self.__packetsToAppend,bufferQueries,bufferResponse,noResponse,delay,[count,queries,outputDirection], writer)
            
            ## We have readed all the pcap, we eliminate the reader resources
            del reader
        
            ### Processing the data that have not been written on the pcap file and it's still in the buffer
            while len(buffer) != 0 and len(self.__packetsToAppend) != 0:
                dt = math.ceil(ta-ti)
                if dt == 0:
                    dt = 1
                pps = queries / dt
                delay = self._calculateDelay(pps)
                (count,queries,ta,writer) = self.__state.processData(buffer,self.__packetsToAppend,bufferQueries,bufferResponse,noResponse,delay,[count,queries,outputDirection], writer)
            ### Checking if some buffer it's not emptied
            while len(buffer) != 0:
                dt = math.ceil(ta-ti)
                if dt == 0:
                    dt = 1
                pps = queries / dt
                delay = self._calculateDelay(pps)
                (count,queries,ta,writer) = self.__state.processData(buffer,self.__packetsToAppend,bufferQueries,bufferResponse,noResponse,delay,[count,queries,outputDirection], writer)

            while len(self.__packetsToAppend) != 0:
                dt = math.ceil(ta-ti)
                if dt == 0:
                    dt = 1
                pps = queries / dt
                delay = self._calculateDelay(pps)
                (count,queries,ta,writer) = self.__state.processData(buffer,self.__packetsToAppend,bufferQueries,bufferResponse,noResponse,delay,[count,queries,outputDirection], writer)
            ## Writing on the file of the buffers needed
            while len(bufferQueries) != 0 and len(bufferResponse) != 0:
                if count == 50000:
                    writer.close()
                    del writer
                    writer = PcapWriter(outputDirection,append = True, sync = True)
                    count = 0 
                if bufferQueries[0].time < bufferResponse[0].time:
                    writer.write(bufferQueries[0])
                    bufferQueries.pop(0)
                    count +=1
                else:
                    writer.write(bufferResponse[0])
                    bufferResponse.pop(0)
                    count +=1
            while len(bufferQueries) != 0:
                if count == 50000:
                    writer.close()
                    del writer
                    writer = PcapWriter(outputDirection,append = True, sync = True)
                    count = 0
                writer.write(bufferQueries[0])
                bufferQueries.pop(0)
                count+=1
            while len(bufferResponse) != 0:
                if count == 50000:
                    writer.close()
                    del writer
                    writer = PcapWriter(outputDirection,append = True,sync = True)
                    count = 0
                writer.write(bufferResponse[0])
                bufferResponse.pop(0)
                count += 1
            
            #### We close the writer and return true because everything goes as planned
            writer.close()
            return True
        except FileNotFoundError:
            #### If the file does not exist, we return false because something went wrong
            print("Error file not found")
            return False