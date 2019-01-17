from scapy.all import *
import math
import sys
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
        self.__serverIp = "200.7.4.7"
        self.__responseDt= 0.0006
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
    def _insertAttackPacket(self,writer: PcapWriter,bufferAttackResponse: list,bufferFileResponse: list,attacksAdded: int, resetCount: int,delay: float,numberOfQueries: int,actualTime: float):
        """
            Refactor function for inserting attack packets on the pcap file
            :param writer:PcapWriter: the writer of the file
            :param attacksAdded:int: the number of attack to added so far
            :param resetCount:int: the count for reseting the writer on the algorithm
            :return: tuple of the new counters for packets added 
        """
        queriePacket = self.__packetsToAppend[0][0]
        responseBuffer = self._minTimeList(bufferFileResponse,bufferAttackResponse)
        if responseBuffer == None:
            actualTime = queriePacket.time
            writer.write(queriePacket)
            if len(self.__packetsToAppend[0]) == 2:
                response = self.__packetsToAppend[0][1]
                response.time += delay
                bufferAttackResponse.append(response)
            self.__packetsToAppend.pop(0)
            attacksAdded+=1
            resetCount+=1
            numberOfQueries+=1
            return (attacksAdded,resetCount,numberOfQueries,actualTime)
        if queriePacket.time < responseBuffer[0].time:
            actualTime = queriePacket.time
            writer.write(queriePacket)
            if len(self.__packetsToAppend[0]) == 0:
                response = self.__packetsToAppend[0][1]
                response.time +=delay
                bufferAttackResponse.append(response)
            self.__packetsToAppend.pop(0)
            attacksAdded+=1
            resetCount+=1
            numberOfQueries+=1
            return (attacksAdded,resetCount,numberOfQueries,actualTime)
        else:
            actualTime = responseBuffer[0].time
            writer.write(responseBuffer[0])
            responseBuffer.pop(0)
            resetCount+=1
            return (attacksAdded,resetCount,numberOfQueries,actualTime)
    def _minTimeList(self,bufferFileResponse: list, bufferAttackResponse: list):

        if len(bufferFileResponse)==0 and len(bufferAttackResponse)==0:
            return None
        if len(bufferFileResponse)==0:
            return bufferAttackResponse
        if len(bufferAttackResponse)==0:
            return bufferFileResponse
        else:
            if bufferFileResponse[0].time < bufferAttackResponse[0].time:
                return bufferFileResponse
            else:
                return bufferAttackResponse
    def _delayInsert(self,writer: PcapWriter,bufferToAppend: list,bufferFileResponse: list,bufferAttackResponse:list,count: int,delay: float,numberOfQueries: int, actualTime: float):
        pktToInsert=bufferToAppend[0]
        if pktToInsert.getlayer(IP).src == self.__serverIp: ## Soy respuesta del servidor
            actualTime = pktToInsert.time
            pktToInsert.time += delay
            bufferFileResponse.append(pktToInsert)
            bufferToAppend.pop(0)
            return (count,numberOfQueries,actualTime)
        ### If the pkt to insert is a querie
        bufferResponse = self._minTimeList(bufferFileResponse,bufferAttackResponse)
        if bufferResponse == None:
            actualTime = bufferToAppend[0].time
            writer.write(bufferToAppend[0])
            bufferToAppend.pop(0)
            return (count+1,numberOfQueries+1,actualTime)
        else:
            if pktToInsert.time < bufferResponse[0].time:
                actualTime = bufferToAppend[0].time
                writer.write(bufferToAppend[0])
                bufferToAppend.pop(0)
                return (count+1,numberOfQueries+1,actualTime)
            else:
                
                actualTime = bufferResponse[0].time
                writer.write(bufferResponse[0])
                bufferResponse.pop(0)
                return (count + 1,numberOfQueries,actualTime)
                
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
            bufferResponseFile = [] # buffer for the server responses of the file with the delay added
            bufferAttackResponse = [] # buffer for the server responses of the attack with the delay added
            
            #### Preparing the delay variables
            ti = 0 #Number of second passed from the first querie readed
            ta = ti #Time of the last package received
            queries = 0 # number of queries without response
            #### Preparing variables to insert the packets
            numPktsIns = len(self.__packetsToAppend)
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
            j=0 # counter of how many attack packets have been added
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
                if count == 50000:
                    writer.close()
                    del writer
                    writer = PcapWriter(outputDirection,append=True,sync=True)
                    count = 0 
                if pktRead == None:
                    break

                #### Putting the packet readed to a buffer.
                buffer.append(pktRead)

                #### Inserting packets on the new pcap file in time order.
                if j < numPktsIns and buffer[0].time>self.__packetsToAppend[0][0].time: ## Comparing the time of the buffer of the file with the buffer of the attack
                    (j,count,queries,ta) = self._insertAttackPacket(writer,bufferAttackResponse,bufferResponseFile,j,count,delay,queries,ta) 
                else:
                    ### Changed
                    (count,queries,ta) = self._delayInsert(writer,buffer,bufferResponseFile,bufferAttackResponse,count,delay,queries,ta)
                    
            #### Loop for adding the rest of the packets when the file is all readed
            #### Ends when all the packets of the buffer are written or all the packets
            #### Of the attack are written
            while len(buffer)!= 0 and j<numPktsIns:
                dt = math.ceil(ta-ti)
                if dt == 0:
                    dt = 1
                pps = queries/dt
                delay = self._calculateDelay(pps)
                #### Checking the writer restart condition
                if count == 50000:
                    del writer
                    writer = PcapWriter(outputDirection,append=True,sync=True)
                    count = 0

                #### Comparing and inserting
                if j < numPktsIns and buffer[0].time>self.__packetsToAppend[0][0].time:
                    (j,count,queries,ta) = self._insertAttackPacket(writer,bufferAttackResponse,bufferResponseFile,j,count,delay,queries,ta) 
                else:
                    (count,queries,ta) = self._delayInsert(writer,buffer,bufferResponseFile,bufferAttackResponse,count,delay,queries,ta)

            #### These loops are for adding the packets left of one type, attacker or buffer.
            #### So just one of these loops are going to be executed
            while j<numPktsIns:
                dt = math.ceil(ta-ti)
                if dt == 0:
                    dt = 1
                pps = queries/dt
                delay = self._calculateDelay(pps)
                if count == 50000:
                    writer.close()
                    del writer
                    writer = PcapWriter(outputDirection,append=True,sync=True)
                    count = 0 
                (j,count,queries,ta) = self._insertAttackPacket(writer,bufferAttackResponse,bufferResponseFile,j,count,delay,queries,ta) 
            while len(buffer)!=0:
                dt = math.ceil(ta-ti)
                if dt == 0:
                    dt = 1
                pps = queries/dt
                delay = self._calculateDelay(pps)
                if count == 50000:
                    writer.close()
                    del writer
                    writer = PcapWriter(outputDirection,append=True,sync=True)
                    count = 0 
                (count,queries,ta) = self._delayInsert(writer,buffer,bufferResponseFile,bufferAttackResponse,count,delay,queries,ta)
            while len(bufferResponseFile)!=0 and len(bufferAttackResponse)!=0:
                if count == 50000:
                    writer.close()
                    del writer
                    writer = PcapWriter(outputDirection,append=True,sync=True)
                    count = 0
                if bufferResponseFile[0].time < bufferAttackResponse[0].time:
                    writer.write(bufferResponseFile[0])
                    bufferResponseFile.pop(0)
                    count+=1
                else:
                    writer.write(bufferAttackResponse[0])
                    bufferAttackResponse.pop(0)
                    count+=1
            while len(bufferResponseFile)!=0:
                if count == 50000:
                    writer.close()
                    del writer
                    writer = PcapWriter(outputDirection, append=True,sync=True)
                    count = 0
                writer.write(bufferResponseFile[0])
                bufferResponseFile.pop(0)
                count+=1
            while len(bufferAttackResponse)!= 0:
                if count == 50000:
                    writer.close()
                    del writer
                    writer = PcapWriter(outputDirection, append = True,sync = True)
                    count = 0
                writer.write(bufferAttackResponse[0])
                bufferAttackResponse.pop(0)
                count+=1
            #### We close the writer and return true because everything goes as planned
            writer.close()
            return True
        ## TODO falta una pasada por los buffer de responses
        except FileNotFoundError:
            #### If the file does not exist, we return false because something went wrong
            print("Error file not found")
            return False
        except:
            #### If something went wrong, we return false
            print("Something went wrong")
            return False
