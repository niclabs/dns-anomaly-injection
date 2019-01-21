from scapy.all import *
import math
import sys
import states.InserterState as state
import states.ReadOkState as OkState
import states.ReadNOkState as NOkState
import states.FileInsertState as InsState
  

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
        self.__state = OkState.ReadOkState(self)
        self.__timestamp = 0.001
        self.__serverTolerance = 30
    def getTimestamp(self):
        
        return self.__timestamp
    def getServerTolerance(self):

        return self.__serverTolerance
    def changeState(self,anotherState):

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

        self.__timestamp = timestamp
        return self
    def withServerTolerance(self, tolerance: int):
        
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
            ### TODO cambiar esto a que sea del inserter mismo
            timestamp = 0.01
            serverManagement = 10
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

                #### Putting the packet readed to a buffer for the file
                buffer.append(pktRead)
                ### Algoritmo de descarte he insercion, podemos hacer refactor con state pattern
                if len(self.__packetsToAppend)==0 or buffer[0].time <= self.__packetsToAppend[0][0].time: ### if we have to put the pcap packet on some buffer
                    ta = buffer[0].time
                    if buffer[0].getlayer(IP).src == self.__serverIp:
                        buffer[0].time += delay
                        if (not buffer[0].haslayer(DNS)) or (buffer[0].getlayer(DNS).id not in noResponse):
                            bufferResponse.append(buffer[0])
                        buffer.pop(0)
                    else:
                        if len(bufferQueries) == 0:
                            bufferQueries.append(buffer[0])
                            buffer.pop(0)
                        else:
                            t0 = bufferQueries[0].time
                            dtInsert = ta-t0 ## veo la diferencia de tiempos
                            while dtInsert >= timestamp and len(bufferQueries) != 0:
                                t0 = bufferQueries[0].time
                                dtInsert = ta-t0
                                if count == 50000:
                                    writer.close()
                                    del writer
                                    writer = PcapWriter(outputDirection,append=True,sync=True)
                                    count = 0
                                if len(bufferResponse) == 0:
                                    pkt = bufferQueries[0]
                                    writer.write(pkt)
                                    bufferQueries.pop(0)
                                else:
                                    if bufferQueries[0].time < bufferResponse[0].time:
                                        pkt = bufferQueries[0]
                                        writer.write(pkt)
                                        bufferQueries.pop(0)
                                    else:
                                        pkt = bufferResponse[0]
                                        writer.write(pkt)
                                        bufferResponse.pop(0) 
                                count+=1
                            if len(bufferQueries) > serverManagement and buffer[0].haslayer(DNS):
                                noResponse[buffer[0].getlayer(DNS).id] = buffer[0].time
                            bufferQueries.append(buffer[0])
                            buffer.pop(0)
                        queries+=1
                elif len(self.__packetsToAppend)!=0:
                    ta = self.__packetsToAppend[0][0].time
                    if self.__packetsToAppend[0][0].haslayer(DNS): ## veo si el servidor lo acepta o ignora de la misma manera que antes
                        if len(bufferQueries) == 0:
                            bufferQueries.append(self.__packetsToAppend[0][0])
                            bufferResponse.append(self.__packetsToAppend[0][1])
                            self.__packetsToAppend.pop(0)
                        else:
                            t0 = bufferQueries[0].time
                            dtInsert = ta-t0
                            while dtInsert >=timestamp and len(bufferQueries)!= 0:
                                t0 = bufferQueries[0].time
                                dtInsert = ta-t0
                                if count == 50000:
                                    writer.close()
                                    del writer
                                    writer = PcapWriter(outputDirection,append=True,sync=True)
                                    count = 0
                                if len(bufferResponse) == 0:
                                    pkt = bufferQueries[0]
                                    writer.write(pkt)
                                    bufferQueries.pop(0)
                                else:
                                    if bufferQueries[0].time < bufferResponse[0].time:
                                        pkt = bufferQueries[0]
                                        writer.write(pkt)
                                        bufferQueries.pop(0)
                                    else:
                                        pkt = bufferResponse[0]
                                        writer.write(pkt)
                                        bufferResponse.pop(0) 
                                count+=1
                            bufferQueries.append(self.__packetsToAppend[0][0])
                            if len(bufferQueries) < serverManagement and len(self.__packetsToAppend[0]) == 2:
                                res = self.__packetsToAppend[0][1]
                                res.time += delay
                                bufferResponse.append(res)
                            self.__packetsToAppend.pop(0)
                            
                    else: ### Si es no tiene DNS lo dejamos pasar.   
                        bufferQueries.append(self.__packetsToAppend[0][0])
                        if len(self.__packetsToAppend[0]) == 2:
                            bufferResponse.append(self.__packetsToAppend[0][1])
                        self.__packetsToAppend.pop(0)
                    queries+=1
            #######################################
            while len(buffer) != 0 and len(self.__packetsToAppend)!= 0: ## Leo lo que resta del archivo
                #### Calculating the delay of the response
                dt = math.ceil(ta-ti)
                if dt == 0:
                    dt = 1
                pps = queries/dt
                delay = self._calculateDelay(pps)
                if buffer[0].time <= self.__packetsToAppend[0][0].time:
                    ta = buffer[0].time
                    if buffer[0].getlayer(IP).src == self.__serverIp:
                        buffer[0].time+=delay
                        if (not buffer[0].haslayer(DNS)) or (buffer[0].getlayer(DNS).id not in noResponse):
                            bufferResponse.append(buffer[0])
                        buffer.pop(0)
                    else:
                        if len(bufferQueries) == 0:
                            bufferQueries.append(buffer[0])
                            buffer.pop(0)
                        else:
                            t0 = bufferQueries[0].time
                            dtInsert = ta - t0
                            while dtInsert >= timestamp and len(bufferQueries)!=0:
                                t0 = bufferQueries[0].time
                                dtInsert = ta - t0
                                if count == 50000:
                                    writer.close()
                                    del writer
                                    writer = PcapWriter(outputDirection,append=True,sync=True)
                                    count = 0
                                if len(bufferResponse) == 0:
                                    pkt = bufferQueries[0]
                                    writer.write(pkt)
                                    bufferQueries.pop(0)
                                else:
                                    if bufferQueries[0].time < bufferResponse[0].time:
                                        pkt = bufferQueries[0]
                                        writer.write(pkt)
                                        bufferQueries.pop(0)
                                    else:
                                        pkt = bufferResponse[0]
                                        writer.write(pkt)
                                        bufferResponse.pop(0)
                                count += 1
                            if len(bufferQueries) > serverManagement and buffer[0].haslayer(DNS):
                                noResponse[buffer[0].getlayer(DNS).id] = buffer[0].time
                            bufferQueries.append(buffer[0])
                            buffer.pop(0)
                        queries+=1
                else:
                    ta = self.__packetsToAppend[0][0].time
                    if self.__packetsToAppend[0][0].haslayer(DNS): ## veo si el servidor lo acepta o ignora de la misma manera que antes
                        if len(bufferQueries) == 0:
                            bufferQueries.append(self.__packetsToAppend[0][0])
                            bufferResponse.append(self.__packetsToAppend[0][1])
                            self.__packetsToAppend.pop(0)
                        else:
                            t0 = bufferQueries[0].time
                            dtInsert = ta-t0
                            while dtInsert >=timestamp and len(bufferQueries)!=0:
                                t0 = bufferQueries[0].time
                                dtInsert = ta-t0
                                if count == 50000:
                                    writer.close()
                                    del writer
                                    writer = PcapWriter(outputDirection,append=True,sync=True)
                                    count = 0
                                if len(bufferResponse) == 0:
                                    pkt = bufferQueries[0]
                                    writer.write(pkt)
                                    bufferQueries.pop(0)
                                else:
                                    if bufferQueries[0].time < bufferResponse[0].time:
                                        pkt = bufferQueries[0]
                                        writer.write(pkt)
                                        bufferQueries.pop(0)
                                    else:
                                        pkt = bufferResponse[0]
                                        writer.write(pkt)
                                        bufferResponse.pop(0) 
                                count+=1
                            bufferQueries.append(self.__packetsToAppend[0][0])
                            if len(bufferQueries) < serverManagement and len(self.__packetsToAppend[0]) == 2:
                                res = self.__packetsToAppend[0][1]
                                res.time += delay
                                bufferResponse.append(res)
                            self.__packetsToAppend.pop(0)
                            
                    else: ### Si es no tiene DNS lo dejamos pasar.   
                        bufferQueries.append(self.__packetsToAppend[0][0])
                        if len(self.__packetsToAppend[0]) == 2:
                            bufferResponse.append(self.__packetsToAppend[0][1])
                        self.__packetsToAppend.pop(0)
                    queries+=1
            print("hola1")
            ## TODO esto va a hacer cambiado cuando tenga varios archivos
            while len(buffer)!=0:
                #### Calculating the delay of the response
                dt = math.ceil(ta-ti)
                if dt == 0:
                    dt = 1
                pps = queries/dt
                delay = self._calculateDelay(pps)
                ta = buffer[0].time
                if buffer[0].getlayer(IP).src == self.__serverIp:
                    buffer[0].time+=delay
                    if (not buffer[0].haslayer(DNS)) or (buffer[0].getlayer(DNS).id not in noResponse):
                        bufferResponse.append(buffer[0])
                    buffer.pop(0)
                else:
                    if len(bufferQueries) == 0:
                        bufferQueries.append(buffer[0])
                        buffer.pop(0)
                    else:
                        t0 = bufferQueries[0].time
                        dtInsert = ta - t0
                        while dtInsert >= timestamp and len(bufferQueries)!= 0:
                            t0 = bufferQueries[0].time
                            dtInsert = ta - t0
                            if count == 50000:
                                writer.close()
                                del writer
                                writer = PcapWriter(outputDirection,append=True,sync=True)
                                count = 0
                            if len(bufferResponse) == 0:
                                pkt = bufferQueries[0]
                                writer.write(pkt)
                                bufferQueries.pop(0)
                            else:
                                if bufferQueries[0].time < bufferResponse[0].time:
                                    pskt = bufferQueries[0]
                                    writer.write(pkt)
                                    bufferQueries.pop(0)
                                else:
                                    pkt = bufferResponse[0]
                                    writer.write(pkt)
                                    bufferResponse.pop(0)
                            count += 1
                        if len(bufferQueries) > serverManagement and buffer[0].haslayer(DNS):
                            noResponse[buffer[0].getlayer(DNS).id] = buffer[0].time
                        bufferQueries.append(buffer[0])
                        buffer.pop(0)
                    queries+=1
            print("hola2")
            ### TODO esto va a hacer cambiado cuando tenga varios archivos.
            while len(self.__packetsToAppend)!= 0:
                ta = self.__packetsToAppend[0][0].time
                if self.__packetsToAppend[0][0].haslayer(DNS): ## veo si el servidor lo acepta o ignora de la misma manera que antes
                    if len(bufferQueries) == 0:
                        bufferQueries.append(self.__packetsToAppend[0][0])
                        bufferResponse.append(self.__packetsToAppend[0][1])
                        self.__packetsToAppend.pop(0)
                    else:
                        t0 = bufferQueries[0].time
                        dtInsert = ta-t0
                        while dtInsert >=timestamp and len(bufferQueries)!= 0:
                            t0 = bufferQueries[0].time
                            dtInsert = ta-t0
                            if count == 50000:
                                writer.close()
                                del writer
                                writer = PcapWriter(outputDirection,append=True,sync=True)
                                count = 0
                            if len(bufferResponse) == 0:
                                pkt = bufferQueries[0]
                                writer.write(pkt)
                                bufferQueries.pop(0)
                            else:
                                if bufferQueries[0].time < bufferResponse[0].time:
                                    pkt = bufferQueries[0]
                                    writer.write(pkt)
                                    bufferQueries.pop(0)
                                else:
                                    pkt = bufferResponse[0]
                                    writer.write(pkt)
                                    bufferResponse.pop(0) 
                            count+=1
                        bufferQueries.append(self.__packetsToAppend[0][0])
                        if len(bufferQueries) < serverManagement and len(self.__packetsToAppend[0]) == 2:
                            res = self.__packetsToAppend[0][1]
                            res.time += delay
                            bufferResponse.append(res)
                        self.__packetsToAppend.pop(0)
                        
                else: ### Si es no tiene DNS lo dejamos pasar.   
                    bufferQueries.append(self.__packetsToAppend[0][0])
                    if len(self.__packetsToAppend[0]) == 2:
                        bufferResponse.append(self.__packetsToAppend[0][1])
                    self.__packetsToAppend.pop(0)
                queries+=1
            print("hola3")
            while len(bufferQueries)!=0 and len(bufferResponse)!=0:
                if count == 50000:
                    writer.close()
                    del writer
                    writer = PcapWriter(outputDirection,append=True,sync=True)
                    count = 0
                if bufferQueries[0].time < bufferResponse[0].time:
                    writer.write(bufferQueries[0])
                    bufferQueries.pop(0)
                    count+=1
                else:
                    writer.write(bufferResponse[0])
                    bufferResponse.pop(0)
                    count+=1
            print("hola4")
            while len(bufferQueries)!=0:
                if count == 50000:
                    writer.close()
                    del writer
                    writer = PcapWriter(outputDirection,append=True,sync=True)
                    count = 0
                writer.write(bufferQueries[0])
                bufferQueries.pop(0)
                count+=1
            print("hola5")
            while len(bufferResponse) != 0:
                if count == 50000:
                    wrriter.close()
                    del writer
                    writer = PcapWriter(outputDirection,append=True,sync=True)
                    count = 0
                writer.write(bufferResponse[0])
                bufferResponse.pop(0)
                count+=1
            
            #### We close the writer and return true because everything goes as planned
            writer.close()
            return True
        except FileNotFoundError:
            #### If the file does not exist, we return false because something went wrong
            print("Error file not found")
            return False
        """except:
            #### If something went wrong, we return false
            print("Something went wrong")
            return False"""