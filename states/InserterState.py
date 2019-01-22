from scapy.all import *
import sys
sys.path.append('..')
import PacketInserter
"""
    Inserter state class is an super class for all the states that the inserter can have. 
    It follows the state design pattern
    @author Joaquin Cruz
"""
class InserterState:
    def __init__(self,inserter: PacketInserter):
        """
            An inserter state have a reference to the PacketInserter which he is being used
            :param: inserter is the PacketInserter reference
        """
        self._inserter = inserter
    def getInserter(self):
        """
            Getter for the inserter field
            :return: the reference of the inserter
        """
        return self._inserter
    def setInserter(self,anotherInserter):
        """
            Setter for the inserter reference
            :param: anotherInserter is the new inserter reference for the state
        """
        self._inserter = anotherInserter
    def processData(self,bufferFile: list, bufferAttack: list,queryList: list, responseList: list, noResponse: dict,delay: float, data: list,writer: PcapWriter):
        """
            Abstract method for the state to process the data given.
            :param: bufferFile is the list buffer of packets of the file that is being readed
            :param: bufferAttack is the list buffer of packets of the attack to be introduced, this are tuples which form is (request,response)
            :param: queryList is the list buffer for the packets to be inserted that are queries
            :param: responseList is the buffer list for the response that are going to be written on the pcap file
            :param: noResponse is the dictionary of id's for the packets of queries that will not have responses
            :param: delay is the delay to be added of the responses
            :param: data is the extra data that this method will need, like the output direction, counter for reseting the writer, etc...
            :param: writer is the pcap file writer object
        """
        pass
"""
    ReadOkState is an state of the inserter that simulates that the server can create responses for all the packages
    that the queries need. It can pass to an ReadNOkState gathering more request that the server can handle and to the file
    insert if the first querie and the last one have a dt greater or equal than the timestamp.
    @author Joaquin Cruz
"""
class ReadOkState(InserterState):
    def __init__(self,inserter: PacketInserter):
        super().__init__(inserter)
    def processData(self,bufferFile: list, bufferAttack: list,queryList: list, responseList: list, noResponse: dict,delay: float, data: list,writer: PcapWriter):
        """
            Process data simulating an server state Ok of the number of queries received, generating responses to them 
            :param: bufferFile is the list buffer of packets of the file that is being readed
            :param: bufferAttack is the list buffer of packets of the attack to be introduced, this are tuples which form is (request,response)
            :param: queryList is the list buffer for the packets to be inserted that are queries
            :param: responseList is the buffer list for the response that are going to be written on the pcap file
            :param: noResponse is the dictionary of id's for the packets of queries that will not have responses
            :param: delay is the delay to be added of the responses
            :param: data is the extra data that this method will need, like the output direction, counter for reseting the writer, etc...
            :param: writer is the pcap file writer object
        """
        count = data[0]
        queries = data[1]
        outputDirection = data[2]
        if len(bufferAttack) == 0 or (len(bufferFile) !=0 and bufferFile[0].time <= bufferAttack[0][0].time):
            ta = bufferFile[0].time
            if bufferFile[0].getlayer(IP).src == self.getInserter().getServerIp():
                bufferFile[0].time += delay
                if (not bufferFile[0].haslayer(DNS)) or (bufferFile[0].getlayer(DNS).id not in noResponse):
                    responseList.append(bufferFile[0])
                bufferFile.pop(0)
            else:
                queryList.append(bufferFile[0])
                bufferFile.pop(0)
                queries+=1
        elif len(bufferAttack)!=0:
            ta = bufferAttack[0][0].time
            queryList.append(bufferAttack[0][0])
            if len(bufferAttack[0]) == 2:
                bufferAttack[0][1].time +=delay
                responseList.append(bufferAttack[0][1])
            bufferAttack.pop(0)
            queries+=1
        if len(queryList) >= self.getInserter().getServerTolerance():
            self.getInserter().changeState(ReadNOkState(self.getInserter()))
        if len(queryList) != 0:
            t0 = queryList[0].time
        elif len(responseList) != 0:
            t0 = responseList[0].time
        else:
            t0 = ta
        dtInsert = ta - t0
        if dtInsert >= self.getInserter().getTimestamp():
            self.getInserter().changeState(FileInsertState(self.getInserter()))
        return (count,queries,ta,writer)
"""
    ReadNOkState is an state of simulation of a not response generated server.
    @author Joaquin Cruz
"""
class ReadNOkState(InserterState):
    def __init__(self,inserter: PacketInserter):
        super().__init__(inserter)
    def processData(self,bufferFile: list, bufferAttack: list,queryList: list, responseList: list, noResponse: dict,delay: float,data: list,writer: PcapWriter):
        """
            Simulates the receiving of queries of a collapsed server, this is, it does not generate responses of the packets received
            :param: bufferFile is the list buffer of packets of the file that is being readed
            :param: bufferAttack is the list buffer of packets of the attack to be introduced, this are tuples which form is (request,response)
            :param: queryList is the list buffer for the packets to be inserted that are queries
            :param: responseList is the buffer list for the response that are going to be written on the pcap file
            :param: noResponse is the dictionary of id's for the packets of queries that will not have responses
            :param: delay is the delay to be added of the responses
            :param: data is the extra data that this method will need, like the output direction, counter for reseting the writer, etc...
            :param: writer is the pcap file writer object
        """
        ### Establish the data given
        count = data[0]
        queries = data[1]
        outputDirection = data[2]
        
        ### we see if we put an file or an attack on our file
        if len(bufferAttack) == 0 or (len(bufferFile) !=0 and bufferFile[0].time <= bufferAttack[0][0].time):
            ta = bufferFile[0].time
            if bufferFile[0].getlayer(IP).src == self.getInserter().getServerIp():
                bufferFile[0].time += delay
                if (not bufferFile[0].haslayer(DNS)) or (bufferFile[0].getlayer(DNS).id not in noResponse):
                    responseList.append(bufferFile[0])
                bufferFile.pop(0)
            else:
                queryList.append(bufferFile[0])
                if bufferFile[0].haslayer(DNS):
                    noResponse[bufferFile[0].getlayer(DNS).id] = bufferFile[0].time
                bufferFile.pop(0)
                queries += 1
        elif len(bufferAttack) != 0:
            ta = bufferAttack[0][0].time
            queryList.append(bufferAttack[0][0])
            bufferAttack.pop(0)
            queries += 1
        if len(queryList) != 0:
            t0 = queryList[0].time
        elif len(responseList) != 0:
            t0 = responseList[0].time
        else:
            t0 = ta
        dtInsert = ta - t0
        if dtInsert >= self.getInserter().getTimestamp():
            self.getInserter().changeState(FileInsertState(self.getInserter()))
        if len(queryList) < self.getInserter().getServerTolerance():
            self.getInserter().changeState(ReadOkState(self.getInserter()))      
        return (count,queries,ta,writer)
"""
    The FileInsertState is an subclass of the InserterState that represents the state of the inserter
    when he have to insert packets on the pcap file. At the end of this execution (inserting the packets) this
    states change to an server ok or server not ok state.
    @author Joaquin Cruz
"""
class FileInsertState(InserterState):
    def __init__(self,inserter : PacketInserter):
        super().__init__(inserter)
    def processData(self,bufferFile: list, bufferAttack: list, queryList: list, responseList: list, noResponse: dict, delay: float,data: list,writer: PcapWriter):
        """
            Process the buffers for the insertion when the dt of the buffers is greater than the timestamp given, then returns to one of the
            two states of the server.
            :param: bufferFile is the list buffer of packets of the file that is being readed
            :param: bufferAttack is the list buffer of packets of the attack to be introduced, this are tuples which form is (request,response)
            :param: queryList is the list buffer for the packets to be inserted that are queries
            :param: responseList is the buffer list for the response that are going to be written on the pcap file
            :param: noResponse is the dictionary of id's for the packets of queries that will not have responses
            :param: delay is the delay to be added of the responses
            :param: data is the extra data that this method will need, like the output direction, counter for reseting the writer, etc...
            :param: writer is the pcap file writer object
            :return: a tuple of (count,queries,ta,writer) where the count is the number of packages inserted, queries is the number of
            queries done to the server in total, ta is the actual time and writer is the PcapWriter that can be modified
        """
        ### Extract the data of the arrays given
        t0 = queryList[0].time
        count = data[0]
        queries = data[1]
        outputDirection = data[2]

        ### Calculates the actual time
        if len(bufferFile) == 0 and len(bufferAttack) == 0:
            return 
        if len(bufferFile) == 0:
            ta = bufferAttack[0].time
        elif len(bufferAttack) == 0:
            ta = bufferFile[0].time
        elif len(bufferFile)!= 0 and len(bufferAttack)!= 0:
            ta = min(bufferFile[0].time,bufferAttack[0][0].time)
        
        ### Starts to write on the file 
        dtInsert = ta - t0
        writerAux = writer
        while dtInsert >= self.getInserter().getTimestamp() and len(queryList) != 0:
            t0 = queryList[0].time
            dtInsert = ta - t0
            if count == 50000:
                writer.close()
                del writer
                writerAux = PcapWriter(outputDirection,append = True,sync=True) 
                writer = writerAux
                count = 0
                continue
            if len(responseList) == 0:
                pkt = queryList[0]
                writerAux.write(pkt)
                queryList.pop(0)
            else:
                if queryList[0].time < responseList[0].time:
                    pkt = queryList[0]
                    writerAux.write(pkt)
                    queryList.pop(0)
                else:
                    pkt = responseList[0]
                    writerAux.write(pkt)
                    responseList.pop(0)
            count+=1
        ### After inserting, we manage the transitions
        if len(queryList) >= self.getInserter().getServerTolerance():
            self.getInserter().changeState(ReadNOkState(self.getInserter()))
        else:
            self.getInserter().changeState(ReadOkState(self.getInserter()))
        return (count,queries,ta,writerAux)
