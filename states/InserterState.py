from scapy.all import *
import sys
sys.path.append('..')
import PacketInserter
class InserterState:
    def __init__(self,inserter: PacketInserter):
        self._inserter = inserter
    def getInserter(self):
        return self._inserter
    def setInserter(self,anotherInserter):
        self._inserter = anotherInserter
    def processData(self):
        pass

class ReadOkState(InserterState):
    def __init__(self,inserter: PacketInserter):
        super().__init__(inserter)
    def processData(self,bufferFile: list, bufferAttack: list,queryList: list, responseList: list, noResponse: dict,delay: float, data: list,writer: PcapWriter):
        count = data[0]
        queries = data[1]
        outputDirection = data[2]
        if len(bufferAttack) == 0 or bufferFile[0].time <= bufferAttack[0][0].time:
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
        return (count,queries,ta)

class ReadNOkState(InserterState):
    def __init__(self,inserter: PacketInserter):
        super().__init__(inserter)
    def processData(self,bufferFile: list, bufferAttack: list,queryList: list, responseList: list, noResponse: dict,delay: float,data: list,writer: PcapWriter):
        count = data[0]
        queries = data[1]
        outputDirection = data[2]
        if len(bufferAttack) == 0 or bufferFile[0].time <= bufferAttack[0][0].time:
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
        return (count,queries,ta)

class FileInsertState(InserterState):
    def __init__(self,inserter : PacketInserter):
        super().__init__(inserter) 
    def processData(self,bufferFile: list, bufferAttack: list, queryList: list, responseList: list, noResponse: dict, delay: float,data: list,writer: PcapWriter):
        t0 = queryList[0].time
        count = data[0]
        queries = data[1]
        outputDirection = data[2]
        if len(bufferFile) == 0 and len(bufferAttack) == 0:
            return ##TODO ver que onda este caso
        if len(bufferFile) == 0:
            ta = bufferAttack[0].time
        elif len(bufferAttack) == 0:
            ta = bufferFile[0].time
        elif len(bufferFile)!= 0 and len(bufferAttack)!= 0: 
            ta = min(bufferFile[0].time,bufferAttack[0][0].time)
        dtInsert = ta - t0
        while dtInsert >= self.getInserter().getTimestamp() and len(queryList) != 0:
            t0 = queryList[0].time
            dtInsert = ta - t0
            if count == 50000:
                del writer
                writer = PcapWriter(outputDirection,append = True,sync=True) 
                count = 0
                continue
            if len(responseList) == 0:
                pkt = queryList[0]
                writer.write(pkt)
                queryList.pop(0)
            else:
                if queryList[0].time < responseList[0].time:
                    pkt = queryList[0]
                    writer.write(pkt)
                    queryList.pop(0)
                else:
                    pkt = responseList[0]
                    writer.write(pkt)
                    responseList.pop(0)
            count+=1
        if len(queryList) >= self.getInserter().getServerTolerance():
            self.getInserter().changeState(ReadNOkState(self.getInserter()))
        else:
            self.getInserter().changeState(ReadOkState(self.getInserter()))
        return (count,queries,ta)