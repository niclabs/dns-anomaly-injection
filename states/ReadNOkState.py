from scapy.all import *
import sys
sys.path.append('..')
from .InserterState import InserterState
import PacketInserter
from .ReadOkState import ReadOkState
from .FileInsertState import FileInsertState
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
        t0 = queryList[0].time
        dtInsert = ta - t0
        if dtInsert >= self.getInserter().getTimestamp(): 
            self.getInserter().changeState(FileInsertState(self.getInserter()))
        if len(queryList) < self.getInserter().getServerTolerance():
            self.getInserter().changeState(ReadOkState(self.getInserter()))      
        return (count,queries)