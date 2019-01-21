from scapy.all import *
import sys
from .InserterState import InserterState
sys.path.append('..')
import PacketInserter
from .ReadNOkState import ReadNOkState
from .FileInsertState import FileInsertState
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
        t0 = queryList[0].time
        dtInsert = ta - t0
        if dtInsert >= self.getInserter().getTimestamp():
            self.getInserter().changeState(FileInsertState(self.getInserter()))
        return (count,queries)

            