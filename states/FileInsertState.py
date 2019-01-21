from scapy.all import *
import sys
sys.path.append('..')
import PacketInserter
from .InserterState import InserterState
from .ReadNOkState import ReadNOkState
from .ReadOkState import ReadOkState
class FileInsertState(InserterState):
    def __init__(self,inserter : PacketInserter):
        super().__init__(inserter) 
    def processData(self,bufferFile: list, bufferAttack: list, queryList: list, responseList: list, noResponse: dict, delay: float,data: list):
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
            ta = min(bufferFile[0].time,bufferAttack[0].time)
        dtInsert = ta - t0
        while dtInsert >= self.getInserter().getTimestamp() and len(queryList) != 0:
            t0 = queryList[0].time
            dtInsert = ta - t0
            if count == 50000: ## TODO de donde sale el count
                writer.close() ## TODO de donde sale el writer
                del writer
                writer = PcapWriter(outputDirection,append = True,sync=True) ## TODO de donde sale el outputDirection
                count = 0
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
        return (count,queries)