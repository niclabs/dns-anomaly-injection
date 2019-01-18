from PacketInserter import *
from scapy.all import *
class InserterState:
    def __init__(self,inserter: PacketInserter):
        self._inserter = PacketInserter
    def getInserter(self):
        return self._inserter
    def setInserter(self,anotherInserter: PacketInserter):
        self._inserter = anotherInserter
    def processData(self):
        pass
    def changeState(self,anotherState: InserterState):
        pass
class ReadOkState(InserterState):
    def __init__(self,inserter: PacketInserter):
        super().__init__(inserter)
    def processData(self,bufferFile: list, bufferAttack: list,queryList: list, responseList: list, noResponse: dict,delay: float):
        if len(bufferAttack) == 0 and len(bufferFile) == 0:
            return
        if len(bufferAttack) == 0 or bufferFile[0].time <= bufferAttack[0][0].time:
                ta = bufferFile[0].time
                if bufferFile[0].getlayer(IP).src == self._inserter.getServerIp():
                    bufferFile[0]+=delay
                    if (not bufferFile[0].haslayer(DNS)) or (bufferFile[0].getlayer(DNS).id not in noResponse):
                        responseList.append(bufferFile[0])
                    bufferFile.pop(0)
                
                else: ## Si soy query
                    if len(queryList) == 0:
                        queryList.append(bufferFile[0])
                        bufferFile.pop(0)
                    else:
                        t0 = queryList[0].time
                        dtInsert = ta - t0
                        ##TODO ver el paso de estados para insercion

                        
class FileInsertState(InserterState):
    def __init__(self,inserter: PacketInserter):
        super().__init__(inserter)
            
