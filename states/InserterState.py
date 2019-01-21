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