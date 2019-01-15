from PacketBuilder import *
from scapy.all import *
import unittest 
class PacketBuilderTest(unittest.TestCase):
    def __init__(self):
        super().__init__()
    def setUp(self):
        self.builder = PacketBuilder()
        self.srcIp="190.54.120.33"
        self.srcPort = 5000
        self.dstPort = 53
        self.dstIp = "200.7.4.7"
    def test_basic_SYN(self):
        tether = Ether()
        tip = IP(src=self.srcIp,dst=self.dstIp)
        ttcp = TCP(sport=self.srcPort,dport=self.dstPort,flags='S')
        pktexpected = tether / tip / ttcp
        pktbuilded = self.builder\
                  .withSrcIP(self.getVariable("Source IP"))\
                  .withDestIP(self.getVariable("Destiny IP"))\
                  .withSrcPort(self.getVariable("Source Port"))\
                  .withFlags("S")\
                  .build()
        self.assertEqual(pktbuilded,pktexpected)
    def test_basic_SA(self):
        tether = Ether()
        tip = IP(src=self.srcIp,dst=self.dstIp)
        ttcp = TCP(sport=self.srcPort,dport=self.dstPort,flags='SA')
        pktexpected = tether / tip / ttcp
        pktbuilded = self.builder\
                  .withSrcIP(self.getVariable("Source IP"))\
                  .withDestIP(self.getVariable("Destiny IP"))\
                  .withSrcPort(self.getVariable("Source Port"))\
                  .withFlags("SA")\
                  .build()
        self.assertEqual(pktbuilded,pktexpected)
if __name__=="__main__":
    unittest.main()