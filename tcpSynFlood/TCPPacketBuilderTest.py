from TCPPacketBuilder import *
from scapy.all import *
import unittest 
import random
class TCPPacketBuilderTest(unittest.TestCase):
    def setUp(self):
        self.builder = TCPPacketBuilder()
        self.srcIp="190.54.120.33"
        self.srcPort = 5000
        self.dstPort = 53
        self.dstIp = "200.7.4.7"
        self.etherSrc = "18:66:da:4d:c0:08"
        self.etherDst = "18:66:da:e6:36:56"
        self.ipId = int(RandShort())
    def test_init(self):
        pktBuilder = self.builder
        self.assertEqual("",pktBuilder.getSrcIP())
        self.assertEqual("",pktBuilder.getDestIP())
        self.assertEqual(5000,pktBuilder.getSrcPort())
        self.assertEqual(53,pktBuilder.getDestPort())
        self.assertEqual("",pktBuilder.getFlags())
        self.assertEqual("18:66:da:4d:c0:08",pktBuilder.getEtherSrc())
        self.assertEqual("18:66:da:e6:36:56",pktBuilder.getEtherResp())
        self.assertAlmostEqual(0.0,pktBuilder.getTime())
    def test_setting(self):
        pktBuilder = self.builder
        self.assertEqual(pktBuilder,pktBuilder.withSrcIP(""))
        pktBuilder.withSrcIP("190.40.39.20")
        self.assertEqual("190.40.39.20",pktBuilder.getSrcIP())
        pktBuilder.withDestIP("200.7.4.7")
        self.assertEqual("200.7.4.7",pktBuilder.getDestIP())
        pktBuilder.withSrcPort(3000)
        self.assertEqual(3000,pktBuilder.getSrcPort())
        pktBuilder.withDestPort(55)
        self.assertEqual(55,pktBuilder.getDestPort())
        pktBuilder.withFlags('S')
        self.assertEqual('S',pktBuilder.getFlags())
        pktBuilder.withTime(0.00015)
        self.assertAlmostEqual(0.00015,pktBuilder.getTime())
        pktBuilder.withIpId(self.ipId)
        self.assertEqual(self.ipId,pktBuilder.getIdIp())
    def test_build_SYN(self):
        tether = Ether(src=self.etherSrc,dst=self.etherDst)
        tip = IP(id=self.ipId,src=self.srcIp,dst=self.dstIp)
        ttcp = TCP(sport=self.srcPort,dport=self.dstPort,flags='S')
        pktexpected = tether / tip / ttcp
        pktbuilded = self.builder\
                  .withSrcIP(self.srcIp)\
                  .withDestIP(self.dstIp)\
                  .withSrcPort(self.srcPort)\
                  .withDestPort(self.dstPort)\
                  .withFlags("S")\
                  .withIpId(self.ipId)\
                  .build()
        self.assertTrue(pktbuilded.haslayer(Ether))
        self.assertTrue(pktbuilded.haslayer(IP))
        self.assertTrue(pktbuilded.haslayer(TCP))
        self.assertEqual(self.srcIp,pktbuilded.getlayer(IP).src)
        self.assertEqual(self.dstIp,pktbuilded.getlayer(IP).dst)
        self.assertEqual('S',pktbuilded.getlayer(TCP).flags)
        self.assertEqual(self.srcPort,pktbuilded.getlayer(TCP).sport)
        self.assertEqual(self.dstPort,pktbuilded.getlayer(TCP).dport)
        self.assertEqual(self.ipId,pktbuilded.getlayer(IP).id)
        self.assertEqual(pktbuilded,pktexpected)
    def test_build_SA(self):
        tether = Ether(src=self.etherSrc,dst=self.etherDst)
        tip = IP(id=self.ipId,src=self.srcIp,dst=self.dstIp)
        ttcp = TCP(sport=self.srcPort,dport=self.dstPort,flags='SA')
        pktexpected = tether / tip / ttcp
        pktbuilded = self.builder\
                  .withSrcIP(self.srcIp)\
                  .withDestIP(self.dstIp)\
                  .withSrcPort(self.srcPort)\
                  .withFlags("SA")\
                  .withIpId(self.ipId)\
                  .build()
        self.assertEqual('SA',pktbuilded.getlayer(TCP).flags)
        self.assertEqual(pktbuilded,pktexpected)
if __name__=="__main__":
    unittest.main()