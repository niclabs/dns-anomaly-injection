import unittest
from DNSPacketBuilder import *
import random
from scapy.all import *

class DNSPacketBuilderTest(unittest.TestCase):
    def setUp(self):
        self.builder = DNSPacketBuilder()
        self.srcIp="190.54.120.33"
        self.srcPort = 5000
        self.dstPort = 53
        self.dstIp = "200.7.4.7"
        self.etherSrc = "18:66:da:4d:c0:08"
        self.etherDst = "18:66:da:e6:36:56"
        self.domain = "google.cl."
        self.idDNS = int(RandShort())
        self.qrIdIp = int(RandShort())
        self.rspIdIp = int(RandShort())
    def test_init(self):
        dnsBuilder = self.builder
        self.assertEqual("",dnsBuilder.getSrcIP())
        self.assertEqual("",dnsBuilder.getDestIP())
        self.assertEqual(5000,dnsBuilder.getSrcPort())
        self.assertEqual(53,dnsBuilder.getDestPort())
        self.assertEqual("18:66:da:4d:c0:08",dnsBuilder.getEtherSrc())
        self.assertEqual("18:66:da:e6:36:56",dnsBuilder.getEtherResp())
        self.assertAlmostEqual(0.0,dnsBuilder.getTime())
        self.assertEqual("",dnsBuilder.getDomain())
        self.assertEqual(0,dnsBuilder.getIdDNS())
        self.assertAlmostEqual(0.00015,dnsBuilder.getResponseDT())
    def test_construct_query(self):
        ether = Ether(src= self.etherSrc, dst=self.etherDst)
        ip = IP(id=self.qrIdIp,src=self.srcIp,dst=self.dstIp)
        udp = UDP(sport=self.srcPort,dport=self.dstPort)
        qrDom = DNSQR(qname= str(self.domain))
        dns = DNS(rd=0,id=self.idDNS,opcode = 'QUERY',qdcount=1,qd=qrDom,qr=0)
        pkt = ether / ip / udp / dns
        (request,response) = self.builder\
                            .withEtherSrc(self.etherSrc)\
                            .withEtherResp(self.etherDst)\
                            .withSrcIP(self.srcIp)\
                            .withDestIP(self.dstIp)\
                            .withQrIpId(self.qrIdIp)\
                            .withSrcPort(self.srcPort)\
                            .withDestPort(self.dstPort)\
                            .withDomain(self.domain)\
                            .withIdDNS(self.idDNS)\
                            .build()
        self.assertEqual(pkt,request)
    def test_construct_response(self):
        ether = Ether(src= self.etherDst, dst=self.etherSrc)
        ip = IP(id=self.rspIdIp,src=self.dstIp,dst=self.srcIp)
        udp = UDP(sport=self.dstPort,dport=self.srcPort)
        dns = DNS(id=self.idDNS,qr=1,an=None,ns=None,ar=None,ancount=0,nscount=0,arcount=0,rcode=3)
        pkt = ether / ip / udp / dns
        (request,response)=self.builder\
                            .withEtherSrc(self.etherSrc)\
                            .withEtherResp(self.etherDst)\
                            .withSrcIP(self.srcIp)\
                            .withDestIP(self.dstIp)\
                            .withRspIpId(self.rspIdIp)\
                            .withSrcPort(self.srcPort)\
                            .withDestPort(self.dstPort)\
                            .withDomain(self.domain)\
                            .withIdDNS(self.idDNS)\
                            .build()
        self.assertEqual(pkt,response)
    def test_construct_both(self):
        etherQr = Ether(src= self.etherSrc, dst=self.etherDst)
        ipQr = IP(id=self.qrIdIp,src=self.srcIp,dst=self.dstIp)
        udpQr = UDP(sport=self.srcPort,dport=self.dstPort)
        qrDom = DNSQR(qname= str(self.domain))
        dnsQr = DNS(rd=0,id=self.idDNS,opcode = 'QUERY',qdcount=1,qd=qrDom,qr=0)
        pktQr = etherQr / ipQr / udpQr / dnsQr
        etherResp = Ether(src= self.etherDst, dst=self.etherSrc)
        ipResp = IP(id=self.rspIdIp,src=self.dstIp,dst=self.srcIp)
        udpResp = UDP(sport=self.dstPort,dport=self.srcPort)
        dnsResp = DNS(id=self.idDNS,qr=1,an=None,ns=None,ar=None,ancount=0,nscount=0,arcount=0,rcode=3)
        pktResp = etherResp / ipResp / udpResp / dnsResp
        (request,response) = self.builder\
                            .withEtherSrc(self.etherSrc)\
                            .withEtherResp(self.etherDst)\
                            .withSrcIP(self.srcIp)\
                            .withDestIP(self.dstIp)\
                            .withQrIpId(self.qrIdIp)\
                            .withRspIpId(self.rspIdIp)\
                            .withSrcPort(self.srcPort)\
                            .withDestPort(self.dstPort)\
                            .withDomain(self.domain)\
                            .withIdDNS(self.idDNS)\
                            .build()
        self.assertEqual((pktQr,pktResp),(request,response))
if __name__ == "__main__":
    unittest.main()