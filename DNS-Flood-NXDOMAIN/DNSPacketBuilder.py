try:
    import sys
    sys.path.append('../TCP-SYN-Flood')
    from AbstractPacketBuilder import *
    from scapy.all import *
except:
    raise Exception("You don't have some libraries, pls install")
class DNSPacketBuilder(AbstractPacketBuilder):
    def __init__(self):
        self._domain = ""
        self._idDNS = 0
        self._responseDT = 0.00015
        self._qrIpId = 0
        self._rspIpId = 0
        super().__init__()
    def getDomain(self):
        
        return self._domain
    def getIdDNS(self):
        
        return self._idDNS
    def getResponseDT(self):
        
        return self._responseDT
    def getQrIpId(self):

        return self._qrIpId
    def getRspIpId(self):
        
        return self._rspIpId
    def withDomain(self,name: str):
        self._domain = name
        return self
    def withIdDNS(self,id: int):
        self._idDNS = id
        return self
    def withQrIpId(self,id: int):

        self._qrIpId = id
        return self
    def withRspIpId(self,id: int):

        self._rspIpId = id
        return self
    def _buildRequest(self):
        ether = Ether(src=self.getEtherSrc(), dst=self.getEtherResp())
        ip = IP(id=self.getQrIpId(),src=self.getSrcIP(),dst=self.getDestIP())
        udp = UDP(sport = self.getSrcPort(),dport= self.getDestPort())
        queryDomain = DNSQR(qname=str(self._domain))
        dns = DNS(rd=0,id=self._idDNS,opcode='QUERY',qdcount=1,qd=queryDomain,qr=0)
        pkt = ether / ip / udp / dns
        pkt.time = self.getTime()
        return pkt
    def _buildResponse(self):
        srcEther = self.getEtherSrc()
        dstEther = self.getEtherResp()
        ether = Ether(src=dstEther, dst=srcEther)
        ip = IP(id=self._rspIpId,src=self.getDestIP(),dst=self.getSrcIP())
        udp = UDP(sport=self.getDestPort(),dport=self.getSrcPort())
        dns = DNS(id=self._idDNS,qr=1,an=None,ns=None,ar=None,ancount=0,nscount=0,arcount=0,rcode=3)
        pkt = ether / ip / udp / dns
        pkt.time = self.getTime() + self._responseDT
        return pkt
    def build(self):
        return (self._buildRequest(),self._buildResponse())