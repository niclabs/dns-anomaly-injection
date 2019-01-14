try:
    import sys
    sys.path.append('../TCP-SYN-Flood')
    from PacketBuilder import *
    from scapy.all import *
except:
    raise Exception("You don't have some libraries, pls install")
class DNSPacketBuilder(PacketBuilder):
    def __init__(self):
        super().__init__()
        self._domain = ""
        self._idDNS = 0
        self._responseDT = 0.00015
    def withDomain(self,name: str):
        self._domain = name
        return self
    def withIdDNS(self,id: int):
        self._idDNS = id
        return self
    def _buildRequest(self):
        idIP = int(RandShort())
        ether = Ether()
        ip = IP(src=self.getSrcIP(),dst=self.getDestIP(),id=idIP)
        udp = UDP(sport = self.getSrcPort,dport= self.getDestPort())
        queryDomain = DNSQR(qname=str(self._domain))
        dns = DNS(rd=0,id=self._idDNS,qd=queryDomain)
        pkt = ether / ip / udp / dns
        pkt.time = self.getTime()
        return pkt
    def _buildResponse(self):
        idIP = int(RandShort())
        ether = Ether()
        ip = IP(src=self.getSrcIP(),dst=self.getDestIP(),id=idIP)
        udp = UDP(sport=self.getSrcPort(),dport=self.getDestPort())
        dns = DNS(id=self._idDNS,an=None,ns=None,ar=None,ancount=0,nscount=0,arcount=0,rcode=3) #TODO the fields to make a nxdomain response
        pkt = ether / ip / udp / dns
        pkt.time = self.getTime() + self._responseDT
        return pkt
    def build(self):
        return (self._buildRequest(),self._buildResponse())