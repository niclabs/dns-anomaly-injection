try:
    import sys
    sys.path.append('../TCP-SYN-Flood')
    from AbstractPacketBuilder import *
    from scapy.all import *
except:
    raise Exception("You don't have some libraries, pls install")
class DNSPacketBuilder(AbstractPacketBuilder):
    def __init__(self):
        """
            Constructor method for the builder to the DNS packets
            :param: domain: the domain that the DNS query will ask for
            :param: idDNS: the id that the DNS request and response share
            :param: responseDT: the delta of time that the request and response has
            :param: qrIpId: the request query id of it's Ip layer
            :param: rspIpId: the response id of it's IP layer
        """
        self._domain = ""
        self._idDNS = 0
        self._responseDT = 0.00015
        self._qrIpId = 0
        self._rspIpId = 0
        super().__init__()
    def getDomain(self):
        """
            Getter for the domain field of the builder
            :return: the domain of the request query
        """
        return self._domain
    def getIdDNS(self):
        """
            Getter for the DNS id field of the builder
            :return: the DNS id field.
        """
        return self._idDNS
    def getResponseDT(self):
        """
            Getter for the delta of time between the request and response of the builder
            :return: the delta of time field of the builder
        """
        return self._responseDT
    def getQrIpId(self):
        """
            Getter for the request query id of it's IP layer
            :return: the query Ip id
        """
        return self._qrIpId
    def getRspIpId(self):
        """
            Getter for the response id of it's Ip layer that the packet will have.
            :return: the response Ip id
        """
        return self._rspIpId
    def withDomain(self,name: str):
        """
            Sets the domain that the dns query will ask for when the packet will be built
        """
        self._domain = name
        return self
    def withIdDNS(self,id: int):
        """
            Sets the id of the dns layers
        """
        self._idDNS = id
        return self
    def withQrIpId(self,id: int):
        """
            Establishes the id of the request Ip layer
        """
        self._qrIpId = id
        return self
    def withRspIpId(self,id: int):
        """
            Sets the id of the response IP layer
        """
        self._rspIpId = id
        return self
    def _buildRequest(self):
        """
            Build a request DNS packet for the DNS NXDOMAIN flood
            :return: the false domain query packet
        """
        ether = Ether(src=self.getEtherSrc(), dst=self.getEtherResp())
        ip = IP(id=self.getQrIpId(),src=self.getSrcIP(),dst=self.getDestIP())
        udp = UDP(sport = self.getSrcPort(),dport= self.getDestPort())
        queryDomain = DNSQR(qname=str(self._domain))
        dns = DNS(rd=0,id=self._idDNS,opcode='QUERY',qdcount=1,qd=queryDomain,qr=0)
        pkt = ether / ip / udp / dns
        pkt.time = self.getTime()
        return pkt
    def _buildResponse(self):
        """
            Build the DNS server response for the DNS NXDOMAIN flood
            :return: the server, name not found, response packet
        """
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
        """
        Build a tuple (request,response) of the DNS NXDOMAIN flood
        :return: tuple of the packets for the simulation
        """
        return (self._buildRequest(),self._buildResponse())