try:
    from scapy.all import *
    from AbstractPacketBuilder import *
except:
    pass
class PacketBuilder(AbstractPacketBuilder):
    def __init__(self):
        """
            Creates a new packet builder object for TCP types of packets
            :param: flags: the flags that the TCP will have.
            :param: idIp: the id that the IP layer will have.
        """
        self._flags = ""
        self._idIp = 0
        super().__init__()
    def getFlags(self):
        """
            Getter method for the flags that are going to be in the packets
        """
        return self._flags
    def getIdIp(self):
        """
            Getter for the id of the Ip layer
        """
        return self._idIp
    def withFlags(self,flags : str):
        """
            Sets the flags used for the tcp package
            :param flags:str: the flags that's going to be on the package
        """   
        self._flags = flags
        return self
    def withIpId(self,id: int):
        """
            Method that establishes what the id of the ip layer will be.
        """
        self._idIp = id
        return self
    def build(self):
        """
            Method that creates a new TCP package given the fields of the builder object
            :param self: the package builder reference
        """
        srcEther = self.getEtherSrc()
        dstEther = self.getEtherResp()
        srcIp = self.getSrcIP()
        dstIp = self.getDestIP()
        srcPort = self.getSrcPort()
        dstPort = self.getDestPort()
        pktTime = self.getTime()
        idIp = self._idIp
        ePkt=Ether(src=srcEther, dst=dstEther)
        ipPkt = IP(src=srcIp,dst=dstIp,id=idIp,proto='tcp')
        tcpPkt = TCP(sport = srcPort,dport = dstPort,flags = self._flags)
        pkt = ePkt/ ipPkt / tcpPkt
        pkt.time=pktTime
        return pkt