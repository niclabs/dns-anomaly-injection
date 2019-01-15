try:
    from scapy.all import *
except:
    pass
class PacketBuilder:
    def __init__(self):
        """
            Creates a new packet builder object
            :param self: reference to the object
        """
        self._srcip = ""
        self._dip = ""
        self._sport = 5000
        self._dport = 53
        self._flags = ""
        self._etherSrc = ""
        self._etherRsp = ""
        self._time = float(0)
    def getSrcIP(self):
        """
            Getter method for the source ip field
        """
        return self._srcip
    def getDestIP(self):
        """
            Give the destiny ip field
        """
        return self._dip
    def getSrcPort(self):
        """
            Give us the source port of the packet
        """
        return self._sport
    def getDestPort(self):
        """
            Getter for the destiny port of the packet to build
        """
        return self._dport
    def getFlags(self):
        """
            Getter method for the flags that are going to be in the packets
        """
        return self._flags
    def getTime(self):
        """
            Give us the time of the packate being sent
        """
        return self._time
    def withSrcIP(self,ip: str):
        """
            Set the source Ip for the packet that is going to be created
            :param self: reference of the package builder
            :param ip:str: the ip of the package that is going to be created
        """
        self._srcip = ip
        return self
    def withDestIP(self,ip: str):
        """
            Sets the destiny Ip of the package that the builder creates
            :param self: the package builder
            :param ip:str: the destination Ip of the package
        """   
        self._dip = ip
        return self
    def withSrcPort(self,port: int):
        """
            Sets the source port of the package
            :param self: the package builder
            :param port:int: the source port of the package
        """   
        self._sport = port
        return self
    def withDestPort(self,port: int):
        """
            Sets the destination port of the package
            :param self: a reference to the builder
            :param port:int: the new destiny port
        """
        self._dport = port
        return self
    def withFlags(self,flags : str):
        """
            Sets the flags used for the tcp package
            :param self: a reference to the package builder
            :param flags:str: the flags that's going to be on the package
        """   
        self._flags = flags
        return self
    def withEtherSrc(self,ethersrc: str):

        self._etherSrc = ethersrc
        return self
    def withEtherResp(self,etherresp: str):
        self._etherRsp = etherresp
        return self
    def withTime(self,time: float):

        self._time=time
        return self
    def build(self):
        """
            Method that creates a new TCP package
            :param self: the package builder reference
        """
        idIp = int(RandShort())
        ePkt=Ether(src=self._etherSrc, dst=self._etherRsp)
        ipPkt = IP(src=self._srcip,dst=self._dip,id=idIp,proto='tcp')
        tcpPkt = TCP(sport=self._sport,dport = self._dport,flags = self._flags)
        pkt = ePkt/ ipPkt / tcpPkt
        pkt.time=self._time
        return pkt