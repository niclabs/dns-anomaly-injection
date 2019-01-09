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
        self.__srcip = ""
        self.__dip = ""
        self.__sport = 5000
        self.__dport = 53
        self.__flags = ""
    def withSrcIP(self,ip: str):
        """
            Set the source Ip for the packet that is going to be created
            :param self: reference of the package builder
            :param ip:str: the ip of the package that is going to be created
        """
        self.__srcip = ip
        return self
    def withDestIP(self,ip: str):
        """
            Sets the destiny Ip of the package that the builder creates
            :param self: the package builder
            :param ip:str: the destination Ip of the package
        """   
        self.__dip = ip
        return self
    def withSrcPort(self,port: int):
        """
            Sets the source port of the package
            :param self: the package builder
            :param port:int: the source port of the package
        """   
        self.__sport = port
        return self
    def withFlags(self,flags : str):
        """
            Sets the flags used for the tcp package
            :param self: a reference to the package builder
            :param flags:str: the flags that's going to be on the package
        """   
        self.__flags = flags
        return self
    def build(self):
        """
            Method that creates a new TCP package
            :param self: the package builder reference
        """
        ePkt=Ether()
        ipPkt = IP(src=self.__srcip,dst=self.__dip)
        tcpPkt = TCP(sport=self.__sport,dport = self.__dport,flags = self.__flags)
        pkt = ePkt/ ipPkt / tcpPkt
        return pkt