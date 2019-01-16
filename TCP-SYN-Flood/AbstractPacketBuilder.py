from abc import ABC, abstractmethod
"""
AbstractPacketBuilder is an abstract class made for the packet builder classes in DNS and TCP
packets.
@author Joaquin Cruz
"""
class AbstractPacketBuilder(ABC):
    def __init__(self):
        """
            Abstract constructor of the object, all builder must set the
            following parameters:
            :param: srcip: It's the IP of the computer that the package is generated and sent
            :param: dip: It's the IP of the computer that the package will be received
            :param: srcPort: Port of the computer where the packet is generated, the default is 5000
            because if generally an unused port. Can be changed afterwards
            :param: dstPort: Port of the computer where the packet is receive, by default is 53
            this is because the DNS server listen to TCP and DNS packet at port 53
            :param: etherSrc: Ether source parameters of the ether layer of the packet that will be created
            :param: etherRsp: Ether response paramter of the ether layer of the packet that will be created by
            the builder
            :param: time: It's the time when the packet created have been sent. 
        """
        self._srcip = ""
        self._dip = ""
        self._srcPort = 5000
        self._dstPort = 53
        self._etherSrc = "18:66:da:4d:c0:08"
        self._etherRsp = "18:66:da:e6:36:56"
        self._time = float(0)
        super().__init__()
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
        return self._srcPort
    def getDestPort(self):
        """
            Getter for the destiny port of the packet to build
        """
        return self._dstPort
    def getEtherSrc(self):
        """
            Return the ether src parameter that the builder give to build the packet.
            :return: the ether src field
        """   
        return self._etherSrc
    def getEtherResp(self):
        """
            Returns the ether dst parameter of the packet to be build.
            :return: the ether dst field of the builder
        """
        return self._etherRsp
    def getTime(self):
        """
            Give us the time of the packate being sent
            :return: the time of the package to be built
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
        self._srcPort = port
        return self
    def withDestPort(self,port: int):
        """
            Sets the destination port of the package
            :param self: a reference to the builder
            :param port:int: the new destiny port
        """
        self._dstPort = port
        return self
    def withEtherSrc(self,ethersrc: str):
        """
            Establish the ether src parameter that the packet will have when it's
            going to be build
        """
        self._etherSrc = ethersrc
        return self
    def withEtherResp(self,etherresp: str):
        """
            Establishes the ether dst parameter that the packet will have when it's
            going to be build
        """
        self._etherRsp = etherresp
        return self
    def withTime(self,time: float):
        """
            Sets the time sent of the parameter that is going to be builded
        """
        self._time=time
        return self
    @abstractmethod
    def build(self):
        """
            Build abstract method, builds the packet given the parameters that the builder have at the
            moment the message is sent
        """
        pass