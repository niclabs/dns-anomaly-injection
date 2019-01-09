try:
    from PacketBuilder import *
    from scapy.all import *
    from Test import *
except:
    raise Exception("Missing a module")
class PacketBuilderTest(Test):
    def __init__(self):
        super().__init__()
    def setUp(self):
        self.addVariable("builder",PacketBuilder())
        self.addVariable("Source IP","190.54.120.33")
        self.addVariable("Source Port",5000)
        self.addVariable("Destiny Port",53)
        self.addVariable("Destiny IP","200.7.4.7")
    def test_basic(self):
        tether = Ether()
        tip = IP(src=self.getVariable("Source IP"),dst=self.getVariable("Destiny IP"))
        ttcp = TCP(sport=self.getVariable("Source Port"),dport=self.getVariable("Destiny Port"),flags='S')
        pktexpected = tether / tip / ttcp
        pktbuilded = self.getVariable("builder")\
                  .withSrcIP(self.getVariable("Source IP"))\
                  .withDestIP(self.getVariable("Destiny IP"))\
                  .withSrcPort(self.getVariable("Source Port"))\
                  .withFlags("S")\
                  .build()
        assert pktbuilded == pktexpected

if __name__=="__main__":
    tester = PacketBuilderTest()
    tester.run()