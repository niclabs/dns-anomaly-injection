from Test import *
from PacketInserter import *
from scapy.all import *
class PacketInserterTest(Test):
    def __init__(self):
        super().__init__()
    def setUp(self):
        self.addVariable("inserter",PacketInserter())
        self.addVariable("input","lol.pcap")
        self.addVariable("output","lol-out.pcap")
        self.addVariable("none-pkts",[])
        self.addVariable("Input Direction","input/")
        self.addVariable("Output Direction","output/")
    def test_basic(self):
        ins  = self.getVariable("inserter")
        assert ins.getPacketsToAppend() == []
        assert ins.getInputName() == ""
        assert ins.getOutputName() == ""
        assert ins.getInputDir() == ""
        assert ins.getOutputDir() == ""
        assert ins.getDelay() == 0.0
    ##TODO changes tests
if __name__ == "__main__":
    test = PacketInserterTest()
    test.run()