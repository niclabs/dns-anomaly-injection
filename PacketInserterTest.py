import unittest
import sys
sys.path.append("TCP-SYN-Flood/")
from PacketInserter import *
from scapy.all import *
from TCPPacketBuilder import *

class PacketInserterTest(unittest.TestCase):
    def setUp(self):
        self.inserter = PacketInserter()
    def test_well_construct_test(self):
        ins = self.inserter
        self.assertEqual([],ins.getPacketsToAppend())
        self.assertEqual("",ins.getInputName())
        self.assertEqual("", ins.getOutputName())
        self.assertEqual("",ins.getInputDir())
        self.assertEqual("",ins.getOutputDir())
        self.assertAlmostEqual(0.0,ins.getDelay())
    def test_setter_getter(self):
        ins = self.inserter
        dullPacket = Ether()/IP()
        ins.withPackets([dullPacket])
        self.assertEqual([dullPacket],ins.getPacketsToAppend())
        ins.withPcapInput("lol.pcap")
        self.assertEqual("lol.pcap",ins.getInputName())
        ins.withInputDir("input/")
        self.assertEqual("input/",ins.getInputDir())
        ins.withPcapOutput("lol-modified.pcap")
        self.assertEqual("lol-modified.pcap",ins.getOutputName())
        ins.withResponseDt(0.008)
        self.assertAlmostEqual(0.008,ins.getResponseDt())
        ins.with
    def test_insertion_light(self):
        pass
    def test_insertion_full(self):
        pass
    ##TODO changes tests, generate more test

if __name__ == "__main__":
    unittest.main()