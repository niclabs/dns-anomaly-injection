import unittest
from PacketInserter import *
from scapy.all import *
import states.InserterState as state
import tcpSynFlood.TCPPacketBuilder as pktBuilder
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
        self.assertAlmostEqual(0.0006,ins.getResponseDt())
        self.assertEqual(state.ReadOkState(ins),ins.getState())
        self.assertAlmostEqual(0.001,ins.getTimestamp())
        self.assertEqual(30,ins.getServerTolerance())
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
        ins.withServerIp("200.3.1.2")
        self.assertEqual("200.3.1.2",ins.getServerIp())
        ins.withTimestamp(0.01)
        self.assertAlmostEqual(0.01,ins.getTimestamp())
        ins.withServerTolerance(30)
        self.assertEqual(30,ins.getServerTolerance())
    def test_insertion_light(self):
        pass
    def test_insertion_full(self):
        pass

if __name__ == "__main__":
    unittest.main()