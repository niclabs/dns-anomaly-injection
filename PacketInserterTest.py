import unittest
from PacketInserter import *
from scapy.all import *
class PacketInserterTest(unittest.TestCase):
    def setUp(self):
        self.inserter = PacketInserter()
    def test_basic(self):
        ins = self.inserter
        self.assertEqual([],ins.getPacketsToAppend())
        self.assertEqual("",ins.getInputName())
        self.assertEqual("", ins.getOutputName())
        self.assertEqual("",ins.getInputDir())
        self.assertEqual("",ins.getOutputDir())
        self.assertAlmostEqual(0.0,ins.getDelay())
    ##TODO changes tests
if __name__ == "__main__":
    unittest.main()