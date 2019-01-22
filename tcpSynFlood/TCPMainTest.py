import unittest
from scapy.all import *
import TCPMain as m
"""
Object that test the functions of the TCPMain.py file
@author Joaquin Cruz
"""
class TCPMainTest(unittest.TestCase):
    def setUp(self):
        self.basicArgs = ["main.py","test1k.pcap","1","0","1"]
        self.sixSecondsArgs = ["main.py","test1k.pcap","4","0","6"]
        self.one50kArgs = ["main.py","test50k.pcap","3","0","1"]
        self.six50kArgs = ["main.py","test50k.pcap","7","1","6"]
    def test_basic(self):
        ok = m.main(self.basicArgs,"--test_basic")
        self.assertEqual(0,ok)
    def test_sixSecond(self):
        ok = m.main(self.sixSecondsArgs,"--test_sixSeconds")
        self.assertEqual(0,ok)
    def test_oneSecond_50k(self):
        ok = m.main(self.one50kArgs,"--test_oneSecond")
        self.assertEqual(0,ok)
    def test_sixSecond_50k(self):
        ok = m.main(self.six50kArgs,"--test_sixSecond")
        self.assertEqual(0,ok)
if __name__ == "__main__":
    unittest.main()