import unittest
from scapy.all import *
import TCPMain as m
"""
Object that test the functions of the TCPMain.py file
@author Joaquin Cruz
"""
class TCPMainTest(unittest.TestCase):
    def setUp(self):
        self.basicArgs = ["main.py","test1k.pcap","190.54.120.40","0","1"]
        self.sixSecondsArgs = ["main.py","test1k.pcap","190.54.120.40","0","6"]
    def test_basic(self):
        ok = m.main(self.basicArgs,"--test_basic")
        self.assertEqual(0,ok)
    def test_sixSecond(self):
        ok = m.main(self.sixSecondsArgs,"--test_sixSeconds")
        self.assertEqual(0,ok)

if __name__ == "__main__":
    unittest.main()