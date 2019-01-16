import unittest
import sys
import DNSMain as m
class DNSMainTest(unittest.TestCase):

    def setUp(self):
        self.basicArgs = ["main.py","test1k.pcap","190.54.120.40","1","2"]
        self.sixSecondsArgs = ["main.py","test1k.pcap","190.54.120.40","0","6"]
    def test_basic(self):
        ok = m.main(self.basicArgs,"--test_basic")
        self.assertEqual(0,ok)
    def test_sixSecond(self):
        ok = m.main(self.sixSecondsArgs,"--test_sixSeconds")
        self.assertEqual(0,ok)

if __name__ == "__main__":
    unittest.main()