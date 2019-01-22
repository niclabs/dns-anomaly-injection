import unittest
import TCPMain as m
class LargeTest(unittest.TestCase):
    def setUp(self):
        self.args = ["main.py","test.pcap","10","0","5"]
    def test_large(self):
        ok = m.main(self.args,"--large_test")
        self.assertEqual(0,ok)
if __name__ == "__main__":
    unittest.main()