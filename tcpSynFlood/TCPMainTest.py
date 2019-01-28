import unittest
import argparse
from scapy.all import *
import TCPMain as m
"""
Object that test the functions of the TCPMain.py file
@author Joaquin Cruz
"""
class TCPMainTest(unittest.TestCase):
    def setUp(self):
        self.parser = argparse.ArgumentParser(description = "Simulacion de ataque TCP SYN Flood")
        self.parser.add_argument('-n','--num_packets',dest='pps',default=3500,type=int,help="Mean of the packets per second of the attack")
        self.parser.add_argument('-i','--input_file',dest='fileInput',action='store',default='',help="Input pcap file name with his extension",type=str)
        self.parser.add_argument('-it','--initial_time',dest='it',action='store',default=0,help='Initial time of the attack, when the first attack packet will be introduced, measured in seconds and by default is 0',type=int)
        self.parser.add_argument('-d','--duration',dest='duration',action='store',default=1,help='The time duration of the attack, also measured in second and by default is 1',type=int)
        self.parser.add_argument('-z','--zombies',dest='numberIp',action='store',default=1,help="Number of ip's of the botnet, if it's 1 the type of attack is DOS. By default is 1.",type=int)
        self.parser.add_argument('-o','--output',dest='fileOutput',action='store',help='Path to the output directory of modified pcap file',type=str)
        self.parser.add_argument('-w','--window_size',dest='timestamp',action='store',default=0.01,help='Time for the measure window when the server is going or not to be down, this time is on seconds, for default is 0.01',type=float)
        self.parser.add_argument('-p','--packets_per_window',dest='tolerance',action='store',default=42,help='Server number of packets per the time of measure window, by default is 42',type=int)
        self.parser.add_argument('-s','--server_ip',dest='serverIp',action='store',default="200.7.4.7",help="DNS server's ip, by default is 200.7.4.7",type=str)
        self.basicArgs = ['-i',"input/test1k.pcap",'--duration','1','-o',"output/test1k-modified--test_basic.pcap"]
        self.sixSecondsArgs = ['-i',"input/test1k.pcap",'-z','4','-d','6','-o',"output/test1k-modified--sixSeconds.pcap"]
        self.one50kArgs = ['-i',"input/test50k.pcap",'-z',"3",'-o',"output/test50k-modified--test_oneSecond.pcap"]
        self.six50kArgs = ['-i',"input/test50k.pcap",'-z',"7",'-d',"6",'-o',"output/test50k-modified--test_sixSecond.pcap"]
    def test_basic(self):
        ok = m.main(self.parser.parse_args(self.basicArgs),"--test_basic")
        self.assertEqual(0,ok)
    def test_sixSecond(self):
        ok = m.main(self.parser.parse_args(self.sixSecondsArgs),"--test_sixSecond")
        self.assertEqual(0,ok)
    def test_oneSecond_50k(self):
        ok = m.main(self.parser.parse_args(self.one50kArgs),"--test_oneSecond")
        self.assertEqual(0,ok)
    def test_sixSecond_50k(self):
        ok = m.main(self.parser.parse_args(self.six50kArgs),"--test_sixSecond")
        self.assertEqual(0,ok)
    def test_createPackets(self):
        pkts = m.createPackets("input/test1k.pcap","200.7.4.7",20)
        self.assertEqual(20,len(pkts))
        for (x,y) in pkts:
            self.assertTrue(x.haslayer(Ether))
            self.assertTrue(x.haslayer(IP))
            self.assertTrue(x.haslayer(TCP))
            self.assertFalse(x.haslayer(DNS))
            self.assertTrue(y.haslayer(Ether))
            self.assertTrue(y.haslayer(IP))
            self.assertTrue(y.haslayer(TCP))
            self.assertFalse(y.haslayer(DNS))
            self.assertEqual("200.7.4.7",y.getlayer(IP).src)
            self.assertEqual(x.getlayer(IP).dst,y.getlayer(IP).src)
            self.assertEqual(x.getlayer(IP).src,y.getlayer(IP).dst)
            self.assertEqual(x.getlayer(TCP).flags,'S')
            self.assertEqual(y.getlayer(TCP).flags,'SA')
if __name__ == "__main__":
    unittest.main()
