import unittest
import argparse
import TCPMain as m
class LargeTest(unittest.TestCase):
    def setUp(self):
        self.parser = argparse.ArgumentParser(description = "Simulacion de ataque NXDOMAIN")
        self.parser.add_argument('-n','--num_packets',dest='pps',default=2500,type=int,help="Mean of the packets per second of the attack")
        self.parser.add_argument('-i','--input_file',dest='fileInput',action='store',default='',help="Input pcap file name with his extension",type=str)
        self.parser.add_argument('-it','--initial_time',dest='it',action='store',default=0,help='Initial time of the attack, when the first attack packet will be introduced, measured in seconds and by default is 0',type=int)
        self.parser.add_argument('-d','--duration',dest='duration',action='store',default=1,help='The time duration of the attack, also measured in second and by default is 1',type=int)
        self.parser.add_argument('-z','--zombies',dest='numberIp',action='store',default=1,help="Number of ip's of the botnet, if it's 1 the type of attack is DOS. By default is 1.",type=int)
        self.parser.add_argument('-o','--output',dest='fileOutput',action='store',help='Path to the output directory of modified pcap file',type=str)
        self.parser.add_argument('-w','--window_size',dest='timestamp',action='store',default=0.01,help='Time for the measure window when the server is going or not to be down, this time is on seconds, for default is 0.01',type=float)
        self.parser.add_argument('-p','--packets_per_window',dest='tolerance',action='store',default=42,help='Server number of packets per the time of measure window, by default is 42',type=int)
        self.parser.add_argument('-s','--server_ip',dest='serverIp',action='store',default="200.7.4.7",help="DNS server's ip, by default is 200.7.4.7",type=str)
        self.args = ['-i',"input/test.pcap",'-z',"10",'-d',"5",'-o',"output/test-modified--large_test.pcap"]
    def test_large(self):
        ok = m.main(self.parser.parse_args(self.args),"--large_test")
        self.assertEqual(0,ok)
if __name__ == "__main__":
    unittest.main()
