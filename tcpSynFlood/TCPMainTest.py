import unittest
from scapy.all import *
import TCPMain as m
"""
Object that test the functions of the TCPMain.py file
@author Joaquin Cruz
"""
class TCPMainTest(unittest.TestCase):
    def setUp(self):

        parser = argparse.ArgumentParser(description = "Simulacion de ataque NXDOMAIN")
        parser.add_argument('--di','--directory_input',dest='inputDirectory',action='store',default='input/',help="Nombre del directorio donde esta el input con / de la ruta",type=str)
        parser.add_argument('--fi','--file_input',dest='fileInput',action='store',default='',help="Nombre del archivo pcap con su respesctivas extensiones",type=str)
        parser.add_argument('--ti','--initial_time',dest='ti',action='store',default=0,help='',type=int)
        parser.add_argument('--dt','--duration',dest='duration',action='store',default=1,help='',type=int)
        parser.add_argument('--ipn','--ip_number',dest='numberIp',action='store',default=1,help='',type=int)
        parser.add_argument('--do','--directory_output',dest='outputDirectory',action='store',default='output/',help='',type=str)
        main(parser.parse_args())
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