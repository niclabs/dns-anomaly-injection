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
        self.parser.add_argument('-di','--directory_input',dest='inputDirectory',action='store',default='input/',help="Nombre del directorio donde esta el input con / de la ruta",type=str)
        self.parser.add_argument('-pps','--packetsPerSecond',dest='pps',default=3500,type=int,help="Packets per second of the attack")
        self.parser.add_argument('-dpps''--desv_packets_per_second',dest='des',default=250,type=int,help="Standard desviation of the packets per second of the attack")
        self.parser.add_argument('-fi','--file_input',dest='fileInput',action='store',default='',help="Nombre del archivo pcap con su respesctivas extensiones",type=str)
        self.parser.add_argument('-ti','--initial_time',dest='ti',action='store',default=0,help='tiempo de inicio del ataque desde el primer paquete del primer archivo',type=int)
        self.parser.add_argument('-dt','--duration',dest='duration',action='store',default=1,help='tiempo de duracion del ataque, medido en segundos',type=int)
        self.parser.add_argument('-ipn','--ip_number',dest='numberIp',action='store',default=1,help='cantidad de ips del DDOS, por default es 1',type=int)
        self.parser.add_argument('-do','--directory_output',dest='outputDirectory',action='store',default='output/',help='direccion del archivo modificado del output',type=str)
        self.parser.add_argument('-time','--timestamp',dest='timestamp',action='store',default=0.01,help='tiempo de la ventana de medicion, medido en segundos',type=float)
        self.parser.add_argument('-tol','--tolerance',dest='tolerance',action='store',default=42,help='tolerancia del servidor',type=int)
        self.parser.add_argument('-sip','--server_ip',dest='serverIp',action='store',default="200.7.4.7",help='Ip del servidor dns, default 200.7.4.7',type=str)
        self.basicArgs = ['-fi',"test1k.pcap",'--duration','1']
        self.sixSecondsArgs = ['-fi',"test1k.pcap",'-ipn','4','-dt','6']
        self.one50kArgs = ['-fi',"test50k.pcap",'-ipn',"3"]
        self.six50kArgs = ['-fi',"test50k.pcap",'-ipn',"7",'-dt',"6"]
    def test_basic(self):
        ok = m.main(self.parser.parse_args(self.basicArgs),"--test_basic")
        self.assertEqual(0,ok)
    def test_sixSecond(self):
        ok = m.main(self.parser.parse_args(self.sixSecondsArgs),"--test_sixSeconds")
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