import argparse
import unittest
import DNSMain as m
class DNSMainLargeTest(unittest.TestCase):
    def setUp(self):
        self.parser = argparse.ArgumentParser(description = "Simulacion de ataque NXDOMAIN")
        self.parser.add_argument('--di','--directory_input',dest='inputDirectory',action='store',default='input/',help="Nombre del directorio donde esta el input con / de la ruta",type=str)
        self.parser.add_argument('--fi','--file_input',dest='fileInput',action='store',help="Nombre del archivo pcap con su respesctivas extensiones",type=str)
        self.parser.add_argument('--ti','--initial_time',dest='ti',action='store',default=0,help='',type=int)
        self.parser.add_argument('--dt','--duration',dest='duration',action='store',default=1,help='',type=int)
        self.parser.add_argument('--ipn','--ip_number',dest='numberIp',action='store',default=1,help='',type=int)
        self.parser.add_argument('--do','--directory_output',dest='outputDirectory',action='store',default='output/',help='',type=str)
        self.args = ['--fi',"test.pcap",'--ipn',"10",'--dt',"5"]
    def test_large(self):
        ok = m.main(self.parser.parse_args(self.args),"--large_test")
        self.assertEqual(0,ok)

if __name__ == '__main__':
    unittest.main()