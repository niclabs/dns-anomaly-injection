import unittest
import argparse
import TCPMain as m
class LargeTest(unittest.TestCase):
    def setUp(self):
        self.parser = argparse.ArgumentParser(description = "Simulacion de ataque NXDOMAIN")
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
        self.parser.add_argument('-sip','--server_ip',dest='serverIp',action='store',default="200.7.4.7",help='Ip del servidor, por default es 200.7.4.7',type=str)
        self.args = ['-fi',"test.pcap",'-ipn',"10",'-dt',"5"]
    def test_large(self):
        ok = m.main(self.parser.parse_args(self.args),"--large_test")
        self.assertEqual(0,ok)
if __name__ == "__main__":
    unittest.main()