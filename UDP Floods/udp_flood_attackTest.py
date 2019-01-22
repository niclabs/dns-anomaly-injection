from udp_flood_attack import *
import unittest

class udp_flood_attackTest(unittest.TestCase):

    def test_udpFloodAttack(self):
        puertos=[[80,25,137,1024,53],[161,123,111,500,69,28960,19,9987,5353,12203,2049,9915,63392,520]]
        ataque=udpFloodAttack('200.7.4.7', ['190.34.123.200'], [567], puertos, 0, 10, 140, 4, 0.1)

        numPkts=0
        for i in range(len(ataque)):
            numPkts+=len(ataque[i])
            self.assertTrue(len(ataque[i])==1 or len(ataque[i])==2, '\nerror en la cantidad de paquetes pregunta y respuesta\nScript "udp_flood_attack", funcion "udpFloodAttack"')
            self.assertTrue( ataque[i][0].time<=10-0.1 and ataque[i][0].time>=0, '\nerror en el tiempo del paquete\nScript "udp_flood_attack", funcion "udpFloodAttack"')
            self.assertTrue( (ataque[i][0][2].dport in puertos[0]) or (ataque[i][0][2].dport in puertos[1]), '\nerror en el puerto del paquete\nScript "udp_flood_attack", funcion "udpFloodAttack"')
            self.assertEqual(ataque[i][0][2].sport, 567, '\nerror en el puerto del paquete\nScript "udp_flood_attack", funcion "udpFloodAttack"')

        self.assertTrue(numPkts>140, '\nerror en la cantidad de paquetes\nScript "udp_flood_attack", funcion "udpFloodAttack"')
        self.assertEqual(len(ataque), 140, '\nerror en la cantidad de paquetes\nScript "udp_flood_attack", funcion "udpFloodAttack"')


    def test_udpPairGen(self):
        packUDP_openPort=udpPairGen(300, 700, 1, '200.7.4.7', '190.34.123.200', 12.6, 0.1)
        packUDP_closePort=udpPairGen(300, 700, 0, '200.7.4.7', '190.34.123.200', 12.6, 0.1)
        self.assertEqual(packUDP_openPort[0], packUDP_closePort[0], '\nproblemas entre el paquete de pregunta de puerto abierto y cerrado\nScript "udp_flood_attack", funcion "udpPairGen"')

        self.assertEqual(packUDP_closePort[0].time, 12.6, '\nerror en el tiempo del paquete\nScript "udp_flood_attack", funcion "udpPairGen"')
        self.assertEqual(packUDP_closePort[1].time, 12.7, '\nerror en el tiempo del paquete\nScript "udp_flood_attack", funcion "udpPairGen"')
        self.assertEqual(packUDP_closePort[0].src, '18:66:da:e6:36:56', '\nerror en la direccion del paquete\nScript "udp_flood_attack", funcion "udpPairGen"')
        self.assertEqual(packUDP_closePort[0].dst, '18:66:da:4d:c0:08', '\nerror en la direccion del paquete\nScript "udp_flood_attack", funcion "udpPairGen"')
        self.assertEqual(packUDP_closePort[1].dst, '18:66:da:e6:36:56', '\nerror en la direccion del paquete\nScript "udp_flood_attack", funcion "udpPairGen"')
        self.assertEqual(packUDP_closePort[1].src, '18:66:da:4d:c0:08', '\nerror en la direccion del paquete\nScript "udp_flood_attack", funcion "udpPairGen"')
        self.assertEqual(packUDP_closePort[0][1].src, '200.7.4.7', '\nerror en la direccion del paquete IP\nScript "udp_flood_attack", funcion "udpPairGen"')
        self.assertEqual(packUDP_closePort[0][1].dst, '190.34.123.200', '\nerror en la direccion del paquete IP\nScript "udp_flood_attack", funcion "udpPairGen"')
        self.assertEqual(packUDP_closePort[0][2].sport, 300, '\nerror en el puerto del paquete\nScript "udp_flood_attack", funcion "udpPairGen"')
        self.assertEqual(packUDP_closePort[0][2].dport, 700, '\nerror en el puerto del paquete\nScript "udp_flood_attack", funcion "udpPairGen"')
        self.assertEqual(packUDP_closePort[1][1].dst, '200.7.4.7', '\nerror en la direccion del paqueteIP\nScript "udp_flood_attack", funcion "udpPairGen"')
        self.assertEqual(packUDP_closePort[1][1].src, '190.34.123.200', '\nerror en la direccion del paqueteIP\nScript "udp_flood_attack", funcion "udpPairGen"')
        self.assertEqual(packUDP_closePort[1][2].type, 3, '\nerror en el paquete ICMP\nScript "udp_flood_attack", funcion "udpPairGen"')
        self.assertEqual(packUDP_closePort[1][2].code, 3, '\nerror en el paquete ICMP\nScript "udp_flood_attack", funcion "udpPairGen"')



if __name__ == '__main__':
    unittest.main()