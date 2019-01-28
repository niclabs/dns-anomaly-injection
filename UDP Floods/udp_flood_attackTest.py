from udp_flood_attack import *
import unittest

class udp_flood_attackTest(unittest.TestCase):

    def test_udpFloodAttack(self):
        puertos=[[80,25,137,1024,53],[161,123,111,500,69,28960,19,9987,5353,12203,2049,9915,63392,520]]
        ataque=udpFloodAttack('200.7.4.7', ['190.34.123.200'], [567], puertos, 0, 10, 140, 4, 0.1, 0, 1)

        icmpResp=0
        for i in range(len(ataque)):
            if not(ataque[i][2]):
                icmpResp+=1
            self.assertEqual(len(ataque[i]), 9, '\nerror en la cantidad de argumentos\nScript "udp_flood_attack", funcion "udpFloodAttack"')
            self.assertEqual(ataque[i][3], '190.34.123.200', '\nerror en la IP de origen\nScript "udp_flood_attack", funcion "udpFloodAttack"')
            self.assertEqual(ataque[i][4], '200.7.4.7', '\nerror en la IP de destino\nScript "udp_flood_attack", funcion "udpFloodAttack"')
            self.assertTrue( ataque[i][5]<=10-0.1 and ataque[i][5]>=0, '\nerror en el tiempo del paquete\nScript "udp_flood_attack", funcion "udpFloodAttack"')
            self.assertTrue( (ataque[i][1] in puertos[0]) or (ataque[i][1] in puertos[1]), '\nerror en el puerto del paquete\nScript "udp_flood_attack", funcion "udpFloodAttack"')
            self.assertEqual(ataque[i][0], 567, '\nerror en el puerto del paquete\nScript "udp_flood_attack", funcion "udpFloodAttack"')

        self.assertTrue(icmpResp>0, '\nerror en la cantidad de respuestas\nScript "udp_flood_attack", funcion "udpFloodAttack"')
        self.assertEqual(len(ataque), 140, '\nerror en la cantidad de paquetes\nScript "udp_flood_attack", funcion "udpFloodAttack"')


    def test_udpFloodAttack_icmp( self ):
        puertos=[[80,25,137,1024,53],[161,123,111,500,69,28960,19,9987,5353,12203,2049,9915,63392,520]]
        ips = ['39.199.1.200', '195.23.145.200']
        portsrc = [200,145]
        args = udpFloodAttack( '200.7.4.7', ips, portsrc, puertos, 0, 120, 80, 0, -1, 1, 3 )
        ataque = generadorParesUDPflood( args )

        t = []
        c = 0
        for i in range( len( ataque ) ):
            if not( args[i][2] ):
                c += 1
                t.append( args[i][5] )
                self.assertEqual( len( ataque[i] ), 2, 'error en el largo del array pregunta-respuesta: Script "PacketCreator", funcion "PacketCreator" seccion "UDP attack"' )
                if c>=4:
                    self.assertTrue( ( t[c-1]-t[c-3] )<=60 )
            else:
                self.assertEqual( len( ataque[i] ), 1, 'error en el largo del array pregunta-respuesta: Script "PacketCreator", funcion "PacketCreator" seccion "UDP attack"' )


    def test_generadorParesUDPflood(self):
        puertos=[[80,25,137,1024,53],[161,123,111,500,69,28960,19,9987,5353,12203,2049,9915,63392,520]]
        args=udpFloodAttack('200.7.4.7', ['190.34.123.200'], [567], puertos, 0, 10, 40, 4, 0.1, 0, 1)
        ataque=generadorParesUDPflood(args)

        numPkts=0
        for i in range(len(ataque)):
            numPkts+=len(ataque[i])
            self.assertTrue(len(ataque[i])==1 or len(ataque[i])==2, '\nerror en la cantidad de paquetes pregunta y respuesta\nScript "udp_flood_attack", funcion "udpFloodAttack"')
            self.assertTrue( ataque[i][0].time<=10-0.1 and ataque[i][0].time>=0, '\nerror en el tiempo del paquete\nScript "udp_flood_attack", funcion "udpFloodAttack"')
            self.assertTrue( (ataque[i][0][2].dport in puertos[0]) or (ataque[i][0][2].dport in puertos[1]), '\nerror en el puerto del paquete\nScript "udp_flood_attack", funcion "udpFloodAttack"')
            self.assertEqual(ataque[i][0][2].sport, 567, '\nerror en el puerto del paquete\nScript "udp_flood_attack", funcion "udpFloodAttack"')

        self.assertTrue(numPkts>=40, '\nerror en la cantidad de paquetes\nScript "udp_flood_attack", funcion "udpFloodAttack"')
        self.assertEqual(len(ataque), 40, '\nerror en la cantidad de paquetes\nScript "udp_flood_attack", funcion "udpFloodAttack"')



    def test_udpPairGen_query(self):
        packUDP_openPort=udpPairGen(300, 700, 1, '200.7.4.7', '190.34.123.200', 12.6, 0.1, 6, 0)
        packUDP_closePort=udpPairGen(300, 700, 0, '200.7.4.7', '190.34.123.200', 12.6, 0.1, 6, 0)
        self.assertEqual(packUDP_openPort[0],packUDP_closePort[0], '\nproblemas entre el paquete de pregunta de puerto abierto y cerrado\nScript "udp_flood_attack", funcion "udpPairGen"')
        ask=packUDP_openPort[0]

        self.assertEqual(ask.time, 12.6, '\nerror en el tiempo del paquete\nScript "udp_flood_attack", funcion "udpPairGen"')
        self.assertEqual(ask.src, '18:66:da:e6:36:56', '\nerror en la direccion de origen del paquete\nScript "udp_flood_attack", funcion "udpPairGen"')
        self.assertEqual(ask.dst, '18:66:da:4d:c0:08', '\nerror en la direccion de destino del paquete\nScript "udp_flood_attack", funcion "udpPairGen"')
        self.assertEqual(ask[1].src, '200.7.4.7', '\nerror en la direccion de origen del paquete IP\nScript "udp_flood_attack", funcion "udpPairGen"')
        self.assertEqual(ask[1].dst, '190.34.123.200', '\nerror en la direccion de destino del paquete IP\nScript "udp_flood_attack", funcion "udpPairGen"')
        self.assertEqual(ask[2].sport, 300, '\nerror en el puerto de origen del paquete UDP\nScript "udp_flood_attack", funcion "udpPairGen"')
        self.assertEqual(ask[2].dport, 700, '\nerror en el puerto de destino del paquete UDP\nScript "udp_flood_attack", funcion "udpPairGen"')
        self.assertEqual(len(ask[3].load), 1458,'\nerror en los datos del paquete UDP\nScript "udp_flood_attack", funcion "udpPairGen"')


    def test_udpPairGen_response(self):
        packUDP_closePort=udpPairGen(300, 700, 0, '200.7.4.7', '190.34.123.200', 12.6, 0.1, 6, 0)
        ans=packUDP_closePort[1]

        self.assertEqual(ans.time, 12.7, '\nerror en el tiempo del paquete\nScript "udp_flood_attack", funcion "udpPairGen"')
        self.assertEqual(ans.dst, '18:66:da:e6:36:56', '\nerror en la direccion de destino del paquete\nScript "udp_flood_attack", funcion "udpPairGen"')
        self.assertEqual(ans.src, '18:66:da:4d:c0:08', '\nerror en la direccion de origen del paquete\nScript "udp_flood_attack", funcion "udpPairGen"')
        self.assertEqual(ans[1].dst, '200.7.4.7', '\nerror en la direccion de destino del paquete IP\nScript "udp_flood_attack", funcion "udpPairGen"')
        self.assertEqual(ans[1].src, '190.34.123.200', '\nerror en la direccion de origen del paquete IP\nScript "udp_flood_attack", funcion "udpPairGen"')
        self.assertEqual(ans[2].type, 3, '\nerror en el paquete ICMP\nScript "udp_flood_attack", funcion "udpPairGen"')
        self.assertEqual(ans[2].code, 3, '\nerror en el paquete ICMP\nScript "udp_flood_attack", funcion "udpPairGen"')



if __name__ == '__main__':
    unittest.main()
