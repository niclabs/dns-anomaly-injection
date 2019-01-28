from udp_flood_attack import *
import unittest

class udp_flood_attackTest(unittest.TestCase):

    def test_udpFloodAttack(self):
        puertos=[[80,25,137,1024,53],[161,123,111,500,69,28960,19,9987,5353,12203,2049,9915,63392,520]]
        ataque=udpFloodAttack('200.7.4.7', ['190.34.123.200'], [567], puertos, 0, 10, 140, 4, 0, 1)

        icmpResp=0
        for i in range(len(ataque)):
            if not(ataque[i][2]):
                icmpResp+=1
            self.assertEqual(len(ataque[i]), 9, 'error en la cantidad de argumentos: Script "udp_flood_attack", funcion "udpFloodAttack"')
            self.assertEqual(ataque[i][3], '190.34.123.200', 'error en la IP de origen: Script "udp_flood_attack", funcion "udpFloodAttack"')
            self.assertEqual(ataque[i][4], '200.7.4.7', 'error en la IP de destino: Script "udp_flood_attack", funcion "udpFloodAttack"')
            self.assertTrue( ataque[i][5]<=11 and ataque[i][5]>=0, 'error en el tiempo del paquete: Script "udp_flood_attack", funcion "udpFloodAttack"')
            self.assertTrue( (ataque[i][1] in puertos[0]) or (ataque[i][1] in puertos[1]), 'error en el puerto del paquete: Script "udp_flood_attack", funcion "udpFloodAttack"')
            self.assertEqual(ataque[i][0], 567, 'error en el puerto del paquete: Script "udp_flood_attack", funcion "udpFloodAttack"')

        self.assertTrue(icmpResp>0, 'error en la cantidad de respuestas: Script "udp_flood_attack", funcion "udpFloodAttack"')
        self.assertEqual(len(ataque), 140, 'error en la cantidad de paquetes: Script "udp_flood_attack", funcion "udpFloodAttack"')


    def test_udpFloodAttack_icmp( self ):
        puertos=[[80,25,137,1024,53],[161,123,111,500,69,28960,19,9987,5353,12203,2049,9915,63392,520]]
        ips = ['39.199.1.200', '195.23.145.200']
        portsrc = [200,145]
        args = udpFloodAttack( '200.7.4.7', ips, portsrc, puertos, 0, 120, 80, 0, 1, 3 )
        ataque = []
        for i in range( len( ataque ) ):
            ataque.append( generadorParesUDPflood( args[i] ) )

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
        args=udpFloodAttack('200.7.4.7', ['190.34.123.200'], [567], puertos, 0, 10, 40, 4, 0, 1)
        ataque = []
        for i in range( len( args ) ):
            ataque.append( generadorParesUDPflood( args[i] ) )

        numPkts=0
        for i in range(len(ataque)):
            numPkts+=len(ataque[i])
            self.assertTrue(len(ataque[i])==1 or len(ataque[i])==2, 'error en la cantidad de paquetes pregunta y respuesta: Script "udp_flood_attack", funcion "udpFloodAttack"')
            self.assertTrue( ataque[i][0].time<=10 and ataque[i][0].time>=0, 'error en el tiempo del paquete: Script "udp_flood_attack", funcion "udpFloodAttack"')
            self.assertTrue( (ataque[i][0][2].dport in puertos[0]) or (ataque[i][0][2].dport in puertos[1]), 'error en el puerto del paquete: Script "udp_flood_attack", funcion "udpFloodAttack"')
            self.assertEqual(ataque[i][0][2].sport, 567, 'error en el puerto del paquete: Script "udp_flood_attack", funcion "udpFloodAttack"')

        self.assertTrue(numPkts>=40, 'error en la cantidad de paquetes: Script "udp_flood_attack", funcion "udpFloodAttack"')
        self.assertEqual(len(ataque), 40, 'error en la cantidad de paquetes: Script "udp_flood_attack", funcion "udpFloodAttack"')



    def test_udpPairGen_query(self):
        packUDP_openPort=udpPairGen(300, 700, 1, '200.7.4.7', '190.34.123.200', 12.6, 0.1, 6, 0)
        packUDP_closePort=udpPairGen(300, 700, 0, '200.7.4.7', '190.34.123.200', 12.6, 0.1, 6, 0)
        self.assertEqual(packUDP_openPort[0],packUDP_closePort[0], 'problemas entre el paquete de pregunta de puerto abierto y cerrado: Script "udp_flood_attack", funcion "udpPairGen"')
        ask=packUDP_openPort[0]

        self.assertEqual(ask.time, 12.6, 'error en el tiempo del paquete: Script "udp_flood_attack", funcion "udpPairGen"')
        self.assertEqual(ask.src, '18:66:da:e6:36:56', 'error en la direccion de origen del paquete: Script "udp_flood_attack", funcion "udpPairGen"')
        self.assertEqual(ask.dst, '18:66:da:4d:c0:08', 'error en la direccion de destino del paquete: Script "udp_flood_attack", funcion "udpPairGen"')
        self.assertEqual(ask[1].src, '200.7.4.7', 'error en la direccion de origen del paquete IP: Script "udp_flood_attack", funcion "udpPairGen"')
        self.assertEqual(ask[1].dst, '190.34.123.200', 'error en la direccion de destino del paquete IP: Script "udp_flood_attack", funcion "udpPairGen"')
        self.assertEqual(ask[2].sport, 300, 'error en el puerto de origen del paquete UDP: Script "udp_flood_attack", funcion "udpPairGen"')
        self.assertEqual(ask[2].dport, 700, 'error en el puerto de destino del paquete UDP: Script "udp_flood_attack", funcion "udpPairGen"')
        self.assertEqual(len(ask[3].load), 1458,'error en los datos del paquete UDP: Script "udp_flood_attack", funcion "udpPairGen"')


    def test_udpPairGen_response(self):
        packUDP_closePort=udpPairGen(300, 700, 0, '200.7.4.7', '190.34.123.200', 12.6, 0.1, 6, 0)
        ans=packUDP_closePort[1]

        self.assertEqual(ans.time, 12.7, 'error en el tiempo del paquete: Script "udp_flood_attack", funcion "udpPairGen"')
        self.assertEqual(ans.dst, '18:66:da:e6:36:56', 'error en la direccion de destino del paquete: Script "udp_flood_attack", funcion "udpPairGen"')
        self.assertEqual(ans.src, '18:66:da:4d:c0:08', 'error en la direccion de origen del paquete: Script "udp_flood_attack", funcion "udpPairGen"')
        self.assertEqual(ans[1].dst, '200.7.4.7', 'error en la direccion de destino del paquete IP: Script "udp_flood_attack", funcion "udpPairGen"')
        self.assertEqual(ans[1].src, '190.34.123.200', 'error en la direccion de origen del paquete IP: Script "udp_flood_attack", funcion "udpPairGen"')
        self.assertEqual(ans[2].type, 3, 'error en el paquete ICMP: Script "udp_flood_attack", funcion "udpPairGen"')
        self.assertEqual(ans[2].code, 3, 'error en el paquete ICMP: Script "udp_flood_attack", funcion "udpPairGen"')



if __name__ == '__main__':
    unittest.main()
