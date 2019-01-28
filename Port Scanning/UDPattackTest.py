from PacketCreator import *
import unittest

class PacketCreatorTest( unittest.TestCase ):

    def test_PacketCreator_UDPattack( self ):
        puertos=[[80,25,137,1024,53],[161,123,111,500,69,28960,19,9987,5353,12203,2049,9915,63392,520]]
        ataque=PacketCreator( '200.7.4.7', ['56.145.96.4'], [37599], puertos, 13, 25, 13, 9, 0.13, False, 0, 1 )
        self.assertEqual( len( ataque ), 13, 'error en la cantidad de paquetes en el ataque: Script "PacketCreator", funcion "PacketCreator" seccion "UDP attack"' )

        for i in range( len( ataque ) ):
            self.assertEqual( ataque[i][0], 37599, 'error en el puerto de la pregunta: Script "PacketCreator", funcion "PacketCreator" seccion "UDP attack"' )
            self.assertTrue( ( ataque[i][1] in puertos[0] ) or ( ataque[i][1] in puertos[1] ), 'error en el puerto de la pregunta: Script "PacketCreator", funcion "PacketCreator" seccion "UDP attack"' )
            self.assertEqual( ataque[i][3], '56.145.96.4', 'error en la direccion IP de origen en el paquete IP: Script "PacketCreator", funcion "PacketCreator" seccion "Domain attack"' )
            self.assertEqual( ataque[i][4], '200.7.4.7', 'error en la direccion IP de destino en el paquete IP: Script "PacketCreator", funcion "PacketCreator" seccion "Domain attack"' )
            self.assertTrue( ataque[i][5]<=25-0.13 and ataque[i][5]>=13, 'error en el tiempo del ataque: Script "PacketCreator", funcion "PacketCreator" seccion "UDP attack"' )


    def test_PacketCreator_UDPattack_icmp( self ):
        puertos = [[80,25,137,1024,53],[161,123,111,500,69,28960,19,9987,5353,12203,2049,9915,63392,520]]
        ips = ['39.199.1.200', '195.23.145.200']
        portsrc = [200,145]
        args = PacketCreator( '200.7.4.7', ips, portsrc, puertos, 0, 120, 80, 0, -1, 1, 3, 1 )
        ataque = generadorParesPortScanningUDP( args )

        t = []
        c = 0
        for i in range( len( ataque ) ):
            if args[i][2]:
                c += 1
                t.append( args[i][5] )
                self.assertEqual( len( ataque[i] ), 2, 'error en el largo del array pregunta-respuesta: Script "PacketCreator", funcion "PacketCreator" seccion "UDP attack"' )
                if c>=4:
                    self.assertTrue( ( t[c-1]-t[c-3] )<=60 )
            else:
                self.assertEqual( len( ataque[i] ), 1, 'error en el largo del array pregunta-respuesta: Script "PacketCreator", funcion "PacketCreator" seccion "UDP attack"' )



    def test_generadorParesPortScanningUDP( self ):
        puertos=[[80,25,137,1024,53],[161,123,111,500,69,28960,19,9987,5353,12203,2049,9915,63392,520]]
        args=PacketCreator( '200.7.4.7', ['56.145.96.4'], [37599], puertos, 13, 25, 13, 9, 0.13, False, 0, 1 )
        ataque=generadorParesPortScanningUDP( args )
        self.assertEqual( len( ataque ), 13, 'error en la cantidad de paquetes en el ataque: Script "PacketCreator", funcion "generadorParesPortScanningUDP"' )

        numPkts=0
        for i in range( len( ataque ) ):
            numPkts+=len( ataque[i] )
            self.assertTrue( len( ataque[i] )==1 or len( ataque[i] )==2, 'error en el largo del array pregunta respuesta: Script "PacketCreator", funcion "generadorParesPortScanningUDP"' )
            self.assertTrue( ataque[i][0].time<=25-0.13 and ataque[i][0].time>=13, 'error en el tiempo del ataque: Script "PacketCreator", funcion "generadorParesPortScanningUDP"' )
            self.assertTrue( ( ataque[i][0][2].dport in puertos[0] ) or ( ataque[i][0][2].dport in puertos[1] ), 'error en el puerto de la pregunta: Script "PacketCreator", funcion "generadorParesPortScanningUDP"' )
            self.assertEqual( ataque[i][0][2].sport, 37599, 'error en el puerto de la pregunta: Script "PacketCreator", funcion "generadorParesPortScanningUDP"' )
            self.assertEqual( ataque[i][0][1].src, '56.145.96.4', 'error en la direccion IP de origen en el paquete IP: Script "PacketCreator", funcion "generadorParesPortScanningUDP"' )
            self.assertEqual( ataque[i][0][1].dst, '200.7.4.7', 'error en la direccion IP de destino en el paquete IP: Script "PacketCreator", funcion "generadorParesPortScanningUDP"' )

        self.assertTrue( numPkts>=13, 'error en la cantidad de paquetes en el ataque: Script "PacketCreator", funcion "generadorParesPortScanningUDP"' )


    def test_UDP_DDoS_attack( self ):
        udpAt=UDP_DDoS_attack( 25, '200.7.4.7', [[],list( range( 25,80,2 ) )], 160, 162, 40, 5, 0.001, False, 2 )
        ips=randomIP( 25, 5, 1 )
        ports=randomSourcePorts( 25, 5 )
        packAt=PacketCreator( '200.7.4.7', ips, ports, [[],list( range( 25,80,2 ) )], 160, 162, 40, 5, 0.001, False, 2, 1 )
        self.assertEqual( udpAt, packAt, 'error en la funcion "UDP_DDoS_attack"' )


    def test_UDP_Attack( self ):
        puertos=[[80,25,137,1024,53],[161,123,111,500,69,28960,19,9987,5353,12203,2049,9915,63392,520]]
        udpAt=UDP_attack( '200.7.4.7', '56.145.96.4', 37599, puertos, 13, 25, 300, 9, 0.13, False, 2 )
        packAt=PacketCreator( '200.7.4.7', ['56.145.96.4'], [37599], puertos, 13, 25, 300, 9, 0.13, False, 2, 1 )
        self.assertEqual( udpAt, packAt, 'error en la funcion "UDP_attack"' )


    def test_UDPgen_query( self ):
        packUDP=UDPgen( 4678, 25, 0, '56.145.96.4', '200.7.4.7', 132.54, 0.001 )
        ask=packUDP[0]
        self.assertEqual( len( packUDP ), 1, 'error en la cantidad de preguntas y respuestas: Script "PacketCreator", funcion "UDPgen"' )

        self.assertEqual( ask.time, 132.54, 'error en el tiempo del paquete Ethernet: Script "PacketCreator", funcion "UDPgen"' )
        self.assertEqual( ask.src, '18:66:da:e6:36:56', 'error en la direccion del paquete Ethernet: Script "PacketCreator", funcion "UDPgen"' )
        self.assertEqual( ask.dst, '18:66:da:4d:c0:08', 'error en la direccion del paquete Ethernet: Script "PacketCreator", funcion "UDPgen"' )
        self.assertEqual( ask[1].src, '56.145.96.4', 'error en la direccion de origen del paquete IP: Script "PacketCreator", funcion "UDPgen"' )
        self.assertEqual( ask[1].dst, '200.7.4.7', 'error en la direccion de destino del paquete IP: Script "PacketCreator", funcion "UDPgen"' )
        self.assertEqual( ask[2].sport, 4678, 'error en el puerto de origen del paquete UDP: Script "PacketCreator", funcion "UDPgen"' )
        self.assertEqual( ask[2].dport, 25, 'error en el puerto de destino del paquete UDP: Script "PacketCreator", funcion "UDPgen"' )


    def test_UDPgen_response( self ):
        packUDP=UDPgen( 4678, 25, 1, '56.145.96.4', '200.7.4.7', 132.54, 0.001 )
        ans=packUDP[1]
        self.assertEqual( len( packUDP ), 2, 'error en la cantidad de preguntas y respuestas: Script "PacketCreator", funcion "UDPgen"' )

        self.assertEqual( ans.time, 132.54+0.001, 'error en el tiempo del paquete Ethernet: Script "PacketCreator", funcion "UDPgen"' )
        self.assertEqual( ans.src, '18:66:da:4d:c0:08', 'error en la direccion del paquete Ethernet: Script "PacketCreator", funcion "UDPgen"' )
        self.assertEqual( ans.dst, '18:66:da:e6:36:56', 'error en la direccion del paquete Ethernet: Script "PacketCreator", funcion "UDPgen"' )
        self.assertEqual( ans[1].src, '200.7.4.7', 'error en la direccion de origen del paquete IP: Script "PacketCreator", funcion "UDPgen"' )
        self.assertEqual( ans[1].dst, '56.145.96.4', 'error en la direccion de destino del paquete IP: Script "PacketCreator", funcion "UDPgen"' )
        self.assertEqual( ans[2].type, 3, 'error en el campo "type" en el paquete ICMP: Script "PacketCreator", funcion "UDPgen"' )
        self.assertEqual( ans[2].code, 3, 'error en el campo "code" en el paquete ICMP: Script "PacketCreator", funcion "UDPgen"' )





if __name__ == '__main__':
    unittest.main()
