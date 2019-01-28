from PacketCreator import *
import unittest

class PacketCreatorTest( unittest.TestCase ):

    def test_PacketCreator_TCP_Attack( self ):
        puertos = [[80,25,137,1024,53],[161,123,111,500,69,28960,19,9987,5353,12203,2049,9915,63392,520]]
        ip = ['190.34.123.200','56.145.96.4']
        port = [10240,6799]
        ataque = PacketCreator( '200.7.4.7', ip, port, puertos, 0, 5, 11, 9, 0, 0, 0 )
        self.assertEqual( len( ataque ), 11, 'error en la cantidad de paquetes en el ataque: Script "PacketCreator", funcion "PacketCreator" seccion "TCP attack"' )

        for i in range( len( ataque ) ):
            self.assertTrue( ataque[i][0] in port )
            self.assertTrue( ( ataque[i][1] in puertos[0] ) or ( ataque[i][1] in puertos[1] ), 'error en el puerto del paquete: Script "PacketCreator", funcion "PacketCreator" seccion "TCP attack"' )

            self.assertTrue( ataque[i][3] in ip, 'error en la direccion IP de origen en el paquete IP: Script "PacketCreator", funcion "PacketCreator" seccion "TCP attack"' )
            self.assertEqual( ataque[i][4], '200.7.4.7', 'error en la direccion IP de destino en el paquete IP: Script "PacketCreator", funcion "PacketCreator" seccion "TCP attack"' )
            self.assertTrue( ataque[i][5] <=  5-0.3 and ataque[i][5] >=  0, 'error en el tiempo del paquete: Script "PacketCreator", funcion "PacketCreator" seccion "TCP attack"' )

    def test_generadorParesPortScanningTCP( self ):
        puertos = [[80,25,137,1024,53],[161,123,111,500,69,28960,19,9987,5353,12203,2049,9915,63392,520]]
        ip = ['190.34.123.200','56.145.96.4']
        port = [10240,6799]
        args = PacketCreator( '200.7.4.7', ip, port, puertos, 0, 5, 11, 9, 0, 0, 0 )
        ataque = []
        for i in range( len( args ) ):
            ataque.append( generadorParesPortScanningTCP( args[i] ) )
        self.assertEqual( len( ataque ), 11, 'error en la cantidad de paquetes en el ataque: Script "PacketCreator", funcion "generadorParesPortScanningTCP"' )

        numPkts = 0
        for i in range( len( ataque ) ):
            numPkts += len( ataque[i] )
            self.assertTrue( len( ataque[i] ) == 1 or len( ataque[i] ) == 2, 'error en la cantidad de paquetes en el ataque: Script "PacketCreator", funcion "generadorParesPortScanningTCP"' )
            self.assertTrue( ataque[i][0].time <=  5 and ataque[i][0].time >=  0, 'error en el tiempo del paquete: Script "PacketCreator", funcion "generadorParesPortScanningTCP"' )
            self.assertTrue( ataque[i][0][1].src in ip, 'error en la direccion IP de origen en el paquete IP: Script "PacketCreator", funcion "generadorParesPortScanningTCP"' )
            self.assertEqual( ataque[i][0][1].dst, '200.7.4.7', 'error en la direccion IP de destino en el paquete IP: Script "PacketCreator", funcion "generadorParesPortScanningTCP"' )
            self.assertTrue( ( ataque[i][0][2].dport in puertos[0] ) or ( ataque[i][0][2].dport in puertos[1] ), 'error en el puerto del paquete: Script "PacketCreator", funcion "generadorParesPortScanningTCP"' )
            self.assertTrue( ataque[i][0][2].sport in port, 'error en el puerto del paquete: Script "PacketCreator", funcion "generadorParesPortScanningTCP"' )

        self.assertTrue( numPkts >=  11, 'error en la cantidad de paquetes: Script "PacketCreator", funcion "generadorParesPortScanningTCP"' )


    def test_TCP_DDoS_attack( self ):
        tcpAt = TCP_DDoS_attack( 25, '200.7.1.7', [[],list( range( 0,80,5 ) )], 12, 15.5, 20, 9 )
        ips = randomIP( 25, 9, 1 )
        ports = randomSourcePorts( 25, 9 )
        packAt = PacketCreator( '200.7.1.7', ips, ports, [[],list( range( 0,80,5 ) )], 12, 15.5, 20, 9, 0, 0, 0 )
        self.assertEqual( tcpAt, packAt, 'error en la funcion "TCP_DDoS_attack"' )


    def test_TCP_attack( self ):
        puertos = [[80,25,137,1024,53],[161,123,111,500,69,28960,19,9987,5353,12203,2049,9915,63392,520]]
        tcpAt = TCP_attack( '200.7.4.7', '190.34.123.200', 10240, puertos, 0, 25, 50, 9 )
        PackAt = PacketCreator( '200.7.4.7', ['190.34.123.200'], [10240], puertos, 0, 25, 50, 9, 0, 0, 0 )
        self.assertEqual( tcpAt, PackAt, 'error en la funcion "TCP_attack"' )


    def test_TCPgen_query( self ):
        packTCP_openPort = TCPgen( 300, 700, 1, '190.34.123.200', '200.7.4.7', 12.6, 0.1 )
        packTCP_closePort = TCPgen( 300, 700, 0, '190.34.123.200', '200.7.4.7', 12.6, 0.1 )
        self.assertFalse( packTCP_openPort[0][2].id == packTCP_closePort[0][2].id, ': problemas entre el paquete de pregunta de puerto abierto y cerrado: Script "PacketCreator", funcion "TCPgen"' )
        self.assertEqual( packTCP_openPort[0][3].id, packTCP_openPort[1][3].id, ': problemas entre el paquete de pregunta de puerto abierto y cerrado: Script "PacketCreator", funcion "TCPgen"' )

        self.assertEqual( packTCP_openPort[0].time, 12.6, 'error en el tiempo del paquete: Script "PacketCreator", funcion "TCPgen"' )
        self.assertEqual( packTCP_openPort[0].src, '18:66:da:e6:36:56', 'error en la direccion del paquete: Script "PacketCreator", funcion "TCPgen"' )
        self.assertEqual( packTCP_openPort[0].dst, '18:66:da:4d:c0:08', 'error en la direccion del paquete: Script "PacketCreator", funcion "TCPgen"' )
        self.assertEqual( packTCP_openPort[0][1].dst, '200.7.4.7', 'error en la direccion del paquete IP: Script "PacketCreator", funcion "TCPgen"' )
        self.assertEqual( packTCP_openPort[0][1].src, '190.34.123.200', 'error en la direccion del paquete IP: Script "PacketCreator", funcion "TCPgen"' )
        self.assertEqual( packTCP_openPort[0][2].sport, 300, 'error en el puerto del paquete: Script "PacketCreator", funcion "TCPgen"' )
        self.assertEqual( packTCP_openPort[0][2].dport, 700, 'error en el puerto del paquete: Script "PacketCreator", funcion "TCPgen"' )
        self.assertEqual( packTCP_openPort[0][2].flags, 'S', 'error en las banderas del paquete: Script "PacketCreator", funcion "TCPgen"' )
        self.assertEqual( packTCP_openPort[0][3].rd, 0, 'error en el paquete DNS: Script "PacketCreator", funcion "TCPgen"' )


    def test_TCPgen_response( self ):
        packTCP_openPort = TCPgen( 300, 700, 1, '190.34.123.200', '200.7.4.7', 12.6, 0.1 )
        packTCP_closePort = TCPgen( 300, 700, 0, '190.34.123.200', '200.7.4.7', 12.6, 0.1 )
        respOpen = packTCP_openPort[1]
        self.assertFalse( respOpen == packTCP_closePort[1], ': problemas entre el paquete de respuesta de puerto abierto y cerrado: Script "PacketCreator", funcion "TCPgen"' )
        self.assertEqual( respOpen[2].flags, 'SA', 'error en las banderas del paquete: Script "PacketCreator", funcion "TCPgen"' )
        self.assertEqual( packTCP_closePort[1][2].flags, 'R', 'error en las banderas del paquete: Script "PacketCreator", funcion "TCPgen"' )

        self.assertEqual( respOpen.time, 12.7, 'error en el tiempo del paquete: Script "PacketCreator", funcion "TCPgen"' )
        self.assertEqual( respOpen.dst, '18:66:da:e6:36:56', 'error en la direccion del paquete: Script "PacketCreator", funcion "TCPgen"' )
        self.assertEqual( respOpen.src, '18:66:da:4d:c0:08', 'error en la direccion del paquete: Script "PacketCreator", funcion "TCPgen"' )
        self.assertEqual( respOpen[1].src, '200.7.4.7', 'error en la direccion del paqueteIP: Script "PacketCreator", funcion "TCPgen"' )
        self.assertEqual( respOpen[1].dst, '190.34.123.200', 'error en la direccion del paqueteIP: Script "PacketCreator", funcion "TCPgen"' )
        self.assertEqual( respOpen[2].sport, 700, 'error en el puerto de origen del paquete: Script "PacketCreator", funcion "TCPgen"' )
        self.assertEqual( respOpen[2].dport, 300, 'error en el puerto de destino del paquete: Script "PacketCreator", funcion "TCPgen"' )
        self.assertEqual( respOpen[3].aa, 1, 'error en el paquete DNS: Script "PacketCreator", funcion "TCPgen"' )


if __name__  ==  '__main__':
    unittest.main()
