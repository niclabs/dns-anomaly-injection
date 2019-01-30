from PacketCreator import *
from pprint import pprint
import unittest

class PacketCreatorTest( unittest.TestCase ):

    def test_argsPacketsCreator_Dom_Attack( self ):
        domList = ['a.cl', 'b.cl', 'c.cl']
        ataque = argsPacketsCreator( '200.7.4.7', ['190.34.123.200'], [10240], domList, 10, 15, 20, 9, 0, 0, 2 )
        self.assertEqual( len( ataque ), 20, 'error en la cantidad de paquetes en el ataque: Script "PacketCreator", funcion "argsPacketsCreator" seccion "Domain attack"' )

        for i in range( len( ataque ) ):
            self.assertEqual( ataque[i][0], 10240, 'error en el puerto de origen: Script "PacketCreator", funcion "argsPacketsCreator" seccion "Domain attack"' )
            self.assertTrue( ataque[i][1] in domList, 'error en el dominio de la pregunta: Script "PacketCreator", funcion "argsPacketsCreator" seccion "Domain attack"' )
            self.assertEqual( ataque[i][2], '190.34.123.200', 'error en la direccion IP de origen en el paquete IP: Script "PacketCreator", funcion "argsPacketsCreator" seccion "Domain attack"' )
            self.assertEqual( ataque[i][3], '200.7.4.7', 'error en la direccion IP de origen en el paquete IP: Script "PacketCreator", funcion "argsPacketsCreator" seccion "Domain attack"' )
            self.assertTrue( ataque[i][4] <=  15 and ataque[i][4] >=  10, 'error en el tiempo del ataque: Script "PacketCreator", funcion "argsPacketsCreator" seccion "Domain attack"' )



    def test_generadorParesPortScanningDom( self ):
        domList = ['a.cl', 'b.cl', 'c.cl']
        args = argsPacketsCreator( '200.7.4.7', ['190.34.123.200'], [10240], domList, 10, 15, 20, 9, 0, 0, 2 )
        ataque = []
        for i in range( len( args ) ):
            ataque.append( generadorParesPortScanningDom( args[i] ) )
        self.assertEqual( len( ataque ), 20, 'error en la cantidad de paquetes en el ataque: Script "PacketCreator", funcion "argsPacketsCreator" seccion "Domain attack"' )

        numPkts = 0
        for i in range( len( ataque ) ):
            numPkts += len( ataque[i] )
            self.assertEqual( len( ataque[i] ), 2, 'error en el largo del array pregunta respuesta: Script "PacketCreator", funcion "generadorParesPortScanningDom"' )
            self.assertTrue( ataque[i][0].time <=  15 and ataque[i][0].time >=  10, 'error en el tiempo del ataque: Script "PacketCreator", funcion "generadorParesPortScanningDom"' )
            self.assertTrue( ataque[i][1].time <=  16 and ataque[i][1].time >=  10, 'error en el tiempo del ataque: Script "PacketCreator", funcion "generadorParesPortScanningDom"' )
            self.assertEqual( ataque[i][0][1].src, '190.34.123.200', 'error en la direccion IP de origen en el paquete IP: Script "PacketCreator", funcion "generadorParesPortScanningDom"' )
            self.assertEqual( ataque[i][1][1].src, '200.7.4.7', 'error en la direccion IP de origen en el paquete IP: Script "PacketCreator", funcion "generadorParesPortScanningDom"' )
            self.assertEqual( ataque[i][0][1].dst, '200.7.4.7', 'error en la direccion IP de destino en el paquete IP: Script "PacketCreator", funcion "generadorParesPortScanningDom"' )
            self.assertEqual( ataque[i][1][1].dst, '190.34.123.200', 'error en la direccion IP de destino en el paquete IP: Script "PacketCreator", funcion "generadorParesPortScanningDom"' )
            self.assertTrue( ( domList[0] in str( ataque[i][0][4].qname ) ) or ( domList[1] in str( ataque[i][0][4].qname ) ) or ( domList[2] in str( ataque[i][0][4].qname ) ), 'error en el dominio de la pregunta: Script "PacketCreator", funcion "generadorParesPortScanningDom"' )
            self.assertTrue( ( domList[0] in str( ataque[i][1][5].rrname ) ) or ( domList[1] in str( ataque[i][1][5].rrname ) ) or ( domList[2] in str( ataque[i][1][5].rrname ) ), 'error en el dominio de la pregunta: Script "PacketCreator", funcion "generadorParesPortScanningDom"' )

        self.assertEqual( numPkts, 40, 'error en la cantidad de paquetes en el ataque: Script "PacketCreator", funcion "generadorParesPortScanningDom"' )


    def test_Domain_DDoS_attack( self ):
        domAt = Domain_DDoS_attack( 35, '200.7.4.7', 0, 0.5, 60, 7 )
        ips = randomIP( 35, 7, 1 )
        ports = randomSourcePorts( 35, 7 )
        domsFile = 'ultimos-dominios-1m.txt'
        f  =  open( domsFile, "r" )
        domsList = []
        bool = 1
        while( bool ):
            dominio = f.readline().split( ',' )
            domsList += [dominio[0]]
            if ( domsList[-1] == '' ) or len( domsList ) == ( 60+2 ):
                domsList = domsList[1:-1]
                bool = 0
                break
        f.close()
        packAt = argsPacketsCreator( '200.7.4.7', ips, ports, domsList, 0, 0.5, 60, 7, 0, 0, 2 )
        self.assertEqual( domAt, packAt, 'error en la funcion "Domain_DDoS_attack"' )


    def test_Domain_attack( self ):
        domAtaque = Domain_attack( '200.7.4.7', '190.34.123.200', 10240, 10, 25, 50, 9 )
        domsFile = 'ultimos-dominios-1m.txt'
        f  =  open( domsFile, "r" )
        domsList = []
        bool = 1
        while( bool ):
            dominio = f.readline().split( ',' )
            domsList += [dominio[0]]
            if ( domsList[-1] == '' ) or len( domsList ) == ( 50+2 ):
                domsList = domsList[1:-1]
                bool = 0
                break
        f.close()
        PackAt = argsPacketsCreator( '200.7.4.7', ['190.34.123.200'], [10240], domsList, 10, 25, 50, 9, 0, 0, 2 )
        self.assertEqual( domAtaque, PackAt, 'error en la funcion "Domain_attack"' )


    def test_DomainGen_query( self ):
        packDomain = DomainGen( 7340, 'buzoku.cl', '190.34.123.200', '200.7.4.7', 345.56, 0.02 )
        ask = packDomain[0]
        self.assertEqual( len( packDomain ), 2, 'error con la cantidad de preguntas y respuestas en el pack: Script "PacketCreator", funcion "DomainGen"' )
        self.assertEqual( ask[3].id, packDomain[1][3].id, 'error en la id del paquete DNS: Script "PacketCreator", funcion "DomainGen"' )

        self.assertEqual( ask.time, 345.56, 'error en el tiempo del paquete Ethernet: Script "PacketCreator", funcion "DomainGen"' )
        self.assertEqual( ask.src, '18:66:da:e6:36:56', 'error en la direccion del paquete Ethernet: Script "PacketCreator", funcion "DomainGen"' )
        self.assertEqual( ask.dst, '18:66:da:4d:c0:08', 'error en la direccion del paquete Ethernet: Script "PacketCreator", funcion "DomainGen"' )
        self.assertEqual( ask[1].src, '190.34.123.200', 'error en la direccion de origen del paquete IP: Script "PacketCreator", funcion "DomainGen"' )
        self.assertEqual( ask[1].dst, '200.7.4.7', 'error en la direccion de destino del paquete IP: Script "PacketCreator", funcion "DomainGen"' )
        self.assertEqual( ask[2].sport, 7340, 'error en el puerto de origen del paquete UDP: Script "PacketCreator", funcion "DomainGen"' )
        self.assertEqual( ask[2].dport, 53, 'error en el puerto de destino del paquete UDP: Script "PacketCreator", funcion "DomainGen"' )
        self.assertEqual( ask[3].opcode, 0, 'error en campo "opcode" del paquete DNS: Script "PacketCreator", funcion "DomainGen"' )
        self.assertEqual( ask[3].rd, 0, 'error en el campo "rd" en paquete DNS: Script "PacketCreator", funcion "DomainGen"' )
        self.assertEqual( ask[3].qdcount, 1, 'error en el campo "qdcount" en paquete DNS: Script "PacketCreator", funcion "DomainGen"' )
        self.assertEqual( ask[3].qr, 0, 'error en el campo "qr" en paquete DNS: Script "PacketCreator", funcion "DomainGen"' )
        self.assertTrue( 'buzoku.cl.' in str( ask[4].qname ), 'error en el campo "qname" en paquete DNSQR: Script "PacketCreator", funcion "DomainGen"' )


    def test_DomainGen_response( self ):
        packDomain = DomainGen( 7340, 'buzoku.cl', '190.34.123.200', '200.7.4.7', 345.56, 0.02 )
        ans = packDomain[1]

        self.assertEqual( ans.time, 345.56+0.02, 'error en el tiempo del paquete Ethernet: Script "PacketCreator", funcion "DomainGen"' )
        self.assertEqual( ans.dst, '18:66:da:e6:36:56', 'error en la direccion de destino del paquete Ethernet: Script "PacketCreator", funcion "DomainGen"' )
        self.assertEqual( ans.src, '18:66:da:4d:c0:08', 'error en la direccion de origen del paquete Ethernet: Script "PacketCreator", funcion "DomainGen"' )
        self.assertEqual( ans[1].src, '200.7.4.7', 'error en la direccion de origen del paquete IP: Script "PacketCreator", funcion "DomainGen"' )
        self.assertEqual( ans[1].dst, '190.34.123.200', 'error en la direccion de destino del paquete IP: Script "PacketCreator", funcion "DomainGen"' )
        self.assertEqual( ans[2].sport, 53, 'error en el puerto de origen del paquete UDP: Script "PacketCreator", funcion "DomainGen"' )
        self.assertEqual( ans[2].dport, 7340, 'error en el puerto de destino del paquete UDP: Script "PacketCreator", funcion "DomainGen"' )
        self.assertEqual( ans[3].opcode, 0, 'error en campo "opcode" del paquete DNS: Script "PacketCreator", funcion "DomainGen"' )
        self.assertEqual( ans[3].rd, 0, 'error en el campo "rd" en paquete DNS: Script "PacketCreator", funcion "DomainGen"' )
        self.assertEqual( ans[3].qr, 1, 'error en el campo "qr" en paquete DNS: Script "PacketCreator", funcion "DomainGen"' )
        self.assertTrue( 'buzoku.cl.' in str( ans[5].rrname ) , 'error en el campo "qname" en paquete DNSRR: Script "PacketCreator", funcion "DomainGen"' )
        self.assertEqual( ans[5].type, 2, 'error en el campo "type" en paquete DNSRR: Script "PacketCreator", funcion "DomainGen"' )


    def test_pickDelayResp_intervalo_aleatorio( self ):
        new0_interResp = pickDelayResp( 0 )
        new1_interResp = pickDelayResp( 1 )
        new2_interResp = pickDelayResp( 2 )

        self.assertTrue( new0_interResp <=  ( 0.0324164173995+( 0.661281423818*4 ) ) and new0_interResp >=  0 )
        self.assertTrue( new1_interResp <=  ( 0.000322919547395+( 0.018900697143*4 ) ) and new1_interResp >=  0 )
        self.assertTrue( new2_interResp <=  ( 0.000322919547395+( 0.018900697143*4 ) ) and new0_interResp >=  0 )




if __name__  ==  '__main__':
    unittest.main()
