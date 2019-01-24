from PacketCreator import *
import unittest

class PacketCreatorTest(unittest.TestCase):

    def test_PacketCreator_TCP_Attack(self):
        puertos=[[80,25,137,1024,53],[161,123,111,500,69,28960,19,9987,5353,12203,2049,9915,63392,520]]
        ip=['190.34.123.200','56.145.96.4']
        port=[10240,6799]
        ataque=PacketCreator('200.7.4.7', ip, port, puertos, 0, 5, 11, 9, 0.3, 0, 0, 0)
        self.assertEqual(len(ataque), 11, 'error en la cantidad de paquetes en el ataque: Script "PacketCreator", funcion "PacketCreator" seccion "TCP attack"')

        numPkts=0
        for i in range(len(ataque)):
            numPkts+=len(ataque[i])
            self.assertTrue(len(ataque[i])==1 or len(ataque[i])==2, 'error en la cantidad de paquetes pregunta y respuesta: Script "PacketCreator", funcion "PacketCreator" seccion "TCP attack"')
            self.assertTrue(ataque[i][0].time<=5-0.3 and ataque[i][0].time>=0, 'error en el tiempo del paquete: Script "PacketCreator", funcion "PacketCreator" seccion "TCP attack"')
            self.assertTrue(ataque[i][0][1].src in ip, 'error en la direccion IP de origen en el paquete IP: Script "PacketCreator", funcion "PacketCreator" seccion "TCP attack"')
            self.assertEqual(ataque[i][0][1].dst, '200.7.4.7', 'error en la direccion IP de destino en el paquete IP: Script "PacketCreator", funcion "PacketCreator" seccion "TCP attack"')
            self.assertTrue((ataque[i][0][2].dport in puertos[0]) or (ataque[i][0][2].dport in puertos[1]), 'error en el puerto del paquete: Script "PacketCreator", funcion "PacketCreator" seccion "TCP attack"')
            self.assertTrue(ataque[i][0][2].sport in port, 'error en el puerto del paquete: Script "PacketCreator", funcion "PacketCreator" seccion "TCP attack"')

        self.assertTrue(numPkts>=11, 'error en la cantidad de paquetes: Script "PacketCreator", funcion "PacketCreator" seccion "TCP attack"')


    def test_PacketCreator_UDPattack(self):
        puertos=[[80,25,137,1024,53],[161,123,111,500,69,28960,19,9987,5353,12203,2049,9915,63392,520]]
        littleUDPatq=PacketCreator('200.7.4.7', ['56.145.96.4'], [37599], puertos, 13, 25, 13, 9, 0.13, False, 0, 1)
        self.assertEqual(len(littleUDPatq), 13, 'error en la cantidad de paquetes en el ataque: Script "PacketCreator", funcion "PacketCreator" seccion "UDP attack"')

        numPkts=0
        for i in range(13):
            numPkts+=len(littleUDPatq[i])
            self.assertTrue(len(littleUDPatq[i])==1 or len(littleUDPatq[i])==2, 'error en el largo del array pregunta respuesta: Script "PacketCreator", funcion "PacketCreator" seccion "UDP attack"')
            self.assertTrue(littleUDPatq[i][0].time<=25-0.13 and littleUDPatq[i][0].time>=13, 'error en el tiempo del ataque: Script "PacketCreator", funcion "PacketCreator" seccion "UDP attack"')
            self.assertTrue((littleUDPatq[i][0][2].dport in puertos[0]) or (littleUDPatq[i][0][2].dport in puertos[1]), 'error en el puerto de la pregunta: Script "PacketCreator", funcion "PacketCreator" seccion "UDP attack"')
            self.assertEqual(littleUDPatq[i][0][2].sport, 37599, 'error en el puerto de la pregunta: Script "PacketCreator", funcion "PacketCreator" seccion "UDP attack"')
            self.assertEqual(littleUDPatq[i][0][1].src, '56.145.96.4', 'error en la direccion IP de origen en el paquete IP: Script "PacketCreator", funcion "PacketCreator" seccion "Domain attack"')
            self.assertEqual(littleUDPatq[i][0][1].dst, '200.7.4.7', 'error en la direccion IP de destino en el paquete IP: Script "PacketCreator", funcion "PacketCreator" seccion "Domain attack"')

        self.assertTrue(numPkts>=13, 'error en la cantidad de paquetes en el ataque: Script "PacketCreator", funcion "PacketCreator" seccion "UDP attack"')


    def test_PacketCreator_Dom_Attack(self):
        domList=['a.cl', 'b.cl', 'c.cl']
        domPeque=PacketCreator('200.7.4.7', ['190.34.123.200'], [10240], domList, 10, 15, 10, 9, 0.003, 0, 0, 2)
        self.assertEqual(len(domPeque), 10, 'error en la cantidad de paquetes en el ataque: Script "PacketCreator", funcion "PacketCreator" seccion "Domain attack"')

        numPkts=0
        for i in range(10):
            numPkts+=len(domPeque[i])
            self.assertEqual(len(domPeque[i]), 2, 'error en el largo del array pregunta respuesta: Script "PacketCreator", funcion "PacketCreator" seccion "Domain attack"')
            self.assertTrue(domPeque[i][0].time<=15 and domPeque[i][0].time>=10-0.003, 'error en el tiempo del ataque: Script "PacketCreator", funcion "PacketCreator" seccion "Domain attack"')
            self.assertTrue(domPeque[i][1].time<=15.003 and domPeque[i][1].time>=10, 'error en el tiempo del ataque: Script "PacketCreator", funcion "PacketCreator" seccion "Domain attack"')
            self.assertEqual(domPeque[i][0][1].src, '190.34.123.200', 'error en la direccion IP de origen en el paquete IP: Script "PacketCreator", funcion "PacketCreator" seccion "Domain attack"')
            self.assertEqual(domPeque[i][1][1].src, '200.7.4.7', 'error en la direccion IP de origen en el paquete IP: Script "PacketCreator", funcion "PacketCreator" seccion "Domain attack"')
            self.assertEqual(domPeque[i][0][1].dst, '200.7.4.7', 'error en la direccion IP de destino en el paquete IP: Script "PacketCreator", funcion "PacketCreator" seccion "Domain attack"')
            self.assertEqual(domPeque[i][1][1].dst, '190.34.123.200', 'error en la direccion IP de destino en el paquete IP: Script "PacketCreator", funcion "PacketCreator" seccion "Domain attack"')
            self.assertTrue((domList[0] in str(domPeque[i][0][4].qname)) or (domList[1] in str(domPeque[i][0][4].qname)) or (domList[2] in str(domPeque[i][0][4].qname)), 'error en el dominio de la pregunta: Script "PacketCreator", funcion "PacketCreator" seccion "Domain attack"')
            self.assertTrue((domList[0] in str(domPeque[i][1][5].rrname)) or (domList[1] in str(domPeque[i][1][5].rrname)) or (domList[2] in str(domPeque[i][1][5].rrname)), 'error en el dominio de la pregunta: Script "PacketCreator", funcion "PacketCreator" seccion "Domain attack"')

        self.assertEqual(numPkts, 20, 'error en la cantidad de paquetes en el ataque: Script "PacketCreator", funcion "PacketCreator" seccion "Domain attack"')


    def test_TCP_DDoS_attack(self):
        tcpAt=TCP_DDoS_attack(25, '200.7.1.7', [[],list(range(0,80,5))], 12, 15.5, 20, 9, 0.32)
        ips=randomIP(25, 9, 1)
        ports=randomSourcePorts(25, 9)
        packAt=PacketCreator('200.7.1.7', ips, ports, [[],list(range(0,80,5))], 12, 15.5, 20, 9, 0.32, 0, 0, 0)
        self.assertEqual(tcpAt, packAt, 'error en la funcion "TCP_DDoS_attack"')


    def test_TCP_attack(self):
        puertos=[[80,25,137,1024,53],[161,123,111,500,69,28960,19,9987,5353,12203,2049,9915,63392,520]]
        tcpAt=TCP_attack('200.7.4.7', '190.34.123.200', 10240, puertos, 0, 25, 50, 9, 0.3)
        PackAt=PacketCreator('200.7.4.7', ['190.34.123.200'], [10240], puertos, 0, 25, 50, 9, 0.3, 0, 0, 0)
        self.assertEqual(tcpAt, PackAt, 'error en la funcion "TCP_attack"')


    def test_TCPgen_query(self):
        packTCP_openPort=TCPgen(300, 700, 1, '190.34.123.200', '200.7.4.7', 12.6, 0.1)
        packTCP_closePort=TCPgen(300, 700, 0, '190.34.123.200', '200.7.4.7', 12.6, 0.1)
        self.assertFalse(packTCP_openPort[0][2].id==packTCP_closePort[0][2].id, ': problemas entre el paquete de pregunta de puerto abierto y cerrado: Script "PacketCreator", funcion "TCPgen"')
        self.assertEqual(packTCP_openPort[0][3].id, packTCP_openPort[1][3].id, ': problemas entre el paquete de pregunta de puerto abierto y cerrado: Script "PacketCreator", funcion "TCPgen"')

        self.assertEqual(packTCP_openPort[0].time, 12.6, 'error en el tiempo del paquete: Script "PacketCreator", funcion "TCPgen"')
        self.assertEqual(packTCP_openPort[0].src, '18:66:da:e6:36:56', 'error en la direccion del paquete: Script "PacketCreator", funcion "TCPgen"')
        self.assertEqual(packTCP_openPort[0].dst, '18:66:da:4d:c0:08', 'error en la direccion del paquete: Script "PacketCreator", funcion "TCPgen"')
        self.assertEqual(packTCP_openPort[0][1].dst, '200.7.4.7', 'error en la direccion del paquete IP: Script "PacketCreator", funcion "TCPgen"')
        self.assertEqual(packTCP_openPort[0][1].src, '190.34.123.200', 'error en la direccion del paquete IP: Script "PacketCreator", funcion "TCPgen"')
        self.assertEqual(packTCP_openPort[0][2].sport, 300, 'error en el puerto del paquete: Script "PacketCreator", funcion "TCPgen"')
        self.assertEqual(packTCP_openPort[0][2].dport, 700, 'error en el puerto del paquete: Script "PacketCreator", funcion "TCPgen"')
        self.assertEqual(packTCP_openPort[0][2].flags, 'S', 'error en las banderas del paquete: Script "PacketCreator", funcion "TCPgen"')
        self.assertEqual(packTCP_openPort[0][3].rd, 0, 'error en el paquete DNS: Script "PacketCreator", funcion "TCPgen"')


    def test_TCPgen_response(self):
        packTCP_openPort=TCPgen(300, 700, 1, '190.34.123.200', '200.7.4.7', 12.6, 0.1)
        packTCP_closePort=TCPgen(300, 700, 0, '190.34.123.200', '200.7.4.7', 12.6, 0.1)
        respOpen=packTCP_openPort[1]
        self.assertFalse(respOpen==packTCP_closePort[1], ': problemas entre el paquete de respuesta de puerto abierto y cerrado: Script "PacketCreator", funcion "TCPgen"')
        self.assertEqual(respOpen[2].flags, 'SA', 'error en las banderas del paquete: Script "PacketCreator", funcion "TCPgen"')
        self.assertEqual(packTCP_closePort[1][2].flags, 'R', 'error en las banderas del paquete: Script "PacketCreator", funcion "TCPgen"')

        self.assertEqual(respOpen.time, 12.7, 'error en el tiempo del paquete: Script "PacketCreator", funcion "TCPgen"')
        self.assertEqual(respOpen.dst, '18:66:da:e6:36:56', 'error en la direccion del paquete: Script "PacketCreator", funcion "TCPgen"')
        self.assertEqual(respOpen.src, '18:66:da:4d:c0:08', 'error en la direccion del paquete: Script "PacketCreator", funcion "TCPgen"')
        self.assertEqual(respOpen[1].src, '200.7.4.7', 'error en la direccion del paqueteIP: Script "PacketCreator", funcion "TCPgen"')
        self.assertEqual(respOpen[1].dst, '190.34.123.200', 'error en la direccion del paqueteIP: Script "PacketCreator", funcion "TCPgen"')
        self.assertEqual(respOpen[2].sport, 700, 'error en el puerto de origen del paquete: Script "PacketCreator", funcion "TCPgen"')
        self.assertEqual(respOpen[2].dport, 300, 'error en el puerto de destino del paquete: Script "PacketCreator", funcion "TCPgen"')
        self.assertEqual(respOpen[3].aa, 1, 'error en el paquete DNS: Script "PacketCreator", funcion "TCPgen"')


    def test_UDP_DDoS_attack(self):
        udpAt=UDP_DDoS_attack(25, '200.7.4.7', [[],list(range(25,80,2))], 160, 162, 40, 5, 0.001, False, 2)
        ips=randomIP(25, 5, 1)
        ports=randomSourcePorts(25, 5)
        packAt=PacketCreator('200.7.4.7', ips, ports, [[],list(range(25,80,2))], 160, 162, 40, 5, 0.001, False, 2, 1)
        self.assertEqual(udpAt, packAt, 'error en la funcion "UDP_DDoS_attack"')


    def test_UDP_Attack(self):
        puertos=[[80,25,137,1024,53],[161,123,111,500,69,28960,19,9987,5353,12203,2049,9915,63392,520]]
        udpAt=UDP_attack('200.7.4.7', '56.145.96.4', 37599, puertos, 13, 25, 300, 9, 0.13, False, 2)
        packAt=PacketCreator('200.7.4.7', ['56.145.96.4'], [37599], puertos, 13, 25, 300, 9, 0.13, False, 2, 1)
        self.assertEqual(udpAt, packAt, 'error en la funcion "UDP_attack"')


    def test_UDPgen_query(self):
        packUDP=UDPgen(4678, 25, 0, '56.145.96.4', '200.7.4.7', 132.54, 0.001)
        ask=packUDP[0]
        self.assertEqual(len(packUDP), 1, 'error en la cantidad de preguntas y respuestas: Script "PacketCreator", funcion "UDPgen"')

        self.assertEqual(ask.time, 132.54, 'error en el tiempo del paquete Ethernet: Script "PacketCreator", funcion "UDPgen"')
        self.assertEqual(ask.src, '18:66:da:e6:36:56', 'error en la direccion del paquete Ethernet: Script "PacketCreator", funcion "UDPgen"')
        self.assertEqual(ask.dst, '18:66:da:4d:c0:08', 'error en la direccion del paquete Ethernet: Script "PacketCreator", funcion "UDPgen"')
        self.assertEqual(ask[1].src, '56.145.96.4', 'error en la direccion de origen del paquete IP: Script "PacketCreator", funcion "UDPgen"')
        self.assertEqual(ask[1].dst, '200.7.4.7', 'error en la direccion de destino del paquete IP: Script "PacketCreator", funcion "UDPgen"')
        self.assertEqual(ask[2].sport, 4678, 'error en el puerto de origen del paquete UDP: Script "PacketCreator", funcion "UDPgen"')
        self.assertEqual(ask[2].dport, 25, 'error en el puerto de destino del paquete UDP: Script "PacketCreator", funcion "UDPgen"')


    def test_UDPgen_response(self):
        packUDP=UDPgen(4678, 25, 1, '56.145.96.4', '200.7.4.7', 132.54, 0.001)
        ans=packUDP[1]
        self.assertEqual(len(packUDP), 2, 'error en la cantidad de preguntas y respuestas: Script "PacketCreator", funcion "UDPgen"')

        self.assertEqual(ans.time, 132.54+0.001, 'error en el tiempo del paquete Ethernet: Script "PacketCreator", funcion "UDPgen"')
        self.assertEqual(ans.src, '18:66:da:4d:c0:08', 'error en la direccion del paquete Ethernet: Script "PacketCreator", funcion "UDPgen"')
        self.assertEqual(ans.dst, '18:66:da:e6:36:56', 'error en la direccion del paquete Ethernet: Script "PacketCreator", funcion "UDPgen"')
        self.assertEqual(ans[1].src, '200.7.4.7', 'error en la direccion de origen del paquete IP: Script "PacketCreator", funcion "UDPgen"')
        self.assertEqual(ans[1].dst, '56.145.96.4', 'error en la direccion de destino del paquete IP: Script "PacketCreator", funcion "UDPgen"')
        self.assertEqual(ans[2].type, 3, 'error en el campo "type" en el paquete ICMP: Script "PacketCreator", funcion "UDPgen"')
        self.assertEqual(ans[2].code, 3, 'error en el campo "code" en el paquete ICMP: Script "PacketCreator", funcion "UDPgen"')


    def test_Domain_DDoS_attack(self):
        domAt=Domain_DDoS_attack(35, '200.7.4.7', 0, 0.5, 60, 7, 0.01)
        ips=randomIP(35, 7, 1)
        ports=randomSourcePorts(35, 7)
        domsFile='ultimos-dominios-1m.txt'
        f = open(domsFile, "r")
        domsList=[]
        bool=1
        while(bool):
            dominio=f.readline().split(',')
            domsList+=[dominio[0]]
            if (domsList[-1]=='') or len(domsList)==(60+2):
                domsList=domsList[1:-1]
                bool=0
                break
        f.close()
        packAt=PacketCreator('200.7.4.7', ips, ports, domsList, 0, 0.5, 60, 7, 0.01, 0, 0, 2)
        self.assertEqual(domAt, packAt, 'error en la funcion "Domain_DDoS_attack"')


    def test_Domain_attack(self):
        domAtaque=Domain_attack('200.7.4.7', '190.34.123.200', 10240, 10, 25, 50, 9, 0.003)
        domsFile='ultimos-dominios-1m.txt'
        f = open(domsFile, "r")
        domsList=[]
        bool=1
        while(bool):
            dominio=f.readline().split(',')
            domsList+=[dominio[0]]
            if (domsList[-1]=='') or len(domsList)==(50+2):
                domsList=domsList[1:-1]
                bool=0
                break
        f.close()
        PackAt=PacketCreator('200.7.4.7', ['190.34.123.200'], [10240], domsList, 10, 25, 50, 9, 0.003, 0, 0, 2)
        self.assertEqual(domAtaque, PackAt, 'error en la funcion "Domain_attack"')


    def test_DomainGen_query(self):
        packDomain=DomainGen(7340, 'buzoku.cl', '190.34.123.200', '200.7.4.7', 345.56, 0.02)
        ask=packDomain[0]
        self.assertEqual(len(packDomain), 2, 'error con la cantidad de preguntas y respuestas en el pack: Script "PacketCreator", funcion "DomainGen"')
        self.assertEqual(ask[3].id, packDomain[1][3].id, 'error en la id del paquete DNS: Script "PacketCreator", funcion "DomainGen"')

        self.assertEqual(ask.time, 345.56, 'error en el tiempo del paquete Ethernet: Script "PacketCreator", funcion "DomainGen"')
        self.assertEqual(ask.src, '18:66:da:e6:36:56', 'error en la direccion del paquete Ethernet: Script "PacketCreator", funcion "DomainGen"')
        self.assertEqual(ask.dst, '18:66:da:4d:c0:08', 'error en la direccion del paquete Ethernet: Script "PacketCreator", funcion "DomainGen"')
        self.assertEqual(ask[1].src, '190.34.123.200', 'error en la direccion de origen del paquete IP: Script "PacketCreator", funcion "DomainGen"')
        self.assertEqual(ask[1].dst, '200.7.4.7', 'error en la direccion de destino del paquete IP: Script "PacketCreator", funcion "DomainGen"')
        self.assertEqual(ask[2].sport, 7340, 'error en el puerto de origen del paquete UDP: Script "PacketCreator", funcion "DomainGen"')
        self.assertEqual(ask[2].dport, 53, 'error en el puerto de destino del paquete UDP: Script "PacketCreator", funcion "DomainGen"')
        self.assertEqual(ask[3].opcode, 0, 'error en campo "opcode" del paquete DNS: Script "PacketCreator", funcion "DomainGen"')
        self.assertEqual(ask[3].rd, 0, 'error en el campo "rd" en paquete DNS: Script "PacketCreator", funcion "DomainGen"')
        self.assertEqual(ask[3].qdcount, 1, 'error en el campo "qdcount" en paquete DNS: Script "PacketCreator", funcion "DomainGen"')
        self.assertEqual(ask[3].qr, 0, 'error en el campo "qr" en paquete DNS: Script "PacketCreator", funcion "DomainGen"')
        self.assertTrue('buzoku.cl.' in str(ask[4].qname), 'error en el campo "qname" en paquete DNSQR: Script "PacketCreator", funcion "DomainGen"')


    def test_DomainGen_response(self):
        packDomain=DomainGen(7340, 'buzoku.cl', '190.34.123.200', '200.7.4.7', 345.56, 0.02)
        ans=packDomain[1]

        self.assertEqual(ans.time, 345.56+0.02, 'error en el tiempo del paquete Ethernet: Script "PacketCreator", funcion "DomainGen"')
        self.assertEqual(ans.dst, '18:66:da:e6:36:56', 'error en la direccion de destino del paquete Ethernet: Script "PacketCreator", funcion "DomainGen"')
        self.assertEqual(ans.src, '18:66:da:4d:c0:08', 'error en la direccion de origen del paquete Ethernet: Script "PacketCreator", funcion "DomainGen"')
        self.assertEqual(ans[1].src, '200.7.4.7', 'error en la direccion de origen del paquete IP: Script "PacketCreator", funcion "DomainGen"')
        self.assertEqual(ans[1].dst, '190.34.123.200', 'error en la direccion de destino del paquete IP: Script "PacketCreator", funcion "DomainGen"')
        self.assertEqual(ans[2].sport, 53, 'error en el puerto de origen del paquete UDP: Script "PacketCreator", funcion "DomainGen"')
        self.assertEqual(ans[2].dport, 7340, 'error en el puerto de destino del paquete UDP: Script "PacketCreator", funcion "DomainGen"')
        self.assertEqual(ans[3].opcode, 0, 'error en campo "opcode" del paquete DNS: Script "PacketCreator", funcion "DomainGen"')
        self.assertEqual(ans[3].rd, 0, 'error en el campo "rd" en paquete DNS: Script "PacketCreator", funcion "DomainGen"')
        self.assertEqual(ans[3].qr, 1, 'error en el campo "qr" en paquete DNS: Script "PacketCreator", funcion "DomainGen"')
        self.assertTrue('buzoku.cl.' in str(ans[5].rrname) , 'error en el campo "qname" en paquete DNSRR: Script "PacketCreator", funcion "DomainGen"')
        self.assertEqual(ans[5].type, 2, 'error en el campo "type" en paquete DNSRR: Script "PacketCreator", funcion "DomainGen"')


    def test_pickDelayResp_intervalo_dado(self):
        interResp=0.2
        new0_interResp=pickDelayResp(interResp, 0)
        new1_interResp=pickDelayResp(interResp, 1)
        new2_interResp=pickDelayResp(interResp, 2)

        self.assertEqual(interResp, new0_interResp)
        self.assertEqual(interResp, new1_interResp)
        self.assertEqual(interResp, new2_interResp)


    def test_pickDelayResp_intervalo_aleatorio(self):
        interResp=-1
        new0_interResp=pickDelayResp(interResp, 0)
        new1_interResp=pickDelayResp(interResp, 1)
        new2_interResp=pickDelayResp(interResp, 2)

        self.assertFalse(interResp==new0_interResp)
        self.assertFalse(interResp==new1_interResp)
        self.assertFalse(interResp==new2_interResp)

        self.assertTrue(new0_interResp<=(0.0324164173995+0.661281423818) and new0_interResp>=0)
        self.assertTrue(new1_interResp<=(0.0001868+0.0000297912738902) and new0_interResp>=(0.0001868-0.0000297912738902))
        self.assertTrue(new2_interResp<=(0.000322919547395+0.018900697143) and new0_interResp>=0)




if __name__ == '__main__':
    unittest.main()
