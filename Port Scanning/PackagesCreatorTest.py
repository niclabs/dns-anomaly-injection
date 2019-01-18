from PackagesCreator import *
import unittest

class PackagesCreatorTest(unittest.TestCase):

    def test_udpFloodAttack(self):
        puertos=[[80,25,137,1024,53],[161,123,111,500,69,28960,19,9987,5353,12203,2049,9915,63392,520]]
        ataque=udpFloodAttack('200.7.4.7', ['190.34.123.200'], [567], puertos, 0, 10, 140, 4, 0.1)

        numPkts=0
        for i in range(len(ataque)):
            numPkts+=len(ataque[i])
            self.assertTrue(len(ataque[i])==1 or len(ataque[i])==2, '\nerror en la cantidad de paquetes pregunta y respuesta\nScript "PackagesCreator", funcion "udpFloodAttack"')
            self.assertTrue( ataque[i][0].time<=10 and ataque[i][0].time>=0, '\nerror en el tiempo del paquete\nScript "PackagesCreator", funcion "udpFloodAttack"')
            self.assertTrue( (ataque[i][0][2].dport in puertos[0]) or (ataque[i][0][2].dport in puertos[1]), '\nerror en el puerto del paquete\nScript "PackagesCreator", funcion "udpFloodAttack"')
            self.assertEqual(ataque[i][0][2].sport, 567, '\nerror en el puerto del paquete\nScript "PackagesCreator", funcion "udpFloodAttack"')

        self.assertTrue(numPkts==140 or numPkts==139, '\nerror en la cantidad de paquetes\nScript "PackagesCreator", funcion "udpFloodAttack"')



    def test_TCP_attack(self):
        puertos=[[80,25,137,1024,53],[161,123,111,500,69,28960,19,9987,5353,12203,2049,9915,63392,520]]
        tcpAt=TCP_attack('200.7.4.7', '190.34.123.200', 10240, puertos, 0, 25, 50, 9, 0.3)
        PackAt=PacketCreator('200.7.4.7', ['190.34.123.200'], [10240], puertos, 0, 25, 50, 9, 0.3, 0)
        self.assertEqual(tcpAt, PackAt, '\nerror en la funcion "TCP_attack"')

    def test_TCPgen_query(self):
        packTCP_openPort=TCPgen(300, 700, 1, '200.7.4.7', '190.34.123.200', 12.6, 0.1)
        packTCP_closePort=TCPgen(300, 700, 0, '200.7.4.7', '190.34.123.200', 12.6, 0.1)
        self.assertEqual(packTCP_openPort[0], packUDP_closePort[0], '\nproblemas entre el paquete de pregunta de puerto abierto y cerrado\nScript "PackagesCreator", funcion "TCPgen"')
        self.assertEqual(packTCP_openPort[0][3].id, packTCP_openPort[1][3].id, '\nproblemas entre el paquete de pregunta de puerto abierto y cerrado\nScript "PackagesCreator", funcion "TCPgen"')

        self.assertEqual(packTCP_openPort[0].time, 12.6, '\nerror en el tiempo del paquete\nScript "PackagesCreator", funcion "TCPgen"')
        self.assertEqual(packTCP_openPort[0].src, '18:66:da:e6:36:56', '\nerror en la direccion del paquete\nScript "PackagesCreator", funcion "TCPgen"')
        self.assertEqual(packTCP_openPort[0].dst, '18:66:da:4d:c0:08', '\nerror en la direccion del paquete\nScript "PackagesCreator", funcion "TCPgen"')
        self.assertEqual(packTCP_openPort[0][1].src, '200.7.4.7', '\nerror en la direccion del paquete IP\nScript "PackagesCreator", funcion "TCPgen"')
        self.assertEqual(packTCP_openPort[0][1].dst, '190.34.123.200', '\nerror en la direccion del paquete IP\nScript "PackagesCreator", funcion "TCPgen"')
        self.assertEqual(packTCP_openPort[0][2].sport, 300, '\nerror en el puerto del paquete\nScript "PackagesCreator", funcion "TCPgen"')
        self.assertEqual(packTCP_openPort[0][2].dport, 700, '\nerror en el puerto del paquete\nScript "PackagesCreator", funcion "TCPgen"')
        self.assertEqual(packTCP_openPort[0][2].flags, 'S', '\nerror en las banderas del paquete\nScript "PackagesCreator", funcion "TCPgen"')
        self.assertEqual(packTCP_openPort[0][3].rd, 0, '\nerror en el paquete DNS\nScript "PackagesCreator", funcion "TCPgen"')

    def test_TCPgen_response(self):
        packTCP_openPort=TCPgen(300, 700, 1, '200.7.4.7', '190.34.123.200', 12.6, 0.1)
        packTCP_closePort=TCPgen(300, 700, 0, '200.7.4.7', '190.34.123.200', 12.6, 0.1)
        respOpen=packTCP_openPort[1]
        self.assertFalse(respOpen==packUDP_closePort[1], '\nproblemas entre el paquete de respuesta de puerto abierto y cerrado\nScript "PackagesCreator", funcion "TCPgen"')
        self.assertEqual(respOpen[2].flags, 'SA', '\nerror en las banderas del paquete\nScript "PackagesCreator", funcion "TCPgen"')
        self.assertEqual(packTCP_closePort[1][2].flags, 'R', '\nerror en las banderas del paquete\nScript "PackagesCreator", funcion "TCPgen"')

        self.assertEqual(respOpen.time, 12.7, '\nerror en el tiempo del paquete\nScript "PackagesCreator", funcion "TCPgen"')
        self.assertEqual(respOpen.dst, '18:66:da:e6:36:56', '\nerror en la direccion del paquete\nScript "PackagesCreator", funcion "TCPgen"')
        self.assertEqual(respOpen.src, '18:66:da:4d:c0:08', '\nerror en la direccion del paquete\nScript "PackagesCreator", funcion "TCPgen"')
        self.assertEqual(respOpen[1].dst, '200.7.4.7', '\nerror en la direccion del paqueteIP\nScript "PackagesCreator", funcion "TCPgen"')
        self.assertEqual(respOpen[1].src, '190.34.123.200', '\nerror en la direccion del paqueteIP\nScript "PackagesCreator", funcion "TCPgen"')
        self.assertEqual(respOpen[2].sport, 700, '\nerror en el puerto del paquete\nScript "PackagesCreator", funcion "TCPgen"')
        self.assertEqual(respOpen[2].dport, 300, '\nerror en el puerto del paquete\nScript "PackagesCreator", funcion "TCPgen"')
        self.assertEqual(respOpen[3].aa, 1, '\nerror en el paquete DNS\nScript "PackagesCreator", funcion "TCPgen"')


def DomainGen(PortSrc, dom, IPsrc, IPservidor, t, interResp):
    dom=dom+'.'
    Id=int(RandShort())
    ################### Query packet ###################
    ipQ=IP(src=IPsrc, dst=IPservidor, proto='udp')
    dnsqr=DNSQR(qname=dom)
    dnsQ=DNS(rd=0, id=Id,opcode='QUERY',qdcount=1,qd=dnsqr, qr=0)
    udpQ=UDP(sport=PortSrc, dport=53)
    SetPaquetesQ=Ether(dst='18:66:da:4d:c0:08', src='18:66:da:e6:36:56')/ipQ/udpQ/dnsQ/dnsqr
    SetPaquetesQ.time=t
    ################### Answer packet ###################
    ether=Ether(src='18:66:da:4d:c0:08', dst='18:66:da:e6:36:56')
    ether.time=t+interResp
    ipA=IP(proto='udp', src=IPservidor, dst=ipQ.src)
    udpA=UDP(sport=53, dport=PortSrc)
    dnsrr=DNSRR(rrname=dom, type='NS')
    dnsA=DNS(id=Id,rd=0, qr=1,opcode='QUERY',qd=dnsqr, ns=dnsrr)
    SetPaquetesA=ether/ipA/udpA/dnsA/dnsqr/dnsrr

    SetPaquetes=[SetPaquetesQ,SetPaquetesA]
    return SetPaquetes


    def test_DomainGen_query(self):
        packTCP_openPort=DomainGen(300, 700, 1, '200.7.4.7', '190.34.123.200', 12.6, 0.1)
        packTCP_closePort=DomainGen(300, 700, 0, '200.7.4.7', '190.34.123.200', 12.6, 0.1)
        self.assertEqual(packTCP_openPort[0], packUDP_closePort[0], '\nproblemas entre el paquete de pregunta de puerto abierto y cerrado\nScript "PackagesCreator", funcion "TCPgen"')
        self.assertEqual(packTCP_openPort[0][3].id, packTCP_openPort[1][3].id, '\nproblemas entre el paquete de pregunta de puerto abierto y cerrado\nScript "PackagesCreator", funcion "TCPgen"')

        self.assertEqual(packTCP_openPort[0].time, 12.6, '\nerror en el tiempo del paquete\nScript "PackagesCreator", funcion "TCPgen"')
        self.assertEqual(packTCP_openPort[0].src, '18:66:da:e6:36:56', '\nerror en la direccion del paquete\nScript "PackagesCreator", funcion "TCPgen"')
        self.assertEqual(packTCP_openPort[0].dst, '18:66:da:4d:c0:08', '\nerror en la direccion del paquete\nScript "PackagesCreator", funcion "TCPgen"')
        self.assertEqual(packTCP_openPort[0][1].src, '200.7.4.7', '\nerror en la direccion del paquete IP\nScript "PackagesCreator", funcion "TCPgen"')
        self.assertEqual(packTCP_openPort[0][1].dst, '190.34.123.200', '\nerror en la direccion del paquete IP\nScript "PackagesCreator", funcion "TCPgen"')
        self.assertEqual(packTCP_openPort[0][2].sport, 300, '\nerror en el puerto del paquete\nScript "PackagesCreator", funcion "TCPgen"')
        self.assertEqual(packTCP_openPort[0][2].dport, 700, '\nerror en el puerto del paquete\nScript "PackagesCreator", funcion "TCPgen"')
        self.assertEqual(packTCP_openPort[0][2].flags, 'S', '\nerror en las banderas del paquete\nScript "PackagesCreator", funcion "TCPgen"')
        self.assertEqual(packTCP_openPort[0][3].rd, 0, '\nerror en el paquete DNS\nScript "PackagesCreator", funcion "TCPgen"')

    def test_DomainGen_response(self):
        packTCP_openPort=TCPgen(300, 700, 1, '200.7.4.7', '190.34.123.200', 12.6, 0.1)
        packTCP_closePort=TCPgen(300, 700, 0, '200.7.4.7', '190.34.123.200', 12.6, 0.1)
        respOpen=packTCP_openPort[1]
        self.assertFalse(respOpen==packUDP_closePort[1], '\nproblemas entre el paquete de respuesta de puerto abierto y cerrado\nScript "PackagesCreator", funcion "TCPgen"')
        self.assertEqual(respOpen[2].flags, 'SA', '\nerror en las banderas del paquete\nScript "PackagesCreator", funcion "TCPgen"')
        self.assertEqual(packTCP_closePort[1][2].flags, 'R', '\nerror en las banderas del paquete\nScript "PackagesCreator", funcion "TCPgen"')

        self.assertEqual(respOpen.time, 12.7, '\nerror en el tiempo del paquete\nScript "PackagesCreator", funcion "TCPgen"')
        self.assertEqual(respOpen.dst, '18:66:da:e6:36:56', '\nerror en la direccion del paquete\nScript "PackagesCreator", funcion "TCPgen"')
        self.assertEqual(respOpen.src, '18:66:da:4d:c0:08', '\nerror en la direccion del paquete\nScript "PackagesCreator", funcion "TCPgen"')
        self.assertEqual(respOpen[1].dst, '200.7.4.7', '\nerror en la direccion del paqueteIP\nScript "PackagesCreator", funcion "TCPgen"')
        self.assertEqual(respOpen[1].src, '190.34.123.200', '\nerror en la direccion del paqueteIP\nScript "PackagesCreator", funcion "TCPgen"')
        self.assertEqual(respOpen[2].sport, 700, '\nerror en el puerto del paquete\nScript "PackagesCreator", funcion "TCPgen"')
        self.assertEqual(respOpen[2].dport, 300, '\nerror en el puerto del paquete\nScript "PackagesCreator", funcion "TCPgen"')
        self.assertEqual(respOpen[3].aa, 1, '\nerror en el paquete DNS\nScript "PackagesCreator", funcion "TCPgen"')



if __name__ == '__main__':
    unittest.main()
