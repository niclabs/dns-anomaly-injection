try:
    from scapy.all import *
    from pprint import pprint
    import numpy as np
    import randFloat as rF


paquete= scapy.all.rdpcap('blanco.1506993600.pcap.gz')
pprint([pkt for pkt in paquete[0:2]])
scapy.all.wrpcap("lol.pcap",paquete[5000,5500])

tIni=1506979200.0 #Es válido solo para el paquete blanco.1506993600.pcap


def genIniFin(IPsrc, puertoInicial, puertoFinal, intervaloPuertos, tiempoInicial, intervaloTMin, intervaloTMax, autoritativo, numPaquetesAEnviar, Seed):
    if autoritativo!=0 or autoritativo!=1:
        autoritativo=1
    puertos=range(puertoInicial,puertoFinal+1,intervaloPuertos) #rango de puertos target

    NuevoSetPaquetesEnviados=Ether(time=rF.gen(Seed, )/IP(dst=puertos, src=IPsrc, version=4)/TCP(flags='S')/DNS(aa=autoritativo, rd=0) #creacion de los paquetes, se almacenan en un array
    pprint([pkt for pkt in paquetes])

def valsPorDefecto()
    genIniFin("200.63.128.5", 0, 1023, 1, 1, 1000, 1, 5000, 473)

pregunta= "El servidor es autoritativo? S(1)/N(0)"
