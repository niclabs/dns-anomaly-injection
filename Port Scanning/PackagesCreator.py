try:
    from scapy.all import *
    from pprint import pprint
    import numpy as np
except:
    raise Exception("Install scapy")

try:
    import randFloats as rF
except:
    raise Exception("randFloat error")


def genIniFin(IPsrc, puertoInicial, puertoFinal, intervaloPuertos, tiempoInicial, tiempoFinal, autoritativo, numPaquetesAEnviar, Seed):
    if autoritativo!=0 or autoritativo!=1:
        autoritativo=1
    dns=DNS(aa=autoritativo, rd=0)
    ip=IP(src=IPsrc, version=4)
    SetPaquetes=Ether()/ip/TCP(flags='S')/dns #creacion de los paquetes, se almacenan en un array
    puertos=list(range(puertoInicial,puertoFinal+1,intervaloPuertos)) #rango de puertos target
    tiempos=rF.gen(Seed, tiempoInicial, tiempoFinal, numPaquetesAEnviar) #tiempos para inyectar paquetes
    NuevoSetPaquetesEnviados=[]
    for i in range(len(tiempos)):
        SetPaquetes.time=tiempos[i]
        if len(puertos)==0:
            puertos=list(range(puertoInicial,puertoFinal+1,intervaloPuertos))
        j=random.randint(0,len(puertos)-1)
        puertoAInsertar=puertos.pop(j)
        SetPaquetes[2].sport=puertoAInsertar
        NuevoSetPaquetesEnviados+=[SetPaquetes]
    #pprint([pkt for pkt in NuevoSetPaquetesEnviados])
    return NuevoSetPaquetesEnviados


def valsPorDefecto(tIni):
    return genIniFin("200.7.4.7", 0, 1023, 1, tIni, tIni+10, 1, 5000, 473)

def inyeccion(nombrePktIni, nombrePktFin):
    nombrePktIni='input/'+nombrePktIni
    paquete= sniff(offline=nombrePktIni, count=2)
    t=paquete[0].time
    attack=PacketList(valsPorDefecto(t))
    datosReales=rdpcap(nombrePktIni)
    wrpcap('output/'+nombrePktFin+'.pcap',attack)

pregunta= "El servidor es autoritativo? S(1)/N(0)"
