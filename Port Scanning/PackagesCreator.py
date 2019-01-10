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
    ###########creacion de los parametros para los paquetes###########
    dns=DNS(aa=autoritativo, rd=0)
    ip=IP(src=IPsrc, version=4)
    ##################################################################
    puertos=list(range(puertoInicial,puertoFinal+1,intervaloPuertos)) #rango de puertos target
    tiempos=rF.gen(Seed, tiempoInicial, tiempoFinal, numPaquetesAEnviar) #tiempos para inyectar paquetes
    NuevoSetPaquetesEnviados=[]
    for i in range(len(tiempos)):
        SetPaquetes=Ether()/ip/TCP(flags='S')/dns
        SetPaquetes.time=tiempos[i]
        if len(puertos)==0:
            puertos=list(range(puertoInicial,puertoFinal+1,intervaloPuertos))
        j=random.randint(0,len(puertos)-1)
        puertoAInsertar=puertos.pop(j)
        SetPaquetes[2].dport=puertoAInsertar
        NuevoSetPaquetesEnviados+=[SetPaquetes]
    #pprint([pkt for pkt in NuevoSetPaquetesEnviados])
    return NuevoSetPaquetesEnviados


def inyeccion(nombrePktIni, nombrePktFin):
    nombrePktIni='input/'+nombrePktIni
    paquete= sniff(offline=nombrePktIni, count=1)
    t=paquete[0].time
    virus=PacketList(genIniFin("200.7.4.7", 0, 1023, 1, t, t+10, 1, 500, 473))
    datosReales=rdpcap(nombrePktIni)
    attack=datosReales+virus
    wrpcap('output/'+nombrePktFin+'.pcap',attack)


continuar=1
while(continuar):
    print("Para definir el valor de un parametro especifico seleccione el numero correspondiente al parametro")


    if tecla==1:
        print("(1) El servidor es autoritativo? (p/d: si) \nSi (1)/No (2)")
        if tecla==2:
            autoritativo=0
        elif tecla==1:
            autoritativo=1
        elif tecla==0:
            continuar=0
            break
        else:
            print("Respuesta invalida")

    if tecla==2:
        print("")

    if tecla==0:
        continuar=0
        break
