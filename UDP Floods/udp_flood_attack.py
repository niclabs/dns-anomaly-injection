try:
    from scapy.all import *
except:
    raise Exception("Install scapy")

try:
    import sys
    sys.path.append("..")
    import randFloats as rF
except:
    raise Exception("randFloat error")

""" Author @Javi801
 Creates an array of two packages (query and response) with given values. Each packet contains an
 Ether pack in its firts layer, an IP pack in its second layer, an TCP or UDP
 pack in its third layer and a DNS pack in its last layer

 Params: IPsrcList -> (list(string)) List of source IP addresses
         PortSrc -> (int) source port
         puertosAbiertosCerrados -> (list(list(int))) list of open and closed
                                    ports list
         tiempoInicial -> (float) time in which the attack begins
         tiempoFinal -> (float) time in which the attack ends
         numPaquetesAEnviar -> (int) number of packages that will be sent
         Seed -> (float) seed for randomize
         interResp -> (float) time between a query and its response

 Return: NuevoSetPaquetesEnviados -> Array of packages that will be insert
"""
def udpFloodAttack(IPsrcList, PortSrc, puertosAbiertosCerrados, tiempoInicial, tiempoFinal, numPaquetesAEnviar, Seed, interResp):
    random.seed(Seed)
    puertos=puertosAbiertosCerrados[0][:]+puertosAbiertosCerrados[1][:] #Los puertos totales son los puertos abiertos mas los cerrados para TCP SYN
    tiempos=rF.gen(Seed, tiempoInicial, tiempoFinal, numPaquetesAEnviar) #tiempos donde se inyectan los paquetes
    NuevoSetPaquetesEnviados=[]
    countPacks=numPaquetesAEnviar
    for i in range(len(tiempos)):
        if len(puertos)==0:
            puertos=puertosAbiertosCerrados[0][:]+puertosAbiertosCerrados[1][:]
        puertoTarget=select(puertos)
        puertos.remove(puertoTarget)
        IPsrc=select(IPsrcList)
        SetPaquetes=udpPairGen(PortSrc, puertoTarget, puertoTarget in puertosAbiertosCerrados[0], IPsrc, tiempos[i], interResp)
        NuevoSetPaquetesEnviados+=[SetPaquetes]
        countPacks=countPacks-len(SetPaquetes)
        if countPacks==0:
            break
    return NuevoSetPaquetesEnviados


"""Author @Javi801
 Creates an array of ethernet packet with especific values for its udp layer,
 and  with given IP packet for query packet. Also, creates an answer packet if
 the server responds.

 Params: PortSrc -> (int) Port from where the packet is sent
         PortDst -> (int) Port where the packet is received
         open -> (boolean) Indicates whether the port is open (true) or not (false)
         IPsrc -> (string) Source IP address
         tiempo -> (float) time at the packet is sent
         interResp -> (float) interval between query and answer

 Return: SetPaquetes -> (list(Ether())) An ethernet packet list
"""
def udpPairGen(PortSrc, PortDst, open, IPsrc, tiempo, interResp):
    ip=IP(src=IPsrc, dst="200.7.4.7", proto='udp')
    etherQ=Ether(src='18:66:da:e6:36:56', dst='18:66:da:4d:c0:08')
    etherQ.time=tiempo
    udpQ=UDP(sport=PortSrc, dport=PortDst)
    QPacket=etherQ/ip/udpQ
    if open:
        etherA=Ether(src='18:66:da:4d:c0:08', dst='18:66:da:e6:36:56')
        etherA.time=tiempo+interResp
        icmp=ICMP(type=3, code=3)
        APacket=etherA/IP(src="200.7.4.7", dst=IPsrc)/icmp
        return [QPacket,APacket]
    return [QPacket]


""" @Javi801
 Gives an random element in a given list

 Param: lista -> list

 Return: element in the given list
"""
def select(lista):
    if len(lista)==0:
        return
    if len(lista)==1:
        return lista[0]
    j=random.randint(0,len(lista)-1)
    return lista[j]
