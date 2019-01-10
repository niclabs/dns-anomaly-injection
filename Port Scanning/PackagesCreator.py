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


### Author @Javi801
# Creates an array of packages with given values. Each package contains an
# ethernet pack in its firts layer, an ip pack in its second layer, an tcp pack
# in its third layer and a dns pack in its last layer
#
# Params: IPsrc ->
#         PortSrc ->
#         puertoInicial ->
#         puertoFinal ->
#         intervaloPuertos ->
#         tiempoInicial ->
#         tiempoFinal ->
#         autoritativo ->
#         numPaquetesAEnviar ->
#         Seed
#
# Return: NuevoSetPaquetesEnviados -> Array of packages, with numPaquetesAEnviar
#                                     as length
###
def genIniFin(IPsrc, PortSrc, puertos, tiempoInicial, tiempoFinal, autoritativo, numPaquetesAEnviar, Seed, interResp):
    if autoritativo!=0 or autoritativo!=1:
        autoritativo=1
    ###########creacion de los parametros para los paquetes###########
    dns=DNS(aa=autoritativo, rd=0)
    ip=IP(src=IPsrc, dst="200.7.4.7", version=4)
    ##################################################################
    totalPuertos=puertos[0]+puertos[1] #puertos abiertos mas puertos cerrados
    tiempos=rF.gen(Seed, tiempoInicial, tiempoFinal, numPaquetesAEnviar) #tiempos para inyectar paquetes
    NuevoSetPaquetesEnviados=[]
    for i in range(len(tiempos)):
        if len(totalPuertos)==0:
            totalPuertos=puertos[0]+puertos[1]
        j=random.randint(0,len(totalPuertos)-1)
        puertoAInsertar=puertos.pop(j)
        SetPaquetes=TCPgen(PortSrc, puertoAInsertar, puertoAInsertar in puertos[0], ip, dns, tiempos[i])
        NuevoSetPaquetesEnviados+=[SetPaquetes]
    #pprint([pkt for pkt in NuevoSetPaquetesEnviados])
    return NuevoSetPaquetesEnviados

### Author @Javi801
# Creates an array of ethernet package (query and answer) with especific values for its tcp layer, and with
# given packages dns and ip
#
# Params: PortSrc -> (int) Port from where the package is sent
#         PortDst -> (int) Port where the package is received
#         ip -> (IP()) package ip
#         dns -> (DNS()) package dns
#         t -> (float) time at the package is sent
#         interResp -> (float) interval between query and answer
#
# Return: SetPaquetes -> An ethernet package
#
###
def TCPgen(PortSrc, PortDst, open, ip, dns, t, interResp):
    SetPaquetesQ=Ether()/ip/TCP(flags='S', sport=PortSrc, dport=PortDst)/dns
    SetPaquetesQ.time=t
    SetPaquetesA=Ether()/IP(src=ip.dst, dst=ip.src, version=4)/TCP(sport=PortSrc, dport=PortDst)
    if open:
        SetPaquetesA[2].flags='SA'
    else:
        SetPaquetesA[2].flags='R'
    SetPaquetes=[SetPaquetesQ,SetPaquetesA]
    return SetPaquetes

### Author @Javi801
# Gives an array of two arrays; first the open ones and, then, the closed
#
# Param: puertoInicial -> (int) first port
#        puertoFinal -> (int) last port
#        intervaloPuertos -> (int) interval between ports
#        abiertos ->  (array[int] or int)
#        cerrados -> (array[int] or int)
#        type -> (int) who is open or closed? 2 => random, 1=> that number of
#                guys, 0=> this guys
#        Seed -> (int) seed for randomize
#
# Return: conversation -> array of ether packages
####
def portsGen(puertoInicial, puertoFinal, intervaloPuertos, abiertos, cerrados, type, Seed):
    random.seed(Seed)
    puertos=list(range(puertoInicial,puertoFinal+1,intervaloPuertos))
    if type==2: #Cantidad aleatoria de puertos abiertos y cerrados
        abiertos=[]
        cerrados=[]
        for i in range(len(puertos)):
            var = random.randint(0,1)
            if var:
                abiertos+=[puertos[i]]
                continue
            cerrados+=[puertos[i]]
        return [abiertos,cerrados]
    if type: #Cantidad dada de puertos abiertos y cerrados, se necesita puertoFinal, puertoInicial, intervaloPuertos, cerrados, abiertos
        return intPorts(abiertos, cerrados, puertos, Seed)
    if len(abiertos)==0 or len(cerrados)==0:
        return ArrayPorts(abiertos, cerrados, puertos, Seed)


def intPorts(abiertos, cerrados, puertos, Seed):
    random.seed(Seed)
    open=[]
    closed=[]
    if cerrados>(-1):
        for i in range(cerrados):
            if i>=len(puertos):
                break
            var = random.randint(0,len(puertos)-1)
            ins=puertos.pop(var)
            closed+=[ins]
        return [puertos, closed]
    if abiertos>(-1):
        for i in range(abiertos):
            if i>=len(puertos):
                break
            var = random.randint(0,len(puertos)-1)
            ins=puertos.pop(var)
            open+=[puertos.pop(var)]
        return [open, puertos]


def ArrayPorts(abiertos, cerrados, puertos, Seed):
    random.seed(Seed)
    op=[]
    cl=[]
    if len(abiertos)==0: #Array con puertos cerrados, abiertos debe ser array vacio
        cl=cerrados
        for i in range(len(puertos)):
            if puertos[i] in cerrados:
                continue
            op+=[puertos[i]]
    elif len(cerrados)==0: #Array con puertos abiertos dado, cerrados debe ser array vacio
        op=abiertos
        for i in range(len(puertos)):
            if puertos[i] in abiertos:
                continue
            cl+=[puertos[i]]
    return [op, cl]

def UDPgen():
    t=0
