try:
    from scapy.all import *
    from pprint import pprint
    import numpy as np
except:
    raise Exception("Install scapy")

try:
    import sys
    sys.path.append("..")
    import randFloats as rF
except:
    raise Exception("randFloat error")

""" Author @Javi801
 Creates an array of packages with given values. Each packet contains an
 Ether pack in its firts layer, an IP pack in its second layer, an TCP or UDP
 pack in its third layer and a DNS pack in its last layer

 Params: ip -> (IP()) IP pack for second layer
         PortSrc -> (int) source port
         datosMultiples -> (list(int) or list(list(int))) values list for
                            variable param
         tiempoInicial -> (float) time in which the attack begins
         tiempoFinal -> (float) time in which the attack ends
         numPaquetesAEnviar -> (int) number of packages that will be sent
         Seed -> (float) seed for randomize
         interResp -> (float) time between a query and its response
         attackType -> (int) type of Port Scanning attack; 0 represent Static
                       Port type, 1 represent UDP type and 2 represent TCP SYN
                       type

 Return: NuevoSetPaquetesEnviados -> Array of packages that will be insert
"""
def PackagesCreator(ip, PortSrc, datosMultiples, tiempoInicial, tiempoFinal, numPaquetesAEnviar, Seed, interResp, attackType):
    random.seed(Seed)
    datos=datosMultiples[:]
    if attackType==2:
        datos=datosMultiples[0][:]+datosMultiples[1][:] #Los puertos totales son los puertos abiertos mas los cerrados para TCP SYN
    copia_seguridad=datos[:]
    tiempos=rF.gen(Seed, tiempoInicial, tiempoFinal, int(numPaquetesAEnviar/2)) #tiempos donde se inyectan los paquetes
    NuevoSetPaquetesEnviados=[]
    for i in range(len(tiempos)):
        if len(datos)==0:
            datos=copia_seguridad[:]
        j=0
        if len(datos)>1:
            j=random.randint(0,len(datos)-1)
        datoAInsertar=datos.pop(j)
        SetPaquetes=[]
        if attackType==2:
            SetPaquetes=TCPgen(PortSrc, datoAInsertar, datoAInsertar in datosMultiples[0], ip, tiempos[i], interResp)
        elif attackType:
            SetPaquetes=UDP_attack()
        else:
            open=random.randint(0,1)
            SetPaquetes=DomainGen(PortSrc, open, datoAInsertar, ip, tiempos[i], interResp)
        NuevoSetPaquetesEnviados+=[SetPaquetes]
    return NuevoSetPaquetesEnviados

"""
Agregar weaitas aquii
"""
def UDP_attack():
    t=0

"""Author @Javi801
 Port Scanning attack simulator, using Static Port type.
 Creates an array of packages with given values using PackagesCreator function.

 Params: IPsrc -> (string) source IP adress
         PortSrc -> (int) source port
         tiempoInicial -> (float) time in which the attack begins
         tiempoFinal -> (float) time in which the attack ends
         numDominios -> (int) number of domains which will be asked
         Seed -> (float) seed for randomize
         interResp -> (float) time between a query and its response

 Return: NuevoSetPaquetesEnviados -> Array of packages that will be insert
"""
def Domain_attack(IPsrc, PortSrc, tiempoInicial, tiempoFinal, numDominios, Seed, interResp):
    domsFile='ultimos-dominios-1m.txt'
    ############# creacion de las capas para los paquetes ############
    ip=IP(src=IPsrc, dst="200.7.4.7", proto='udp')
    ##################################################################
    ############### generando los domininios a atacar ################
    f = open(domsFile, "r")
    domsList=[]
    bool=1
    while(bool):
        dominio=f.readline().split(',')
        domsList+=[dominio[0]]
        if (domsList[-1]=='') or len(domsList)==numDominios:
            domsList=domsList[:-1]
            bool=0
            break
    f.close()
    ##################################################################
    NuevoSetPaquetesEnviados=PackagesCreator(ip, PortSrc, domsList, tiempoInicial, tiempoFinal, numDominios, Seed, interResp, 0)
    return NuevoSetPaquetesEnviados

""" Author @Javi801
 Creates an array of ethernet packet (query and answer) with especific values for its udp layer, and with
 given IP packet for query packet

 Params: PortSrc -> (int) Port from where the packet is sent
         open -> (int) Server's port is open? 1 (y) or 0 (n)
         dom -> (string) target domain
         ipQ -> (IP()) packet ip
         t -> (float) time at the packet is sent
         interResp -> (float) interval between query and answer

 Return: SetPaquetes -> An ethernet packet
"""
def DomainGen(PortSrc, open, dom, ipQ, t, interResp):
    dom=dom+'.'
    Id=int(RandShort())
    ################### Query packet ###################
    dnsqr=DNSQR(qname=dom)
    dnsQ=DNS(rd=0, id=Id,opcode='QUERY',qdcount=1,qd=dnsqr, qr=0)
    udpQ=UDP(sport=PortSrc, dport=53)
    SetPaquetesQ=Ether(dst='18:66:da:4d:c0:08', src='18:66:da:e6:36:56')/ipQ/udpQ/dnsQ/dnsqr
    SetPaquetesQ.time=t
    ################### Answer packet ###################
    ether=Ether(src='18:66:da:4d:c0:08', dst='18:66:da:e6:36:56')
    ether.time=t+interResp
    if open:
        ipA=IP(proto='udp', src="200.7.4.7", dst=ipQ.src)
        udpA=UDP(sport=53, dport=PortSrc)
        dnsrr=DNSRR(rrname=dom, type='NS')
        dnsA=DNS(id=Id,rd=0, qr=1,opcode='QUERY',qd=dnsqr, ns=dnsrr)
        SetPaquetesA=ether/ipA/udpA/dnsA/dnsqr/dnsrr
    else:
        icmp=ICMP(type=3, code=3)
        SetPaquetesA=ether/icmp
    SetPaquetes=[SetPaquetesQ,SetPaquetesA]
    return SetPaquetes


""" Author @Javi801
 Port Scan attack simulator, using TCP SYN type.
 Creates an array of packages with given values using PackagesCreator function.

 Params: IPsrc -> (string) source IP adress
         PortSrc -> (int) source port
         puertos -> (list(int)) target ports list
         tiempoInicial -> (float) time in which the attack begins
         tiempoFinal -> (float) time in which the attack ends
         numPaquetesAEnviar -> (int) number of packages that will be sent
         Seed -> (float) seed for randomize
         interResp -> (float) time between a query and its response

 Return: NuevoSetPaquetesEnviados -> Array of packages, with numPaquetesAEnviar
                                     as length
"""
def TCP_attack(IPsrc, PortSrc, puertos, tiempoInicial, tiempoFinal, numPaquetesAEnviar, Seed, interResp):
    ############# creacion de la ip para los paquetes ############
    ip=IP(src=IPsrc, dst="200.7.4.7", proto='tcp')
    ##################################################################
    NuevoSetPaquetesEnviados=PackagesCreator(ip, PortSrc, puertos, tiempoInicial, tiempoFinal, numPaquetesAEnviar, Seed, interResp, 2)
    return NuevoSetPaquetesEnviados

""" Author @Javi801
 Creates an array of ethernet packet (query and answer) with especific values for its tcp layer, and with
 given IP packet for query packet

 Params: PortSrc -> (int) Port from where the packet is sent
         PortDst -> (int) Port where the packet is received
         open -> (int) Server's port is open? 1 (y) or 0 (n)
         ipQ -> (IP()) packet ip
         t -> (float) time at the packet is sent
         interResp -> (float) interval between query and answer

 Return: SetPaquetes -> An ethernet packet
"""
def TCPgen(PortSrc, PortDst, open, ipQ, t, interResp):
    Id=int(RandShort())
    dnsQ=DNS(rd=0, id=Id)
    tcpQ=TCP(flags='S', sport=PortSrc, dport=PortDst)
    SetPaquetesQ=Ether(dst='18:66:da:4d:c0:08', src='18:66:da:e6:36:56')/ipQ/tcpQ/dnsQ
    SetPaquetesQ.time=t
    ipA=IP(proto='tcp', src=ipQ.dst, dst=ipQ.src)
    tcpA=TCP(sport=PortSrc, dport=PortDst)
    SetPaquetesA=Ether(src='18:66:da:4d:c0:08', dst='18:66:da:e6:36:56')/ipA/tcpA/DNS(id=Id,aa=1)
    SetPaquetesA.time=t+interResp
    if open:
        SetPaquetesA[2].flags='SA'
    else:
        SetPaquetesA[2].flags='R'
    SetPaquetes=[SetPaquetesQ,SetPaquetesA]
    return SetPaquetes

""" Author @Javi801
 Gives an array of two ports arrays; first the open ones and, then, the closed

 Param: puertoInicial -> (int) first port
        puertoFinal -> (int) last port
        intervaloPuertos -> (int) interval between each port
        abiertos ->  (list(int) or int) open port list or number of open ports
        cerrados -> (list(int) or int) closed port list or number of closed ports
        type -> (int): 0 => random numbers of open and closed ports
                       1 => especific number of open OR closed ports (other one
                            must be -1 or less)
                       2 => especific list of open OR closed ports (other one
                            must be empty list)
        Seed -> (float) seed for randomize

 Return: list(int) -> list of two port list
"""
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
    if type==1: #Cantidad dada de puertos abiertos y cerrados, se necesita puertoFinal, puertoInicial, intervaloPuertos, cerrados, abiertos
        return intPorts(abiertos, cerrados, puertos, Seed)
    if len(abiertos)==0 or len(cerrados)==0:
        return ArrayPorts(abiertos, cerrados, puertos, Seed)

""" Author @Javi801
 Gives a list with two ports list; first the open ones and, then, the closed.
 This with a given number of open ports or closed ports

 Params: abiertos -> (int) number of open ports, it can be -1
         cerrados -> (int) number of closed ports, it can be -1
         puertos -> (list(int)) ports list
         Seed -> (float) seed for randomize

 Return: list(int) -> list of two port list
"""
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
            open+=[ins]
        return [open, puertos]

""" Author @Javi801
 Gives a list with two ports list; first the open ones and, then, the closed.
 This with a given list of open ports or closed ports

 Params: abiertos -> (list(int)) open ports list, it can be []
         cerrados -> (list(int)) closed ports list, it can be []
         puertos -> (list(int)) ports list
         Seed -> (float) seed for randomize

 Return: list(int) -> list of two port list
"""
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
