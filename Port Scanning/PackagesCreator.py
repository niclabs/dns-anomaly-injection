try:
    from scapy.all import *
    from PortsGenerartor import *
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
         attackType -> (int) type of Port Scanning attack;
                       - 0 => TCP SYN attack type
                       - 1 => UDP attack type
                       - 2 or more => Static Port attack type

 Return: NuevoSetPaquetesEnviados -> Array of packages that will be insert
"""
def PackagesCreator(ip, PortSrc, datosMultiples, tiempoInicial, tiempoFinal, numPaquetesAEnviar, Seed, interResp, attackType):
    random.seed(Seed)
    datos=datosMultiples[:]
    if attackType==0 or attackType==1:
        datos=datosMultiples[0][:]+datosMultiples[1][:] #Los puertos totales son los puertos abiertos mas los cerrados para TCP SYN
    copia_seguridad=datos[:]
    tiempos=rF.gen(Seed, tiempoInicial, tiempoFinal, int(numPaquetesAEnviar/2)) #tiempos donde se inyectan los paquetes
    NuevoSetPaquetesEnviados=[]
    last_icmpResp=0
    for i in range(len(tiempos)):
        if len(datos)==0:
            datos=copia_seguridad[:]
        j=0
        if len(datos)>1:
            j=random.randint(0,len(datos)-1)
        datoAInsertar=datos.pop(j)
        if attackType==0:
            SetPaquetes=TCPgen(PortSrc, datoAInsertar, datoAInsertar in datosMultiples[0], ip, tiempos[i], interResp)
        elif attackType==1:
            icmpResp=not(datoAInsertar in datosMultiples[0]) and (tiempos[i]-last_icmpResp)>=60
            if icmpResp:
                last_icmpResp=tiempos[i]+interResp
                copia_seguridad.remove(datoAInsertar) #Se elimina el puerto cerrado de la lista pues ya se obtuvo un mensaje ICMP
            SetPaquetes=UDPgen(PortSrc, datoAInsertar, icmpResp, ip, tiempos[i], interResp)
        else:
            SetPaquetes=DomainGen(PortSrc, datoAInsertar, ip, tiempos[i], interResp)
        NuevoSetPaquetesEnviados+=[SetPaquetes]
    return NuevoSetPaquetesEnviados

"""Author @Javi801
 Port Scan attack simulator, using UDP type.
 Creates an array of packages with given values using PackagesCreator function.

 Params: IPsrc -> (string) source IP adress
         PortSrc -> (int) source port
         puertos -> (list(int)) target ports list
         tiempoInicial -> (float) time in which the attack begins
         tiempoFinal -> (float) time in which the attack ends
         numPaquetesAEnviar -> (int) number of packages that will be sent
         Seed -> (float) seed for randomize
         interResp -> (float) time between a query and its response


 Return: NuevoSetPaquetesEnviados -> Array of packages that will be insert
"""
def UDP_attack(IPsrc, PortSrc, puertos, tiempoInicial, tiempoFinal, numPaquetesAEnviar, Seed, interResp):
    ############# creacion de la ip para los paquetes ############
    ip=IP(src=IPsrc, dst="200.7.4.7", proto='udp')
    ##################################################################
    return PackagesCreator(ip, PortSrc, puertos, tiempoInicial, tiempoFinal, numPaquetesAEnviar, Seed, interResp, 1)


"""Author @Javi801
 Creates an array of ethernet packet with especific values for its udp layer,
 and  with given IP packet for query packet. Also, creates an answer packet if
 the server responds.

 Params: PortSrc -> (int) Port from where the packet is sent
         PortDst -> (int) Port where the packet is received
         icmpResp -> (boolean) true only if the server responds with an ICMP
                     packet
         ip -> (IP()) IP packet
         tiempo -> (float) time at the packet is sent
         interResp -> (float) interval between query and answer

 Return: SetPaquetes -> (list(Ether())) An ethernet packet list
"""
def UDPgen(PortSrc, PortDst, icmpResp, ip, tiempo, interResp):
    etherQ=Ether(src='18:66:da:e6:36:56', dst='18:66:da:4d:c0:08')
    etherQ.time=tiempo
    udpQ=UDP(sport=PortSrc, dport=PortDst)
    QPacket=etherQ/ip/udpQ
    if icmpResp:
        etherA=Ether(src='18:66:da:4d:c0:08', dst='18:66:da:e6:36:56')
        etherA.time=tiempo+interResp
        icmp=ICMP(type=3, code=3)
        APacket=etherA/icmp
        return [QPacket,APacket]
    return [QPacket]

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
    ############# creacion de las capas para los paquetes ############
    ip=IP(src=IPsrc, dst="200.7.4.7", proto='udp')
    ##################################################################
    ############### generando los domininios a atacar ################
    domsFile='ultimos-dominios-1m.txt'
    f = open(domsFile, "r")
    domsList=[]
    bool=1
    while(bool):
        dominio=f.readline().split(',')
        domsList+=[dominio[0]]
        if (domsList[-1]=='') or len(domsList)==(numDominios+2):
            domsList=domsList[1:-1]
            bool=0
            break
    f.close()
    ##################################################################
    NuevoSetPaquetesEnviados=PackagesCreator(ip, PortSrc, domsList, tiempoInicial, tiempoFinal, numDominios, Seed, interResp, 2)
    return NuevoSetPaquetesEnviados

""" Author @Javi801
 Creates an array of ethernet packet (query and answer) with especific values
 for its udp layer, and with given IP packet for query packet

 Params: PortSrc -> (int) Port from where the packet is sent
         dom -> (string) target domain
         ipQ -> (IP()) packet ip
         t -> (float) time at the packet is sent
         interResp -> (float) interval between query and answer

 Return: SetPaquetes -> (list(Ether())) An ethernet packet list
"""
def DomainGen(PortSrc, dom, ipQ, t, interResp):
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
    ipA=IP(proto='udp', src="200.7.4.7", dst=ipQ.src)
    udpA=UDP(sport=53, dport=PortSrc)
    dnsrr=DNSRR(rrname=dom, type='NS')
    dnsA=DNS(id=Id,rd=0, qr=1,opcode='QUERY',qd=dnsqr, ns=dnsrr)
    SetPaquetesA=ether/ipA/udpA/dnsA/dnsqr/dnsrr

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
    NuevoSetPaquetesEnviados=PackagesCreator(ip, PortSrc, puertos, tiempoInicial, tiempoFinal, numPaquetesAEnviar, Seed, interResp, 0)
    return NuevoSetPaquetesEnviados

""" Author @Javi801
 Creates an array of ethernet packet (query and answer) with especific values
 for its tcp layer, and with given IP packet for query packet

 Params: PortSrc -> (int) Port from where the packet is sent
         PortDst -> (int) Port where the packet is received
         open -> (int) Server's port is open? 1 (y) or 0 (n)
         ipQ -> (IP()) packet ip
         t -> (float) time at the packet is sent
         interResp -> (float) interval between query and answer

 Return: SetPaquetes -> (list(Ether())) An ethernet packet list
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
