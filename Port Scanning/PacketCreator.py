try:
    from scapy.all import *
except:
    raise Exception("Install scapy")

try:
    import sys
    sys.path.append("..")
    import randFloats as rF
    from ipGenerator import *
    from PortsGenerator import *
except:
    raise Exception("randFloat or ipGenerator error")

"""Author @Javi801
 Port Scan attack simulator, using UDP type.
 Creates an array of packages with given values using PacketCreator function.

 Params: IPservidor -> (str) server IP address
         IPsrc -> (string) source IP address
         PortSrc -> (int) source port
         puertos -> (list(int)) target ports list
         tiempoInicial -> (float) time in which the attack begins
         tiempoFinal -> (float) time in which the attack ends
         numPaquetesAEnviar -> (int) number of packages that will be sent
         Seed -> (float) seed for randomize
         interResp -> (float) time between a query and its response


 Return: NuevoSetPaquetesEnviados -> Array of packages that will be insert
"""
def UDP_attack(IPservidor: str, IPsrc: str, PortSrc: int, puertos: list, tiempoInicial: float, tiempoFinal: float, numPaquetesAEnviar: int, Seed: float, interResp: float, UDP_ICMP_Limit, icmpTasa: int):
    return PacketCreator(IPservidor, [IPsrc], [PortSrc], puertos, tiempoInicial, tiempoFinal, numPaquetesAEnviar, Seed, interResp, UDP_ICMP_Limit, icmpTasa, 1)

"""Author @Javi801
 DDoS Port Scan attack simulator, using UDP type.
 Creates an array of packages with given values using PacketCreator function.

 Params: totalIPs -> (int) total of source IP address
         IPservidor -> (str) server IP address
         puertos -> (list(int)) target ports list
         tiempoInicial -> (float) time in which the attack begins
         tiempoFinal -> (float) time in which the attack ends
         numPaquetesAEnviar -> (int) number of packages that will be sent
         Seed -> (float) seed for randomize
         interResp -> (float) time between a query and its response


 Return: NuevoSetPaquetesEnviados -> Array of packages that will be insert
"""
def UDP_DDoS_attack(totalIPs: int, IPservidor: str, puertos: list, tiempoInicial: float, tiempoFinal: float, numPaquetesAEnviar: int, Seed: float, interResp: float, UDP_ICMP_Limit, icmpTasa: int):
    IPsrcList=randomIP(totalIPs, Seed, 1)
    PortSrcList=randomSourcePorts(totalIPs, Seed)
    return PacketCreator(IPservidor, IPsrcList, PortSrcList, puertos, tiempoInicial, tiempoFinal, numPaquetesAEnviar, Seed, interResp, UDP_ICMP_Limit, icmpTasa, 1)


"""Author @Javi801
 Creates an array of ethernet packet with especific values for its udp layer,
 and  with given IP packet for query packet. Also, creates an answer packet if
 the server responds.

 Params: PortSrc -> (int) Port from where the packet is sent
         PortDst -> (int) Port where the packet is received
         icmpResp -> (boolean) true only if the server responds with an ICMP
                     packet
         IPsrc -> (str) source IP address
         IPservidor -> (str) server IP address
         tiempo -> (float) time at the packet is sent
         interResp -> (float) interval between query and answer

 Return: SetPaquetes -> (list(Ether())) An ethernet packet list
"""
def UDPgen(PortSrc: int, PortDst: int, icmpResp, IPsrc: str, IPservidor: str, tiempo: float, interResp: float):
    ipQ=IP(src=IPsrc, dst=IPservidor, proto='udp')
    etherQ=Ether(src='18:66:da:e6:36:56', dst='18:66:da:4d:c0:08')
    etherQ.time=tiempo
    udpQ=UDP(sport=PortSrc, dport=PortDst)
    QPacket=etherQ/ipQ/udpQ
    if icmpResp:
        etherA=Ether(src='18:66:da:4d:c0:08', dst='18:66:da:e6:36:56')
        etherA.time=tiempo+interResp
        icmp=ICMP(type=3, code=3)
        APacket=etherA/IP(src=IPservidor, dst=IPsrc)/icmp
        return [QPacket,APacket]
    return [QPacket]

"""Author @Javi801
 Port Scanning attack simulator, using Static Port type.
 Creates an array of packages with given values using PacketCreator function.

 Params: IPsrc -> (string) source IP address
         IPservidor -> (str) server IP address
         PortSrc -> (int) source port
         tiempoInicial -> (float) time in which the attack begins
         tiempoFinal -> (float) time in which the attack ends
         numDominios -> (int) number of domains which will be asked
         Seed -> (float) seed for randomize
         interResp -> (float) time between a query and its response

 Return: NuevoSetPaquetesEnviados -> Array of packages that will be insert
"""
def Domain_attack(IPservidor: str, IPsrc: str, PortSrc: int, tiempoInicial: float, tiempoFinal: float, numDominios: int, Seed: float, interResp: float):
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
    return PacketCreator(IPservidor, [IPsrc], [PortSrc], domsList, tiempoInicial, tiempoFinal, numDominios, Seed, interResp, 0, 0, 2)

"""Author @Javi801
 DDoS Port Scanning attack simulator, using Static Port type.
 Creates an array of packages with given values using PacketCreator function.

 Params: totalIPs -> (int) total of source IP address
         IPservidor -> (str) server IP address
         tiempoInicial -> (float) time in which the attack begins
         tiempoFinal -> (float) time in which the attack ends
         numDominios -> (int) number of domains which will be asked
         Seed -> (float) seed for randomize
         interResp -> (float) time between a query and its response

 Return: NuevoSetPaquetesEnviados -> Array of packages that will be insert
"""
def Domain_DDoS_attack(totalIPs: int, IPservidor: str, tiempoInicial: float, tiempoFinal: float, numDominios: int, Seed: float, interResp: float):
    IPsrcList=randomIP(totalIPs, Seed, 1)
    PortSrcList=randomSourcePorts(totalIPs, Seed)
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
    return PacketCreator(IPservidor, IPsrcList, PortSrcList, domsList, tiempoInicial, tiempoFinal, numDominios, Seed, interResp, 0, 0, 2)

""" Author @Javi801
 Creates an array of ethernet packet (query and answer) with especific values
 for its udp layer, and with given IP packet for query packet

 Params: PortSrc -> (int) Port from where the packet is sent
         dom -> (string) target domain
         IPsrc -> (str) source IP address
         IPservidor -> (str) server IP address
         t -> (float) time at the packet is sent
         interResp -> (float) interval between query and answer

 Return: SetPaquetes -> (list(Ether())) An ethernet packet list
"""
def DomainGen(PortSrc: int, dom: str, IPsrc: str, IPservidor: str, t: float, interResp: float):
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


""" Author @Javi801
 Port Scan attack simulator, using TCP SYN type.
 Creates an array of packages with given values using PacketCreator function.

 Params: IPservidor -> (str) server IP address
         IPsrc -> (string) source IP address
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
def TCP_attack(IPservidor: str, IPsrc: str, PortSrc: int, puertos: list, tiempoInicial: float, tiempoFinal: float, numPaquetesAEnviar: int, Seed: float, interResp: float):
    return PacketCreator(IPservidor, [IPsrc], [PortSrc], puertos, tiempoInicial, tiempoFinal, numPaquetesAEnviar, Seed, interResp, 0, 0, 0)

""" Author @Javi801
 DDoS Port Scan attack simulator, using TCP SYN type.
 Creates an array of packages with given values using PacketCreator function.

 Params: totalIPs -> (int) total of source IP address
         IPservidor -> (str) server IP address
         puertos -> (list(int)) target ports list
         tiempoInicial -> (float) time in which the attack begins
         tiempoFinal -> (float) time in which the attack ends
         numPaquetesAEnviar -> (int) number of packages that will be sent
         Seed -> (float) seed for randomize
         interResp -> (float) time between a query and its response

 Return: NuevoSetPaquetesEnviados -> Array of packages, with numPaquetesAEnviar
                                     as length
"""
def TCP_DDoS_attack(totalIPs: int, IPservidor: str, puertos: list, tiempoInicial: float, tiempoFinal: float, numPaquetesAEnviar: int, Seed: float, interResp: float):
    IPsrcList=randomIP(totalIPs, Seed, 1)
    PortSrcList=randomSourcePorts(totalIPs, Seed)
    return PacketCreator(IPservidor, IPsrcList, PortSrcList, puertos, tiempoInicial, tiempoFinal, numPaquetesAEnviar, Seed, interResp, 0, 0, 0)

""" Author @Javi801
 Creates an array of ethernet packet (query and answer) with especific values
 for its tcp layer, and with given IP packet for query packet

 Params: PortSrc -> (int) Port from where the packet is sent
         PortDst -> (int) Port where the packet is received
         open -> (boolean) Indicates whether the port is open (true) or not (false)
         IPsrc -> (str) source IP address
         IPservidor -> (str) server IP address
         t -> (float) time at the packet is sent
         interResp -> (float) interval between query and answer

 Return: SetPaquetes -> (list(Ether())) An ethernet packet list
"""
def TCPgen(PortSrc: int, PortDst: int, open, IPsrc: str, IPservidor: str, t: float, interResp: float):
    ipQ=IP(src=IPsrc, dst=IPservidor, proto='tcp')
    Id=int(RandShort())
    dnsQ=DNS(rd=0, id=Id)
    tcpQ=TCP(flags='S', sport=PortSrc, dport=PortDst)
    SetPaquetesQ=Ether(dst='18:66:da:4d:c0:08', src='18:66:da:e6:36:56')/ipQ/tcpQ/dnsQ
    SetPaquetesQ.time=t

    ipA=IP(proto='tcp', src=IPservidor, dst=IPsrc)
    tcpA=TCP(sport=PortDst, dport=PortSrc)
    SetPaquetesA=Ether(src='18:66:da:4d:c0:08', dst='18:66:da:e6:36:56')/ipA/tcpA/DNS(id=Id,aa=1)
    SetPaquetesA.time=t+interResp
    if open:
        SetPaquetesA[2].flags='SA'
    else:
        SetPaquetesA[2].flags='R'
    SetPaquetes=[SetPaquetesQ,SetPaquetesA]
    return SetPaquetes


""" Author @Javi801
 Creates an array of packages with given values. Each packet contains an
 Ether pack in its firts layer, an IP pack in its second layer, an TCP or UDP
 pack in its third layer and a DNS pack in its last layer

 Params: IPservidor -> (str) server IP address
         IPlist -> (list(str)) list of source IP addresses
         PortSrcList -> (list(int)) list of source ports
         datosMultiples -> (list(int) or list(list(int))) values list for
                            variable param
         tiempoInicial -> (float) time in which the attack begins
         tiempoFinal -> (float) time in which the attack ends
         numPaquetesAEnviar -> (int) number of packages that will be sent
         Seed -> (float) seed for randomize
         interResp -> (float) time between a query and its response
         UDP_ICMP_Limit -> (boolean) True if the server have limit rate por ICMP
                           response, False if not
         icmpTasa -> (int) Number of ICMP responses with the limit rate
         attackType -> (int) type of Port Scanning attack;
                       - 0 => TCP SYN attack type
                       - 1 => UDP attack type
                       - 2 or more => Static Port attack type

 Return: NuevoSetPaquetesEnviados -> Array of packages that will be insert
"""
def PacketCreator(IPservidor: str, IPlist: list, PortSrcList: list, datosMultiples: list, tiempoInicial: float, tiempoFinal: float, numPaquetesAEnviar: int, Seed: float, interResp: float, UDP_ICMP_Limit, icmpTasa: int, attackType: int):
    random.seed(Seed)
    datos=datosMultiples[:]
    if attackType==0 or attackType==1:
        datos=datosMultiples[0][:]+datosMultiples[1][:] #Los puertos totales son los puertos abiertos mas los cerrados para TCP SYN
    copia_seguridad=datos[:]
    tiempos=rF.gen(Seed, tiempoInicial, tiempoFinal-interResp, numPaquetesAEnviar) #tiempos donde se inyectan los paquetes
    NuevoSetPaquetesEnviados=[]
    last_icmpResp=[0]
    for i in range(len(tiempos)):
        if len(datos)==0:
            datos=copia_seguridad[:]
        #Se selecciona el puerto o dominio a atacar
        j=0
        if len(datos)>1:
            j=random.randint(0,len(datos)-1)
        datoAInsertar=datos.pop(j)
        #Se selecciona la IP y el puerto de origen
        k=0
        if len(IPlist)>1:
            k=random.randint(0,len(PortSrcList)-1)
        IPsrc=IPlist[k]
        PortSrc=PortSrcList[k]
        #Se crea la tupla pregunta-respuesta
        if attackType==0: #Si el ataque es TCP
            SetPaquetes=TCPgen(PortSrc, datoAInsertar, datoAInsertar in datosMultiples[0], IPsrc, IPservidor, tiempos[i], pickDelayResp(interResp, attackType))
        elif attackType==1: #Si el ataque es UDP
            dt=pickDelayResp(interResp, attackType)
            if UDP_ICMP_Limit:
                icmpResp=(datoAInsertar in datosMultiples[1]) and ((tiempos[i]-last_icmpResp[0])>=1 or len(last_icmpResp)<icmpTasa)
                if icmpResp:
                    last_icmpResp+=[tiempos[i]+dt]
                    if len(last_icmpResp)>icmpTasa:
                        last_icmpResp.pop(0)
            else:
                icmpResp=True
            SetPaquetes=UDPgen(PortSrc, datoAInsertar, icmpResp, IPsrc, IPservidor, tiempos[i], dt)
            if icmpResp and datoAInsertar in datosMultiples[1]:
                copia_seguridad.remove(datoAInsertar)
        else: #Si el ataque es dirigido a otro servidor pero pasa por este
            SetPaquetes=DomainGen(PortSrc, datoAInsertar, IPsrc, IPservidor, tiempos[i], pickDelayResp(interResp, attackType))

        NuevoSetPaquetesEnviados+=[SetPaquetes]

        if len(copia_seguridad)==0:
            return NuevoSetPaquetesEnviados
    return NuevoSetPaquetesEnviados


""" @Javi801
 Gives a response interval, considering the type of simulated attack and the
 response interval given.

 Params: interResp -> (float) previous time between a query and its response
         attackType -> (int) type of Port Scanning attack;
               - 0 => TCP SYN attack type
               - 1 => UDP attack type
               - 2 or more => Static Port attack type


 Return: dt -> (float) response interval
"""
def pickDelayResp(interResp, attackType):
    if interResp>=0:
        return interResp
    dt=0
    while dt==0:
        if attackType==0: #Ataque es tipo TCP
            dt=abs(random.gauss(0.0324164173995, 0.661281423818))
        elif attackType==1: #Si el ataque es tipo UDP la respuesta es ICMP
            dt=abs(random.gauss(0.0001868, 0.0000297912738902))
        else:
            dt=abs(random.gauss(0.000322919547395, 0.018900697143))
    return dt
