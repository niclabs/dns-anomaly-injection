try:
    import string
    import random
    from scapy.all import *
except:
    raise Exception( "Install scapy" )

try:
    import sys
    sys.path.append( ".." )
    import randFloats as rF
except:
    raise Exception( "randFloat error" )

""" Author @Javi801
 Creates an array of two packages ( query and response ) with given values. Each packet contains an
 Ether pack in its firts layer, an IP pack in its second layer, an TCP or UDP
 pack in its third layer and a DNS pack in its last layer

 Params: IPservidor -> ( str ) server IP address
         IPsrcList -> ( list( str ) ) List of source IP addresses
         PortSrc -> ( int ) source port
         puertosAbiertosCerrados -> ( list( list( int ) ) ) list of open and closed
                                    ports list
         tiempoInicial -> ( float ) time in which the attack begins
         tiempoFinal -> ( float ) time in which the attack ends
         numPaquetesAEnviar -> ( int ) number of packages that will be sent
         Seed -> ( float ) seed for randomize
         interResp -> ( float ) time between a query and its response

 Return: NuevoSetPaquetesEnviados -> Array of packages that will be insert
"""
def udpFloodAttack( IPservidor: str, IPsrcList: list, PortSrcList: list, puertosAbiertosCerrados: list, tiempoInicial: float, tiempoFinal: float, numPaquetesAEnviar: int, Seed: float, interResp: float, UDP_ICMP_Limit, icmpTasa: int ):
    random.seed( Seed )
    puertos = puertosAbiertosCerrados[0][:]+puertosAbiertosCerrados[1][:] #Los puertos totales son los puertos abiertos mas los cerrados para TCP SYN
    copia_seguridad = puertos[:]
    tiempos = rF.gen( Seed, tiempoInicial, tiempoFinal-interResp, numPaquetesAEnviar ) #tiempos donde se inyectan los paquetes
    SetPaquetesEnviados = []
    last_icmpResp = [0]
    for i in range( len( tiempos ) ):
        if len( puertos ) == 0:
            puertos = copia_seguridad[:]
        j = 0
        if len( puertos )>1:
            j = random.randint( 0,len( puertos )-1 )
        puertoTarget = puertos.pop( j )
        IPsrc = IPsrcList[0]
        PortSrc = PortSrcList[0]
        if len( IPsrcList )>1:
            j = random.randint( 0,len( IPsrcList )-1 )
            IPsrc = IPsrcList[j]
            if len( PortSrcList )>1:
                PortSrc = PortSrcList[j]
        dt = pickDelayResp( interResp )
        if UDP_ICMP_Limit:
            icmpResp = ( puertoTarget in puertosAbiertosCerrados[1] ) and ( ( tiempos[i]-last_icmpResp[0] ) >=  1 or len( last_icmpResp )<icmpTasa )
            if icmpResp:
                last_icmpResp += [tiempos[i]+dt]
                if len( last_icmpResp )>icmpTasa:
                    last_icmpResp.pop( 0 )
        else:
            icmpResp = True
        if icmpResp and puertoTarget in puertosAbiertosCerrados[1]:
            copia_seguridad.remove( puertoTarget )
        argumentosSetPaquetes = [PortSrc, puertoTarget, not( icmpResp ), IPsrc, IPservidor, tiempos[i], dt, len( SetPaquetesEnviados ), Seed]
        SetPaquetesEnviados.append( argumentosSetPaquetes )
    return SetPaquetesEnviados


""" Author @Javi801
 Creates an array of packets with the values in the list as arguments, to do
 this use uses the function "udpPairGen"

 Params: args -> ( list() ) Params for UDPgen function

 Return: paquetes -> ( list() ) Array of packets that will be insert
"""
def generadorParesUDPflood( args ):
    SetPaquetes = []
    for i in range( len( args ) ):
        PortSrc = args[i][0]
        puertoTarget = args[i][1]
        icmpResp = args[i][2]
        IPsrc = args[i][3]
        IPservidor = args[i][4]
        tiempoPregunta = args[i][5]
        dt = args[i][6]
        contador = args[i][7]
        Seed = args[i][8]
        Par = udpPairGen( PortSrc, puertoTarget, icmpResp, IPsrc, IPservidor, tiempoPregunta, dt, contador, Seed )
        SetPaquetes.append( Par )
    return SetPaquetes


"""Author @Javi801
 Creates an array of ethernet packet with especific values for its udp layer,
 and  with given IP packet for query packet. Also, creates an answer packet if
 the server responds.

 Params: PortSrc -> ( int ) Port from where the packet is sent
         PortDst -> ( int ) Port where the packet is received
         open -> ( boolean ) Indicates whether the port is open ( true ) or not ( false )
         IPsrc -> ( str ) Source IP address
         IPservidor -> ( str ) Server IP address
         tiempo -> ( float ) time at the packet is sent
         interResp -> ( float ) interval between query and answer
         contador -> ( int ) total of packs sents
         Seed -> ( float ) seed for randomize

 Return: SetPaquetes -> ( list( Ether() ) ) An ethernet packet list
"""
def udpPairGen( PortSrc: int, PortDst: int, open, IPsrc: str, IPservidor: str, tiempo: float, interResp: float, contador: int, Seed: float ):
    ip = IP( src = IPsrc, dst = IPservidor, proto = 'udp' )
    etherQ = Ether( src = '18:66:da:e6:36:56', dst = '18:66:da:4d:c0:08' )
    etherQ.time = tiempo
    udpQ = UDP( sport = PortSrc, dport = PortDst )
    datos = Raw( load = rF.randomString( 0,contador,1458,1, Seed ) ) #Datos de peso
    QPacket = etherQ/ip/udpQ/datos
    if not( open ):
        etherA = Ether( src = '18:66:da:4d:c0:08', dst = '18:66:da:e6:36:56' )
        etherA.time = tiempo+interResp
        icmp = ICMP( type = 3, code = 3 )
        APacket = etherA/IP( src = IPservidor, dst = IPsrc )/icmp
        return [QPacket,APacket]
    return [QPacket]

""" @Javi801
 Gives a response interval, considering the type of simulated attack and the
 response interval given.

 Params: interResp -> ( float ) previous time between a query and its response
         attackType -> ( int ) type of Port Scanning attack;
               - 0  = > TCP SYN attack type
               - 1  = > UDP attack type
               - 2 or more  = > Static Port attack type


 Return: dt -> ( float ) response interval
"""
def pickDelayResp( interResp ):
    dt = 0
    if interResp == -1:
        while dt == 0:
            dt = abs( random.gauss( 0.0001868, 0.0000297912738902 ) )
    else:
        dt = interResp
    return dt
