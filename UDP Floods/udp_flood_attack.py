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
    from ipGenerator import *
    from assertFunctions import *
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

 Return: NuevoSetPaquetesEnviados -> Array of packages that will be insert
"""
def udpFloodAttack( IPservidor, IPsrcList, PortSrcList, puertosAbiertosCerrados, tiempoInicial, tiempoFinal, numPaquetesAEnviar, Seed, UDP_ICMP_Limit, icmpTasa ):
    random.seed( Seed )
    puertos = puertosAbiertosCerrados[0][:]+puertosAbiertosCerrados[1][:] #Los puertos totales son los puertos abiertos mas los cerrados para TCP SYN
    copia_seguridad = puertos[:]
    tiempos = rF.gen( Seed, tiempoInicial, tiempoFinal, numPaquetesAEnviar ) #tiempos donde se inyectan los paquetes
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
        dt = pickDelayResp( )
        if UDP_ICMP_Limit:
            icmpResp = ( puertoTarget in puertosAbiertosCerrados[1] ) and ( ( tiempos[i]-last_icmpResp[0] ) >=  1 or len( last_icmpResp )<icmpTasa )
            if icmpResp:
                last_icmpResp += [tiempos[i]+dt]
                if len( last_icmpResp )>icmpTasa:
                    last_icmpResp.pop( 0 )
        else:
            icmpResp = ( puertoTarget in puertosAbiertosCerrados[1] )
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
    mensaje='Error in the parameters to create the packets'
    PortSrc = args[0]
    puertoTarget = args[1]
    list( map( lambda a: check( a, lambda x: ( x >= 0 ) and ( x<=65535 ), mensaje ), [PortSrc, puertoTarget] ) )
    icmpResp = args[2]
    IPsrc = args[3]
    IPservidor = args[4]
    list( map( lambda a: check( a, lambda x: checkValidIp( x ), mensaje ), [IPsrc, IPservidor] ) )
    tiempoPregunta = args[5]
    dt = args[6]
    list( map( lambda a: check( a, lambda x: x >= 0, mensaje ), [tiempoPregunta, dt] ))
    contador = args[7]
    check( contador, lambda x: ( x%1 ) == 0 and x >= 0 , mensaje )
    Seed = args[8]
    return udpPairGen( PortSrc, puertoTarget, icmpResp, IPsrc, IPservidor, tiempoPregunta, dt, contador, Seed )


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
def udpPairGen( PortSrc, PortDst, open, IPsrc, IPservidor, tiempo, interResp, contador, Seed ):
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

 Params: attackType -> ( int ) type of Port Scanning attack;
               - 0  = > TCP SYN attack type
               - 1  = > UDP attack type
               - 2 or more  = > Static Port attack type


 Return: dt -> ( float ) response interval
"""
def pickDelayResp():
    dt = 0
    while dt == 0:
            dt = abs( random.gauss( 0.000322919547395, 0.018900697143 ) )
    return dt
