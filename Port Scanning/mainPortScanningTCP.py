import argparse
from PacketCreator import *
import sys
sys.path.append( ".." )
from PacketInserter import *
from PortsGenerator import *
from assertFunctions import *


def main():
    ###################### Manejo de valores por consola ######################
    parser = argparse.ArgumentParser( description = 'Port Scanning attack simulator' )
    parser.add_argument( "-i", "--input_file", help = "Input file name and directory" )
    parser.add_argument( "-o", "--output_file", help = "Output file name and directory" )
    parser.add_argument( "-d", "--duration", help = "Duration of the attack ( d: 60s )", type = float, default = 60 )
    parser.add_argument( "-z","--num_zombies", help = "Number of computers in the botnet for the DDoS attack ( d: 1 )", type = int, default = 1 )
    parser.add_argument( "-it", "--initial_time", help = "Seconds of delay to begin the attack ( d: 0 )", type = int, default = 0 )
    parser.add_argument( "-n", "--num_packet", help = "Total domains per second to attack ( d: 15000 )", type = int, default = 15000 )
    parser.add_argument( "-p", "--packets_per_window", help = 'Packets per window that the server accepts ( d: 100 per centesima of second )', type = int, default = 100 )
    parser.add_argument( "-w","--window_size", help = 'Window size for server tolerance ( d: centesima of second )', type = float, default = 0.01 )
    parser.add_argument( "-s","--server_ip", help = "IP address of the target server ( d: 200.7.4.7 )", default = '200.7.4.7' )
    parser.add_argument( "-sp", "--sport", help = "Source port ( d: 1280 )", type = int, default = 1280 )
    parser.add_argument( "-sip", "--src_ip", help = "Source IP ( d: random )" )
    parser.add_argument( "-ip", "--initial_port", help = "Initial port to attack ( d: 0 )", type = int, default = 0 )
    parser.add_argument( "-fp", "--final_port", help = "Final port to attack ( d: 40000 )", type = int, default = 40000 )
    parser.add_argument( "-inp", "--inter_port", help = "Interval between ports ( d: 1 )", type = int, default = 1 )
    parser.add_argument( "-op", "--open_port", help = "Total open ports ( d: aleatorio )", type = int )
    parser.add_argument( "-cp", "--closed_port", help = "Total closed ports ( d: aleatorio )", type = int )
    parser.add_argument( "-opl", "--open_port_list", help = "List of open ports, ej:1 2 3 ( d: [] )" )
    parser.add_argument( "-cpl", "--closed_port_list", help = "List of closed ports, ejemplo:1 2 3 ( d: [] )" )
    args = parser.parse_args()

    #################### Manejo de los nombres de archivos ####################
    if not( args.output_file ):
        print( '\nName or directory of the output file invalid' )
        return
    finalDir = args.output_file
    if finalDir[-5:] !=  '.pcap':
        finalDir  +=   '.pcap'
    iniDir = args.input_file
    if not( os.path.exists( iniDir ) ):
        print( '\nName or directory of the input file invalid' )
        return
    ###########################################################################
    paquete = sniff( offline = iniDir, count = 1 )
    tInicial = paquete[0].time + args.initial_time
    duracion = args.duration
    numPaquetesAEnviar = int( ( args.num_packet )*duracion )
    IPservidor = args.server_ip
    totalInfectados = args.num_zombies
    PortSrc = args.sport
    tolerancia = args.packets_per_window
    uTiempo = args.window_size
    Seed = time.time
    puertoInicial = args.initial_port
    puertoFinal = args.final_port
    intervaloPuertos = args.inter_port
    ###################### Limite para la unidad de tiempo #####################
    if uTiempo>1:
        print( 'A window size greater than 1 second is not allowed' )
        tolerancia = tolerancia/uTiempo
        uTiempo = 1
    ############################################################################
    #################### Verificacion de valores ingresados ####################
    check( iniDir, lambda x: '.pcap' in x , 'The file format must be included in the file name to open' )
    check( duracion, lambda x: x>0 , 'The duration of the attack must be greater than 0' )
    check( numPaquetesAEnviar, lambda x: x>0 and ( x%1 ) == 0 , "The number of packets per second to send must be greater than 0" )
    check( totalInfectados, lambda x: x >= 1 , 'The number of pcs zombies must be greater than or equal to 1' )
    check( tolerancia, lambda x: x>0 , 'The number of packets accepted per window must be greater than 0' )
    list( map( lambda a: check( a, lambda x: ( x >= 0 ) and ( x<=65535 ), "Any port must be between 0 and 65535" ), [PortSrc, puertoInicial, puertoFinal] ) )
    check( intervaloPuertos, lambda x: x>0 and ( x%1 ) == 0 , 'The interval between each port must be greater than 0' )
    try:
        assert( puertoInicial <=  puertoFinal )
    except:
        raise Exception( 'The lesser port to attack must be less than the major port to attack' )
    ############################################################################
    ####################### Creacion de puertos a atacar #######################
    if args.open_port or args.closed_port:
        if args.open_port:
            print( "\nWhen you enter the total open ports, the total closed ports cannot be modified" )
            abiertos = args.open_port
            puertos = arrayPortsGen( puertoInicial, puertoFinal, intervaloPuertos, abiertos, -1, Seed )
        elif args.closed_port:
            print( "\nWhen you enter the total closed ports, the total open ports cannot be modified" )
            cerrados = args.closed_port
            puertos = arrayPortsGen( puertoInicial, puertoFinal, intervaloPuertos, -1, cerrados, Seed )
    elif args.open_port_list and args.closed_port_list:
        abiertos = string2numList( args.open_port_list, ' ' )
        cerrados = string2numList( args.closed_port_list, ' ' )
        puertos = [abiertos, cerrados]
    elif args.open_port_list or args.closed_port_list:
        if args.open_port_list:
            abiertos = string2numList( args.open_port_list, ' ' )
            puertos = arrayPortsGen( puertoInicial, puertoFinal, intervaloPuertos, abiertos, [], Seed )
        if args.closed_port_list:
            cerrados = string2numList( args.closed_port_list, ' ' )
            puertos = arrayPortsGen( puertoInicial, puertoFinal, intervaloPuertos, [], cerrados, Seed )
    else:
        puertos = randomPortsGen( puertoInicial, puertoFinal, intervaloPuertos, Seed )
    ############################################################################
    if totalInfectados>1:
        attack = TCP_DDoS_attack( totalInfectados, IPservidor, puertos, tInicial, tInicial+duracion, numPaquetesAEnviar, Seed )
    else:
        if args.src_ip:
            IPsrc = args.src_ip
        else:
            IPsrc = randomIP( 1, Seed, 0 )
        attack = TCP_attack( IPservidor, IPsrc, PortSrc, puertos, tInicial, tInicial+duracion, numPaquetesAEnviar, Seed )

    print( 'Arguments for packets created successfully' )
    ins = PacketInserter()
    operation = ins.withArgs(attack)\
                .withPcapInput(iniDir)\
                .withPcapOutput(finalDir)\
                .withServerIp( IPservidor )\
                .withTimestamp( uTiempo )\
                .withServerTolerance( tolerancia )\
                .insert(generadorParesPortScanningTCP)
    if operation:
        print( "Packages inserted successfully" )
    ############################################################################

""" @Javi801
 Gives an array of ints with a given string, transforming the string into a int list

 Params: string -> ( str ) string to transform
         separador -> ( str ) string to use as separator between each number

 Return: final -> ( list( int ) ) list of ints in the inicial string
"""
def string2numList( string, separador ):
    strList = s.split( separador )
    final = []
    for i in range( len( strList ) ):
        if strList[i] == '':
            continue
        num = int( strList[i] )
        final +=  [num]
    return final

main()
