import argparse
from PacketCreator import *
import sys
sys.path.append( ".." )
from PacketInserter import *
from PortsGenerator import *
from ipGenerator import *
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
    ###################### Limite para la unidad de tiempo #####################
    if uTiempo>1:
        print( '\nA window size greater than 1 second is not allowed' )
        tolerancia = tolerancia/uTiempo
        uTiempo = 1
    ############################################################################
    #################### Verificacion de valores ingresados ####################
    check( iniDir, lambda x: '.pcap' in x , 'The file format must be included in the file name to open' )
    check( duracion, lambda x: x>0 , 'The duration of the attack must be greater than 0' )
    check( numPaquetesAEnviar, lambda x: x>0 and ( x%1 ) == 0 , "The number of packets per second to send must be greater than 0" )
    check( totalInfectados, lambda x: x >= 1 , 'The number of pcs zombies must be greater than or equal to 1' )
    check( tolerancia, lambda x: x>0 , 'The number of packets accepted per window must be greater than 0' )
    check( PortSrc, lambda x: ( x >= 0 ) and ( x<=65535 ), "Source port must be between 0 and 65535" )
    ############################################################################
    if totalInfectados>1:
        attack = Domain_DDoS_attack( totalInfectados, IPservidor, tInicial, tInicial+duracion, numPaquetesAEnviar, Seed )
    else:
        if args.src_ip:
            IPsrc = args.src_ip
        else:
            IPsrc = randomIP( 1, Seed, 0 )
        attack = Domain_attack( IPservidor, IPsrc, PortSrc, tInicial, tInicial+duracion, numPaquetesAEnviar, Seed )
    print( 'Arguments for packets created successfully' )
    ins = PacketInserter()
    operation = ins.withArgs(attack)\
                .withPcapInput(iniDir)\
                .withPcapOutput(finalDir)\
                .withServerIp( IPservidor )\
                .withTimestamp( uTiempo )\
                .withServerTolerance( tolerancia )\
                .insert(generadorParesPortScanningDom)
    if operation:
        print( "Packages inserted successfully" )
    ############################################################################


main()
