import argparse
from udp_flood_attack import *
import sys
sys.path.append("..")
from PacketInserter import *
from PortsGenerator import *
from ipGenerator import *


def main():
    ########################### Valores por defecto ###########################
    Seed=time.time
    attack=[]
    domsFile='ultimos-dominios-1m.txt'
    ###########################################################################
    ###################### Manejo de valores por consola ######################
    parser = argparse.ArgumentParser(description='UDP Flood attack simulator')
    parser.add_argument("-ff", "--final_file", help="Sufijo para el nombre del archivo donde guardar el ataque", default='UDPFloodAttack.pcap')
    parser.add_argument("-f", "--file", help="Nombre del archivo a procesar, ejemplo: ej.pcap")
    parser.add_argument("-ddos","--ddos_type", help="Extender el ataque a tipo distribuido", action="store_true")
    parser.add_argument("-sip","--server_ip", help="Direccion IP del servidor atacado (d: 200.7.4.7)", default='200.7.4.7')
    parser.add_argument("-tip", "--total_ips_src", help="Total de direcciones IP de origen (d: 30)", default=30, type=int)
    parser.add_argument("-ps", "--sport", help="Puerto de origen (d: 1280)", type=int, default=1280)
    parser.add_argument("-pi", "--iport", help="Puerto menor a atacar (d: 1023)", type=int, default=1023)
    parser.add_argument("-pf", "--fport", help="Puerto mayor a atacar (d: 3000)", type=int, default=3000)
    parser.add_argument("-inp", "--inter_port", help="Intervarlo entre un puerto y otro (d: 1)", type=int, default=1)
    parser.add_argument("-op", "--open_port", help="Total de puertos abiertos", type=int, default=20)
    parser.add_argument("-cp", "--closed_port", help="Total de puertos cerrados", type=int, default=500)
    parser.add_argument("-s", "--seed", help="Semilla para aleatorizar datos (d: computer time)", type=float)
    parser.add_argument("-d", "--duration", help="Duracion del ataque (d: 60s)", type=float, default=60)
    parser.add_argument("-n", "--num_packages", help="Total de paquetes a enviar (d: 5000)", type=int, default=5000)
    parser.add_argument("-ir", "--int_resp", help="Intervalo de respuesta inicial (d: 0.0001s)", type=float, default=0.0001)
    args = parser.parse_args()

    #################### Manejo de los nombres de archivos ####################
    nombrePktFin=args.final_file
    if nombrePktFin[-5:]!='.pcap':
        nombrePktFin==nombrePktFin+'.pcap'
    nombrePktIni=args.file
    print("El nombre de archivo a procesar es: ", nombrePktIni)
    index=nombrePktIni.find('.pcap')
    if index==-1:
        print('\nEl nombre del archivo a procesar debe tener una extension valida')
        return
    nombrePktFin=nombrePktIni[:index]+'_'+nombrePktFin
    ###########################################################################

    paquete= sniff(offline='input/'+nombrePktIni, count=1)
    tInicial=paquete[0].time #Tiempo de inicio del ataque
    if args.seed:
        Seed=args.seed
    duracion=args.duration
    numPaquetesAEnviar=args.num_packages
    interResp=args.int_resp
    IPservidor=args.server_ip
    PortSrcList=[args.sport]
    if args.ddos_type:
        PortSrcList=randomSourcePorts(totalIPs, Seed)
    totalIPs=args.total_ips_src
    IPsrcList=randomIP(totalIPs,Seed,args.ddos_type)
    puertoInicial=args.iport
    puertoFinal=args.fport
    intervaloPuertos=args.inter_port
    abiertos=args.open_port
    cerrados=args.closed_port
    #################### Verificacion de valores ingresados ####################
    try:
        assert(len(nombrePktFin)>0 and len(nombrePktIni)>0)
    except:
        raise Exception('Los nombres de archivo no pueden ser vacio')
    try:
        assert(duracion>0)
    except:
        raise Exception('La duracion del ataque debe ser mayor a 0')
    try:
        assert(PortSrc<=65536)
        assert(PortSrc>=0)
        assert(puertoInicial<=65536)
        assert(puertoInicial>=0)
        assert(puertoFinal<=65536)
        assert(puertoFinal>=0)
    except:
        raise Exception("Los puertos indicados deben ser menor a 65537 y mayor o igual a 0")
    try:
        assert(numPaquetesAEnviar>0)
    except:
        raise Exception("El numero de paquetes a enviar debe ser mayor a 0")
    try:
        assert(interResp>0)
    except:
        raise Exception("El intervalo de respuesta debe ser mayor a 0")
    try:
        assert(totalIPs>0)
    except:
        raise Exception('El total de direcciones IP de origen debe ser mayor a 0')
    try:
        assert(puertoInicial<=puertoFinal)
    except:
        raise Exception('El puerto menor a atacar debe ser menor que el puerto mayor a atacar')
    try:
        assert(intervaloPuertos>0)
    except:
        raise Exception('El intervalo entre un puerto y otro debe ser mayor a 0')
    ############################################################################
    ####################### Creacion de puertos a atacar #######################
    if abiertos!=20 and cerrados!=500:
        puertos=arrayPortsGen(puertoInicial, puertoFinal, intervaloPuertos, abiertos, cerrados, Seed)
    elif abiertos!=20:
        puertos=arrayPortsGen(puertoInicial, puertoFinal, intervaloPuertos, abiertos, -1, Seed)
    elif cerrados!=500:
        puertos=arrayPortsGen(puertoInicial, puertoFinal, intervaloPuertos, -1, cerrados, Seed)
    else:
        puertos=randomPortsGen(puertoInicial, puertoFinal, intervaloPuertos, Seed)


    attack=udpFloodAttack(IPservidor, IPsrcList, PortSrc, puertos,  tInicial, tInicial+duracion, numPaquetesAEnviar, Seed, interResp)
    print('Paquetes de ataque creados exitosamente')
    ins = PacketInserter()
    operation = ins.withPackets(attack)\
                .withInputDir("input/")\
                .withPcapInput(nombrePktIni)\
                .withOutputDir("output/")\
                .withPcapOutput(nombrePktFin)\
                .insert()
    if operation:
        print("Paquetes insertados exitosamente")
    ############################################################################


main()
