import argparse
from udp_flood_attack import *
import sys
sys.path.append("..")
from PacketInserter import *
from PortsGenerator import *
from ipGenerator import *

############### Main program ###############
def main():
    ########### Valores por defecto ###########
    Seed=time.time
    attack=[]
    domsFile='ultimos-dominios-1m.txt'
    ###########################################
    ###### Manejo de valores por consola ######
    parser = argparse.ArgumentParser(description='Port Scanning attack simulator')
    parser.add_argument("-ff", "--final_file", help="Nombre del archivo donde guardar el ataque", default='UDPFloodAttack.pcap')
    parser.add_argument("-f", "--file", help="Nombre del archivo a procesar, ejemplo: ej.pcap")
    parser.add_argument("-tip", "--total_ips_src", help="Total de direcciones IP de origen (d: 30)", default=30, type=int)
    parser.add_argument("-ps", "--sport", help="Puerto de origen (d: 1280)", type=int, default=1280)
    parser.add_argument("-pi", "--iport", help="Puerto menor a atacar (d: 0)", type=int, default=0)
    parser.add_argument("-pf", "--fport", help="Puerto mayor a atacar (d: 1023)", type=int, default=1023)
    parser.add_argument("-inp", "--inter_port", help="Intervarlo entre un puerto y otro (d: 1)", type=int, default=1)
    parser.add_argument("-op", "--open_port", help="Total de puertos abiertos (d: 20)", type=int, default=20)
    parser.add_argument("-cp", "--closed_port", help="Total de puertos cerrados (d: 500)", type=int, default=500)
    parser.add_argument("-s", "--seed", help="Semilla para aleatorizar datos (d: computer time)", type=float)
    parser.add_argument("-d", "--duration", help="Duracion del ataque (d: 60s)", type=float, default=60)
    parser.add_argument("-n", "--num_packages", help="Total de paquetes a enviar (d: 5000)", type=int, default=5000)
    parser.add_argument("-ir", "--int_resp", help="Intervalo de respuesta inicial (d: 0.0001s)", type=float, default=0.0001)
    args = parser.parse_args()

    nombrePktFin=args.final_file
    if nombrePktFin[-5:]!='.pcap':
        nombrePktFin+='.pcap'
    nombrePktIni=args.file
    print("El nombre de archivo a procesar es: ", nombrePktIni)
    paquete= sniff(offline='input/'+nombrePktIni, count=1)
    tInicial=paquete[0].time
    if args.seed:
        Seed=args.seed
    duracion=args.duration
    numPaquetesAEnviar=args.num_packages
    interResp=args.int_resp
    PortSrc=args.sport
    totalIPs=args.total_ips_src
    IPsrcList=randomIP(totalIPs,Seed)
    puertoInicial=args.iport
    puertoFinal=args.fport
    intervaloPuertos=args.inter_port
    abiertos=args.open_port
    cerrados=args.closed_port
    ############## Assertions for values ##############
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
    ####################################################
    ########## Creacion de puertos a atacar ############
        if abiertos!=20:
            print("\nAl ingresar el total de puertos abiertos, el total de puertos cerrados no puede ser modificado")
            puertos=arrayPortsGen(puertoInicial, puertoFinal, intervaloPuertos, abiertos, -1, Seed)
        elif args.closed_port:
            print("\nAl ingresar el total de puertos abiertos, el total de puertos cerrados no puede ser modificado")

            puertos=arrayPortsGen(puertoInicial, puertoFinal, intervaloPuertos, -1, cerrados, Seed)
    else:
        puertos=randomPortsGen(puertoInicial, puertoFinal, intervaloPuertos, Seed)

    attack=udpFloodAttack(IPsrcList, PortSrc, puertos,  tInicial, tInicial+duracion, numPaquetesAEnviar, Seed, interResp)
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
############################################



main()
