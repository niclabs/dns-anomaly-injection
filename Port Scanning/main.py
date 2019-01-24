import argparse
from PacketCreator import *
import sys
sys.path.append("..")
from PacketInserter import *
from PortsGenerator import *


def main():
    ########################### Valores por defecto ###########################
    Seed=time.time
    attack=[]
    domsFile='ultimos-dominios-1m.txt'
    ###########################################################################
    ###################### Manejo de valores por consola ######################
    parser = argparse.ArgumentParser(description='Port Scanning attack simulator')
    parser.add_argument("-ff", "--final_file", help="Sufijo para el nombre del archivo donde guardar el ataque", default='PortScanningAttack')
    parser.add_argument("file", help="Nombre del archivo a procesar, ejemplo: ej.pcap")
    parser.add_argument("-tcp", "--tcp_server_attack", help="Ataque Port Scan tipo TCP SYN al servidor", action="store_true")
    parser.add_argument("-udp", "--udp_server_attack", help="Ataque Port Scan tipo UDP SYN al servidor", action="store_true")
    parser.add_argument("-dom", "--domain_attack", help="Ataque Port Scan tipo UDP SYN al servidor", action="store_true")
    parser.add_argument("-ddos","--ddos_type", help="Extender el ataque a tipo distribuido", action="store_true")
    parser.add_argument("-tz","--total_of_zombies", help="Cantidad de computadores en la botnet para el ataque DDoS (d: 15000)", type=int, default=255)
    parser.add_argument("-d", "--duration", help="Duracion del ataque (d: 60s)", type=float, default=60)
    parser.add_argument("-n", "--num_packages", help="Total de paquetes por segundo a enviar (d: 500)", type=int, default=500)
    parser.add_argument("-ir", "--int_resp", help="Intervalo de respuesta  inicial", type=float, default=-1)
    parser.add_argument("-st", "--server_tolerance", help='Cantidad maxima de paquetes por unidad de tiempo que acepta el servidor (d: 42 por centecima de seg)', type=int, default=42)
    parser.add_argument("-ut", "--time_unit", help='Fraccion de segundo con la cual se mide la capacidad del servidor (d: centecima de segundo)', type=float, default=0.01)
    parser.add_argument("-s", "--seed", help="Semilla para aleatorizar datos (d: computer time)", type=float)
    parser.add_argument("-ip", "--ip_src", help="Direccion IP de origen (d: 200.27.161.26)", default='200.27.161.26')
    parser.add_argument("-sip","--server_ip", help="Direccion IP del servidor atacado (d: 200.7.4.7)", default='200.7.4.7')
    parser.add_argument("-ps", "--sport", help="Puerto de origen (d: 1280)", type=int, default=1280)
    parser.add_argument("-pi", "--iport", help="Puerto menor a atacar (d: 0)", type=int, default=0)
    parser.add_argument("-pf", "--fport", help="Puerto mayor a atacar (d: 1023)", type=int, default=1023)
    parser.add_argument("-inp", "--inter_port", help="Intervarlo entre un puerto y otro (d: 1)", type=int, default=1)
    parser.add_argument("-op", "--open_port", help="Total de puertos abiertos (d: aleatorio)", type=int)
    parser.add_argument("-cp", "--closed_port", help="Total de puertos cerrados (d: aleatorio)", type=int)
    parser.add_argument("-opl", "--open_port_list", help="Lista de puertos abiertos, ejemplo:1 2 3 (d: [])")
    parser.add_argument("-cpl", "--closed_port_list", help="Lista de puertos cerrados, ejemplo:1 2 3 (d: [])")
    parser.add_argument("-alr", "--activate_limit_rate", help="Activar el limite de respuestas ICMP por segundo (activar para simular servidor con linux o solaris)", action="store_true")
    parser.add_argument("-lr", "--limit_rate", help="Limite de respuestas ICMP por segundo (d: 2)", type=int, default=2)
    args = parser.parse_args()

    #################### Manejo de los nombres de archivos ####################
    nombrePktFin=args.final_file
    if nombrePktFin[-5:]=='.pcap':
        nombrePktFin==nombrePktFin[-5:]
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
    numPaquetesAEnviar=int((args.num_packages)*duracion)
    interResp=args.int_resp
    IPservidor=args.server_ip
    IPsrc=args.ip_src
    totalInfectados=args.total_of_zombies
    PortSrc=args.sport
    tolerancia=args.server_tolerance
    uTiempo=args.time_unit
    ###################### Limite para la unidad de tiempo #####################
    if uTiempo>1:
        print('Dado el algoritmo de insersicion, no se permite utilizar un valor menor a 1 segundo')
        tolerancia=tolerancia/uTiempo
        uTiempo=1
    ############################################################################
    #################### Verificacion de valores ingresados ####################
    try:
        assert(len(nombrePktFin)>0 and len(nombrePktIni)>0)
    except:
        raise Exception('Los nombres de archivo no pueden ser vacio')
    try:
        assert('.pcap' in nombrePktIni)
    except:
        raise Exception('Se debe incluir el formato de archivo en el nombre del archivo a abrir')
    try:
        assert(duracion>0)
    except:
        raise Exception('La duracion del ataque debe ser mayor a 0')
    try:
        assert(PortSrc<=65535)
        assert(PortSrc>=0)
    except:
        raise Exception("El puerto de origen debe estar entre 0 y 65535")
    try:
        assert(numPaquetesAEnviar>0)
    except:
        raise Exception("El numero de paquetes por segundo a enviar debe ser mayor a 0")
    try:
        assert(interResp>0 or interResp==-1)
    except:
        raise Exception("El intervalo de respuesta debe ser mayor a 0")
    try:
        assert(len(IPsrc)>=0)
    except:
        raise Exception("La direccion IP no puede ser vacia")
    try:
        assert(totalInfectados>1)
    except:
        raise Exception('La cantidad de computadores zombies debe ser mayor a 1')

    ############################################################################
    ####################### Creacion de puertos a atacar #######################
    if args.udp_server_attack or args.tcp_server_attack:

        puertoInicial=args.iport
        puertoFinal=args.fport
        intervaloPuertos=args.inter_port

    #################### Verificacion de valores ingresados ####################
        try:
            assert(puertoInicial<=65536)
            assert(puertoInicial>=0)
            assert(puertoInicial<=65536)
            assert(puertoInicial>=0)
        except:
            raise Exception("Los puertos deben estar entre 0 y 65535")
        try:
            assert(puertoInicial<=puertoFinal)
        except:
            raise Exception('El puerto menor a atacar debe ser menor que el puerto mayor a atacar')
        try:
            assert(intervaloPuertos>0)
        except:
            raise Exception('El intervalo entre un puerto y otro debe ser mayor a 0')
    ############################################################################
        if args.open_port or args.closed_port:
            if args.open_port:
                print("\nAl ingresar el total de puertos abiertos, el total de puertos cerrados no puede ser modificado")
                abiertos=args.open_port
                puertos=arrayPortsGen(puertoInicial, puertoFinal, intervaloPuertos, abiertos, -1, Seed)
            elif args.closed_port:
                print("\nAl ingresar el total de puertos abiertos, el total de puertos cerrados no puede ser modificado")
                cerrados=args.closed_port
                puertos=arrayPortsGen(puertoInicial, puertoFinal, intervaloPuertos, -1, cerrados, Seed)
        elif args.open_port_list and args.closed_port_list:
            abiertos=string2numList(args.open_port_list, ' ')
            cerrados=string2numList(args.closed_port_list, ' ')
            puertos=[abiertos, cerrados]
        elif args.open_port_list or args.closed_port_list:
            if args.open_port_list:
                abiertos=string2numList(args.open_port_list, ' ')
                puertos=arrayPortsGen(puertoInicial, puertoFinal, intervaloPuertos, abiertos, [], Seed)
            if args.closed_port_list:
                cerrados=string2numList(args.closed_port_list, ' ')
                puertos=arrayPortsGen(puertoInicial, puertoFinal, intervaloPuertos, [], cerrados, Seed)
        else:
            puertos=randomPortsGen(puertoInicial, puertoFinal, intervaloPuertos, Seed)
    ############################################################################

        if args.udp_server_attack:
            if args.activate_limit_rate:
                print('Limite de respuestas ICMP por segundo activado')
            if args.ddos_type:
                nombrePktFin+='_UDP_DDoS_attack.pcap'
                attack=UDP_DDoS_attack(totalInfectados, IPservidor, puertos, tInicial, tInicial+duracion, numPaquetesAEnviar, Seed, interResp, args.activate_limit_rate, args.limit_rate)
            else:
                nombrePktFin+='_UDP_attack.pcap'
                attack=UDP_attack(IPservidor, IPsrc, PortSrc, puertos, tInicial, tInicial+duracion, numPaquetesAEnviar, Seed, interResp, args.activate_limit_rate, args.limit_rate)
        if args.tcp_server_attack:
            if args.ddos_type:
                nombrePktFin+='_TCP_DDoS_attack.pcap'
                attack=TCP_DDoS_attack(totalInfectados, IPservidor, puertos, tInicial, tInicial+duracion, numPaquetesAEnviar, Seed, interResp)
            else:
                nombrePktFin+='_TCP_attack.pcap'
                attack=TCP_attack(IPservidor, IPsrc, PortSrc, puertos, tInicial, tInicial+duracion, numPaquetesAEnviar, Seed, interResp)
    elif args.domain_attack:
        if args.ddos_type:
            nombrePktFin+='_Domain_DDoS_attack.pcap'
            attack=Domain_DDoS_attack(totalInfectados, IPservidor, tInicial, tInicial+duracion, numPaquetesAEnviar, Seed, interResp)
        else:
            nombrePktFin+='_Domain_attack.pcap'
            attack=Domain_attack(IPservidor, IPsrc, PortSrc, tInicial, tInicial+duracion, numPaquetesAEnviar, Seed, interResp)
    else:
        print('Debe seleccionar un tipo de ataque, utilice el comando --help o -h para ver las opciones')
        return
    print('Paquetes de ataque creados exitosamente')
    ins = PacketInserter()
    operation = ins.withPackets(attack)\
                .withInputDir("input/")\
                .withPcapInput(nombrePktIni)\
                .withOutputDir("output/")\
                .withPcapOutput(nombrePktFin)\
                .withServerIp(IPservidor)\
                .withTimestamp(uTiempo)\
                .withServerTolerance(tolerancia)\
                .insert()
    if operation:
        print("Paquetes insertados exitosamente")
    ############################################################################

""" @Javi801
 Gives an array of ints with a given string, transforming the string into a int list

 Params: string -> (str) string to transform
         separador -> (str) string to use as separator between each number

 Return: final -> (list(int)) list of ints in the inicial string
"""
def string2numList(string, separador):
    strList=s.split(separador)
    final=[]
    for i in range(len(strList)):
        if strList[i]=='':
            continue
        num=int(strList[i])
        final+=[num]
    return final

main()
