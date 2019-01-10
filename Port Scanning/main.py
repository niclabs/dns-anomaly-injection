import argparse
from PackagesCreator import*
import sys
sys.path.append("..")


############### Main program ###############
def main():
    ########### Valores por defecto ###########
    nombrePktFin='PortScanningAttack.pcap'
    nombrePktIni='.pcap'
    paquete= sniff(offline=nombrePktIni, count=1)
    tInicial=paquete[0].time
    IPsrc="200.27.161,26"
    PortSrc=80
    Seed=time.time
    puertos=[]
    duracion=60
    autoritativo=1
    numPaquetesAEnviar=500
    interResp=0.006673997
    attack=[]
    ###########################################
    ###### Manejo de valores por consola ######
    parser = argparse.ArgumentParser()
    parser.add_argument("-ff", "--final_file", help="Mostrar información de depuración", action="store_true")
    parser.add_argument("-f", "--file", help="Nombre de archivo a procesar")
    parser.add_argument("-tcp", "--tcp_server", help="Ataque Port Scan tipo TCP SYN al servidor")
    parser.add_argument("-upd", "--udp_server", help="Ataque Port Scan tipo UDP SYN al servidor")
    parser.add_argument("-ip", "--ip_src", help="Direccion IP de origen (d: 200.27.161,26)")
    parser.add_argument("-ps", "--sport", help="Puerto de origen (d: 80)")
    parser.add_argument("-pi", "--iport", help="Puerto menor a atacar (d: 0)")
    parser.add_argument("-pf", "--fport", help="Puerto mayor a atacar (d: 1023)")
    parser.add_argument("-inp", "--inter_port", help="Intervarlo entre un puerto y otro (d: 1)")
    parser.add_argument("-op", "--open_port", help="Total de puertos abiertos (d: aleatorio)")
    parser.add_argument("-cp", "--closed_port", help="Total de puertos cerrados (d: aleatorio)")
    parser.add_argument("-opl", "--open_port_list", help="Lista de puertos abiertos (d: [])")
    parser.add_argument("-cpl", "--closed_port_list", help="Lista de puertos cerrados (d: [])")
    parser.add_argument("-s", "--seed", help="Semilla para aleatorizar datos (d: time)")
    parser.add_argument("-d", "--duration", help="Duracion del ataque (d: 60s)")
    parser.add_argument("-a", "--autoritative", help="Servidor autoritativo? y/n (d: y)")
    parser.add_argument("-n", "--num_packages", help="Total de paquetes a enviar (d: 5000)")
    parser.add_argument("-ir", "--int_resp", help="Intervalo de respuesta (d: 0.006673997s)")
    args = parser.parse_args()

    if args.final_file:
        nombrePktFin=args.final_file
    if args.file:
        print "El nombre de archivo a procesar es: ", args.file
        nombrePktIni=args.file
    if args.ip_src:
        IPsrc=args.ip_src


    if args.tcp_server:
        attack=PackagesCreator(IPsrc, puertos, tInicial, tInicial+duracion, autoritativo, numPaquetesAEnviar, Seed)

    #Assertions for given values
    checkValues(nombrePktFin,nombrePktIni, IPsrc, PortSrc, Seed, puertos, duracion, autoritativo, numPaquetesAEnviar, interResp)
    if len(puertos)==0:
        puertos=portsGen(0, 1023, 1, [], [], 2, Seed)

    ins.withPackets(pkts)\
        .withInputDir("input/")\
        .withPcapInput(nombrePktIni)\
        .withOutputDir("output/")\
        .withPcapOutput(nombrePktFin)\
        .insert()
############################################

def checkValues(nombrePktFin,nombrePktIni, IPsrc, PortSrc, Seed, puertos, duracion, autoritativo, numPaquetesAEnviar, interResp):
    try:
        assert(duracion>0)
    except:
        raise Exception("La duracion debe ser mayor a 0")
    try:
        assert(PortSrc>=0)
    except:
        raise Exception("El puerto de origen debe ser mayor a 0")
    try:
        assert(PortSrc<=65536)
    except:
        raise Exception("El puerto de origen debe ser menor a 65536")
    try:
        assert(autoritativo==1 or autoritativo==0)
    except:
        raise Exception("El valor para 'autoritativo' solo puede ser 0 o 1")
    try:
        assert(numPaquetesAEnviar>=0)
    except:
        raise Exception("El numero de paquetes a enviar debe ser positivo")

def TCPinyeccion(nombrePktFin):
    t=0

def UDPinyeccion(nombrePktIni, nombrePktFin):
    t=0

def inyeccionSort():
    t=0

def URLinyeccion():
    t=0

def actualizarDoms():
    url= "https://www.nic.cl/registry/Ultimos.do?t=1m&f=csv"
    print("Se actualizara la informacion desde " + url + "\nDesea actualizar la url? s/n")
    k='n'
    if k=='s':
        print("Ingrese la nueva direccion web:")
        url=0
    #descargar el archivo
