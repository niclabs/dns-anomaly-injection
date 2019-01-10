import argparse
from PackagesCreator import*
import sys
sys.path.append("..")


############### Main program ###############
def main():
    ###### Valores por defecto ######
    nombrePktFin='PortScanningAttack'
    dirPktFin='output/'
    dirPktIni='input/'
    nombrePktIni=''
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
    #################################


    parser = argparse.ArgumentParser()
    parser.add_argument("-v", "--verbose", help="Mostrar información de depuración", action="store_true")
    parser.add_argument("-f", "--file", help="Nombre de archivo a procesar")
    args = parser.parse_args()

    if args.verbose:
    print "depuración activada!!!"

    if args.file:
        print "El nombre de archivo a procesar es: ", args.file

    if len(puertos)==0:
        puertos=portsGen(0, 1023, 1, [], [], 2, Seed)
    #Assertions for given values
    checkValues(nombrePktFin,nombrePktIni, IPsrc, PortSrc, Seed, puertos, duracion, autoritativo, numPaquetesAEnviar, interResp)
    "-sTCP"
        attack=PackagesCreator(IPsrc, puertos, tInicial, tInicial+duracion, 1, numPaquetesAEnviar, Seed)

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
