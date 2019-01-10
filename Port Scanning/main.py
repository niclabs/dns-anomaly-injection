import argparse
from PackagesCreator import*

############### Main program ###############
def main():
    nombrePktFin=''
    IPsrc="200.27.161,26" PortSrc, puertoInicial, puertoFinal, intervaloPuertos, tiempoInicial, tiempoFinal, autoritativo, numPaquetesAEnviar, Seed):

############################################

def TCPinyeccion(nombrePktIni, nombrePktFin):
    nombrePktIni='input/'+nombrePktIni
    paquete= sniff(offline=nombrePktIni, count=1)
    t=paquete[0].time
    virus=PacketList(genIniFin("200.27.161,26", 0, 1023, 1, t, t+10, 1, 500, 473))
    datosReales=rdpcap(nombrePktIni)
    attack=datosReales+virus
    wrpcap('output/'+nombrePktFin+'.pcap',attack)

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
