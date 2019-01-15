from scapy.all import *
from amplificacion import *
from randFloats import *
from random import gauss
import os
import argparse
import socket
#---------------------#
#Archivo de prueba
#---------------------#
#Ejemplo
#python3 amplificacion.py lol.pcap new.pcap /home/niclabs/Downloads/ /home/niclabs/Downloads/ 2.7.4.7 8.8.8.8 33865 3 10 1 hola.cl
def main2():
  #paquetes = rdpcap("/home/niclabs/Downloads/lol.pcap")
  inter = genInter(20, 0, 2, 3)
  p0 = sniff(offline = "/home/niclabs/Downloads/lol.pcap", count = 1)

  ti = p0[0].time
  ip = '8.8.8.8'
  serv = '200.7.4.7'
  srcport = 33865 #Cualquier puerto grande
  q_name = 'hola.chao.cl'
  c = 10
  dt = 0.01
  duracion = 5

  new_packages = amplificationAttack(serv, ip, srcport, duracion, c, ti, dt, q_name)

def main():
    print(socket.gethostbyname(socket.gethostname()))
    arg1= "/home/niclabs/Downloads/"
    arg2= "lol.pcap"
    try:
        f = arg2.split(".")
        assert(f[1] == "pcap")
    except:
        raise Exception("Wrong output file extension")

if __name__ == '__main__':
    main()
