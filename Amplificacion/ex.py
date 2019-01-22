from scapy.all import *
from amplificacion import *
from randFloats import *
from random import gauss
import os
import argparse
import socket
import sys
import gzip
#---------------------#
#Archivo de prueba
#---------------------#
#Ejemplo
#DoS amplified response
#python3 mainAmplification.py -servtol 35 -sf lol.pcap -df new.pcap -sp /home/niclabs/Downloads/ -dp /home/niclabs/Downloads/ -srv 2.7.4.7 -target 8.8.8.8 -sport 33865 -ext 3 -psec 10 -ti 0 -dom hola.cl -rtype
#DoS regular response
#python3 mainAmplification.py -servtol 35 -sf lol.pcap -df new.pcap -sp /home/niclabs/Downloads/ -dp /home/niclabs/Downloads/ -srv 2.7.4.7 -target 8.8.8.8 -sport 33865 -ext 3 -psec 10 -ti 0 -dom hola.cl -domip 3.3.3.3 -sndip 4.4.4.4
#DDoS amplified response
#python3 mainAmplification.py -servtol 50 -sf lol.pcap -df new.pcap -sp /home/niclabs/Downloads/ -dp /home/niclabs/Downloads/ -srv 2.7.4.7 -target 8.8.8.8 -sport 33865 -ext 3 -psec 10 -ti 0 -dom hola.cl -rtype -nbot 30
#DDoS regular response
#python3 mainAmplification.py -servtol 35 -sf lol.pcap -df new.pcap -sp /home/niclabs/Downloads/ -dp /home/niclabs/Downloads/ -srv 2.7.4.7 -target 8.8.8.8 -sport 33865 -ext 3 -psec 10 -ti 0 -dom hola.cl -domip 3.3.3.3 -sndip 4.4.4.4 -nbot 30

def main():
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

  #new_packages = amplificationAttack(serv, ip, srcport, duracion, c, ti, dt, q_name)

def main2():
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
