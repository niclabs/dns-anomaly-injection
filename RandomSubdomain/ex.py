from scapy.all import *
import string
from os import urandom
from randomSubdomain import *
import time
from randFloats import *
#---------------------#
#Archivo de prueba
#---------------------#
#Ejemplo:
#python3 randomSubdomain.py lol.pcap new.pcap /home/niclabs/Downloads/ /home/niclabs/Downloads/ 2.7.4.7 hola.cl 200.6.96.47 3 10 0 0.006 33865
def main():
    dom = 'chao.cl'
    serv = '2.7.4.7'
    ip_dom = '45.55.174.89'
    src_port = 33865
    dt = 0.01
    c = 10
    duracion = 5

    p0 = sniff(offline = "/home/niclabs/Downloads/lol.pcap", count = 1)
    t0 = p0[0].time
    new_packages = randomSubAttack(serv, dom, ip_dom, duracion, c, t0, dt, src_port)
    #wrpcap("file.pcap", new_packages)

if __name__ == '__main__':
    main()
