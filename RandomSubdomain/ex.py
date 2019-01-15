from scapy.all import *
import string
from os import urandom
from randomSubdomain import *
import time
from randFloats import *
import random
#---------------------#
#Archivo de prueba
#---------------------#
#Ejemplo:
#python3 randomSubdomain.py lol.pcap new.pcap /home/niclabs/Downloads/ /home/niclabs/Downloads/ 2.7.4.7 hola.cl 200.6.96.47 3 10 0 33865
def main2():
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

def main():
    print(genIp())
    arg1= "/home/niclabs/Downloads/"
    arg2= "lol.pcap"
    try:
        f = arg2.split(".")
        assert(len(f) == 2)
        assert(f[1] == "pcap")
    except:
        raise Exception("Wrong output file extension")

if __name__ == '__main__':
    main()
