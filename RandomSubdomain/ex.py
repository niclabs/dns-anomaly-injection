from scapy.all import *
import string
from os import urandom
from randomSubdomain import *
import time
from randFloats import *
import random
import sys
import argparse
#---------------------#
#Archivo de prueba
#---------------------#
#Ejemplo:
#DoS
#python3 mainDoSRandomSubdomain.py -servtol 30 -sf lol.pcap -df new.pcap -sp /home/niclabs/Downloads/ -dp /home/niclabs/Downloads/ -srcip 8.8.8.8 -srv 2.7.4.7 -target hola.cl -ext 3 -psec 10 -ti 0 -sport 33865
#DDoS
#
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

def main3():
    print(genIp())
    arg1= "/home/niclabs/Downloads/"
    arg2= "lol.pcap"
    try:
        f = arg2.split(".")
        assert(len(f) == 2)
        assert(f[1] == "pcap")
    except:
        raise Exception("Wrong output file extension")
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-hi", "--hola", help = "print",type= int)
    args = parser.parse_args()
    print(args.hola)

if __name__ == '__main__':
    main()
