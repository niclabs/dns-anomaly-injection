from scapy.all import *
import sys
from os import urandom
from random import randint
from randFloats import *

def amplificationBuilder(ip_src,ip_dest, src_port, q_name, t):
    """
    Constructor de paquetes con las características necesarias para ser una request para el ataque de amplificación
    Tiempo del paquete no es seteado aquí
    Retorna un paquete
    ip_src: ip origen (target)
    ip_dest: ip destino
    src_port: Puerto origen (puerto destino = 53)
    q_name: Dominio por el que se pregunta
    t: tiempo de llegada del paquete (segundos)
    """
    id_IP = int(RandShort())
    id_DNS = int(RandShort())
    p = Ether()/IP(dst=ip_dest, src=ip_src, id = id_IP)/UDP(sport=src_port)/DNS(rd=0, id= id_DNS, qd=DNSQR(qname=str(q_name), qtype = "ALL"),ar=DNSRROPT(rclass=4096))
    p.time = t
    return p

def answerAmplification(p, t):
    """
    Responde al paquete p, la respuesta está amplificada
    p: Request
    t: Tiempo de demora de la respuesta
    Entrega un paquete de respuesta donde contiene un additional record del tipo TXT
    que contiene un string muy grande que también está en la seccion answers de DNS y la extension EDNS0
    """
    id_IP = int(RandShort())

    #Crear additional records
    n = randint(1500, 1950) #Número de bytes del string r_data
    r_data = urandom(n)

    ar1 = DNSRR(type='TXT', rclass=0x8001, rdata = r_data)
    ext = DNSRROPT(rclass=4096) #Extensión EDNS0
    ans = Ether()/IP(dst = p[IP].src, src = p[IP].dst, id = id_IP)/UDP(dport = p[UDP].sport)/DNS(id = p[DNS].id, qr = 1, rd = 0, cd = 1, qd = p[DNS].qd)

    #Agregar additional records
    ans[DNS].ar = ar1/ext

    #Agregar answers
    ans[DNS].an = ar1

    ans.time = p.time + t #Cambiar tiempo paquete respuesta
    return ans

def genInter(Seed, tmin, tmax, cantidad):
    """
    Gives an array with "cantidad" of floats per second between Tmin and Tmax.
    Param: Seed -> (int) seed for randomize
           tmin -> (float) minimun number
           tmax -> (float) maximal number
           cantidad -> (int) number of queries per second
    """
    inter = []
    t0 = tmin
    t1 = tmin + 1
    for i in range(tmax - tmin):
        sub_i = gen(Seed, t0, t1, cantidad)
        inter.extend(sub_i)
        t0 += 1
        t1 += 1
    return inter

def main():
    """
    sys.argv[1]: Archivo pcap
    sys.argv[2]: ip target
    sys.argv[3]: Cantidad de tiempo (segundos)
    sys.argv[4]: Cantidad de requests por segundo
    sys.argv[5]: Fecha de inicio del ataque TODO: ver en que se medirá (Con respecto al paquete)
    sys.argv[6]: Tiempo de demora de la respuesta para cada request
    """

    ip = str(sys.argv[2])
    duracion = int(sys.argv[3])
    c = int(sys.argv[4])
    inicio = sys.argv[5]
    dt = sys.argv[6]

    p0 = sniff(offline = str(sys.argv[1]), count = 1)
    t0 = p0[0].time
    ti = t0 + inicio
    tf = ti + duracion
    serv = '200.7.4.7'
    srcport = 33865 #Cualquier puerto grande

    new_packages = []
    seed = 20 #Semilla para intervalo aleatorio
