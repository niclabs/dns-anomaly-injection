from scapy.all import *
from amplificacion import *
from randFloats import *
#---------------------#
#Archivo de prueba
#---------------------#
def main():
  #paquetes = rdpcap("/home/niclabs/Downloads/lol.pcap")
  inter = genInter(20, 0, 2, 3)
  p0 = sniff(offline = "/home/niclabs/Downloads/lol.pcap", count = 1)

  t0 = p0[0].time
  ip = '8.8.8.8'
  serv = '200.7.4.7'
  srcport = 33865 #Cualquier puerto grande
  q_name = 'hola.chao.cl'
  c = 1
  dt = 0.1

  ti = t0
  tf = ti + 3

  new_packages = []
  seed = 20 #Semilla para intervalo aleatorio
  time = genInter(seed, ti, tf, c)
  for t in time:
      p = amplificationBuilder(ip, serv, srcport, q_name, t)
      a = answerAmplification(p, dt)
      new_packages.append(p)
      new_packages.append(a)
  wrpcap("file.pcap", new_packages)

if __name__ == '__main__':
  main()
