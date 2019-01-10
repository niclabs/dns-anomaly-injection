from scapy.all import *
from amplificacion import *
from randFloats import *
#---------------------#
#Archivo de prueba
#---------------------#
def main():
  #paquetes = rdpcap("/home/niclabs/Downloads/lol.pcap")
  inter = genInter(20, 0, 2, 3)
  print(inter)
  p0 = sniff(offline = "/home/niclabs/Downloads/lol.pcap", count = 1)

  t0 = p0[0].time
  ip = '8.8.8.8'
  serv = '200.7.4.7'
  srcport = 33865 #Cualquier puerto grande
  q_name = 'hola.thepacketgeek.com'

  packets = []
  time_p = 10
  p = amplificationBuilder(ip, serv, srcport, q_name, time_p)
  a = answerAmplification(p, 0.001)
  packets.append(p)
  packets.append(a)
  wrpcap("file.pcap", packets)

if __name__ == '__main__':
  main()
