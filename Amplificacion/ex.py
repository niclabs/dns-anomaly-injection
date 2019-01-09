from scapy.all import *
from amplificacion import *
#---------------------#
#Archivo de prueba
#---------------------#
def main():
  paquetes = rdpcap("/home/niclabs/Downloads/lol.pcap")
  t0 = paquetes[0].time
  ip = '8.8.8.8'
  serv = '200.7.4.7'
  srcport = 33865 #Cualquier puerto grande
  q_name = 'hola.thepacketgeek.com'

  packets = []
  p = amplificationBuilder(ip, serv, srcport, q_name)
  a = answerAmplification(p, 0.001)
  packets.append(p)
  packets.append(a)
  #wrpcap("file.pcap", packets)

if __name__ == '__main__':
  main()
