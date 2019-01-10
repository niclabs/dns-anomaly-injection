from scapy.all import *
from amplificacion import *
#---------------------#
#Archivo de prueba
#---------------------#
def main():
  #paquetes = rdpcap("/home/niclabs/Downloads/lol.pcap")
  p0 = sniff(offline = "/home/niclabs/Downloads/lol.pcap", count = 1)

  t0 = p0[0].time
  print(t0)
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
