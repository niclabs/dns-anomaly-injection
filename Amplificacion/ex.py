from scapy.all import *
from amplificacion import *
#---------------------#
#Archivo de prueba
#---------------------#
def main():
  #file = rdpcap("blanco.1506993600.pcap")
  #En alguna página dice que rclass = 3000
  ip = '8.8.8.8'
  serv = '200.7.4.7'
  srcport = 33865 #Cualquier puerto grande
  #id_dns = int(RandShort())
  #id_ip = int(RandShort())
  q_name = 'hola.thepacketgeek.com'

  packets = []
  p = amplificationBuilder(ip, serv, srcport, q_name)
  #q = amplificationBuilder(ip, serv, srcport + 5, q_name)
  a = answerAmplification(p, 0)

  #new_a = Ether()/IP(dst = p[IP].src, src = p[IP].dst, id = int(RandShort()))/UDP(dport = p[UDP].sport)/DNS(id = p[DNS].id, qr = 1, cd = 1, rd = 0, qd = p[DNS].qd, ar=[DNSRR(), DNSRROPT(rclass=4096)])
  packets.append(p)
  packets.append(a)
  #packets.append(new_a)
  wrpcap("file.pcap", packets)

if __name__ == '__main__':
  main()
