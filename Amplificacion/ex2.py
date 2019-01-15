from scapy.all import *
import numpy as np

#----------Delay time-----------
paquetes = rdpcap("/home/niclabs/Downloads/lol.pcap")
tiempos = []
for i in range(1, 999):
    tiempos.append(paquetes[i+1].time - paquetes[i].time)

print(np.mean(tiempos))
#0.00427404912058
print(np.std(tiempos))
#0.00807278328296

#tiempo promedio javi 0.006673997294210002
