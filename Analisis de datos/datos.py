import csv
import numpy as np

tiempos= []
with open('tcp.csv', newline='') as csvfile:
    reader = csv.reader(csvfile, delimiter=" ")
    i = 0
    for row in reader:
        tiempos.append(float(row[0]))
print(np.mean(tiempos))
print(np.std(tiempos))
