import csv
import numpy as np

tiempos= []
with open('rcode3.csv', newline='') as csvfile:
    reader = csv.reader(csvfile, delimiter=" ")
    for row in reader:
        tiempos.append(float(row[0]))
print(np.mean(tiempos))
print(np.std(tiempos))
