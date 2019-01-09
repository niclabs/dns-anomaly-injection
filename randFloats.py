import random as r

### Author @Javi801
# Gives an array with "cantidad" of random floats, between Tmin and Tmax, using
# a given seed for randomize numbers. It will gives one number per (Tmax/cantidad).
# Param: Seed -> (int) seed for randomize
#       Tmin -> (float) minimun number
#       Tmax -> (float) maximal number
#       cantidad -> (int) total of number required
# Return: an array of float numbers
###
def gen(Seed, Tmin, Tmax, cantidad):
    Tmin=Tmin*1.0
    Tmax=Tmax*1.0
    r.seed(Seed)
    inter=intervalo(Tmin, Tmax, cantidad)
    intervaloInicial=Tmin
    intervaloFinal=inter
    final=[]
    for i in range(cantidad):
        num=r.uniform(intervaloInicial,intervaloFinal)
        final+=[num]
        intervaloInicial=intervaloFinal
        intervaloFinal+=inter
    return final


### Author @Javi801
# Calcule the interval between Tmin and Tmax, consider "cantidad" of intervals
# Param: Tmin -> (float) minimun number
#       Tmax -> (float) maximal number
#       cantidad -> (int) total of number required
# Return: inter -> (float) interval calculated
###
def intervalo(Tmin, Tmax, cantidad):
    Tmin=Tmin*1.0
    Tmax=Tmax*1.0
    inter=(Tmax-Tmin)/cantidad
    return inter


### Author @Javi801
# Gives an array with "cantidad" of random floats, between Tmin and Tmax, using
# a given seed for randomize numbers. The interval between each package is a
# random interval picked between InterMin and InterMax.
#
# Notice that if minimun interval multiplied by "cantidad" and added to minimun
# time is more than maximal time ((InterMin*cantidad)+Tmin>Tmax), then minimun
# interval will be calculated with intervalo() function
#
# Param: Seed -> (int) seed for randomize
#       Tmin -> (float) minimun number
#       Tmax -> (float) maximal number
#       cantidad -> (int) total of number required
#       InterMin -> (float) minimum interval
#       InterMax -> (float) maximal interval
# Return: final -> an array with "cantidad" of floats numbers
###
def genIntervaloAleatorio(Seed, Tmin, Tmax, cantidad, InterMin, InterMax):
    Tmin=Tmin*1.0
    Tmax=Tmax*1.0
    if (InterMin*cantidad)+Tmin>Tmax:
        InterMin=intervalo(Tmin, Tmax, cantidad)
    if InterMin>InterMax:
        InterMin=InterMax
    InterMax=InterMax*1.0
    InterMin=InterMin*1.0
    r.seed(Seed)
    intervaloInicial=Tmin
    intervaloFinal=((r.random()*(InterMax-InterMin))+InterMin*1)+Tmin
    final=[]
    for i in range(cantidad): #Falta asegurar que no se pase de Tmax antes de terminar este for
        num=r.uniform(intervaloInicial,intervaloFinal)
        final+=[num]
        intervaloInicial=intervaloFinal
        intervaloFinal+=(r.random()*(InterMax-InterMin))+InterMin
    return final
