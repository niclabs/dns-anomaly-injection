import random as r

""" Author @Javi801
 Gives an array with "cantidad" of random floats, between Tmin and Tmax, using
 a given seed for randomize numbers. It will gives one number per (Tmax/cantidad).

 Param: Seed -> (float) seed for randomize
       Tmin -> (float) minimun number
       Tmax -> (float) maximal number
       cantidad -> (int) total of number required
       
 Return: an array of float numbers
"""
def gen(Seed, Tmin, Tmax, cantidad):
    Tmin=Tmin*1.0
    Tmax=Tmax*1.0
    r.seed(Seed)
    inter=intervalo(Tmin, Tmax, cantidad)
    intervaloInicial=Tmin
    intervaloFinal=inter+Tmin
    final=[]
    for i in range(cantidad):
        num=r.uniform(intervaloInicial,intervaloFinal)
        final+=[num]
        intervaloInicial+=inter
        intervaloFinal+=inter
    return final


""" Author @Javi801
 Calcule the interval between Tmin and Tmax, consider "cantidad" of intervals

 Param: Tmin -> (float) minimun number
       Tmax -> (float) maximal number
       cantidad -> (int) total of number required

 Return: inter -> (float) interval calculated
"""
def intervalo(Tmin, Tmax, cantidad):
    Tmin=Tmin*1.0
    Tmax=Tmax*1.0
    inter=(Tmax-Tmin)/cantidad
    return inter


"""
Gives an array with "cantidad" of floats per second between Tmin and Tmax.

Param: Seed -> (float) seed for randomize
       tmin -> (float) minimum number
       tmax -> (float) maximal number
       cantidad -> (int) number of queries per second

Note: tmax - tmin must be equals or greater than 1
"""
def genInter(Seed, tmin, tmax, cantidad):
    inter = []
    t0 = tmin
    t1 = tmin + 1
    for i in range(int(tmax - tmin)):
        sub_i = gen(Seed, t0, t1, cantidad)
        inter.extend(sub_i)
        t0 += 1
        t1 += 1
    return inter
