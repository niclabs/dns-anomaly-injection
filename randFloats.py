import random as r
import string

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


""" @Javi801
 Gives an array with letters or letter plus numbers, with the length given. The
 content can be random if you enter the parameter aleatorio=1.

 Param: aleatorio -> (boolean) True if the content must be random, false if not
        contador -> (int) index where start to cut letters and numbers to add at
                    final array
        largo -> (int) length of the array
        solo_letras -> (boolean) True if the content must be only letter, false
                       if it can be numbers as well
        Seed -> (float) seed for randomize

 Return: inter -> (float) interval calculated
"""
def randomString(aleatorio, contador, largo, solo_letras, Seed):
    r.seed(Seed)
    letras=string.ascii_letters
    todo=string.ascii_letters+string.digits
    if aleatorio and solo_letras:
        return ''.join(r.choice(letras) for i in range(largo))
    if aleatorio:
        return ''.join(r.choice(todo) for i in range(largo))
    if solo_letras:
        contador=contador%len(letras)
        final=letras[contador:]
        if len(final)<largo:
            m=int((largo-len(final))/len(letras))
            final+=(letras*m)
            final+=letras[:largo-len(final)]
        final=final[:largo]
        return final
    contador=contador%len(todo)
    final=todo[contador:]
    if len(final)<largo:
        m=int((largo-len(final))/len(todo))
        final+=(todo*m)
        final+=todo[:largo-len(final)]
    final=final[:largo]
    return final
