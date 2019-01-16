import random

""" Author @Javi801
 Gives an array of two ports arrays; first the open ones and, then, the closed.

 Param: puertoInicial -> (int) first port
        puertoFinal -> (int) last port
        intervaloPuertos -> (int) interval between each port
        Seed -> (float) seed for randomize

 Return: list(int) -> list of two port list
"""
def randomPortsGen(puertoInicial, puertoFinal, intervaloPuertos, Seed):
    random.seed(Seed)
    puertos=list(range(puertoInicial,puertoFinal+1,intervaloPuertos))
    abiertosList=[]
    cerradosList=[]
    for i in range(len(puertos)):
        var = random.randint(0,1)
        if var:
            abiertosList+=[puertos[i]]
            continue
        cerradosList+=[puertos[i]]
    return [abiertosList,cerradosList]


""" Author @Javi801
 Gives a list with two ports list; first the open ones and, then, the closed.
 This with a given number of open ports or closed ports

 Params: puertoInicial -> (int) first port
         puertoFinal -> (int) last port
         intervaloPuertos -> (int) interval between each port
         abiertos -> (int) number of open ports, it can be -1
         cerrados -> (int) number of closed ports, it can be -1
         puertos -> (list(int)) ports list
         Seed -> (float) seed for randomize

 Return: list(int) -> list of two port list
"""
def intPortsGen(puertoInicial, puertoFinal, intervaloPuertos, abiertos, cerrados, Seed):
    random.seed(Seed)
    puertos=list(range(puertoInicial,puertoFinal+1,intervaloPuertos))
    open=[]
    closed=[]
    if abiertos<0:
        for i in range(cerrados):
            if 0==len(puertos):
                break
            var = random.randint(0,len(puertos)-1)
            ins=puertos.pop(var)
            closed+=[ins]
        return [puertos, closed]
    if cerrados<0:
        for i in range(abiertos):
            if 0==len(puertos):
                break
            var = random.randint(0,len(puertos)-1)
            ins=puertos.pop(var)
            open+=[ins]
        return [open, puertos]
    if len(puertos)<(abiertos+cerrados):
        puertos=list(range(0,65535))
    for i in range(abiertos+cerrados):
        var = random.randint(0,len(puertos)-1)
        ins=puertos.pop(var)
        num=random.randint(0,abiertos+cerrados)
        prob=num<abiertos
        if len(closed)==cerrados or prob:
            open+=[ins]
        elif len(open)==abiertos or not(prob):
            closed+=[ins]
        elif len(open)==0 and len(closed)==0:
            return [open, closed]
    return [open, closed]


""" Author @Javi801
 Gives a list with two ports list; first the open ones and, then, the closed.
 Between open and closed is expected an empty list and one with content, in
 another case this function does not make sense.

 Params: puertoInicial -> (int) first port
         puertoFinal -> (int) last port
         intervaloPuertos -> (int) interval between each port
         abiertos -> (list(int)) open ports list, it can be []
         cerrados -> (list(int)) closed ports list, it can be []
         Seed -> (float) seed for randomize

 Return: list(int) -> list of two port list
"""
def arrayPortsGen(puertoInicial, puertoFinal, intervaloPuertos, abiertos, cerrados, Seed):
    random.seed(Seed)
    puertos=list(range(puertoInicial,puertoFinal+1,intervaloPuertos))
    op=[]
    cl=[]
    if len(abiertos)==0: #Array con puertos cerrados, abiertos debe ser array vacio
        cl=cerrados
        for i in range(len(puertos)):
            if puertos[i] in cerrados:
                continue
            op+=[puertos[i]]
        return [op, cl]
    if len(cerrados)==0: #Array con puertos abiertos dado, cerrados debe ser array vacio
        op=abiertos
        for i in range(len(puertos)):
            if puertos[i] in abiertos:
                continue
            cl+=[puertos[i]]
        return [op, cl]

""" @Javi801
 Gives and array of valid ports, with a given numbers of ports. This array
 doesn't specify open or closed ports, and it could have repeated ports.

Params: total -> (int) total of ports
        Seed -> (float) seed for randomize

Return: list(int) -> port list
"""
def randomSourcePorts(total, Seed):
    random.seed(Seed)
    puertos=[]
    for i in range(total):
        port=random.randint(0,65536)
        puertos=[port]
    return puertos
