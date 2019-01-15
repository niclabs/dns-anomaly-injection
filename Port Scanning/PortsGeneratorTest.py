from PortsGenerartor import *

def randomPortsGen_Check():
    assert(randomPortsGen(0,1,1,3)==[[],[0,1]])
    prueba=randomPortsGen(0,50,2,3)
    assert(len(prueba)==2, 'error en el largo del array')
    assert(len(prueba[0])+len(prueba[1])==26, 'error en el largo del array')
    assert((2 in prueba[0] or 2 in prueba[1]), 'error en el contenido del array')
    assert(not(31 in prueba[0] or 31 in prueba[1]), 'error en el contenido del array')
    assert(not(60 in prueba[0] or 60 in prueba[1]), 'error en el contenido del array')

def
