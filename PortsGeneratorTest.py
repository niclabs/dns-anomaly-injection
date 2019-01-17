from PortsGenerator import *
import unittest

class PortsGeneratorTest(unittest.TestCase):

    def test_randomPortsGen(self):
        self.assertEqual(randomPortsGen(0,1,1,3),[[],[0,1]])
        prueba=randomPortsGen(0,50,2,3)
        self.assertEqual(len(prueba), 2, 'error en el largo del array\nScript "PortsGenerator", funcion "randomPortsGen"')
        self.assertEqual(len(prueba[0])+len(prueba[1]), 26, 'error en el largo del array\nScript "PortsGenerator", funcion "randomPortsGen"')

        self.assertTrue((2 in prueba[0] or 2 in prueba[1]), 'error en el contenido del array\nScript "PortsGenerator", funcion "randomPortsGen"')
        self.assertFalse(31 in prueba[0] or 31 in prueba[1], 'error en el contenido del array\nScript "PortsGenerator", funcion "randomPortsGen"')
        self.assertFalse(60 in prueba[0] or 60 in prueba[1], 'error en el contenido del array\nScript "PortsGenerator", funcion "randomPortsGen"')

    def test_intPortsGen(self):
        pruebaAbiertos=intPortsGen(0,50,2,50,-1,5)
        self.assertEqual(len(pruebaAbiertos), 2, 'error en el largo del array\nScript "PortsGenerator", funcion "intPortsGen"')
        self.assertEqual(len(pruebaAbiertos[0])+len(pruebaAbiertos[1]), 26, 'error en el largo del array\nScript "PortsGenerator", funcion "intPortsGen"')

        self.assertTrue((2 in pruebaAbiertos[0] or 2 in pruebaAbiertos[1]), 'error en el contenido del array\nScript "PortsGenerator", funcion "intPortsGen"')
        self.assertFalse(31 in pruebaAbiertos[0] or 31 in pruebaAbiertos[1], 'error en el contenido del array\nScript "PortsGenerator", funcion "intPortsGen"')
        self.assertFalse(60 in pruebaAbiertos[0] or 60 in pruebaAbiertos[1], 'error en el contenido del array\nScript "PortsGenerator", funcion "intPortsGen"')

        self.assertEqual(len(pruebaAbiertos[1]), 0, 'error; no deberian haber puertos cerrados\nScript "PortsGenerator", funcion "intPortsGen"')
        self.assertEqual(len(pruebaAbiertos[0]), 26, 'error en la cantidad de puertos abiertos\nScript "PortsGenerator", funcion "intPortsGen"')

        self.assertEqual(intPortsGen(0,5,2,50,-1,5), [[4, 2, 0], []])

        pruebaCerrados=intPortsGen(1023,1170,3,-1,30,5)
        self.assertEqual(len(pruebaCerrados), 2, 'error en el largo del array\nScript "PortsGenerator", funcion "intPortsGen"')
        self.assertEqual(len(pruebaCerrados[0])+len(pruebaCerrados[1]), len(list(range(1023,1171,3))), 'error en el largo del array\nScript "PortsGenerator", funcion "intPortsGen"')

        self.assertTrue(1023 in pruebaCerrados[0] or 1023 in pruebaCerrados[1], 'error en el contenido del array\nScript "PortsGenerator", funcion "intPortsGen"')
        self.assertFalse(1022 in pruebaCerrados[0] or 1022 in pruebaCerrados[1], 'error en el contenido del array\nScript "PortsGenerator", funcion "intPortsGen"')
        self.assertFalse(6000 in pruebaCerrados[0] or 6000 in pruebaCerrados[1], 'error en el contenido del array\nScript "PortsGenerator", funcion "intPortsGen"')

        self.assertEqual(len(pruebaCerrados[1]), 30, 'error en la cantidad de puertos cerrados\nScript "PortsGenerator", funcion "intPortsGen"')
        self.assertEqual(len(pruebaCerrados[0]), 20, 'error en la cantidad de puertos abiertos\nScript "PortsGenerator", funcion "intPortsGen"')

        pruebaAbiertosCerrados=intPortsGen(100,500,2,23,17,6)
        self.assertEqual(len(pruebaAbiertosCerrados), 2, 'error en el largo del array\nScript "PortsGenerator", funcion "intPortsGen"')

        self.assertEqual(len(pruebaAbiertosCerrados[1]), 17, 'error en la cantidad de puertos cerrados\nScript "PortsGenerator", funcion "intPortsGen"')
        self.assertEqual(len(pruebaAbiertosCerrados[0]), 23, 'error en la cantidad de puertos abiertos\nScript "PortsGenerator", funcion "intPortsGen"')


    def test_arrayPortsGen(self):
        prueba=arrayPortsGen(50, 1023, 13, list(range(50,350,10)), [], 4)
        self.assertEqual(len(prueba), 2, 'error en el largo del array\nScript "PortsGenerator", funcion "arrayPortsGen"')

        self.assertTrue((50 in prueba[0] or 50 in prueba[1]), 'error en el contenido del array\nScript "PortsGenerator", funcion "arrayPortsGen"')
        self.assertFalse(31 in prueba[0] or 31 in prueba[1], 'error en el contenido del array\nScript "PortsGenerator", funcion "arrayPortsGen"')
        self.assertFalse(1060 in prueba[0] or 1060 in prueba[1], 'error en el contenido del array\nScript "PortsGenerator", funcion "arrayPortsGen"')

        self.assertEqual(len(prueba[1]), 72, 'error en la cantidad de puertos cerrados\nScript "PortsGenerator", funcion "arrayPortsGen"')
        self.assertEqual(len(prueba[0]), len(list(range(50,350,10))), 'error en la cantidad de puertos abiertos\nScript "PortsGenerator", funcion "arrayPortsGen"')

        self.assertEqual(arrayPortsGen(750, 1023, 13, [763,802,841,906,984,1023], [], 4), [[763, 802, 841, 906, 984, 1023], [750, 776, 789, 815, 828, 854, 867, 880, 893, 919, 932, 945, 958, 971, 997, 1010]])


    def test_randomSourcePorts(self):
        prueba=randomSourcePorts(400, 5)
        self.assertEqual(len(prueba), 400, 'error en el largo del array\nScript "PortsGenerator", funcion "randomSourcePorts"')

        pequenio=randomSourcePorts(20, 5)
        for i in range(20):
            self.assertTrue(pequenio[i]<=49151 and pequenio[i]>=1024, 'error en los valores de los puertos\nScript "PortsGenerator", funcion "randomSourcePorts"')


if __name__ == '__main__':
    unittest.main()
