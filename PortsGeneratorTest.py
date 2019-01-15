from PortsGenerator import *
import unittest

class PortsGeneratorTest(unittest.TestCase):

    def test_randomPortsGen(self):
        self.assertEqual(randomPortsGen(0,1,1,3)==[[],[0,1]])
        prueba=randomPortsGen(0,50,2,3)
        self.assertEqual(len(prueba), 2, 'error en el largo del array\nScript "PortsGenerator", funcion "randomPortsGen"')
        self.assertEqual(len(prueba[0])+len(prueba[1]), 26, 'error en el largo del array\nScript "PortsGenerator", funcion "randomPortsGen"')

        self.assertTrue((2 in prueba[0] or 2 in prueba[1]), 'error en el contenido del array\nScript "PortsGenerator", funcion "randomPortsGen"')
        self.assertFalse(31 in prueba[0] or 31 in prueba[1], 'error en el contenido del array\nScript "PortsGenerator", funcion "randomPortsGen"')
        self.assertFalse(60 in prueba[0] or 60 in prueba[1], 'error en el contenido del array\nScript "PortsGenerator", funcion "randomPortsGen"')

    def test_intPortsGen(self):
        prueba=intPortsGen(0,50,2,50,-1,5)
        self.assertEqual(len(prueba), 2, 'error en el largo del array\nScript "PortsGenerator", funcion "intPortsGen"')
        self.assertEqual(len(prueba[0])+len(prueba[1]), 26, 'error en el largo del array\nScript "PortsGenerator", funcion "intPortsGen"')

        self.assertTrue((2 in prueba[0] or 2 in prueba[1]), 'error en el contenido del array\nScript "PortsGenerator", funcion "intPortsGen"')
        self.assertFalse(31 in prueba[0] or 31 in prueba[1], 'error en el contenido del array\nScript "PortsGenerator", funcion "intPortsGen"')
        self.assertFalse(60 in prueba[0] or 60 in prueba[1], 'error en el contenido del array\nScript "PortsGenerator", funcion "intPortsGen"')

        self.assertEqual(len(prueba[1]), 0, 'error; no deberian haber puertos cerrados\nScript "PortsGenerator", funcion "intPortsGen"')
        self.assertEqual(len(prueba[0]), 26, 'error; faltan puertos abiertos\nScript "PortsGenerator", funcion "intPortsGen"')

        self.assertEqual(intPortsGen(0,5,2,50,-1,5), [[4, 2, 0], []])

    def test_arrayPortsGen(self):
        prueba=arrayPortsGen(50, 1023, 13, list(range(50,350,10)), [], 4)
        self.assertEqual(len(prueba), 2, 'error en el largo del array\nScript "PortsGenerator", funcion "arrayPortsGen"')
        self.assertEqual(len(prueba[0]), len(list(range(50,350,10))), 'error en el largo del array \nScript "PortsGenerator", funcion "arrayPortsGen"')
        self.assertEqual(len(prueba[1]), 72, 'error en el largo del array\nScript "PortsGenerator", funcion "arrayPortsGen"')

        self.assertTrue((50 in prueba[0] or 50 in prueba[1]), 'error en el contenido del array\nScript "PortsGenerator", funcion "arrayPortsGen"')
        self.assertFalse(31 in prueba[0] or 31 in prueba[1], 'error en el contenido del array\nScript "PortsGenerator", funcion "arrayPortsGen"')
        self.assertFalse(1060 in prueba[0] or 1060 in prueba[1], 'error en el contenido del array\nScript "PortsGenerator", funcion "arrayPortsGen"')

        self.assertEqual(len(prueba[1]), 0, 'error; no deberian haber puertos cerrados\nScript "PortsGenerator", funcion "arrayPortsGen"')
        self.assertEqual(len(prueba[0]), 26, 'error; faltan puertos abiertos\nScript "PortsGenerator", funcion "arrayPortsGen"')

        self.assertEqual(intPortsGen(0,5,2,50,-1,5), [[4, 2, 0], []])

if __name__ == '__main__':
    unittest.main()
