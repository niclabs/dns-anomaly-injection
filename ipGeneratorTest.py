from ipGenerator import *
import unittest

class PortsGeneratorTest(unittest.TestCase):

    def test_randomIP_cero(self):
        pruebaCero=randomIP(0,50)
        self.assertEqual(len(pruebaCero), 1, 'error en el largo del array\nScript "ipGenerator", funcion "randomIP"')
        self.assertEqual(pruebaCero, [''], 'error en el contenido del array\nScript "ipGenerator", funcion "randomPortsGen"')

    def test_randomIP_Pref24(self):
        pruebaPref24=randomIP(20,4)
        self.assertEqual(len(pruebaPref24), 20, 'error en el largo del array\nScript "ipGenerator", funcion "randomIP"')
        partes24=pruebaPref24[0].split('.')
        prefijo24=partes24[0]+'.'+partes24[1]+'.'+partes24[2]+'.'
        for i in range(20):
            self.assertTrue(prefijo24 in pruebaPref24[i], 'error en el contenido del array\nScript "ipGenerator", funcion "randomPortsGen"')

    def test_randomIP_Pref16(self):
        pruebaPref16=randomIP(257,4)
        self.assertEqual(len(pruebaPref16), 257, 'error en el largo del array\nScript "ipGenerator", funcion "randomIP"')
        partes16=pruebaPref16[0].split('.')
        prefijo16=partes16[0]+'.'+partes16[1]+'.'
        for i in range(257):
            self.assertTrue(prefijo16 in pruebaPref16[i], 'error en el contenido del array\nScript "ipGenerator", funcion "randomPortsGen"')


if __name__ == '__main__':
    unittest.main()
