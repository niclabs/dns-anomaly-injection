from ipGenerator import *
import unittest

class PortsGeneratorTest(unittest.TestCase):

    def test_randomIP_cero(self):
        pruebaCero=randomIP(0,50,1)
        self.assertEqual(len(pruebaCero), 1, '\nerror en el largo del array\nScript "ipGenerator", funcion "randomIP"')
        self.assertEqual(pruebaCero, [''], '\nerror en el contenido del array\nScript "ipGenerator", funcion "randomIP"')

    def test_randomIP_Pref24(self):
        pruebaPref24=randomIP(20,4,1)
        self.assertEqual(len(pruebaPref24), 20, '\nerror en el largo del array\nScript "ipGenerator", funcion "randomIP"')
        partes24=pruebaPref24[0].split('.')
        prefijo24=partes24[0]+'.'+partes24[1]+'.'+partes24[2]+'.'
        for i in range(20):
            self.assertTrue(prefijo24 in pruebaPref24[i], '\nerror en el contenido del array\nScript "ipGenerator", funcion "randomIP"')

    def test_randomIP_Pref16(self):
        pruebaPref16=randomIP(257,4,1)
        self.assertEqual(len(pruebaPref16), 257, '\nerror en el largo del array\nScript "ipGenerator", funcion "randomIP"')
        partes16=pruebaPref16[0].split('.')
        prefijo16=partes16[0]+'.'+partes16[1]+'.'
        for i in range(257):
            self.assertTrue(prefijo16 in pruebaPref16[i], '\nerror en el contenido del array\nScript "ipGenerator", funcion "randomIP"')

    def test_randomIP_withoutPref(self):
        prueba=randomIP(10,4,0)
        self.assertEqual(len(pruebaPref24), 10, '\nerror en el largo del array\nScript "ipGenerator", funcion "randomIP"')

if __name__ == '__main__':
    unittest.main()
