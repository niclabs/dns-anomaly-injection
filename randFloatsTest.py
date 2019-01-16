from randFloats import *
import unittest

class randFloatsTest(unittest.TestCase):

    def test_gen(self):
        prueba=gen(5,0,30,13)

        self.assertEqual(len(prueba), 13, 'error en el largo del array\nScript "randFloats", funcion "gen"')
        self.assertTrue(prueba[0]>=0, 'error en el valor minimo del array\nScript "randFloats", funcion "gen"')
        self.assertTrue(prueba[12]<=30, 'error en el valor maximo del array\nScript "randFloats", funcion "gen"')

        self.assertEqual(gen(5,0,17,5),[2.1178657626249864, 5.92207576348648, 9.503658122923369, 13.404330964841972, 16.115655154115764])


    def test_intervalo(self):
        prueba=intervalo(0, 50, 2)
        self.assertEqual(prueba, (50-0)/2, 'error en la formula para carlular intervalos\nScript "randFloats", funcion "intervalo"')


    def test_genInter(self):
        t=0


if __name__ == '__main__':
    unittest.main()
