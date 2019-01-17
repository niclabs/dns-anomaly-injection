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
        seed = 10
        tmin = 12
        tmax = 20
        c = 100
        prueba= genInter(seed, tmin, tmax, c)
        self.assertEqual(len(prueba), (tmax - tmin) * c, "Wrong amount of generated times")
        i = 0
        t0 = tmin
        t1 = tmin + 1
        for j in range(int(tmax - tmin)):
            sub_j = gen(seed, t0, t1, c)
            self.assertEqual(sub_j, prueba[i: i+c], "Wrong generated interval")
            i += c
            t0 += 1
            t1 += 1

if __name__ == '__main__':
    unittest.main()
