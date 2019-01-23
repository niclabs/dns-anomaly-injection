from randFloats import *
import string
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

    def test_randomString_solo_letras(self):
        string_random=randomString(1, 0, 10, 1, 0)
        string_contador=randomString(0, 567, 12, 1, 0)
        letras=string.ascii_letters
        c=567%len(letras)

        self.assertEqual(len(string_random), 10, '\nerror en el largo del string\nScript "randFloats", funcion "randomString"')
        self.assertEqual(len(string_contador), 12, '\nerror en el largo del string\nScript "randFloats", funcion "randomString"')

        self.assertEqual(string_contador[0], letras[c], '\nerror en el contenido del string\nScript "randFloats", funcion "randomString"')
        for i in range(10):
            self.assertTrue(string_random[i] in letras, '\nerror en el contenido del string\nScript "randFloats", funcion "randomString"')

        for i in range(12):
            self.assertTrue(string_contador[i] in letras, '\nerror en el contenido del string\nScript "randFloats", funcion "randomString"')
            if i==0:
                continue
            k=letras.find(string_contador[i])-letras.find(string_contador[i-1])
            self.assertTrue(k==1 or k==-51,'\nerror en el contenido del string\nScript "randFloats", funcion "randomString"')


    def test_randomString_letras_numeros(self):
        string_nums_random=randomString(1, 0, 12, 0, 0)
        string_nums_contador=randomString(0, 24, 10, 0, 0)
        todo=string.ascii_letters+string.digits
        c=24%len(todo)

        self.assertEqual(len(string_nums_random), 12, '\nerror en el largo del string\nScript "randFloats", funcion "randomString"')
        self.assertEqual(len(string_nums_contador), 10, '\nerror en el largo del string\nScript "randFloats", funcion "randomString"')

        self.assertEqual(string_nums_contador[0], todo[c], '\nerror en el contenido del string\nScript "randFloats", funcion "randomString"')
        for i in range(12):
            self.assertTrue(string_nums_random[i] in todo, '\nerror en el contenido del string\nScript "randFloats", funcion "randomString"')

        for i in range(10):
            self.assertTrue(string_nums_random[i] in todo, '\nerror en el contenido del string\nScript "randFloats", funcion "randomString"')
            if i==0:
                continue
            k=todo.find(string_nums_contador[i])-todo.find(string_nums_contador[i-1])
            self.assertEqual(k,1,'\nerror en el contenido del string\nScript "randFloats", funcion "randomString"')



if __name__ == '__main__':
    unittest.main()
