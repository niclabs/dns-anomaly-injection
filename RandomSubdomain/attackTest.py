import unittest
from randomSubdomain import *

class attackTest(unittest.TestCase):
    def setUp(self):
        self.src_ip = "8.8.8.8"
        self.serv = "200.7.4.7"
        self.dom = "hola.cl"
        self.dom_ip = genIp()
        self.snd_ip = genIp()
        self.d = 20
        self.c = 300
        self.ti = 10
        self.src_port = 31456
        self.packets = randomSubAttack(self.src_ip, self.serv, self.dom, self.dom_ip, self.snd_ip, self.d, self.c, self.ti, self.src_port)
        self.tuples = self.c * self.d
        self.npackets = self.tuples * 2

    def test_attack_number_generated_packets(self):
        self.assertEqual(len(self.packets), self.tuples, "Not right number of tuples")
        n_packets = 0
        for t in self.packets:
            for p in t:
                n_packets += 1
        self.assertEqual(n_packets, self.npackets, "Not right number of packets")

    def test_attack_time(self):
        ti = self.packets[0][0].time
        tf = self.packets[len(self.packets) - 1][1].time
        self.assertTrue(abs(ti - self.ti) < 1)
        self.assertTrue(abs(tf - self.ti - self.d) < 1)

if __name__ == '__main__':
    unittest.main()
