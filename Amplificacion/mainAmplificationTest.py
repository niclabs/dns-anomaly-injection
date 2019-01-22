import unittest
from mainAmplification import *

class mainAmplificationTest(unittest.TestCase):
    def setUp(self):
        self.serv_ip = "200.7.4.7"
        self.target_ip = "8.8.8.8"
        self.src_port = 31175
        self.ext = 10
        self.c = 40
        self.ti = 10
        self.q_name = "hola.cl"
        self.rtype1 = True
        self.rtype2 = False
        self.dom_ip = genIp()
        self.dom_srv_ip = genIp()
        self.nbotnets = 25
        self.amplified_DDoS_attack = mainDoS(self.serv_ip, self.target_ip, self.src_port, self.ext, self.c , self.nbotnets, self.ti, self.q_name, self.rtype1, self.dom_ip, self.dom_srv_ip)
        self.regular_DDoS_attack = mainDoS(self.serv_ip, self.target_ip, self.src_port, self.ext, self.c , self.nbotnets, self.ti, self.q_name, self.rtype2, self.dom_ip, self.dom_srv_ip)

    def test_amount_created_packets(self):
        n1 = 0
        for t in self.amplified_DDoS_attack:
            self.assertEqual(len(t), 2, "Len of tuples must be 2")
            n1 += 2
        self.assertEqual(len(self.amplified_DDoS_attack), self.c * self.nbotnets * self.ext, "Wrong amount of created tuples: amplified DDoS attack")
        self.assertEqual(n1, self.c * self.nbotnets * self.ext * 2, "Wrong amount of created packets: amplified DDoS attack")
        n2 = 0
        for t in self.regular_DDoS_attack:
            self.assertEqual(len(t), 2, "Len of tuples must be 2")
            n2 += 2
        self.assertEqual(len(self.regular_DDoS_attack), self.c * self.nbotnets * self.ext, "Wrong amount of created tuples: DDoS attack, regular response")
        self.assertEqual(n2, self.c * self.nbotnets * self.ext * 2, "Wrong amount of created packets: DDoS attack, regular response")

    def test_amplified_response_size(self):
        for t in self.amplified_DDoS_attack:
            res = t[1]
            self.assertTrue(len(res) > 3000)

    def test_non_amplified_response_size(self):
        for t in self.regular_DDoS_attack:
            res = t[1]
            self.assertTrue(len(res) < 500)

if __name__ == '__main__':
    unittest.main()
