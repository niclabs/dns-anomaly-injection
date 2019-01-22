from mainRandomSubdomain import *
import unittest

class mainTest(unittest.TestCase):
    def setUp(self):
        self.target_dom = "hola.cl"
        self.server_ip = "2.7.4.7"
        self.domain_ip = genIp()
        self.server_dom_ip = genIp()
        self.ti = 12
        self.ext = 10
        self.c = 50
        self.n_bot = 30
        self.packets1 = main(self.target_dom, self.server_ip, self.domain_ip, self.server_dom_ip, self.ti, self.ext, self.c, self.n_bot)
        self.packets2 = main(self.target_dom, self.server_ip, self.domain_ip, self.server_dom_ip, self.ti, self.ext, self.c, 1)

    def test_number_generated_packets(self):
        n1 = 0
        n2 = 0
        for t in self.packets1:
            self.assertEqual(len(t), 2, "Len of tuples must be 2")
            n1 += 2
        for t in self.packets2:
            self.assertEqual(len(t), 2, "Len of tuples must be 2")
            n2 += 2
        self.assertEqual(n1, self.c * self.n_bot * self.ext* 2, "Wrong amount of generated packets")
        self.assertEqual(n2, self.c * self.ext * 2, "Wrong amount of generated packets")

    def test_attack_structure(self):
        for t in self.packets1:
            p0 = t[0]
            p1 = t[1]
            self.assertEqual(p0[DNS].qr, 0, "Structure must be (request, response)")
            self.assertEqual(p1[DNS].qr, 1, "Structure must be (request, response)")

    def test_attack_time(self):
        ti = self.packets1[0][0].time
        tf = self.packets1[len(self.packets1) - 1][0].time
        self.assertTrue(abs(ti - self.ti) <= 1, "Wrong initial time")
        self.assertTrue(self.ti < ti, "Wrong initial time")
        self.assertTrue(abs(tf - self.ti - self.ext) <= 1, "Wrong last packet arrival time")
        self.assertTrue(tf < self.ti + self.ext, "Wrong last packet arrival time")
        for t in self.packets1:
            p0 = t[0]
            self.assertTrue(p0.time >= self.ti, "Packet out of time range")
            self.assertTrue(p0.time <= self.ti + self.ext, "Packet out of time range")

    def test_attack_packet_structure(self):
        for t in self.packets1:
            req = t[0]
            res = t[1]

            self.assertEqual(res[DNS].id, req[DNS].id, "Wrong response DNS id")
            self.assertEqual(res[DNSQR].qname, req[DNSQR].qname, "Wrong asked domain")

            self.assertEqual(res[UDP].sport, req[UDP].dport, "Wrong response source port")
            self.assertEqual(res[UDP].dport, req[UDP].sport, "Wrong response destination port")

            self.assertEqual(res[IP].proto, 17, "Wrong response protocol")
            self.assertEqual(req[IP].dst, self.server_ip, "Wrong request destination ip")
            self.assertEqual(res[IP].src, req[IP].dst, "Wrong response source ip")
            self.assertEqual(res[IP].dst, req[IP].src, "Wrong response destination ip")

if __name__ == '__main__':
    unittest.main()
