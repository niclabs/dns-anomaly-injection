import unittest
from amplificacion import *

class attackTest(unittest.TestCase):
    def setUp(self):
        self.serv_ip = "200.7.4.7"
        self.target_ip = "8.8.8.8"
        self.src_port = 31175
        self.d = 20
        self.c = 100
        self.ti = 10
        self.q_name = "hola.cl"
        self.packets = amplificationAttack(self.serv_ip, self.target_ip, self.src_port, self.d, self.c, self.ti, self.q_name, 1)

    def test_attack_number_generated_packets(self):
        self.assertEqual(len(self.packets), self.d * self.c, "Wrong number of generated tuples")
        n = 0
        n_req = 0
        n_res = 0
        cond = True
        for t in self.packets:
            for p in t:
                n += 1
                if(p[DNS].qr == 0):
                    n_req += 1
                else:
                    n_res += 1
        self.assertEqual(n, self.d * self.c * 2, "Wrong number of generated packets")
        self.assertEqual(n_req, self.c * self.d, "Wrong number of generated requests")
        self.assertEqual(n_res, self.c * self.d, "Wrong number of generated responses")

    def test_attack_structure(self):
        for t in self.packets:
            self.assertEqual(len(t), 2, "Len of tuples must be 2")
            p0 = t[0]
            p1 = t[1]
            self.assertEqual(p0[DNS].qr, 0, "Structure must be (request, response)")
            self.assertEqual(p1[DNS].qr, 1, "Structure must be (request, response)")

    def test_attack_time(self):
        ti = self.packets[0][0].time
        tf = self.packets[len(self.packets) - 1][0].time
        self.assertTrue(abs(ti - self.ti) <= 1, "Wrong initial time")
        self.assertTrue(self.ti < ti, "Wrong initial time")
        self.assertTrue(abs(tf - self.ti - self.d) <= 1, "Wrong last packet arrival time")
        self.assertTrue(tf < self.ti + self.d, "Wrong last packet arrival time")
        for t in self.packets:
            req = t[0]
            self.assertTrue(req.time >= self.ti,"Packet out of time range")
            self.assertTrue(req.time <= self.ti + self.d,"Packet out of time range")

    def test_attack_packet_structure(self):
        for t in self.packets:
            req = t[0]
            res = t[1]
            self.assertTrue(len(res) > 3000, "Small packet size")
            self.assertTrue(len(res)/len(req) > 37, "Small amplification factor")

            self.assertEqual(res[DNS].id, req[DNS].id, "Wrong response DNS id")
            self.assertEqual(str(req[DNSQR].qname), "b'" + self.q_name + "'")
            self.assertEqual(res[DNSQR].qname, req[DNSQR].qname, "Wrong asked domain")

            self.assertEqual(res[UDP].sport, req[UDP].dport, "Wrong response source port")
            self.assertEqual(res[UDP].dport, req[UDP].sport, "Wrong response destination port")

            self.assertEqual(res[IP].proto, 17, "Wrong response protocol")
            self.assertEqual(req[IP].src, self.target_ip, "Wrong request source ip")
            self.assertEqual(req[IP].dst, self.serv_ip, "Wrong request destination ip")
            self.assertEqual(res[IP].src, req[IP].dst, "Wrong response source ip")
            self.assertEqual(res[IP].dst, req[IP].src, "Wrong response destination ip")

if __name__ == '__main__':
    unittest.main()
