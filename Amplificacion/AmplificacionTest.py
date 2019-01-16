import unittest
from amplificacion import *

class requestBuilderTest(unittest.TestCase):
    def setUp(self):
        self.target_ip = "8.8.8.8"
        self.serv_ip = "200.7.4.7"
        self.src_port = 31175
        self.q_name = "hola.cl"
        self.ti = 10
        self.request = amplificationBuilder(self.target_ip, self.serv_ip, self.src_port, self.q_name, self.ti)


    def test_DNS_layer(self):
        self.assertEqual(self.request[DNS].qr, 0, "Is not a request")
        self.assertEqual(str(self.request[DNSQR].qname), "b'" + self.q_name + "'", "Wrong asked domain")
        self.assertEqual(self.request[DNSRROPT].rclass, 4096, "EDNS0 extension failed")

    def test_UDP_layer(self):
        self.assertEqual(self.request[UDP].sport, self.src_port, "Wrong source port")
        self.assertEqual(self.request[UDP].dport, 53, "Wrong destination port")

    def test_IP_layer(self):
        self.assertEqual(self.request[IP].proto, 17, "IP protocol isn't 17")
        self.assertEqual(self.request[IP].src, self.target_ip, "Wrong source ip")
        self.assertEqual(self.request[IP].dst, self.serv_ip, "Wrong destination ip")

    def test_time(self):
        self.assertEqual(self.request.time, self.ti, "Wrong arrival time")

class responseTest(unittest.TestCase):
    def setUp(self):
        self.target_ip = "8.8.8.8"
        self.serv_ip = "200.7.4.7"
        self.src_port = 31175
        self.q_name = "hola.cl"
        self.ti = 10
        self.dt = 0.0001868
        self.request = amplificationBuilder(self.target_ip, self.serv_ip, self.src_port, self.q_name, self.ti)
        self.response = amplificationResponse(self.request, self.dt)

    def test_DNS_layer(self):
        self.assertEqual(self.response[DNS].id, self.request[DNS].id, "Wrong response DNS id")
        self.assertEqual(self.response[DNS].qr, 1, "Isn't a response")
        self.assertEqual(self.response[DNSQR].qname, self.request[DNSQR].qname, "Wrong asked domain")

    def test_UDP_layer(self):
        self.assertEqual(self.response[UDP].sport, 53, "Wrong response source port")
        self.assertEqual(self.response[UDP].dport, self.src_port, "Wrong response destination port")

    def test_IP_layer(self):
        self.assertEqual(self.response[IP].proto, 17, "Wrong response ip protocol")
        self.assertEqual(self.response[IP].src, self.serv_ip, "Wrong response source ip")
        self.assertEqual(self.response[IP].dst, self.target_ip, "Wrong response destination ip")

    def test_general(self):
        self.assertTrue(len(self.response) > 3000, "Small response")
        self.assertEqual(self.response.time, self.ti + self.dt, "Wrong response arrival time")

if __name__ == '__main__':
    unittest.main()
