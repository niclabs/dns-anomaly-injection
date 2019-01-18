import unittest
from randomSubdomain import *


class checkIpTest(unittest.TestCase):
    def test_checkip(self):
        self.assertTrue(checkValidIp("200.7.4.7"))
        self.assertFalse(checkValidIp("200.7.5"))
        self.assertFalse(checkValidIp("300.7.4.7"))
        self.assertFalse(checkValidIp("200,7,4,7"))
        self.assertFalse(checkValidIp(""))
        self.assertFalse(checkValidIp("200.4.2.3.123"))

class randSubdTest(unittest.TestCase):
    def setUp(self):
        self.seed =  10
        self.symbols = str(string.ascii_letters + string.digits)
        self.subdomain = randomSub(self.seed)

    def test_subdomain(self):
        random.seed(10)
        n = random.randint(10,30)
        ans =  "".join(random.sample(self.symbols, n))
        self.assertEqual(self.subdomain, ans, "Wrong random subdomain")

class genIpTest(unittest.TestCase):
    def setUp(self):
        self.ip = genIp()

    def test_valid_ip(self):
        values = self.ip.split(".")
        self.assertEqual(len(values), 4, "Invalid ip")
        self.assertTrue(int(values[0]) >= 0 and int(values[0])<=255, "Invalid ip")
        self.assertTrue(int(values[1]) >= 0 and int(values[1])<=255, "Invalid ip")
        self.assertTrue(int(values[2]) >= 0 and int(values[2])<=255, "Invalid ip")
        self.assertTrue(int(values[3]) >= 0 and int(values[3])<=255, "Invalid ip")

class requestBuilderTest(unittest.TestCase):
    def setUp(self):
        self.dom = "hola.cl"
        self.src_ip = "8.8.8.8"
        self.dst_ip = "200.7.4.7"
        self.src_port = 33835
        self.t = 20
        self.seed = 5
        self.request = randomSubBuilder(self.dom, self.src_ip, self.dst_ip, self.src_port, self.t, self.seed)

    def test_DNS_layer(self):
        self.assertEqual(self.request[DNS].qr, 0, "Is not a request")
        self.assertEqual(str(self.request[DNSQR].qname), "b'"+ randomSub(self.seed)+"."+self.dom+"'")

    def test_UDP_layer(self):
        self.assertEqual(self.request[UDP].sport, self.src_port, "Wrong source port")
        self.assertEqual(self.request[UDP].dport, 53, "Wrong destination port")

    def test_IP_layer(self):
        self.assertEqual(self.request[IP].proto, 17, "Wrong ip protocol")
        self.assertEqual(self.request[IP].src, self.src_ip, "Wrong source ip")
        self.assertEqual(self.request[IP].dst, self.dst_ip, "Wrong destination ip")

    def test_time(self):
        self.assertEqual(self.request.time, self.t)

class responseTest(unittest.TestCase):
    def setUp(self):
        self.dom = "hola.cl"
        self.dom_ip = genIp()
        self.dom_srv_ip = genIp()
        self.src_ip = "8.8.8.8"
        self.dst_ip = "200.7.4.7"
        self.src_port = 33835
        self.t = 20
        self.dt = 0.0001868
        self.seed = 5
        self.request = randomSubBuilder(self.dom, self.src_ip, self.dst_ip, self.src_port, self.t, self.seed)
        self.response = regularResponse(self.request, self.dom, self.dom_ip, self.dom_srv_ip, self.dt)

    def test_DNS_layer(self):
        self.assertEqual(self.response[DNS].id, self.request[DNS].id, "Wrong response DNS id")
        self.assertEqual(self.response[DNS].qr, 1, "Isn't a response")
        self.assertEqual(self.response[DNS].qd, self.request[DNS].qd, "Is answering a different question")
        self.assertEqual(self.response[DNS].rcode, 0, "DNS rcode must be 0")

    def test_UDP_layer(self):
        self.assertEqual(self.response[UDP].sport, 53, "Wrong response source port")
        self.assertEqual(self.response[UDP].dport, self.request[UDP].sport, "Wrong response destination port")

    def test_IP_layer(self):
        self.assertEqual(self.response[IP].proto, 17, "Wrong response ip protocol")
        self.assertEqual(self.response[IP].src, self.request[IP].dst, "Wrong response source ip")
        self.assertEqual(self.response[IP].dst, self.request[IP].src, "Wrong response destination ip")

    def test_time(self):
        self.assertEqual(self.response.time, self.t + self.dt, "Wrong response arrival time")


if __name__ == '__main__':
    unittest.main()
