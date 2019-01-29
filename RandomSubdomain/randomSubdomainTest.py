import unittest
import numpy as np
from randomSubdomain import *
import sys
sys.path.append("..")
from ipGenerator import checkValidIp

class randSubTest(unittest.TestCase):
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

class randomSubBuilderTest(unittest.TestCase):
    def setUp(self):
        self.dom = "domain.cl"
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

class regularResponseTest(unittest.TestCase):
    def setUp(self):
        self.dom = "domain.cl"
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

class genPacketsTest(unittest.TestCase):
    def setUp(self):
        self.dom = "domain.cl"
        self.src_ip = "8.8.8.8"
        self.dst_ip = "200.7.4.7"
        self.src_port = 33835
        self.t = 20
        self.seed = 5
        self.dom_ip = genIp()
        self.dom_srv_ip = genIp()
        self.dt = 0.0001868
        self.tuple = genPackets([self.dom, self.src_ip, self.dst_ip, self.src_port, self.t, self.seed, self.dom_ip, self.dom_srv_ip, self.dt])

    def test_len(self):
        self.assertEqual(len(self.tuple), 2, "Len must be 2")

    def test_structure(self):
        req = self.tuple[0]
        res = self.tuple[1]
        self.assertEqual(req[DNS].qr, 0, "Structure must be (request, response)")
        self.assertEqual(res[DNS].qr, 1, "Structure must be (request, response)")

    def test_DNS_layer(self):
        req = self.tuple[0]
        res = self.tuple[1]
        self.assertEqual(res[DNS].id, req[DNS].id, "Wrong response DNS id")
        self.assertEqual(res[DNS].qd, req[DNS].qd, "Is answering a different question")
        self.assertEqual(res[DNS].rcode, 0, "DNS rcode must be 0")

    def test_UDP_layer(self):
        req = self.tuple[0]
        res = self.tuple[1]
        self.assertEqual(res[UDP].sport, 53, "Wrong response source port")
        self.assertEqual(res[UDP].dport, req[UDP].sport, "Wrong response destination port")

    def test_IP_layer(self):
        req = self.tuple[0]
        res = self.tuple[1]
        self.assertEqual(res[IP].proto, 17, "Wrong response ip protocol")
        self.assertEqual(res[IP].src, req[IP].dst, "Wrong response source ip")
        self.assertEqual(res[IP].dst, req[IP].src, "Wrong response destination ip")

    def test_time(self):
        res = self.tuple[1]
        self.assertEqual(res.time, self.t + self.dt, "Wrong response arrival time")

class argsBuilderTest(unittest.TestCase):
    def setUp(self):
        self.target_dom = "domain.cl"
        self.serv = "200.7.4.7"
        self.domain_ip = "100.100.100.100"
        self.server_dom_ip = "200.200.200.200"
        self.ti = 10
        self.d = 10
        self.packets = 30
        self.n_bot = 3
        self.arg_ddos = argsBuilder(self.target_dom, self.serv, self.domain_ip, self.server_dom_ip, self.ti, self.d, self.packets, self.n_bot)
        self.arg_dos = argsBuilder(self.target_dom, self.serv, self.domain_ip, self.server_dom_ip, self.ti, self.d, self.packets, 1)

    def test_number_generated_arguments(self):
        self.assertEqual(len(self.arg_ddos), self.d * self.packets * self.n_bot, "Wrong number of created arguments")
        self.assertEqual(len(self.arg_dos), self.d * self.packets, "Wrong number of created arguments")

    def test_arguments_structure(self):
        for arg in self.arg_dos:
            self.assertEqual(arg[0], self.target_dom, "Wrong target domain")
            self.assertEqual(len(arg), 9, "Wrong len of each argument")
            self.assertTrue(checkValidIp(arg[1]), "Invalid source ip")
            self.assertEqual(arg[2], self.serv, "Invalid destination ip")
            self.assertTrue(arg[3] >= 0, "Source port can't be less than 0")
            self.assertTrue(arg[3] <= 65535, "Source port can't be greater than 65535")
            self.assertTrue(arg[4] >= 0, "Request arrival time can't be less than 0")
            self.assertTrue(arg[4] >= self.ti, "Wrong request arrival time")
            self.assertTrue(arg[4] <= self.ti + self.d, "Wrong request arrival time")
            self.assertEqual(arg[6], self.domain_ip, "Wrong domain ip")
            self.assertEqual(arg[7], self.server_dom_ip, "Wrong domain server ip")
            self.assertTrue(arg[8] >= 0, "Response delay time can't be less than 0")

        ip = []
        for arg in self.arg_ddos:
            self.assertEqual(arg[0], self.target_dom, "Wrong target domain")
            self.assertEqual(len(arg), 9, "Wrong len of each argument")
            self.assertTrue(checkValidIp(arg[1]), "Invalid source ip")
            if not arg[1] in ip:
                ip.append(arg[1])
            self.assertEqual(arg[2], self.serv, "Invalid destination ip")
            self.assertTrue(arg[3] >= 0, "Source port can't be less than 0")
            self.assertTrue(arg[3] <= 65535, "Source port can't be greater than 65535")
            self.assertTrue(arg[4] >= 0, "Request arrival time can't be less than 0")
            self.assertTrue(arg[4] >= self.ti, "Wrong request arrival time")
            self.assertTrue(arg[4] <= self.ti + self.d, "Wrong request arrival time")
            self.assertEqual(arg[6], self.domain_ip, "Wrong domain ip")
            self.assertEqual(arg[7], self.server_dom_ip, "Wrong domain server ip")
            self.assertTrue(arg[8] >= 0, "Response delay time can't be less than 0")
        self.assertEqual(len(ip), self.n_bot, "Wrong number of computers in the botnet for the DDoS attack")

class genMultiplePacketsTest(unittest.TestCase):
    def setUp(self):
        self.target_dom = "domain.cl"
        self.serv = "200.7.4.7"
        self.domain_ip = "100.100.100.100"
        self.server_dom_ip = "200.200.200.200"
        self.ti = 10
        self.d = 10
        self.n_packets = 30
        self.n_bot = 10
        self.arg_ddos = argsBuilder(self.target_dom, self.serv, self.domain_ip, self.server_dom_ip, self.ti, self.d, self.n_packets, self.n_bot)
        self.arg_dos = argsBuilder(self.target_dom, self.serv, self.domain_ip, self.server_dom_ip, self.ti, self.d, self.n_packets, 1)
        self.dos_packets = []
        for arg in self.arg_dos:
            tuple = genPackets(arg)
            self.dos_packets.append(tuple)

        self.ddos_packets = []
        for arg in self.arg_ddos:
            tuple = genPackets(arg)
            self.ddos_packets.append(tuple)

    def test_number_generated_packets(self):
        n_dos = 0
        n_ddos = 0
        for t in self.dos_packets:
            self.assertEqual(len(t), 2, "Len of tuples must be 2")
            n_dos += 2
        for t in self.ddos_packets:
            self.assertEqual(len(t), 2, "Len of tuples must be 2")
            n_ddos += 2
        self.assertEqual(n_dos, self.d * self.n_packets * 2, "Wrong number of generated packets, dos attack")
        self.assertEqual(n_ddos, self.d * self.n_packets * self.n_bot * 2, "Wrong number of generated packets, ddos attack")

    def test_attack_structure(self):
        for t in self.dos_packets:
            req = t[0]
            res = t[1]
            self.assertEqual(req[DNS].qr, 0, "Structure must be (request, response), error: DoS attack")
            self.assertEqual(res[DNS].qr, 1, "Structure must be (request, response), error: DoS attack")
        for t in self.ddos_packets:
            req = t[0]
            res= t[1]
            self.assertEqual(req[DNS].qr, 0, "Structure must be (request, response), error: DDoS attack")
            self.assertEqual(res[DNS].qr, 1, "Structure must be (request, response), error: DDoS attack")

    def test_attack_time(self):
        #DoS
        for t in self.dos_packets:
            req = t[0]
            self.assertTrue(req.time >= self.ti, "Request arrival time out of range, error: DoS attack")
            self.assertTrue(req.time <= self.ti + self.d, "Request arrival time out of range, error: DoS attack")
        #DDoS
        for t in self.ddos_packets:
            req = t[0]
            self.assertTrue(req.time >= self.ti, "Request arrival time out of range, error: DDoS attack")
            self.assertTrue(req.time <= self.ti + self.d, "Request arrival time out of range, error: DDoS attack")

    def test_packets_per_second(self):
        #DoS
        n_packets_dos = np.zeros(self.d)
        for t in self.dos_packets:
            req = t[0]
            n = int(req.time - self.ti)
            n_packets_dos[n] += 1
        for c in n_packets_dos:
            self.assertEqual(c, self.n_packets, "Wrong number of packets per second, error: DoS attack")

        #DDoS
        n_packets_ddos = np.zeros(self.d)
        for t in self.ddos_packets:
            req = t[0]
            n = int(req.time - self.ti)
            n_packets_ddos[n] += 1
        for c in n_packets_ddos:
            self.assertEqual(c, self.n_packets * self.n_bot, "Wrong number of packets per second, error: DDoS attack")

    def test_attack_packet_structure(self):
        #DoS
        for t in self.dos_packets:
            req = t[0]
            res = t[1]

            self.assertEqual(res[DNS].id, req[DNS].id, "Wrong response DNS id")
            self.assertEqual(res[DNSQR].qname, req[DNSQR].qname, "Wrong asked domain")

            self.assertEqual(res[UDP].sport, req[UDP].dport, "Wrong response source port")
            self.assertEqual(res[UDP].dport, req[UDP].sport, "Wrong response destination port")

            self.assertEqual(res[IP].proto, 17, "Wrong response protocol")
            self.assertEqual(req[IP].dst, self.serv, "Wrong request destination ip")
            self.assertEqual(res[IP].src, req[IP].dst, "Wrong response source ip")
            self.assertEqual(res[IP].dst, req[IP].src, "Wrong response destination ip")
        #DDoS
        for t in self.ddos_packets:
            req = t[0]
            res = t[1]

            self.assertEqual(res[DNS].id, req[DNS].id, "Wrong response DNS id")
            self.assertEqual(res[DNSQR].qname, req[DNSQR].qname, "Wrong asked domain")

            self.assertEqual(res[UDP].sport, req[UDP].dport, "Wrong response source port")
            self.assertEqual(res[UDP].dport, req[UDP].sport, "Wrong response destination port")

            self.assertEqual(res[IP].proto, 17, "Wrong response protocol")
            self.assertEqual(req[IP].dst, self.serv, "Wrong request destination ip")
            self.assertEqual(res[IP].src, req[IP].dst, "Wrong response source ip")
            self.assertEqual(res[IP].dst, req[IP].src, "Wrong response destination ip")

if __name__ == '__main__':
    unittest.main()
