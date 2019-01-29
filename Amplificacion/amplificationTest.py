import unittest
import numpy as np
from amplification import *

class amplificationBuilderTest(unittest.TestCase):
    def setUp(self):
        self.target_ip = "8.8.8.8"
        self.serv_ip = "200.7.4.7"
        self.src_port = 31175
        self.q_name = "domain.cl"
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
        self.q_name = "domain.cl"
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
        self.assertTrue(len(self.response)/len(self.request) > 37, "Small amplification factor")
        self.assertEqual(self.response.time, self.ti + self.dt, "Wrong response arrival time")

class genPacketsTest(unittest.TestCase):
    def setUp(self):
        self.target_ip = "8.8.8.8"
        self.serv = "200.7.4.7"
        self.sport = 33545
        self.dom = "domain.cl"
        self.t = 15.3
        self.dt = 0.14
        self.dom_ip = "100.100.100.100"
        self.srv_dom_ip = "200.200.200.200"
        self.amplified = True
        self.regular = False
        self.amplifiedTuple = genPackets([self.target_ip, self.serv, self.sport, self.dom, self.t, self.dt, self.dom_ip, self.srv_dom_ip, self.amplified])
        self.regularTuple = genPackets([self.target_ip, self.serv, self.sport, self.dom, self.t, self.dt, self.dom_ip, self.srv_dom_ip, self.regular])

    def test_len(self):
        self.assertEqual(len(self.amplifiedTuple), 2, "Wrong len of amplified tuple")
        self.assertEqual(len(self.regularTuple), 2, "Wrong len of regular tuple")

    def test_tuple_structure(self):
        amp_req = self.amplifiedTuple[0]
        amp_res = self.amplifiedTuple[1]
        reg_req = self.regularTuple[0]
        reg_res = self.regularTuple[1]

        self.assertEqual(amp_req[DNS].qr, 0, "Structure must be (request, response), error: amplified tuple")
        self.assertEqual(amp_res[DNS].qr, 1, "Structure must be (request, response), error: amplified tuple")
        self.assertEqual(reg_req[DNS].qr, 0, "Structure must be (request, response), error: regular tuple")
        self.assertEqual(reg_res[DNS].qr, 1, "Structure must be (request, response), error: regular tuple")

    def test_DNS_layer(self):
        amp_req = self.amplifiedTuple[0]
        amp_res = self.amplifiedTuple[1]
        self.assertEqual(amp_res[DNS].id, amp_req[DNS].id, "Wrong response DNS id, error: amplified tuple")
        self.assertEqual(amp_res[DNS].qd, amp_req[DNS].qd, "Is answering a different question, error: amplified tuple")
        self.assertEqual(amp_res[DNS].rcode, 0, "DNS rcode must be 0, error: amplified tuple")

        reg_req = self.regularTuple[0]
        reg_res = self.regularTuple[1]
        self.assertEqual(reg_res[DNS].id, reg_req[DNS].id, "Wrong response DNS id, error: regular tuple")
        self.assertEqual(reg_res[DNS].qd, reg_req[DNS].qd, "Is answering a different question, error: regular tuple")
        self.assertEqual(reg_res[DNS].rcode, 0, "DNS rcode must be 0, error: regular tuple")

    def test_UDP_layer(self):
        amp_req = self.amplifiedTuple[0]
        amp_res = self.amplifiedTuple[1]
        self.assertEqual(amp_res[UDP].sport, 53, "Wrong response source port, error: amplified tuple")
        self.assertEqual(amp_res[UDP].dport, amp_req[UDP].sport, "Wrong response destination port, error: amplified tuple")

        reg_req = self.regularTuple[0]
        reg_res = self.regularTuple[1]
        self.assertEqual(reg_res[UDP].sport, 53, "Wrong response source port, error: regular tuple")
        self.assertEqual(reg_res[UDP].dport, reg_req[UDP].sport, "Wrong response destination port, error: regular tuple")

    def test_IP_layer(self):
        amp_req = self.amplifiedTuple[0]
        amp_res = self.amplifiedTuple[1]
        self.assertEqual(amp_res[IP].proto, 17, "Wrong response ip protocol, error: amplified tuple")
        self.assertEqual(amp_res[IP].src, amp_req[IP].dst, "Wrong response source ip, error: amplified tuple")
        self.assertEqual(amp_res[IP].dst, amp_req[IP].src, "Wrong response destination ip, error: amplified tuple")

        reg_req = self.regularTuple[0]
        reg_res = self.regularTuple[1]
        self.assertEqual(reg_res[IP].proto, 17, "Wrong response ip protocol, error: regular tuple")
        self.assertEqual(reg_res[IP].src, reg_req[IP].dst, "Wrong response source ip, error: regular tuple")
        self.assertEqual(reg_res[IP].dst, reg_req[IP].src, "Wrong response destination ip, error: regular tuple")

    def test_time(self):
        amp_res = self.amplifiedTuple[1]
        self.assertEqual(amp_res.time, self.t + self.dt, "Wrong response arrival time, error: amplified tuple")
        reg_res = self.regularTuple[1]
        self.assertEqual(reg_res.time, self.t + self.dt, "Wrong response arrival time, error: regular tuple")

    def test_size(self):
        self.assertTrue(len(self.amplifiedTuple[1]) / len(self.amplifiedTuple[0]) >= 37, "Small amplification factor for amplified response")
        self.assertTrue(len(self.regularTuple[1]) / len(self.regularTuple[0]) <= 10, "Big amplification factor for regular response")

class argsBuilderTest(unittest.TestCase):
    def setUp(self):
        self.serv = "200.7.4.7"
        self.target_ip = "8.8.8.8"
        self.sport = 23567
        self.d = 30
        self.c = 20
        self.ti = 14
        self.domain = "domain.cl"
        self.amplifiedResponse = True
        self.regularResponse = False
        self.dom_ip = "100.100.100.100"
        self.serv_dom_ip = "200.200.200.200"
        self.amplifiedArgs = argsBuilder(self.serv, self.target_ip, self.sport, self.d, self.c, self.ti, self.domain, self.amplifiedResponse, self.dom_ip, self.serv_dom_ip)
        self.regularArgs = argsBuilder(self.serv, self.target_ip, self.sport, self.d, self.c, self.ti, self.domain, self.regularResponse, self.dom_ip, self.serv_dom_ip)

    def test_number_generated_arguments(self):
        self.assertEqual(len(self.amplifiedArgs), self.d * self.c, "Wrong number of generated arguments, error: Amplified response")
        self.assertEqual(len(self.regularArgs), self.d * self.c, "Wrong number of generated arguments, error: Regular response")

    def test_arguments_structure(self):
        for arg in self.amplifiedArgs:
            self.assertEqual(arg[0], self.target_ip, "Wrong target ip, error: amplified response")
            self.assertEqual(arg[1], self.serv, "Wrong server ip, error: amplified response")
            self.assertEqual(arg[2], self.sport, "Wrong source port, error: amplified response")
            self.assertEqual(arg[3], self.domain, "Wrong asked domain, error: amplified response")
            self.assertTrue(arg[4] >= 0, "Request arrival time can't be less than 0, error: amplified response")
            self.assertTrue(arg[4] >= self.ti, "Wrong request arrival time, error: amplified response")
            self.assertTrue(arg[4] <= self.ti + self.d, "Wrong request arrival time, error: amplified response")
            self.assertTrue(arg[5] >= 0, "Response delay time can't be less than 0, error: amplified response")
            self.assertEqual(arg[6], self.dom_ip, "Wrong domain ip, error: amplified response")
            self.assertEqual(arg[7], self.serv_dom_ip, "Wrong domain server ip, error: amplified response")
            self.assertTrue(arg[8], "Wrong answer type, error: amplified response")

        for arg in self.regularArgs:
            self.assertEqual(arg[0], self.target_ip, "Wrong target ip, error: regular response")
            self.assertEqual(arg[1], self.serv, "Wrong server ip, error: regular response")
            self.assertEqual(arg[2], self.sport, "Wrong source port, error: regular response")
            self.assertEqual(arg[3], self.domain, "Wrong asked domain, error: regular response")
            self.assertTrue(arg[4] >= 0, "Request arrival time can't be less than 0, error: regular response")
            self.assertTrue(arg[4] >= self.ti, "Wrong request arrival time, error: regular response")
            self.assertTrue(arg[4] <= self.ti + self.d, "Wrong request arrival time, error: regular response")
            self.assertTrue(arg[5] >= 0, "Response delay time can't be less than 0, error: regular response")
            self.assertEqual(arg[6], self.dom_ip, "Wrong domain ip, error: regular response")
            self.assertEqual(arg[7], self.serv_dom_ip, "Wrong domain server ip, error: regular response")
            self.assertFalse(arg[8], "Wrong answer type, error: regular response")

    def test_packets_per_second(self):
        n_amplified = np.zeros(self.d)
        n_regular = np.zeros(self.d)
        for t in self.amplifiedArgs:
            n = int(t[4] - self.ti)
            n_amplified[n] += 1
        for c in n_amplified:
            self.assertEqual(c, self.c, "Wrong amount of packets per second, error: amplified response")

        for t in self.regularArgs:
            n = int(t[4] - self.ti)
            n_regular[n]+= 1
        for c in n_regular:
            self.assertEqual(c, self.c, "Wrong amount of packets per second, error: regular response")

class genMultiplePacketsTest(unittest.TestCase):
    def setUp(self):
        self.serv = "200.7.4.7"
        self.target_ip = "8.8.8.8"
        self.sport = 23567
        self.d = 30
        self.c = 20
        self.ti = 14
        self.domain = "domain.cl"
        self.amplifiedResponse = True
        self.regularResponse = False
        self.dom_ip = "100.100.100.100"
        self.serv_dom_ip = "200.200.200.200"
        self.amplifiedArgs = argsBuilder(self.serv, self.target_ip, self.sport, self.d, self.c, self.ti, self.domain, self.amplifiedResponse, self.dom_ip, self.serv_dom_ip)
        self.regularArgs = argsBuilder(self.serv, self.target_ip, self.sport, self.d, self.c, self.ti, self.domain, self.regularResponse, self.dom_ip, self.serv_dom_ip)
        self.amplifiedPackets = []
        self.regularPackets = []
        for arg in self.amplifiedArgs:
            tuple = genPackets(arg)
            self.amplifiedPackets.append(tuple)
        for arg in self.regularArgs:
            tuple = genPackets(arg)
            self.regularPackets.append(tuple)

    def test_amount_generated_packets(self):
        n_amplified = 0
        n_regular = 0

        for t in self.amplifiedPackets:
            self.assertEqual(len(t), 2, "Len of tuples must be 2, error: Amplified response")
            n_amplified += 2

        for t in self.regularPackets:
            self.assertEqual(len(t), 2, "Len of tuples must be 2, error: Regular response")
            n_regular += 2
        self.assertEqual(n_amplified, self.d * self.c * 2, "Wrong number of generated packets, error: Amplified response")
        self.assertEqual(n_regular, self.d * self.c * 2, "Wrong number of generated packets, error: Regular response")

    def test_attack_structure(self):
        for t in self.amplifiedPackets:
            req = t[0]
            res = t[1]
            self.assertEqual(req[DNS].qr, 0, "Structure must be (request, response), error: Amplified packets")
            self.assertEqual(res[DNS].qr, 1, "Structure must be (request, response), error: Amplified packets")
        for t in self.regularPackets:
            req = t[0]
            res= t[1]
            self.assertEqual(req[DNS].qr, 0, "Structure must be (request, response), error: Regular packets")
            self.assertEqual(res[DNS].qr, 1, "Structure must be (request, response), error: Regular packets")

    def test_attack_time(self):
        for t in self.amplifiedPackets:
            req = t[0]
            self.assertTrue(req.time >= self.ti, "Request arrival time out of range, error: Amplified packets")
            self.assertTrue(req.time <= self.ti + self.d, "Request arrival time out of range, error: Amplified packets")

        for t in self.regularPackets:
            req = t[0]
            self.assertTrue(req.time >= self.ti, "Request arrival time out of range, error: Regular packets")
            self.assertTrue(req.time <= self.ti + self.d, "Request arrival time out of range, error: Regular packets")

    def test_packets_per_second(self):
        n_packets_amp = np.zeros(self.d)
        for t in self.amplifiedPackets:
            req = t[0]
            n = int(req.time - self.ti)
            n_packets_amp[n] += 1
        for c in n_packets_amp:
            self.assertEqual(c, self.c, "Wrong number of packets per second, error: Amplified packets")

        n_packets_reg = np.zeros(self.d)
        for t in self.regularPackets:
            req = t[0]
            n = int(req.time - self.ti)
            n_packets_reg[n] += 1
        for c in n_packets_reg:
            self.assertEqual(c, self.c, "Wrong number of packets per second, error: Regular packets")

    def test_amplified_response_size(self):
        for t in self.amplifiedPackets:
            res = t[1]
            self.assertTrue(len(res) > 3000, "Small response, size must be greater than 3000 bytes")

    def test_non_amplified_response_size(self):
        for t in self.regularPackets:
            res = t[1]
            self.assertTrue(len(res) < 500, "Big response, size must be less than 500 bytes")

    def test_attack_packet_structure(self):
        for t in self.amplifiedPackets:
            req = t[0]
            res = t[1]
            self.assertEqual(res[DNS].id, req[DNS].id, "Wrong response DNS id, error: Amplified packets")
            self.assertEqual(res[DNS].qd, req[DNS].qd, "Is answering a different question, error: Amplified packets")
            self.assertEqual(res[DNS].rcode, 0, "DNS rcode must be 0, error: Amplified packets")

            self.assertEqual(res[UDP].sport, 53, "Wrong response source port, error: Amplified packets")
            self.assertEqual(res[UDP].dport, req[UDP].sport, "Wrong response destination port, error: Amplified packets")

            self.assertEqual(res[IP].proto, 17, "Wrong response ip protocol, error: Amplified packets")
            self.assertEqual(res[IP].src, req[IP].dst, "Wrong response source ip, error: Amplified packets")
            self.assertEqual(res[IP].dst, req[IP].src, "Wrong response destination ip, error: Amplified packets")

        for t in self.regularPackets:
            req = t[0]
            res = t[1]
            self.assertEqual(res[DNS].id, req[DNS].id, "Wrong response DNS id, error: Regular packets")
            self.assertEqual(res[DNS].qd, req[DNS].qd, "Is answering a different question, error: Regular packets")
            self.assertEqual(res[DNS].rcode, 0, "DNS rcode must be 0, error: Regular packets")

            self.assertEqual(res[UDP].sport, 53, "Wrong response source port, error: Regular packets")
            self.assertEqual(res[UDP].dport, req[UDP].sport, "Wrong response destination port, error: Regular packets")

            self.assertEqual(res[IP].proto, 17, "Wrong response ip protocol, error: Regular packets")
            self.assertEqual(res[IP].src, req[IP].dst, "Wrong response source ip, error: Regular packets")
            self.assertEqual(res[IP].dst, req[IP].src, "Wrong response destination ip, error: Regular packets")





if __name__ == '__main__':
    unittest.main()
