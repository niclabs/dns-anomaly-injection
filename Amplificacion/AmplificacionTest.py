import unittest
import socket
from amplificacion import *

class builderTestCase(unittest.TestCase):
    def setUp(self):
        target_ip = "8.8.8.8"
        serv_ip = "200.7.4.7"
        src_port = 31175
        q_name = "hola.cl"
        ti = 10
        p = amplificationBuilder(target_ip, serv_ip, src_port, q_name, ti)


    def test_DNS_layer(self):
        self.assertEqual(self.p[DNS].qr, 1, "Is not a request")

if __name__ == '__main__':
