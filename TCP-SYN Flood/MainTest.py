from Test import *
from scapy.all import *
import main as m
"""
Object that test the functions of the main.py file
@author Joaquin Cruz
"""
class MainTest(Test):
    def __init__(self):
        super().__init__()
    def setUp(self):
        self.addVariable("lista vacia",PacketList())
        self.addVariable("response vacia",PacketList())
        self.addVariable("dip","190.54.120.31")
        self.addVariable("dest","200.7.4.7")
        self.addVariable("")
    def test_basic():

#TODO all tests
if __name__=="__main__":
    MainTest().run()