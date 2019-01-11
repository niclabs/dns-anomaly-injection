import sys
sys.path.append('..')
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
        self.addVariable("poco",1)
        self.addVariable("nada",0)
        self.addVariable("significativo",700)
        self.addVariable("sip","190.54.120.40")
        self.addVariable("dip","200.7.4.7")
        self.addVariable("file","lol.pcap")
    def test_basic(self):
        ##TODO
        pass
    def test_create_many(self):
        #TODO all tests
        pass
if __name__=="__main__":
    MainTest().run()