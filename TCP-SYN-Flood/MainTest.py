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
        self.addVariable("basico",1)
        self.addVariable("mediano",6)
        self.addVariable("sip","190.54.120.40")
        self.addVariable("dip","200.7.4.7")
        self.addVariable("file","lol.pcap")
    def test_basic(self):
        origin = self.getVariable("sip")
        duration = self.getVariable("basico")
        arguments = ["main.py","test1k.pcap",origin,duration]
        ok=m.main(arguments,test="--test_basic")
        assert ok == 0
    def test_insert6s(self):
        origin = self.getVariable("sip")
        duration = self.getVariable("mediano")
        arguments = ["main.py","test1k.pcap",origin,duration]
        ok = m.main(arguments,test="--test_medium")
        assert ok == 0
if __name__=="__main__":
    args = sys.argv
    try:
        if len(args)== 1 or args[1] == 'all':
            MainTest().run()
        else:
            for i in range(1,len(args)):
                MainTest().run(args[i])
    except IndexError:
        raise Exception("Se utiliza de la forma:\nTest a realizar (all o nada para todos)")