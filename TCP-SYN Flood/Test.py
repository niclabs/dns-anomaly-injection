from types import FunctionType
class Test:
    def __init__(self):
        """
        Creates a new test instance to be runned
            :param self: 
        """
        self._variables={}
    def setUp(self):
        pass
    def addVariable(self,name: str,value):
        self._variables[name]=value
    def getVariable(self,name: str):
        return self._variables[name]
    def run(self):
        tests_to_run = [method for method in dir(self) if callable(getattr(self,method)) if  method.startswith('test') or method.startswith('setUp')]
        for method in tests_to_run:
            try:
                getattr(self,method)()
                if method.startswith('test'):
                    print( method+"-- Passed")
            except AssertionError:
                print (method+"--Failed")
