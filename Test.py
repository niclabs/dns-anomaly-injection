from types import FunctionType
"""
Test class which proposite is to be inherited when doing tests.
This works like this:
First write a subclass of this test class, overriding the setup method
Every variable has to be added to the dictionary of the super class
Then create the tests method, that has to start with test in it's name
Finally, create the python runner (if __name__=="__main__") and create the subclass
object, executes it's run method (inhereted)
:author: Joaquin 
"""
class Test:
    def __init__(self):
        """
        Creates a new test instance to be runned
            :param self: 
        """
        self._variables={}
    def setUp(self):
        """
        Have to be inhereted when doing test, sets ups the variables in this method
        """
        pass
    def addVariable(self,name: str,value):
        """
        Add a global variable to use in the tests
        :name:str: the name of the variable to be added
        :value: the value of the variable that is added
        """
        self._variables[name]=value
    def getVariable(self,name: str):
        """
        Gets a global test variable given it's name
        :name:str: the name of the variable
        :return: the variable value
        """
        return self._variables[name]
    def run(self,specific=None):
        """
        Method that runs the tests.
        """
        assert specific == None or type(specific)== str
        before = [method for method in dir(self) if callable(getattr(self,method)) if method.startswith('setUp')]
        tests_to_run = [method for method in dir(self) if callable(getattr(self,method)) if  method.startswith('test')]
        for method in before:
            getattr(self,method)()
        if specific != None:
            for method in tests_to_run:
                if specific == method:
                    try:
                        getattr(self,method)()
                        if method.startswith('test'+specific):
                            print( method+"-- Passed")
                    except AssertionError:
                        print (method+"--Failed")
        else:
            for method in tests_to_run:
                try:
                    getattr(self,method)()
                    if method.startswith('test'):
                        print( method+"-- Passed")
                except AssertionError:
                    print (method+"--Failed")
