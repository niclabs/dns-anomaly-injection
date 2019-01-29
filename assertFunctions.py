""" @Javi801
 Check if "fun" returns true when using "valor" as an argument, otherwise it
 displays the given message

 Params: valor -> an argument for "fun" function
         fun -> a lambda function that returns a boolean
         mensaje -> (str) error message
"""
def check( valor, fun, mensaje ):
    try:
        assert( fun( valor ) )
    except:
        raise Exception( mensaje )
