import random
import string

"""@Javi801
 Gives an array of random IP addresses, without the IP 200.7.4.7

 Param: total -> (int) numbers of IP addresses in the array.
        Seed -> (float) seed for randomize.
        ddos -> (boolean) true if the IPs addresses have a prefix ('cause the
                attack is DDoS type) or false if not.

 Return: ips -> (list(str)) array of IP addresses.
"""
def randomIP(total, Seed, ddos):
    random.seed(Seed)
    if total>256 and ddos:
        ('Se creara una botnet con prefijo IP /16')
    if total<1:
        print('Se intenta generar un numero 0 o negativo de IP')
        return ['']
    ips=[]
    j=random.randint(0,255)
    k=random.randint(0,255)
    l=random.randint(0,255)
    for i in range(total):
        ip='200.7.4.7'
        while(ip=='200.7.4.7'):
            if ddos and total>256:
                l=random.randint(0,255)
            elif not(ddos):
                j=random.randint(0,255)
                k=random.randint(0,255)
                l=random.randint(0,255)
            m=random.randint(0,255)
            ip=str(j)+'.'+str(k)+'.'+str(l)+'.'+str(m)
        ips+=[ip]
    return ips

def checkValidIp(ip : string):
    """
    Check if an ip is valid
    Param: ip: String
    return: Boolean
    """
    values = ip.split(".")
    if(len(values) != 4):
        return False
    else:
        for v in values:
            if(int(v) < 0 or int(v) > 255):
                return False
    return True
