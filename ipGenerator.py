import random

"""@Javi801
 Gives an array of random IP addresses, without the IP 200.7.4.7

 Param: total -> (int) numbers of IP addresses in the array
        Seed -> (float) seed for randomize

 Return: ips -> (list(str)) array of IP addresses
"""
def randomIP(total, Seed):
    random.seed(Seed)
    if total>256:
        ('Se creara una botnet con prefijo IP /16')
    if total<1:
        print('Se intenta generar un numero 0 o negativo de IP')
        return ['']
    ips=[]
    j=random.randint(0,255)
    k=random.randint(0,255)
    l=random.randint(0,255)
    for i in range(total):
        bool=1
        while(bool):
            if total>256:
                l=random.randint(0,255)
            m=random.randint(0,255)
            ip=str(j)+'.'+str(k)+'.'+str(l)+'.'+str(m)
            if ip!='200.7.4.7':
                ips+=[ip]
                bool=0
    return ips
