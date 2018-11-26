import math
from bitstring import BitArray

#encrypts original message
def encrypt(n, x0, m,k,h):
    t = int(m.length/h)
    mb = m.bin
    low = 0
    up = h
    xp = x0
    
    
    ctext = []
    for i in range(t):
        xp = pow(xp,2,n)
        p = BitArray('0b'+bin(xp)).bin[0-h:]
        c = BitArray('0b'+p)
        c ^= BitArray('0b'+mb[low:up])
        ctext.append(c)
        low += h
        up += h
    
    ctext.append(pow(xp,2,n))
    return ctext

#decrypts ciphertext
def decrypt(p,q,enc,a,b,n,k,h):
    t = len(enc)-1
    xt = enc[-1]
    d1 = pow(int((p+1)/4),t+1,p-1)
    d2 = pow(int((q+1)/4),t+1,q-1)
    u = pow(xt,d1,p)
    v = pow(xt,d2,q)
    xp = ((v*a*p)+(u*b*q))%n
    
    m = ''
    
    for i in range(t):
        xp = pow(xp,2,n)
        p = BitArray('0b'+bin(xp)).bin[0-h:]
        p = BitArray('0b'+p)
        p ^= enc[i]       
        m += p.bin  
    
    return m

if __name__ == '__main__':
    #given parameters
    p = 499
    q = 547
    a = -57
    b = 52
    n = p*q
    k = int(math.log(n,2))
    h = int(math.log(k,2))    
    x0 = 159201
    m = BitArray('0b10011100000100001100')
    #generates encryption
    enc = encrypt(n, x0, m,k,h)
    #makes encryption prettier to print and does so
    Benc = []
    for i in range(len(enc)-1):
        Benc.append(enc[i].bin)
        
    Benc.append(enc[-1])
    
    print('Ciphertext is:',Benc)
    
    #generates and prints original message
    print('Original message back:',decrypt(p,q,enc,a,b,n,k,h))