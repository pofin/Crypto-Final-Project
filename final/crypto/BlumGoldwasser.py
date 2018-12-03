import math
from bitstring import BitArray
from cryptosystem import Pkc
import random 


#miller rabin I stole from my test makeup
#used to make sure p and q are prime
def millrab(n):
    k = 0
    q = n-1
        
    if n%2 == 0:
        return False    
        
    while True:
        if q%2 == 0:
            k += 1
            q = int(q/2)
        else:
            break
         
    for i in range(10):  
        a = random.randint(2,n-1)
        x = pow(a,q,n)
        if x == 1: 
            continue
            
        for t in range(k):
            y = pow(a,((pow(2,t))*q),n)
            if y != (n-1):
                return False                  
        
    return True

class BlumGoldwasser(Pkc):
    def __init__(self):
        self.p = 0
        self.q = 0
        self.n = 0
        self.a = 0
        self.b = 0
        self.h = 0
        self.recv_pub_key = 0
        self.recv_h = 0
    
    #encrypts message with reciever's public key
    #returns a tuple (ctext,x_t+1)
    def encrypt_public(self, message):
        m = BitArray(message.encode("latin-1"))
        n = self.recv_pub_key
        h = self.recv_h
        t = int(m.length/h)
        mb = m.bin
        low = 0
        up = h
        r = random.randint(1,n)
        xp = pow(r,2,n)
        
        first = True
        for i in range(t):
            xp = pow(xp,2,n)
            p = BitArray('0b'+bin(xp)).bin[0-h:]
            c = BitArray('0b'+p)
            c ^= BitArray('0b'+mb[low:up])
            if first:
                first = False
                ctext = c.copy()
            else:
                ctext.append(c)
            low += h
            up += h
    
        return (ctext.bytes.decode("latin-1"),pow(xp,2,n))       
    
    #message must be in form (ctext,x_t+1)
    #decrypts message that was encrypted with its public key
    def decrypt_private(self, message):
        m = BitArray(message[0].encode("latin-1"))
        t = int(m.length/self.h)
        xt = message[1]
        d1 = pow(int((self.p+1)/4),t+1,self.p-1)
        d2 = pow(int((self.q+1)/4),t+1,self.q-1)
        u = pow(xt,d1,self.p)
        v = pow(xt,d2,self.q)
        xp = ((v*self.a*self.p)+(u*self.b*self.q))%self.n
        
        mb = m.bin
        mess = ''
        low = 0
        up = self.h        
        
        for i in range(t):
            xp = pow(xp,2,self.n)
            chunk = BitArray('0b'+bin(xp)).bin[0-self.h:]
            chunk = BitArray('0b'+chunk)
            chunk ^= BitArray('0b'+mb[low:up])      
            mess += chunk.bin  
            low += self.h
            up += self.h            
        
        return BitArray('0b'+mess).bytes.decode("latin-1")        
        
    def gen_key_pair(self):
        #generates a random # that is 3 mod 4
        while (True):
            self.p = (4 * random.randint(0,10000))+3
            if (millrab(self.p)):
                break
            
        while (True):
            self.q = (4 * random.randint(0,10000))+3
            #makes sure self.q /= self.p
            if self.q == self.p:
                continue
            if (millrab(self.q)):
                break        
        self.a = pow(self.p,self.q-2,self.q)
        self.b = pow(self.q,self.p-2,self.p)
        self.n = self.p*self.q
        self.h = int(math.log(int(math.log(self.n,2)),2))
        
    
    #sets the reciever's pub_key that the message is encrypted with 
    def set_recv_pub_key(self, pub_key):
        self.recv_pub_key = pub_key
        self.recv_h = int(math.log(int(math.log(pub_key,2)),2))
    
    #returns public and private key in a tuple with the 
    #second element the a list of the private keys p,q
    def get_key_pair(self):
        return (self.n,[self.p,self.q])
    
    #returns the reciever's pub_key that the message is encrypted with 
    def get_recv_pub_key(self, pub_key):
        return self.recv_pub_key    
    
    #set the values of a key pair
    #pub_key = int , priv_key = list of ints [p,q,a,b,h]
    #assumes pub_key = priv_key[0]*priv_key[1]
    #and that priv_key[0]=priv_key[1]=3 mod 4
    def set_key_pair(self, pub_key, priv_key):
        self.n = pub_key
        self.p = priv_key[0]
        self.q = priv_key[1]
        self.a = pow(self.q,self.p-2,self.p)
        self.b = pow(self.p,self.q-2,self.q)
        self.h = int(math.log(int(math.log(self.n,2)),2))
    
    #copys crypto system with specified public key
    #private key is zeroed out
    def copy_with_public_key(self, pub_key):
        temp = BlumGoldwasser()
        temp.set_key_pair(pub_key,[0,0])
        return temp
    
    
if __name__ == '__main__':
    
    x = BlumGoldwasser()
    x.gen_key_pair()
    #print(x.get_key_pair())
    y = BlumGoldwasser()
    y.gen_key_pair()
    #print(x.get_key_pair())
    temp = y.get_key_pair()[0]
    x.set_recv_pub_key(temp)
    ctext = x.encrypt_public("string")
    print(ctext)
    print(y.decrypt_private(ctext))
    
    
    



