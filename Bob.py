from bitstring import BitArray
from ToyDES import *
import time;
import socket
import sys

#simple function on nonce to prove KS recieved correctly
def f(nonce):
    val = nonce*2
    val = int(val/3)
    return val


if __name__ == '__main__':
    BKDC = socket.socket()         
    host = socket.gethostname() 
    port = 12346    
    
    
    
    #D-F Key exchange
    q = 353
    alpha = 3
    X = 55
    YB = (alpha**X)%q
    
    #receive YK
    BKDC.connect((host, port))
    YK = BitArray(BKDC.recv(1024)).uint    
    
    #send YB to KDC
    BKDC.send(bytes([YB]))
    BKDC.close()

    #compute KB
    KBK = (YK**X)%q
    KB = BitArray(int=KBK,length = 10)
    
    #Socket to Alice
    BA = socket.socket()          
    port = 12347     
    
    #connect to Alice
    BA.connect((host,port))
    
    #Recieve M3
    enM3 = BitArray(BA.recv(1024))
    
    #decrypt M3
    M3 = multDES(enM3,KB,1)
    
    KS = BitArray('0b'+M3.bin[:10])
    
    RT = BitArray('0b'+M3.bin[26:])
    T = int(time.time())
    #check that RT is valid 
    if ((T - RT.uint) > 86400) or (T-RT.uint) < 0 :
        sys.exit("Invalid Timestamp")    
    
    #Generate Nonce2
    N2 = BitArray('0b00111100')
    
    #encrypt N2 using KS
    M4 = DES(N2,KS,0)
    
    #send M4 to Alice
    BA.send(M4.bytes)
    
    #recieve M5
    enM5 = BitArray(BA.recv(1024))
    
    BA.close()
    #decrypt M5
    M5 = DES(enM5,KS,1)
    
    RN = M5.uint
    CN = f(N2.uint)
    
    if (RN != CN):
        sys.exit("KS failed")
        
    print(True)