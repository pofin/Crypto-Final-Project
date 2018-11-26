from bitstring import BitArray
from ToyDES import *
import time;
import socket
import sys

#simple function on nonce to prove KS recieved correctly
def f(nonce):
    val = nonce*2
    val = val/3
    return val

if __name__ == '__main__':
    #set up socket to KDC
    AKDC = socket.socket()        
    host = socket.gethostname() 
    port = 12345                
    AKDC.bind((host, port))    
    
    #D-F Key exchange
    q = 353
    alpha = 3
    X = 19
    YA = (alpha**X)%q
    
    #send YA to KDC
    AKDC.listen()
    conKDC, addr = AKDC.accept()
    conKDC.send(bytes([YA]))
    
    #recieve YK
    YK = BitArray(conKDC.recv(1024)).uint
    
    #compute KA
    KAK = (YK**X)%q
    KA = BitArray(int=KAK,length = 10)
    
    #IDs are assigned
    IDA = 'Al'
    IDB = 'Bo'
    
    #generate nonce1
    N1 = 'non'
    
    #combine message for step 1
    M1 = BitArray(IDA.encode())
    M1.append(BitArray(IDB.encode()))
    M1.append(BitArray(N1.encode()))
    
    
    #send M1 to KDC
    conKDC.send(M1.bytes)
    
    
    #recieve M2 from KDC
    enM2 = BitArray(conKDC.recv(1024))
    
    #decrypt M2
    M2 = multDES(enM2,KA,1)
    KS = BitArray('0b'+M2.bin[:10])
    
    half = int(len(M2.bin)/2)
    
    RT = BitArray('0b'+M2.bin[26:half])
    T = int(time.time())
    
    #check that RT is valid 
    if ((T - RT.uint) > 86400) or (T-RT.uint) < 0 :
        sys.exit("Invalid Timestamp")
    
    M3 = BitArray('0b'+M2.bin[half:]) 
    
    #socket to Bob
    AB = socket.socket()        
    port = 12347                
    AB.bind((host, port))    
    
    #connect to Bob
    AB.listen()
    conB, addr = AB.accept()
    
    
    #send enM3 to Bob
    conB.send(M3.bytes)    
    
    #receive M4
    enM4 = BitArray(conB.recv(1024))
    
    #decrypt M4
    M4 = DES(enM4,KS,1)
    
    #perform function f
    noncepr = int(f(M4.uint))
    
    M5 = BitArray(int=noncepr,length = 8)
    
    #encrypt and send M5
    enM5 = DES(M5,KS,0)
    
    conB.send(enM5.bytes)
    conB.close()