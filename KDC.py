from bitstring import BitArray
from ToyDES import *
import time;
import socket
import random

if __name__ == '__main__':
    AKDC = socket.socket()         
    host = socket.gethostname()
    port = 12345    
    
    
    
    #D-F Key exchange
    q = 353
    alpha = 3
    X = 255
    YK = (alpha**X)%q
    
    #receive YA
    AKDC.connect((host,port))
    YA = BitArray(AKDC.recv(1024)).uint
    
    #compute KA
    KAK = (YA**X)%q
    KA = BitArray(int=KAK,length = 10)
    #send YK to A
    AKDC.send(bytes([YK]))
    
    #socket from KDC to Bob
    BKDC = socket.socket()         
    port = 12346                
    BKDC.bind((host, port))     
    
    #send YK to B
    BKDC.listen()
    conB, addr = BKDC.accept()
    conB.send(bytes([YK]))    
    
    #receive YB
    YB = BitArray(conB.recv(1024)).uint
    conB.close()
    
    #compute KB
    KBK = (YB**X)%q
    KB = BitArray(int=KBK,length = 10)
    
    #Receive M1
    M1 = BitArray(AKDC.recv(1024))
    
    #generate KS
    KS = BitArray(uint = random.randint(0,1023),length=10)
    
    IDA = BitArray('0b'+M1.bin[:16]) 
    IDB = BitArray('0b'+M1.bin[16:32])
    
    T = int(time.time())
    leng = len(bin(T)) 
    rem = leng%8
    if (rem <= 6):
        leng += (6-rem)
    else:
        leng += 7
    BT = BitArray(uint = T,length = leng)
    
    M2 = KS.copy()
    M2.append(IDB)
    M2.append(BT)
    
    M3 = KS.copy()
    M3.append(IDA)
    M3.append(BT)
    
    enM3 = multDES(M3,KB,0)
    
    M2.append(enM3)
    enM2 = multDES(M2,KA,0)
    
    #sending M2 to Alice
    AKDC.send(enM2.bytes)
    
    AKDC.close()