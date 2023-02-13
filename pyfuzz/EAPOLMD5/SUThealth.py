#!/usr/bin/env python
import os
import time
import binascii
import hashlib
import logging
from os import system
from time import sleep
from scapy.all import *
from binascii import hexlify
from threading import Thread
from binascii import unhexlify
from colorama import Fore, Back , Style
Directorypath = os.path.dirname(__file__)

##########################################################################################################################################
def EAPOL_MD5_SUThealth_start(sourceinterface, sourcemacaddress, username, hexdump2pass, casenum):
  # send EAPOL-START and sniff "id" from the EAP-REQUEST Identity
    class snifthread1(Thread):
          def __init__(self):
              Thread.__init__(self)
          def run(self):   
              s = sniff(filter="ether proto 0x888e", iface=sourceinterface, count=2)             
              self.val1 = s[1][EAP].id
              sleep(1)
              self.val2 = s[1][EAP].code
             
      
    class sendthread1(Thread):
          def __init__(self):
              Thread.__init__(self)  
          def run(self):  
              sleep(1)
              sendp(Ether(src=sourcemacaddress, dst="01:80:c2:00:00:03")/EAPOL(type=1), iface=sourceinterface)
            
    thread1 = snifthread1()
    thread2 = sendthread1()
    thread1.start()
    thread2.start()
    thread1.join()
    thread2.join()
 
    if thread1.val2 != 1 :
       print("   Case-DI:" + str(casenum) + "-------------->" + Fore.RED+ "\033[1mFAILED\033[0m"+Style.RESET_ALL) 
    else:     
       idREQ = thread1.val1
       EAPOL_MD5_SUThealth_responseId(sourceinterface, sourcemacaddress, username, hexdump2pass, casenum, idREQ)
########################################################################################################################################## 



########################################################################################################################################## 
def EAPOL_MD5_SUThealth_responseId(sourceinterface, sourcemacaddress, username, hexdump2pass, casenum, idREQ):
 # send EAP-RESPONSE Identity and sniff "id,value" from the EAP-REQUEST Challenge 
    class snifthread2(Thread):
          def __init__(self):
              Thread.__init__(self)
          def run(self):   
               s = sniff(filter="ether proto 0x888e", iface=sourceinterface, count=2)
               self.val3 = s[1][EAP].code 
               sleep(1)               
               if self.val3 == 4:
                     print("   Case-DI: " + str(casenum) + "-------------->" + Fore.RED+ "\033[1m FAILED\033[0m" + Style.RESET_ALL)                     
               else:
                     self.val1 = s[1][EAP_MD5].id
                     sleep(1)
                     self.val2 = s[1][EAP_MD5].value            
    class sendthread2(Thread):
          def __init__(self):
              Thread.__init__(self)  
          def run(self):  
              sleep(1)
              sendp(Ether(src=sourcemacaddress, dst="01:80:c2:00:00:03")/EAPOL(type=0)/  EAP(type=1,code=2,id=idREQ,desired_auth_types=EAP_MD5,identity=username), iface=sourceinterface)
            
    thread3 = snifthread2()
    thread4 = sendthread2()
    thread3.start()
    thread4.start()
    thread3.join()
    thread4.join()
    try:
       idCH = thread3.val1                           
       valREQCH = binascii.hexlify(thread3.val2).decode("ascii")    
       hexdump2valREQCH = r"\x" + r"\x".join(valREQCH[n : n+2] for  n in range(0, len(valREQCH), 2))
       hexdump2idCH = ("{0:#0{1}x}".format(thread3.val1,4)).replace("0","\\",1)  
 
       # the EAP-RESPONSE Challenge that we need to md5sum and transfer to bytestring
       valRESCH = hexdump2idCH + hexdump2pass + hexdump2valREQCH
       valRESCH = valRESCH.replace('\\x', '')
 
       bytesobject = bytes.fromhex(valRESCH)
       asciistring = bytesobject.decode("latin-1")
 
       encode = asciistring.encode("latin-1", "ignore")
       byt = bytes(encode)
       md5= hashlib.md5(byt).hexdigest()
 
       msg = bytes.fromhex(md5)
    # save logging error 
    except Exception as Argument:
           f = open ("log.txt", "a")
           f.write(str(Argument))
           f.close()
           print(Fore.RED + "Failure:check" + Directorypath + "/log.txt for more details"+Style.RESET_ALL)
           sys.exit(1)
            
    EAPOL_MD5_SUThealth_responseCh(sourceinterface, sourcemacaddress, casenum, idCH, msg) 
########################################################################################################################################## 




########################################################################################################################################## 
def EAPOL_MD5_SUThealth_responseCh(sourceinterface, sourcemacaddress, casenum, idCH, msg):
    # send EAP-RESPONSE Challenge and sniff "succ,fail" from the Success or Fail
    class snifthread3(Thread):
          def __init__(self):
              Thread.__init__(self)
          def run(self):   
              s = sniff(filter="ether proto 0x888e", iface=sourceinterface, count=2)
              self.val1 = s[1][EAP].code 
     
      
    class sendthread3(Thread):
          def __init__(self):
              Thread.__init__(self)  
          def run(self): 
              sleep(1)
              sendp(Ether(src=sourcemacaddress, dst="01:80:c2:00:00:03")/EAPOL(type=0)/EAP_MD5(code=2,id=idCH,type=4,value=msg), iface=sourceinterface)
            
    thread5 = snifthread3()
    thread6 = sendthread3()
    thread5.start()
    thread6.start()
    thread5.join()
    thread6.join()
    codeSF = thread5.val1
    if codeSF == 4:
       print("   Case-DI: " + str(casenum) + "-------------->" + Fore.RED + "\033[1m FAILED\033[0m"+ Style.RESET_ALL)    
       
    else:
       print("   Case-DI: " + str(casenum) + "-------------->" + Fore.GREEN + "\033[1m PASSED\033[0m"+ Style.RESET_ALL)         
       print(Style.RESET_ALL)
