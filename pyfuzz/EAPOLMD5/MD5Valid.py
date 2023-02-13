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
import pyfuzz.EAPOLMD5.MD5Invalid as InvalidMD5
#from pyfuzz.EAPOLMD5 import MD5Invalid as InvalidMD5
Directorypath = os.path.dirname(__file__)


##########################################################################################################################################
# EAPOL-MD5 Interporability Function
def EAPOL_MD5_INTERPORABILITY():
 
  # user input (FreeRadius username)
    username=input(Fore.BLUE+"\033[1m>>\033[0m" +Fore.BLUE+" Enter FreeRadius username:"+Style.RESET_ALL)
    while not username:      
          username=input(Fore.BLUE+"\033[1m>>\033[0m" +Fore.BLUE+ " Please Re-Enter FreeRadius username:"+Style.RESET_ALL) 


  # user input (FreeRadius password) 
    password = binascii.hexlify(bytes(input(Fore.BLUE+"\033[1m>>\033[0m" +Fore.BLUE+ " Enter FreeRadius password:"+Style.RESET_ALL), encoding="ascii")).decode("utf-8")
    if not password:
           print("   you entred an empty value as password")
    hexdump2pass = r"\x" + r"\x".join(password[n : n+2] for  n in range(0, len(password), 2))
  
   
  # user input (source interface)   
    sourceinterface=input(Fore.BLUE+"\033[1m>>\033[0m" +Fore.BLUE+ " Enter source interface:"+Style.RESET_ALL)                 
    while not sourceinterface: 
              sourceinterface = input(Fore.BLUE+"\033[1m>>\033[0m" +Fore.BLUE+ " Please Re-Enter source interface:"+Style.RESET_ALL) 
    try:
      interfacestatus = open('/sys/class/net/' + sourceinterface + '/carrier').read().strip()
      if interfacestatus == '1':
         print("   Physical connection between PyFuzz and authenticator on " + sourceinterface + Fore.GREEN + "\033[1m : GOOD\033[0m")
      else:
         print("   Physical connection between PyFuzz and authenticator on " + sourceinterface + Fore.RED + "\033[1m : BAD\033[0m")
         sys.exit(1)
    # save logging error  
    except Exception as Argument:
           f = open ("log.txt", "a")
           f.write(str(Argument))
           f.close()
           print(Fore.RED + "Error:please make sure that you entred a correct interface name"+Style.RESET_ALL)
           print(Fore.RED + "Error:check" + Directorypath + "/log.txt for more details"+Style.RESET_ALL)
           sys.exit(1)
    

  # user input (source macadd)
    sourcemacaddress = open('/sys/class/net/' + sourceinterface + '/address').read().strip()
    print(Fore.BLUE+"\033[1m>>\033[0m" +Fore.BLUE+ " Enter source mac-address: " +Style.RESET_ALL + sourcemacaddress)
    while not sourcemacaddress:       
              sourcemacaddress=input(Fore.BLUE+"\033[1m>>\033[0m" +Fore.BLUE+ " Please Re-Enter source mac-address:"+Style.RESET_ALL) 
 
    print(Style.RESET_ALL)

##########################################################################################################################################

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
    
    try:
      while thread1.val2 != 1:               
              thread1 = snifthread1()
              thread2 = sendthread1()
              thread1.start()
              thread2.start()
              thread1.join()
              thread2.join()
    except Exception as Argument:
              f = open ("log.txt", "a")
              f.write(str(Argument))
              f.close()
              print(Fore.RED + "Error:please repeat the test, pyfuzz didn't capt the EAP-Request"+Style.RESET_ALL)
              print(Fore.RED + "Error:check" + Directorypath + "/log.txt for more details"+Style.RESET_ALL)
              sys.exit(1)
 
   
    idREQ = thread1.val1           
                                             
 # send EAP-RESPONSE Identity and sniff "id,value" from the EAP-REQUEST Challenge 
    class snifthread2(Thread):
          def __init__(self):
              Thread.__init__(self)
          def run(self):   
               s = sniff(filter="ether proto 0x888e", iface=sourceinterface, count=2)
               self.val3 = s[1][EAP].code 
               sleep(1)               
               if self.val3 == 4:
                     print(Fore.RED + "Error:pyfuzz receive Failure msg from authenticator on its EAP-Response"+Style.RESET_ALL)
                     print(Fore.RED + "Error:Repeat Test again or verifiy your connectivity then repeat the test"+Style.RESET_ALL)
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
       print("Interoperability " + Fore.RED + "\033[1mFAILED\033[0m " + Fore.WHITE + ",Fuzzing not ready to use:")
       print("please verify your indentity username and password then re-test")
    else:
       print("Interoperability " + Fore.GREEN + "\033[1mPASSED\033[0m " + Fore.WHITE + ",Fuzzing ready to use")
       print("sending LOGOFF EAPOL")
       sendp(Ether(src=sourcemacaddress, dst="01:80:c2:00:00:03")/EAPOL(type=2), iface=sourceinterface)  
       InvalidMD5.EAPOL_MD5_FUZZING(sourceinterface, sourcemacaddress, username, hexdump2pass)
       print(Style.RESET_ALL)

   
