#!python
import sys
import os
import pyfuzz.EAPOLMD5.MD5Valid as ValidMD5
#from pyfuzz.EAPOLMD5 import MD5Valid as ValidMD5
from colorama import Fore, Back , Style

def start():
   # clear Banner
   os.system('clear')
   print(Fore.YELLOW + """ \033[1m
+------PyFuzz Protocols------+
|    EAP     |    RADIUS     |
+-----1--------------2-------+
   \033[0m """)
   print ("\033[1m[Thank You For Choosing PyFuzz release-1 For Your Fuzzing Activity]\033[0m")
   print()
   Directorypath = os.path.dirname(__file__)


   # Protocol selection
   Protocol=input(Fore.RED+"\033[1mA: Enter Fuzzing Protocol:\033[0m"+Style.RESET_ALL)
   while not Protocol:
             Protocol=input(Fore.RED+"\033[1mA: Please, Enter Fuzzing Protocol:\033[0m"+Style.RESET_ALL)
   if Protocol == "1":
      print("EAP have two templates: MD5 [option: 1] and TLS [option: 2]")      
   elif Protocol =="2":
        print("not ready, work will start soon")
        sys.exit(1)
         
   # Templates selection
   print()
   Template=input(Fore.RED+"\033[1mB: Enter Fuzzing Template:\033[0m"+Style.RESET_ALL)
   while not Template: 
             Template=input(Fore.RED+"\033[1mB: Please, Enter Fuzzing Template:\033[0m"+Style.RESET_ALL)

   if ((Protocol == "1") and (Template =="1")):
      print("\x1B[3mEAPOL-MD5 Developed by vraihack, version: 1.0.0\x1B[0m")
      print("\x1B[3mLearn more about EAPOL-MD5 and how we tested:/pyfuzz/documents/TD-EAPOL-MD5.pdf\x1B[0m")
      print()
      print(Fore.RED+'\033[1mC: Interoperability Verification\033[0m'+Style.RESET_ALL)  
      ValidMD5.EAPOL_MD5_INTERPORABILITY() 
      
   elif ((Protocol == "1") and (Template =="2")):
        print("not ready, work will start soon")
        sys.exit(1)
      
   else :
        print("Please choose a valid option: 1, 2, 3 ....")

if __name__ == "__main__":
    exit(start())
