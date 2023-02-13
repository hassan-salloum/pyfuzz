import os
import re
import time
import hashlib
import binascii
from tabulate import tabulate
from os import system
from time import sleep
from scapy.all import *
from binascii import hexlify
from threading import Thread
from datetime import datetime
from datetime import date
from colorama import Fore, Back , Style
import pyfuzz.EAPOLMD5.SUThealth as CheckSUT

##########################################################################################################################################
def EAPOL_MD5_FUZZING(sourceinterface, sourcemacaddress, username, hexdump2pass):
    print()
    print(Fore.RED+"\033[1mD: Fuzzing Category:\033[0m"+Style.RESET_ALL)
    
	    
    # Fuzzing category in EAPOL-MD5 that we can Fuzz
    categchoice_table = [["Category", "Quick-Description"],
                         [1, "EAPOL-Start.EthFrame"],
                         [2, "EAP-Response-Identity.EthFrame"],
                         [3, "EAP-Response-Challenge.EthFrame"]]
    print(tabulate(categchoice_table, headers="firstrow",missingval="-", tablefmt="grid"))    
    categchoice=input(Fore.BLUE+"\033[1m>>\033[0m" +Fore.BLUE+ " Enter Fuzzing category choice:"+Style.RESET_ALL)
    while not categchoice:
	      categchoice=input(Fore.BLUE+"\033[1m>>\033[0m" +Fore.BLUE+ " Please, Enter Fuzzing category choice:"+Style.RESET_ALL)
	 
    # Fuzzing cases in each category
    if categchoice == '1' :
       casechoice_table = [["Case-ID","Category.EAPOL-Start","Quick-Description"],
                           [1, "EthernetFrame","replace the whole ethernet-Frame with random bytes"],
	                   [2, "EthernetFrame.header","Incorrect source/destination mac address"],
                           [3, "EthernetFrame.type","Incorresponding type value"],
                           [4, "EthernetFrame.Padding","Added padding bytes"],
	      
                           [5, "EthernetFrame.payload","Replace the whole EAPOL-Start packet with random bytes"],
                           [6, "EthernetFrame.payload.packet.version","Incorresponding version"],
                           [7, "EthernetFrame.payload.packet.type","Incorresponding type value"],
                           [8, "EthernetFrame.payload.packet.length","Incorresponding length value"],
	      
                           [9, "EthernetFrame.payload.packet.body","Addeding body field with random bytes"]]
       print(tabulate(casechoice_table, headers="firstrow",missingval="-", tablefmt="grid"))
	    
    elif categchoice == '2' :
         casechoice_table = [["Case-ID","Category.EAP-Response-Identity","Quick-Description"],
                             [10, "EthernetFrame","replace the whole ethernet-Frame with random bytes"],
                             [11, "EthernetFrame.header","Incorrect source/destination mac-address"],
                             [12, "EthernetFrame.type","Incorresponding Type value"],
                             [13, "EthernetFrame.Padding","Added padding bytes"],
	      
                             [14, "EthernetFrame.payload","Replace the whole EAPOL-Start packet with random bytes"],
                             [15, "EthernetFrame.payload.packet.version","Incorresponding Version"],
                             [16, "EthernetFrame.payload.packet.type","Incorresponding Type value"],
                             [17, "EthernetFrame.payload.packet.length","Incorresponding length value"],
	      
                             [18, "EthernetFrame.payload.packet.body","Replace the whole body with random bytes"],
                             [19, "EthernetFrame.payload.packet.body.format.code","Incorresponding Code value"],
                             [20, "EthernetFrame.payload.packet.body.format.Id","Incorresponding Id value"],
                             [21, "EthernetFrame.payload.packet.body.format.Lenght","Incorresponding Length value"],
                             [22, "EthernetFrame.payload.packet.body.format.Type","Incorresponding Type value"],
                             [23, "EthernetFrame.payload.packet.body.format.username","Incorresponding Username value"]]
         print(tabulate(casechoice_table, headers="firstrow",missingval="-", tablefmt="grid"))
	     
    elif categchoice == '3' :       
         casechoice_table = [["Case-ID","Category.EAP-Response-Challenge","Quick-Description"], 
                             [24, "EthernetFrame","replace the whole ethernet-Frame with random bytes"],
                             [25, "EthernetFrame.header","Incorrect source/destination mac-address"],
                             [26, "EthernetFrame.type","Incorresponding Type value"],
                             [27, "EthernetFrame.Padding","Added padding bytes"],
	      
                             [28, "EthernetFrame.payload","Replace the whole EAPOL-Start packet with random bytes"],
                             [29, "EthernetFrame.payload.packet.version","Incorresponding Version"],
                             [30, "EthernetFrame.payload.packet.type","Incorresponding Type value"],
                             [31, "EthernetFrame.payload.packet.length","Incorresponding length value"],
	      
                             [32, "EthernetFrame.payload.packet.body","Replace the whole body with random bytes"],
                             [33, "EthernetFrame.payload.packet.body.format.code","Incorresponding Code value"],
                             [34, "EthernetFrame.payload.packet.body.format.Id","Incorresponding Id value"],
                             [35, "EthernetFrame.payload.packet.body.format.Lenght","Incorresponding Length value"],
                             [36, "EthernetFrame.payload.packet.body.format.Type","Incorresponding Type value"],
                             [37, "EthernetFrame.payload.packet.body.format.username","Incorresponding Username value"],
	      
                             [38, "EthernetFrame.payload.packet.body.format.challenge.type","Incorresponding Type value"],
                             [39, "EthernetFrame.payload.packet.body.format.challenge.valuesize","Incorresponding ValueSize"],
                             [40, "EthernetFrame.payload.packet.body.format.challenge.value","Incorrect Value"],
                             [41, "EthernetFrame.payload.packet.body.format.challenge.ExtraValue","Incorresponding ExtraValue"]]
         print(tabulate(casechoice_table, headers="firstrow",missingval="-", tablefmt="grid"))
    
    # the call cases funtion according to user input (copy past this one for other invalid template)  
    userlist = [] 
    casechoice=input(Fore.BLUE+"\033[1m>>\033[0m" +Fore.BLUE+" Enter ID cases choice(e.g 4 or 1+4 or 1+2-4+7-9):"+Style.RESET_ALL)
    while not casechoice:
	      casechoice=input(Fore.BLUE+"\033[1m>>\033[0m" +Fore.BLUE+" Please, Enter ID cases choice(e.g 4 or 1+4 or 1+2-4+7-9):"+Style.RESET_ALL)
	
    array = re.split(r"(\D+)", casechoice)    
    Directorypath = os.path.dirname(__file__)
    
    if array[0].isdecimal() :
       Firstcurrentval = int(array[0]) 
       userlist.append(Firstcurrentval)          
       counter = 1
    else:
       print(Fore.RED + "Error: You entered a bad case ID format"+Style.RESET_ALL)
       sys.exit()
          
    while counter < (len(array)-1):
    
         if array[counter] == '+' and array[counter+1].isdecimal():
            #print("we found delimter +")
            Firstcurrentval = int(array[counter+1])
            userlist.append(Firstcurrentval)         
            counter+=2     
            
         elif array[counter] == '-' and array[counter+1].isdecimal():
            #print("we found delimter -")
            Lastcurrentval = int(array[counter+1])            
            while Firstcurrentval < Lastcurrentval: 
                  userlist.append(Firstcurrentval+1)               
                  Firstcurrentval+=1
            counter+=2
            
         else:
            print(Fore.RED + "Error: You entered a bad case ID format"+Style.RESET_ALL)
            sys.exit()
       
    print(userlist) 
	    
##########################################################################################################################################
    ######################################Scappy EAPOL-Start packet format#############################################   
    #<Ether  dst=01:80:c2:00:00:03 src=b8:27:eb:55:66:03 type=EAPOL |                                                 #
    #<EAPOL  version=802.1X-2001 type=EAPOL-Start len=0 |>>                                                           #
    ###################################################################################################################


    ######################################Scappy Response-Identity packet format#######################################
    #<Ether  dst=01:80:c2:00:00:03 src=b8:27:eb:55:66:03 type=EAPOL |                                                 #
    #<EAPOL  version=802.1X-2001 type=EAP-Packet len=16 |                                                             #
    #<EAP    code=Response id=1 len=16 type=Identity identity='user_radius' |>>>                                      #
    ###################################################################################################################


    ######################################Scappy Response-Challenge packet format######################################
    #<Ether  dst=01:80:c2:00:00:03 src=b8:27:eb:55:66:03 type=EAPOL |                                                 #
    #<EAPOL  version=802.1X-2001 type=EAP-Packet len=22 |                                                             #
    #<EAP_MD5  code=Response id=2 len=22 type=MD5-Challenge value_size=16 value=05db8f903dc9adc5874eb2cab3aa725b |>>> #
    ###################################################################################################################
##########################################################################################################################################    

    # define the function blocks
    def case1():
        print("   EAPOL-Start: replace the whole ethernet-Frame with random bytes")
        print("   case under Dev")
        print()

    def case2():
        print("   EAPOL-Start: Incorrect source/destination mac address")
        print("   case under Dev")
        print()	
    
    def case3():
        print("   EAPOL-Start: Incorresponding type value")
        print("   case under Dev")
        print()
	
    def case4():
        print("   EAPOL-Start: Added padding bytes")
        print("   case under Dev")
        print()
	
    def case5():
        print("   EAPOL-Start: Replace the whole EAPOL-Start packet with random bytes")
        print("   case under Dev")
        print()

    def case6():
        print("   EAPOL-Start: Incorresponding version")
        sendp(Ether(src=sourcemacaddress, dst="01:80:c2:00:00:03")/EAPOL(type=12), iface=sourceinterface)
        sleep(1)
        print("   sending LOGOFF EAPOL")
        sendp(Ether(src=sourcemacaddress, dst="01:80:c2:00:00:03")/EAPOL(type=2), iface=sourceinterface)
        sleep(1)
        print(Fore.YELLOW + "   CHECK CONNECTION AFTER FUZZ"+Style.RESET_ALL)
        CheckSUT.EAPOL_MD5_SUThealth_start(sourceinterface, sourcemacaddress, username, hexdump2pass, casenum)
        print()

    def case7():
        print("   EAPOL-Start: Incorresponding type value")
        print("   case under Dev")
        print()

    def case8():
        print("   EAPOL-Start: Incorresponding length value")
        print("   case under Dev")
        print()
    
    def case9():
        print("   EAPOL-Start: Addeding body field with random bytes")
        print("   case under Dev")
        print()

    def case10():
        print("   EAP-Response-Identity: replace the whole ethernet-Frame with random bytes")
        print("   case under Dev")
        print()

    def case11():
        print("   EAP-Response-Identity: Incorrect source/destination mac-address")
        print("   case under Dev")
        print()

    def case12():
        print("   EAP-Response-Identity: Incorresponding Type value")
        print("   case under Dev")
        print()
    
    def case13():
        print("   EAP-Response-Identity: Added padding bytes")
        print("   case under Dev")
        print()

    def case14():
        print("   EAP-Response-Identity: Replace the whole EAPOL-Start packet with random bytes")
        print("   case under Dev")
        print()

    def case15():
        print("   EAP-Response-Identity: Incorresponding Version")
        print("   case under Dev")

    def case16():
        print("   EAP-Response-Identity: Incorresponding Type value")
        print("   case under Dev")
        print()
    
    def case17():
        print("   EAP-Response-Identity: Incorresponding length value")
        print("   case under Dev")
        print()

    def case18():
        print("   EAP-Response-Identity: Replace the whole body with random bytes")
        print("   case under Dev")
        print()

    def case19():
        print("   EAP-Response-Identity: Incorresponding Code value")
        print("   case under Dev")
        print()

    def case20():
        print("   EAP-Response-Identity: Incorresponding Id value")
        print("   case under Dev")
        print()
    
    def case21():
        print("   EAP-Response-Identity: Incorresponding Length value")
        print("   case under Dev")
        print()

    def case22():
        print("   EAP-Response-Identity: Incorresponding Type value")
        print("   case under Dev")
        print()

    def case23():
        print("   EAP-Response-Identity: Incorresponding Username value")
        print("   case under Dev")
        print()

    def case24():
        print("   EAP-Response-Challenge: replace the whole ethernet-Frame with random bytes")
        print("   case under Dev")
        print()
    
    def case25():
        print("   EAP-Response-Challenge: Incorrect source/destination mac-address")
        print("   case under Dev")
        print()

    def case26():
        print("   EAP-Response-Challenge: Incorresponding Type value")
        print("   case under Dev")
        print()

    def case27():
        print("   EAP-Response-Challenge: Added padding bytes")
        print("   case under Dev")
        print()

    def case28():
        print("   EAP-Response-Challenge: Replace the whole EAPOL-Start packet with random bytes")
        print("   case under Dev")
        print()
    
    def case29():
        print("   EAP-Response-Challenge: Incorresponding Version")
        print("   case under Dev")
        print()

    def case30():
        print("  EAP-Response-Challenge: Incorresponding Type value")
        print("  case under Dev")
        print()

    def case31():
        print("  EAP-Response-Challenge: Incorresponding length value")
        print("  case under Dev")
        print()

    def case32():
        print("   EAP-Response-Challenge: Replace the whole body with random bytes")
        print("   case under Dev")
        print()
    
    def case33():
        print("   EAP-Response-Challenge: Incorresponding Code value")
        print("   case under Dev")
        print()

    def case34():
        print("   EAP-Response-Challenge: Incorresponding Id value")
        print("   case under Dev")
        print()

    def case35():
        print("  EAP-Response-Challenge: Incorresponding Length value")
        print("  case under Dev")
        print()

    def case36():
        print("   EAP-Response-Challenge: Incorresponding Type value")
        print("   case under Dev")
        print()
    
    def case37():
        print("   EAP-Response-Challenge: Incorresponding Username value")
        print("   case under Dev")
        print()

    def case38():
        print("   EAP-Response-Challenge: Incorresponding Type value")
        print("   case under Dev")
        print()

    def case39():
        print("   EAP-Response-Challenge: Incorresponding ValueSize")
        print("   case under Dev")
        print()

    def case40():
        print("   EAP-Response-Challenge: Incorrect Value")
        print("   case under Dev")
        print()
    
    def case41():
        print("   EAP-Response-Challenge: Incorresponding ExtraValue")
        print("   case under Dev")
        print()
    
    # fuzzing result saved in pcap format
    Directorypath = os.path.dirname(__file__)
    pcapresult = AsyncSniffer(filter="ether proto 0x888e", store=True, iface=sourceinterface)
    pcapresult.start()  

    # repetition cases number
    repetition=input(Fore.BLUE+"\033[1m>>\033[0m" +Fore.BLUE+" Enter repetition number >=1 for tests cases:"+Style.RESET_ALL)
    while not repetition or repetition < '1':
	      repetition=input(Fore.BLUE+"\033[1m>>\033[0m" +Fore.BLUE+" Please, Enter repetition number for tests cases:"+Style.RESET_ALL)
    
    for repeat in range(int(repetition)):
        for action in range(len(userlist)):
            casenum = userlist[action]
            if userlist[action] == 1: 
               case1()
            elif userlist[action] == 2:
                 case2()       
            elif userlist[action] == 3:
                 case3()       
            elif userlist[action] == 4:
                 case4()
            elif userlist[action] == 5:
                 case5()       
            elif userlist[action] == 6:
                 case6()       
            elif userlist[action] == 7:
                 case7()       
            elif userlist[action] == 8:
                 case8()       
            elif userlist[action] == 9:
                 case9()       
            elif userlist[action] == 10:
                 case10()       
            elif userlist[action] == 11:
                 case11()       
            elif userlist[action] == 12:
                 case12()       
            elif userlist[action] == 13:
                 case13()       
            elif userlist[action] == 14:
                 case14()       
            elif userlist[action] == 15:
                 case15()       
            elif userlist[action] == 16:
                 case16()       
            elif userlist[action] == 17:
                 case17()       
            elif userlist[action] == 18:
                 case18()       
            elif userlist[action] == 19:
                 case19()       
            elif userlist[action] == 20:
                 case20()       
            elif userlist[action] == 21:
                 case21()       
            elif userlist[action] == 22:
                 case22()       
            elif userlist[action] == 23:
                 case23()       
            elif userlist[action] == 24:
                 case24()       
            elif userlist[action] == 25:
                 case25()       
            elif userlist[action] == 26:
                 case26()       
            elif userlist[action] == 27:
                 case27()       
            elif userlist[action] == 28:
                 case28()       
            elif userlist[action] == 29:
                 case29()       
            elif userlist[action] == 30:
                 case30()       
            elif userlist[action] == 31:
                 case31()       
            elif userlist[action] == 32:
                 case32()       
            elif userlist[action] == 33:
                 case33()       
            elif userlist[action] == 34:
                 case34()       
            elif userlist[action] == 35:
                 case35()       
            elif userlist[action] == 36:
                 case36()       
            elif userlist[action] == 37:
                 case37()       
            elif userlist[action] == 38:
                 case38()       
            elif userlist[action] == 39:
                 case39()       
            elif userlist[action] == 40:
                 case40()       
            elif userlist[action] == 41:
                 case41()
			
    # reminder message about the output
    pcapresult.stop()
    results=pcapresult.results 
    now = datetime.now()
    current_time = str(now.strftime("%H:%M:%S"))
    current_day = str(date.today())
    wrpcap(Directorypath + "/RESULTS/EAPOLMD5_" + current_day + "_" + current_time + ".pcap", results)    
    print("\x1B[3mFuzzing result saved in:" + Directorypath + "/RESULTS/EAPOLMD5_" + current_day + "_" + current_time + ".pcap\x1B[0m")
