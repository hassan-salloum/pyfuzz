#### Technical steps, you may need to follow if you want to contribute in pyfuzz
-------------------------------------------------------------------------------------------------------------------------------
First, This is the Project tree:
   
    |______LICENSE
    |______README.md
    |______contribute.md
    |______setup.py
    |______setup.cfg
    |______requirements-dev.txt
    |______log.txt 
    |______documents
    |______templates
               |______main.py
               |________init__.py
               |______EAPOLMD5
                             |________init__.py
                             |______SUThealth.py
                             |______MD5Invalid.py
                             |______MD5Valid.py
                             |______RESULTS
                                          |______DoNotDelete.pcap
               |______EAPOLTLS
                        |________init__.py
                        |______SUThealth.py
                        |______TLSInvalid.py
                        |______TLSValid.py
                        |______RESULTS
                                     |______DoNotDelete.pcap
                            
1- git clone the pyfuzz to work directory.

2- Added project to your path (no need to build): export PYTHONPATH="${PYTHONPATH}:/path/to/pyfuzz/"

3- cd /path/to/pyfuzz

4- Install the requirement-dev.txt : pip3 install -r requirements-dev.txt

5- Inside the "templates" repo create a new folder named (X e.g EAPOLTLS in case you want to develop the EAPOLTLS).

6- Inside the "EAPOLTLS" folder create:
- __init__.py : empty just for building package purpose
- SUThealth.py : this will be used to verify the health ofthe SUT after the sending of malformed packets
- TLSValid.py : where the "TLSValid.py" will be used in the Interoporability check
- TLSInvalid.py : and the "TLSInvalid.py" will be used to send tests cases (malformed packets).
- RESULTS : added to it any empty file (for cloning pupose an empty repo can't be pushed to github, you can take DoNotDelete.pcap from EAPOLMD5) 

7- Test your code: python3 /path/to/pyfuzz/pyfuzz/main.py

8- Create a techincal-document that describe how you Fuzz it in details and and add this later to the "documents" repo
