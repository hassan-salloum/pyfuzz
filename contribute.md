#### Logistic steps you may need to follow if you want to contribute in pyfuzz
-------------------------------------------------------------------------------------------------------------------------------
1- send me an <a href="mailto:vrai.hack@hotmail.com?">email</a> about your interst to contribute in the developmenet of the X (e.g EAPOLTLS) template.

2- After confiormation from our side, Your Github name will be assinged on the Template in the README and in the main.py.

3- Few days later, You will receive a "detailed technical document"  that describe what you must to do and how your code should cover from functioanlity (this will allow us to ensure the expectation need from the template that you want to develop) 

4- You will receive a monthly notification to ensure progression (in absence of response on our emails, we will consider that your are no longer interest in the contribution)

5- Mergin can be done after code review and test/validation for our side.


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

#### Importants
-------------------------------------------------------------------------------------------------------------------------------
Note 1: Pyfuzz not the first fuzzing tool so to inspire your coding way, you may need to study other tools (reduce time):[check this out](https://github.com/VraiHack/pyfuzz/blob/main/documents/For%20contributer%20only-Inspire%20your%20coding%20way..xlsx). But keep in mind, pyfuzz not an automation tool, we need hard coding and not module calling from other fuzzing tool.

Note 2: Do not use library in your code that require dedicated python version (e.g match only support python3.10), we need the tool to work on simple linux system.

Note 3: Avoid if you can the usage of bash subprocess in your coding (we need a tool fully coded in python)
