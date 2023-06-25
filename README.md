# pyfuzz
EAP/RADIUS Mutation Protocol Fuzzing tool written in python act like client/server that will send malformed packets toward SUT/DUT. 

PyFuzz use scapy as a principal module. The benefits from PyFuzz is to allow the end user to added more complex test cases depending on the SUT functionality.

pyfuzz responsable to verify the SUT health after the sending of each malformed packets.

#### Please note: pyfuzz will cover other protocols but for the moment pyfuzz focus only on EAPOL/RADIUS fuzzing.

### PyFuzz Funtionality
-------------------------------------------------------------------------------------------------------------------------------
Once you install pyfuzz by following these steps:
```diff
git clone https://github.com/VraiHack/pyfuzz
cd PyFuzz
pip install .
PyFuzz
``` 
1- The user will be asked to choose a Fuzzing protocol and a Fuzzing templates

2- Then, he will be aksed to configure PyFuzz according to the slected template.

3- An interporability check will be done to make sure that SUT respond on valid packet (e2e communciation).

4- If interoporability "passed" the end user will be asked to choose Fuzzing test cases to run.

5- The end user will be responsable to check and verify the health, alarms, status of the SUT during the Fuzz.

### pyfuzz Client Templates Status (release-1)
-------------------------------------------------------------------------------------------------------------------------------
| Protocols | Templates status | Readiness | Tested-Verified | Templates-Version | Developer.name | Tutorial
| --- | --- | --- | --- | --- | --- | --- |
| EAP | EAPOL-MD5 | OnGoing: adding more invalid cases | Ubuntu 20.04.5 / Kali 2022.4  | 1.0.0 | VraiHack | [youtube](https://www.youtube.com/watch?v=jLkujI5uhn4)
| EAP | EAPOL-TLS | Not-Started | ...... | 1.0.0 | NotAssigned --- |
| RADIUS | eap-md5-response | Not-Started | ...... | 1.0.0 | NotAssigned --- |
| RADIUS | client access-response | Not-Started | ...... | 1.0.0 | NotAssigned --- |
| RADIUS | client accounting-response | Not-Started | ...... | 1.0.0 | NotAssigned --- |

release-1: mean only one template ready to use

These days, i am writing a book in HW security beside of my work so i really don't have time to complete this project alone even if i have all the code steps in my head ,concerning other templates but no time to type them.

For that, if you Want to contribute that will be Great, you will learn a lot! Please take a few minutes to [read this](https://github.com/VraiHack/pyfuzz/blob/main/contribute.md)!
