## Deprecated

**This project is no longer supported and is not maintained.**

# pyfuzz
EAP/RADIUS Mutation Protocol Fuzzing tool written in python act like client/server that will send malformed packets toward SUT/DUT. 
PyFuzz use scapy as a principal module. The benefits from PyFuzz is to allow the end user to added more complex test cases depending on the SUT functionality.
pyfuzz responsable to verify the SUT health after the sending of each malformed packets.

### Pyfuzz Funtionality
-------------------------------------------------------------------------------------------------------------------------------
Once you install pyfuzz by following these steps:
```diff
git clone https://github.com/VraiHack/pyfuzz
cd PyFuzz
pip3 install -r requirements-dev.txt
python3 /path/to/pyfuzz/pyfuzz/main.py
``` 
1- The user will be asked to choose a Fuzzing protocol (EAP or RADIUS) and a Fuzzing templates (for the moment only support EAP)

2- Then, he will be aksed to configure PyFuzz according to the slected template.

3- An interporability check will be done to make sure that SUT respond on valid packet (e2e communciation).

4- If interoporability "passed" the end user will be asked to choose Fuzzing test cases to run.

5- The end user will be responsable to check and verify the health, alarms, status of the SUT during the Fuzz.

### pyfuzz Client Templates Status (release-1)
-------------------------------------------------------------------------------------------------------------------------------
| Protocols | Templates status | Readiness | Tested-Verified | Templates-Version | Developer.name | Tutorial
| --- | --- | --- | --- | --- | --- | --- |
| EAP | EAPOL-MD5 | OnGoing: adding more invalid cases | Ubuntu 20.04.5 / Kali 2022.4  | 1.0.0 | VraiHack | [youtube](https://www.youtube.com/watch?v=jLkujI5uhn4)

release-1: mean only one template ready to use
