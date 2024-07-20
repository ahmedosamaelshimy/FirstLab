# UnpatchedYet?
#### Category:
`Endpoint Forensics` `Network Forensics`

# Difficulty:
`Easy`

#### Tags:
`sysmon` `wireshark` `mimikatz` `T1003` `T1012` `T1572 ` `T1505.003` `T1190` `T1021.001` `T1112`


#### Instructions:
- Uncompress the lab (pass: cyberdefenders.org)


#### Scenario:
The HR manager, faced a critical security breach when his laptop became the entry point for a cyberattack due to unpatched software. The attack is done by exploiting a vulnerability in one of his software, allowing the attacker to drop malicious files and gain access to the system.

#### Tools
- Wireshark
- Event Viewer or LogViewPlus
- mimikatz

<hr>

#### Q1: The attacker started the attack by sending a modified http request. What was the target URL used to apply the exploit?
```
/RestAPI/ImportTechnicians?step=1
/*******/*****************?****=*
```

#### Q2: What Programming Language was the Exploit written in and the library used and it's version?
```
python-requests/2.28.1
******-********/*.**.*
```

#### Q3: To exploit the vulnerability the attacker Uploaded a Malicious File. What is the name of that file?
```
msiexec.exe
*******.***
```

#### Q4: What is the name of the Vulnerable Software that have been Exploited?
```
ManageEngine ServiceDesk Plus
************ *********** ****
```

#### Q5: The Exploit consists of 2 stages, in the first stage the attacker uploads the malicious file, and in the second stage it involved initiating instalation of Site24x7 and the installation is done by executing the malicious file that have been uploaded by the attacker. What Command Used in the installation?
```
msiexec.exe /i Site24x7WindowsAgent.msi EDITA1=null /qn
*******.*** /* ********************.*** ******=**** /**
```
> [!TIP] evtx time?

#### Q6: When the malicious file is executed another file is written can you tell where it is located? (Absolute Path including the filename) 
```
C:\Program Files (x86)\ManageEngine\ServiceDesk\custom\login\wbsh.jsp
*:\******* ***** (***)\************\***********\******\*****\****.***
```

####

