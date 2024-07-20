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
> [!TIP]
> evtx time?

#### Q6: When the malicious file is executed another file is written can you tell where it is located? (Absolute Path including the filename) 
```
C:\Program Files (x86)\ManageEngine\ServiceDesk\custom\login\wbsh.jsp
*:\******* ***** (***)\************\***********\******\*****\****.***
```
> [!TIP]
> 1. evtx + pcap...
> 2. maybe http?

#### Q7: What is the type of the attack that can happen using this file?
```
Web Shell
*** *****
```

#### Q8: Can you tell what is the path of the exe file used to execute this file?
```
C:\Program Files (x86)\ManageEngine\ServiceDesk\jre\bin\java.exe
*:\******* ***** (***)\************\***********\***\***\****.***

```

#### Q9: Now the attacker reached to the initial access, can you tell what privilege does he has? (What User?)
```
NT AUTHORITY\SYSTEM
** *********\******
```

#### Q10: What is the Authentication Method/Protocol did the Threat Actor check for?
```
WDigest
*******
```

#### Q11: The Attacker Modified a registery value write the full registiry path including this value
```
HKLM\System\CurrentControlSet\Control\SecurityProviders\WDigest\UseLogonCredential
****\******\*****************\*******\*****************\*******\******************
```

#### Q12: When this method is enabled. In what format are passwords stored in memory?
```
plaintext
*********
```

#### Q13: What is the proccess that the attacker tried to dump?
```
LSASS
*****
```

#### Q14: What dll file did the attacker use to apply the dump?
```
comsvcs.dll
```

#### Q15: The attacker dumped the process and wrote the dumo to a certain file, and then he downloaded it. can you tell the size of that file? (in bytes)
```
00000
*****
```

#### Q16: Did it Work? (yay, nay)
```
nay
***
```
> [!TIP]
> Based on the Size

### Q17: The Attacker downloaded a file to the Victim's Machine can you tell from where did he download it? (<IP>:<PORT>)
```
192.168.1.2:9000
```

#### Q18: This file seems to be a calculator!!. hmm...? I think it's not a calculator. what is it? 
```
procdump.exe
********.***
```
> [!TIP]
> Invistigate the real filename

#### Q19: Another file has been downloaded from the system. What Was its Size? (in bytes)
```
54998530
********
```
#### Q20: What command did the cover his tracks?
```

```

#### Q21: In the lab files you will see a bin file which has the Credintials and also a password of ZIP file (the second part of the lab). What is USERNAME:PASSWORD? (DON'T CHEAT)
```
Victim:victim123
******:*********
```

#### Q22: 

