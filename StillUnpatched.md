# Still Unpatched?
#### Category:
`Endpoint Forensics` `Network Forensics`

# Difficulty:
`Easy`

#### Tags:
`sysmon` `wireshark` `mimikatz` `T1003` `T1012` `T1572 ` `T1505.003` `T1021.001` `T1112`


#### Instructions:
- Uncompress the lab (pass: cyberdefenders.org)


#### Scenario:
The HR manager, faced a critical security breach when his laptop became the entry point for a cyberattack due to unpatched software. The attack is done by exploiting a vulnerability in one of his software, allowing the attacker to drop malicious files and gain access to the system.

#### Tools
- Wireshark
- Event Viewer or LogViewPlus
- mimikatz

<hr>
#

#### Q1: The attacker started the attack by sending a modified http request. What was the target URL used to apply the exploit?
```
/*******/*****************?****=*
```




Answer: `/RestAPI/ImportTechnicians?step=1`


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
*******.***
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

#### Q17: The Attacker downloaded a file to the Victim's Machine can you tell from where did he download it? (<IP>:<PORT>)
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
Remove-Item -Path "C:\Windows\Temp\logct2.dmp", "C:\Windows\Temp\logctl.zip"
```

#### Q21: In the lab files you will see a bin file which has the OS Credintials and also a password of ZIP file (the second part of the lab). What is USERNAME:PASSWORD? (DON'T CHEAT)
```
Victim:victim123
******:*********
```

#### Q22: After a while the attacker started to search for a confidential data. can you tell what was the first directory he looked at?
```
C:\Users\Victim\Pictures
*:\*****\******\********

```

#### Q23: What Did he try to steal? (filename)
```
Employees.xls
*********.***
```

#### Q25: The fun is not over yet. he decided to download another file to the victim machine. what is the name of that file at the server?
```
file.exe
****.***
```
#### Q26: Then he checked for a service status. What was it?
```
TermService
***********
```

#### Q27: After That he was hungry for more evil. He needed to ensure that they can remotely access the system. How can he access the system Remotely, what protocol does he need?
```
RDP
***
```

#### Q27: What Registery Value Did he change? (path included)
```
HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\fDenyTSConnections
****\******\*****************\*******\******** ******\******************
```
> [!TIP]
> evtx

#### Q28: There is a .bat file was created. Where is it? (Absolute Path including the filename)
```
C:\Users\Victim\Documents\FXS.bat
```


#### Q29: As we noticed this hacker is smart. he never use the real filename. What is the real filename of the file he downloaded combined with its MD5 hash? <FILENAME.EXE>:MD5
```
plink.exe:CC62BA67C1200202D1DA784EA0313408
*****.***:********************************
```

#### Q30: Like you did notice this batch will be used in Establishing SSH Connection. What is the IP address of SSH Server and its Port? (<ip_addr>:<port>)
```
192.168.1.2:443
***.***.*.*:***
```

#### Q31: The actor used the technique of port forwarding to listen on the remote port: `ANS1`, and forward the requests to `ANS2`. ANS* = <ip_addr>:<port>
```
127.0.0.1:49800, 192.168.20.145:3389
ASN1, ANS2
```

#### Q32: What is the type of SSH Server that the attacker uses? (Software Name)
```
SSH-2.0-9.38 FlowSsh: Bitvise SSH Server (WinSSHD) 9.38
SSH-*.*-*.** *******:******** *** ****** (*******) *.**
```
> [!TIP]
> How many handshakes?

#### Q33: Over this SSH Connection the Attacker was able to RDP. Can you identify the timestamp of the first time ? (Y-M-D 24:00)

```
2024-07-20 14:02
****-**-** **:**
```
> [!TIP]
> RDP Clipboard Monitor

<hr>
<br>

# Still Unpatched? Walkthrough

#### We are given a ZIP File with password "cyberdefenders.org"

![image](https://github.com/user-attachments/assets/bdd7e906-7f82-49f6-a7fd-df0870c169cd)


- We Got 4 files [1.pcap, sysmon_log.evtx, logc2.bin, 2.zip]

- After Reading the Tags and The Scenario we can understand that there is a Software that have a vulnerability and this vulnerability have been exploited. Then the attacker gained dumped some credentials `T1003` also there is a webshell  `T1505.003` and RDP `T1021.001`.

### OK, Let's See What We Got Here...
<br>

#### Q1: The attacker started the attack by sending a modified http request. What was the target URL used to apply the exploit?
```
/*******/*****************?****=*
```

- Open `1.pcap` on wireshark
- filter `http`
- Looks we got a POST request from ip `192.168.20.134` which he will probably be the attacker in this lab.
![image](https://github.com/user-attachments/assets/265a38f4-c5be-46ea-8489-87298fa78f81)
- He sent this request to `192.168.20.147` on port `8080` to /RestAPI/ImportTechnicians?step=1
##### - Answer: ```/RestAPI/ImportTechnicians?step=1```

<br>

#### Q2: What Programming Language was the Exploit written in and the library used and it's version?
```
******-********/*.**.*
```
- We can easily look at the User-Agent of the Request and Find our Answer.
![image](https://github.com/user-attachments/assets/011a6a6b-66a6-49a3-9931-ca1477e3132b)

##### - Answer: ```python-requests/2.28.1```

<br>

#### Q3: To exploit the vulnerability the attacker Uploaded a Malicious File. What is the name of that file?
```
*******.***
```
- Untill now the answer still can be found in the same packet
![image](https://github.com/user-attachments/assets/b1d7b46a-3bdd-4431-990b-52e300d5ec8c)


##### - Answer: `msiexec.exe`

<br>

#### Q4: What is the name of the Vulnerable Software that have been Exploited?
```
************ *********** ****
```
- We can look at the evtx file and find the answer or invistigate some packets, let's do both.
- 1. pcap file: if looked at the response of `GET /favicon.ico` we can easily find the Answer in the HTML <title> tag. 

![image](https://github.com/user-attachments/assets/13525953-254f-421d-93bd-c3b61fa597c7)

![image](https://github.com/user-attachments/assets/ef068a20-e2ea-4e0e-a60a-dd7e6e9ffd93)

- 2. evtx file: 

#### - Answer  `ManageEngine ServiceDesk Plus`

<br>

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
*******.***
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
Remove-Item -Path "C:\Windows\Temp\logct2.dmp", "C:\Windows\Temp\logctl.zip"
```

#### Q21: In the lab files you will see a bin file which has the OS Credintials and also a password of ZIP file (the second part of the lab). What is USERNAME:PASSWORD? (DON'T CHEAT)
```
Victim:victim123
******:*********
```

#### Q22: After a while the attacker started to search for a confidential data. can you tell what was the first directory he looked at?
```
C:\Users\Victim\Pictures
*:\*****\******\********

```

#### Q23: What Did he try to steal? (filename)
```
Employees.xls
*********.***
```

#### Q25: The fun is not over yet. he decided to download another file to the victim machine. what is the name of that file at the server?
```
file.exe
****.***
```
#### Q26: Then he checked for a service status. What was it?
```
TermService
***********
```

#### Q27: After That he was hungry for more evil. He needed to ensure that they can remotely access the system. How can he access the system Remotely, what protocol does he need?
```
RDP
***
```

#### Q27: What Registery Value Did he change? (path included)
```
HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\fDenyTSConnections
****\******\*****************\*******\******** ******\******************
```
> [!TIP]
> evtx

#### Q28: There is a .bat file was created. Where is it? (Absolute Path including the filename)
```
C:\Users\Victim\Documents\FXS.bat
```


#### Q29: As we noticed this hacker is smart. he never use the real filename. What is the real filename of the file he downloaded combined with its MD5 hash? <FILENAME.EXE>:MD5
```
plink.exe:CC62BA67C1200202D1DA784EA0313408
*****.***:********************************
```

#### Q30: Like you did notice this batch will be used in Establishing SSH Connection. What is the IP address of SSH Server and its Port? (<ip_addr>:<port>)
```
192.168.1.2:443
***.***.*.*:***
```

#### Q31: The actor used the technique of port forwarding to listen on the remote port: `ANS1`, and forward the requests to `ANS2`. ANS* = <ip_addr>:<port>
```
127.0.0.1:49800, 192.168.20.145:3389
ASN1, ANS2
```

#### Q32: What is the type of SSH Server that the attacker uses? (Software Name)
```
SSH-2.0-9.38 FlowSsh: Bitvise SSH Server (WinSSHD) 9.38
SSH-*.*-*.** *******:******** *** ****** (*******) *.**
```
> [!TIP]
> How many handshakes?

#### Q33: Over this SSH Connection the Attacker was able to RDP. Can you identify the timestamp of the first time ? (Y-M-D 24:00)

```
2024-07-20 14:02
****-**-** **:**
```
> [!TIP]
> RDP Clipboard Monitor

<hr>
