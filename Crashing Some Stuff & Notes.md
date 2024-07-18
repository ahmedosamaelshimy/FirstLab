


PWF - Investigation #001
System Information
    Computername.
        HKLM\System\CurrentControlSet\Control\Computername\
    Windows Version:
        NT\Currentversion\
    Timezone:
        HKLM\System\CurrentControlSet\Control\TimeZonelnformation\
    Network Information:
        ices\Tcpi p\Parameters\lnterfaces\{i nterface-name}
    Shutdown time:
        me
    Defender settings:
        HKLM\Software\Microsoft\Windows Defender\








[LSASS](https://www.synacktiv.com/en/publications/windows-secrets-extraction-a-summary)
Recovering LSASS memory is probably the most known technique to retrieve sensitive secrets. Indeed, this process is responsible for handling authentication on Windows and can contain the following elements:

User / Machine hashes.
Cleartext credentials (if wdigest is enabled).
Kerberos tickets (TGT and ST).
DPAPI cached keys.
As such, successfully recovering these elements is often the best way to elevate privileges from a first compromise to Domain Administrator in an Active Directory environment. As this process is highly sensitive, attackers and defenders are battling, antivirus are getting better and new techniques are regularly discovered to bypass them.

Moreover, Microsoft has introduced different protections over the years to protect against these attacks such as RunAsPPL and Credential Guards.

As this article is focused on the offensive side, let's talk about the different techniques one can use to retrieve LSASS secrets.





[WDigest settings](https://support.microsoft.com/en-us/topic/microsoft-security-advisory-update-to-improve-credentials-protection-and-management-may-13-2014-93434251-04ac-b7f3-52aa-9f951c14b649)

After you install this security update, you can control how installed WDigest credentials can be saved by using a registry setting. To prevent WDigest credentials from being stored in memory, a Group Policy setting can be applied to the UseLogonCredential registry entry under the following subkey:

HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\WDigest

If the UseLogonCredential value is set to 0, WDigest will not store credentials in memory.

If the UseLogonCredential value is set to 1, WDigest will store credentials in memory.

After you install this security update, the default setting for this value is 1 in Windows 7, Windows Server 2008 R2, Windows 8, and Windows Server 2012. You can use the "easy fix" solution in this article to change this setting to 0. This will disable WDigest passwords from being stored in memory.

Note By default in Windows 8.1 and Windows Server 2012 R2 and later versions, caching of credentials in memory for WDigest is disabled (the UseLogonCredential value defaults to 0 when the registry entry is not present).

The observed change in behavior when the UseLogonCredential value is set to 0 is that you may notice that credentials are required more frequently when you use WDigest.
