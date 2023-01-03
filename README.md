# nse-exchange

Nmap NSE scripts to check against exchange vulnerability (CVE-2022-41082).
NSE scripts check most popular exposed services on the Internet. It is basic script which checks if virtual patching works.

### Examples

Since, there is no patch currently - only workarounds are checked if host is vulnerable.

Simple Example:
```
nmap -sV -T4 -v --script=http-vuln-cve-2022 scanme.nmap.org
```

Faster run (large subnets):
```
nmap -p443 -T4 -v --script=http-vuln-cve-2022 10.0.0.0/16
```

## Sample Output

### Vulnerable
Vulnerable:
```
nmap -Pn -T4 -p443 --script=http-vuln-cve2022-41082.nse 127.0.0.1

Starting Nmap 7.92 ( https://nmap.org ) at 2022-10-01 13:37 CEST
Nmap scan report for localhost (127.0.0.1)
Host is up (0.030s latency).

PORT    STATE SERVICE
443/tcp open  https
| http-vuln-cve2022-41082:
|   VULNERABLE:
|   Microsoft Exchange - 0-day RCE
|     State: VULNERABLE
|     IDs:  CVE:CVE-2022-41082
|     Risk factor: High  CVSSv2: 10.0 (HIGH) (AV:N/AC:L/AU:N/C:C/I:C/A:C)
|       Exchange 0-day vuln: CVE-2022-41082
|
|     Disclosure date: 2022-09-29
|     References:
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-41082
|       https://microsoft.github.io/CSS-Exchange/Security/EOMTv2/
|       https://www.microsoft.com/security/blog/2022/09/30/analyzing-attacks-using-the-exchange-vulnerabilities-cve-2022-41040-and-cve-2022-41082/
|_      https://msrc-blog.microsoft.com/2022/09/29/customer-guidance-for-reported-zero-day-vulnerabilities-in-microsoft-exchange-server/

Nmap done: 1 IP address (1 host up) scanned in 0.59 seconds
```

### Not Vulnerable

```
nmap -Pn -T4 -p443 --script=http-vuln-cve2022-41082.nse scanme.nmap.org

Starting Nmap 7.92 ( https://nmap.org ) at 2022-10-01 13:39 CEST
Nmap scan report for scanme.nmap.org (45.33.32.156)
Host is up (0.17s latency).

PORT    STATE  SERVICE
443/tcp closed https

Nmap done: 1 IP address (1 host up) scanned in 1.62 seconds
```

# References

General references and links to the vulnerability

## Microsoft

[Microsoft Blog](https://www.microsoft.com/security/blog/2022/09/30/analyzing-attacks-using-the-exchange-vulnerabilities-cve-2022-41040-and-cve-2022-41082/) - Microsoft blog about CVE-2022-41082

[Microsoft Mitigation Tool](https://microsoft.github.io/CSS-Exchange/Security/EOMTv2) - Microsoft Exchange On-premises Mitigation Tool v2

[Microsoft Guidance](https://msrc-blog.microsoft.com/2022/09/29/customer-guidance-for-reported-zero-day-vulnerabilities-in-microsoft-exchange-server/) - Microsoft Customer Guidance for Reported Zero-day Vulnerabilities in Microsoft Exchange Server

## Other testing tools

[VNCCERT-CC 0dayex-checker](https://github.com/VNCERT-CC/0dayex-checker) - Zeroday Microsoft Exchange Server checker (Virtual Patching checker)


# Credits

Authored by Vlatko Kosturjak (Diverto). Thanks to Dalibor S.

