# DC0084 - Active Directory Credential Request

## Description

Requests for authentication credentials via Kerberos or other methods like NTLM and LDAP queries. Examples:

- Kerberos TGT and Service Tickets (Event IDs 4768, 4769)
- NTLM Authentication Events
- LDAP Bind Requests.

## Log Sources

| Log Source | Channel |
|------------|---------|
| `WinEventLog:Security` | EventCode=4768 |
| `WinEventLog:Security` | EventCode=4769 |
| `WinEventLog:Kerberos` | Kerberos TGS-REQ anomalies without KDC validation (Silver Ticket behavior) |
| `WinEventLog:Security` | EventCode=4929 |
| `linux:syslog` | Unusual kinit or klist activity |
