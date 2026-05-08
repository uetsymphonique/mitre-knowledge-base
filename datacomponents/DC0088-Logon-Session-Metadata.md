# DC0088 - Logon Session Metadata

## Description

Contextual data about a logon session, such as username, logon type, access tokens (security context, user SIDs, logon identifiers, and logon SID), and any activity associated within it

## Log Sources

| Log Source | Channel |
|------------|---------|
| `Logon Session` | None |
| `WinEventLog:Security` | EventCode=4672 |
| `macos:unifiedlog` | LoginWindow context with associated PID linked to reopened plist paths |
| `WinEventLog:Security` | EventCode=4672, 4634 |
| `azure:signinlogs` | SAML-based login with anomalous issuer or NotOnOrAfter lifetime |
| `m365:unified` | Abnormal user claims or unexpected elevated role assignment in SAML assertion |
| `macos:unifiedlog` | authd generating multiple MFA token requests |
| `linux:syslog` | None |
| `WinEventLog:Security` | EventCode=4624, 4625, 4768, 4769 |
| `linux:syslog` | sssd / sudo logs |
| `esxi:hostd` | /var/log/hostd.log |
| `WinEventLog:Security` | EventCode=4778, EventCode=4779 |
| `auditd:SYSCALL` | ssh logins or execve of remote commands |
| `macos:unifiedlog` | Remote login (ssh) or screen sharing authentication attempts |
| `kubernetes:audit` | Unauthorized container creation or kubelet exec logs |
| `auditd:USER_LOGIN` | USER_LOGIN |
| `macos:unifiedlog` | loginwindow or sshd |
| `WinEventLog:Security` | EventCode=4800, 4801 |
| `WinEventLog:Security` | EventCode=4776, 4771, 4770 |
| `auditd:SYSCALL` | execve,socket,connect,openat |
| `macos:unifiedlog` | Group membership change for admin or wheel |
| `azure:audit` | Add delegated admin / Assign admin roles / Update application consent |
| `saas:okta` | user.session.start, app.oauth2.as.authorize, policy.mfa.bypass |
| `gcp:audit` | google.iam.credentials.generateAccessToken / serviceAccountTokenCreator |
| `saas:salesforce` | ConnectedApp OAuth policy change / Login as user |
| `macos:unifiedlog` | Unusual Kerberos TGS-REQ without TGT or anomalous ticket lifetime |
| `saas:okta` | user.authentication.sso |
| `m365:unified` | FileAccessed, SharingSet |
| `m365:signinlogs` | UserLogin |
| `macos:unifiedlog` | loginwindow, sshd |
| `NSM:Connections` | Successful sudo or ssh from unknown IPs |
| `macos:unifiedlog` | loginwindow or sshd events with external IP |
| `macos:unifiedlog` | process = 'sshd' |
| `esxi:auth` | None |
