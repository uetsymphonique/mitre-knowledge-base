# DC0067 - Logon Session Creation

## Description

The successful establishment of a new user session following a successful authentication attempt. This typically signifies that a user has provided valid credentials or authentication tokens, and the system has initiated a session associated with that user account. This data is crucial for tracking authentication events and identifying potential unauthorized access. Examples: 

- Windows Systems
    - Event ID: 4624
        - Logon Type: 2 (Interactive) or 10 (Remote Interactive via RDP).
        - Account Name: JohnDoe
        - Source Network Address: 192.168.1.100
        - Authentication Package: NTLM
- Linux Systems
    - /var/log/utmp or /var/log/wtmp:
        - Log format: login user [tty] from [source_ip]
        - User: jane
        - IP: 10.0.0.5
        - Timestamp: 2024-12-28 08:30:00
- macOS Systems
    - /var/log/asl.log or unified logging framework:
        - Log: com.apple.securityd: Authentication succeeded for user 'admin'
- Cloud Environments
    - Azure Sign-In Logs:
        - Activity: Sign-in successful
        - Client App: Browser
        - Location: Unknown (Country: X)
- Google Workspace
    - Activity: Login
        - Event Type: successful_login
        - Source IP: 203.0.113.55

## Log Sources

| Log Source | Channel |
|------------|---------|
| `Logon Session` | None |
| `macos:unifiedlog` | UserLoggedIn |
| `AWS:CloudTrail` | ConsoleLogin, AssumeRole, ListResources |
| `azure:signin` | UserLoginSuccess, TokenIssued |
| `Okta:SystemLog` | user.authentication.sso, app.oauth.grant |
| `m365:signinlogs` | SignInSuccess, RoleAssignmentRead |
| `m365:unified` | UserLoggedIn |
| `gcp:audit` | LoginAudit, DriveAudit |
| `saas:auth` | LoginSuccess, APIKeyUse, AdminAction |
| `azure:signinlogs` | Abnormal sign-in from scripting tools (PowerShell, AADInternals) |
| `azure:signinlogs` | Suspicious login to cloud mailbox system |
| `azure:signinlogs` | Failed MFA attempts, unusual conditional access triggers, login attempts from unexpected IP ranges |
| `AWS:CloudTrail` | ConsoleLogin |
| `WinEventLog:Security` | EventCode=4624, 4648 |
| `NSM:Connections` | Mismatch between recorded user logon and active sessions (e.g., wtmp/utmp entries without corresponding authentication in auth.log) |
| `macos:unifiedlog` | Authentication inconsistencies where commands are executed without corresponding login events |
| `CloudTrail:Signin` | SAML login without corresponding IdP authentication log |
| `m365:sharepoint` | File access with forged or anomalous SAML claims |
| `AWS:CloudTrail` | Web console logins using session cookies without corresponding MFA event |
| `saas:access` | Multiple concurrent logins using same cookie from different locations |
| `AWS:CloudTrail` | ConsoleLogin: If IdP backed by cloud provider, Console login from new IP/agent after correlated endpoint compromise |
| `macos:unifiedlog` | authentication |
| `AWS:CloudTrail` | SendSSHPublicKey, StartSession (SSM), EC2InstanceConnect |
| `azure:signin` | Microsoft.Compute/virtualMachines/serialConsole/connect/action |
| `gcp:audit` | cloud.ssh.publicKey.inserted, compute.instances.osLogin |
| `NSM:Connections` | Missing new login event but session activity continues |
| `macos:unifiedlog` | Session reuse without new auth event |
| `AWS:CloudTrail` | Temporary security credentials used to authenticate into management console or APIs |
| `macos:unifiedlog` | Access to Keychain items or browser credential stores |
| `m365:signinlogs` | Token usage events with device/user mismatch |
| `saas:github` | Login from unusual IP, device fingerprint, or location; access token creation from new client |
| `linux:syslog` | sshd: Accepted password/publickey |
| `macos:unifiedlog` | eventMessage CONTAINS 'screensharingd' or 'AuthorizationRefCreate' |
| `AWS:CloudTrail` | AWS ConsoleLogin, StartSession |
| `esxi:vmkernel` | vim.fault.*, DCUI login, SSH shell |
| `AWS:CloudTrail` | GetConsoleOutput |
| `saas:okta` | user.session.start |
| `m365:unified` | ViewAdminReport |
| `saas:zoom` | Zoom Admin Dashboard accessed from unfamiliar IP/device |
| `WinEventLog:Security` | Anomalous logon without MFA enforcement |
| `networkdevice:Firewall` | Login from untrusted IP, or new admin account accessing firewall console/API |
| `linux:syslog` | authentication success after file access |
| `macos:unifiedlog` | Keychain or user login post-access |
| `AWS:CloudTrail` | sudden role assumption after credential file access |
| `NSM:Connections` | Accepted publickey for user from unusual IP or without tty |
| `saas:confluence` | logon |
| `linux:syslog` | auth.log / secure.log |
| `esxi:auth` | Shell login or escalation |
| `linux:auth` | User login event followed by unexpected process tree |
| `azure:signinlogs` | InteractiveUserLogin: Discovery behavior linked to privileged logins from atypical IP ranges |
| `m365:signinlogs` | UserLogin: Discovery operations shortly after account logins from new geolocations |
| `saas:auth` | Login, TokenGranted: Discovery actions tied to anomalous login sessions or tokens |
| `NSM:Connections` | simultaneous or anomalous logon sessions across multiple systems |
| `macos:unifiedlog` | authentication plugin load or modification events |
| `azure:ad` | SignInEvents |
| `linux:syslog` | Accepted publickey/password for * from * port * ssh2 |
| `macos:unifiedlog` | loginwindow or sshd successful login events |
| `azure:signinlogs` | InteractiveUser, ServicePrincipalSignIn |
| `AWS:CloudTrail` | AssumeRole,AssumeRoleWithSAML,AssumeRoleWithWebIdentity |
| `azure:signinlogs` | InteractiveUser, NonInteractiveUser |
| `azure:signinlogs` | UserLogin, ConditionalAccessPolicyEvaluated |
| `saas:okta` | session.token.reuse |
| `auditd:SYSCALL` | capset or setns |
| `gcp:audit` | admin.googleapis.com |
| `m365:signinlogs` | UserLoggedIn |
| `WinEventLog:Security` | EventCode=4624 |
| `linux:syslog` | None |
