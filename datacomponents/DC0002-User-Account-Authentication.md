# DC0002 - User Account Authentication

## Description

An attempt (successful and failed login attempts) by a user, service, or application to gain access to a network, system, or cloud-based resource. This typically involves credentials such as passwords, tokens, multi-factor authentication (MFA), or biometric validation.

## Log Sources

| Log Source | Channel |
|------------|---------|
| `User Account` | None |
| `NSM:Flow` | TGS-REQ and AS-REQ seen for new user shortly after domain-modifying process |
| `WinEventLog:Security` | EventCode=4625 |
| `saas:okta` | session.impersonation.start |
| `Okta:SystemLog` | eventType: user.authentication.sso, app.oauth2.token.grant |
| `azure:signinlogs` | Success logs from high-risk accounts |
| `networkdevice:syslog` | config access, authentication logs |
| `ESXiLogs:authlog` | Unexpected login followed by encoding commands |
| `saas:okta` | Unusual OAuth app requesting message-read scopes for Slack/Teams/Jira |
| `NSM:Connections` | Accepted password or publickey for user from remote IP |
| `macos:unifiedlog` | successful sudo or authentication for account not normally associated with admin actions |
| `esxi:vpxa` | user login from unexpected IP or non-admin user role |
| `m365:signinlogs` | Sign-in from anomalous location or impossible travel condition |
| `networkdevice:syslog` | User privilege escalation to level 15/root prior to destructive commands |
| `networkdevice:syslog` | authorization/accounting logs |
| `WinEventLog:Security` | EventCode=4769, 1200, 1202 |
| `linux:syslog` | sudo/date/timedatectl execution by non-standard users |
| `saas:audit` | Repeated requests to SMS-generating endpoints using anomalous or new user agents, IP ranges, or geographies. |
| `azure:signinlogs` | Multiple MFA challenge requests without successful primary login |
| `AWS:CloudTrail` | AssumeRole or ConsoleLogin with repeated MFA failures followed by repeated MFA requests |
| `auditd:AUTH` | pam_unix or pam_google_authenticator invoked repeatedly within short interval |
| `WinEventLog:Security` | EventCode=4768, 4769, 4770 |
| `NSM:Connections` | Repeated failed authentication attempts or replay patterns |
| `azure:signinlogs` | TokenIssued, TokenRenewed: Unexpected or anomalous token issuance events |
| `azure:signinlogs` | SignIn: Sign-ins flagged as atypical (new geographic region, unfamiliar device id) shortly after correlated endpoint/browser compromise times |
| `AWS:CloudTrail` | sts:GetFederationToken |
| `m365:unified` | Delegated permission grants without user login event |
| `saas:salesforce` | API login using access_token without login history |
| `AWS:CloudTrail` | AssumeRoleWithWebIdentity |
| `azure:signinlogs` | Operation=UserLogin |
| `esxi:auth` | interactive shell or SSH access preceding storage enumeration |
| `NSM:Connections` | Successful login without expected MFA challenge |
| `macos:unifiedlog` | Login success without MFA step |
| `kubernetes:apiserver` | get/list requests to /api/v1/secrets or /api/v1/namespaces/*/serviceaccounts |
| `auditd:SYSCALL` | pam_authenticate, sshd |
| `macos:unifiedlog` | log show --predicate 'eventMessage contains "Authentication"' |
| `esxi:vpxd` | /var/log/vmware/vpxd.log |
| `azure:signinlogs` | Unusual Token Usage or Application Consent |
| `networkdevice:syslog` | Failed and successful logins to network devices outside approved admin IP ranges |
| `azure:signinlogs` | OperationName=SetDomainAuthentication OR Set-FederatedDomain |
| `network:auth` | repeated successful authentications with previously unknown accounts or anomalous password acceptance |
| `azure:signinlogs` | Sign-in with unfamiliar location/device + portal navigation |
| `m365:signinlogs` | UserLoginSuccess |
| `saas:salesforce` | Login |
| `networkdevice:syslog` | Privileged login followed by destructive format command |
| `networkdevice:syslog` | admin login events |
| `networkdevice:syslog` | Privileged login followed by destructive command sequence |
| `azure:signinlogs` | Login from newly created account |
| `auditd:SYSCALL` | execution of ssh, scp, or sftp using previously unseen credentials or keys |
| `m365:unified` | login using refresh_token with no preceding authentication context |
| `saas:googleworkspace` | API access without user login |
| `WinEventLog:Security` | EventCode=4769 |
| `WinEventLog:Security` | EventCode=4776, 4625 |
| `azure:signinlogs` | Interactive/Non-Interactive Sign-In |
| `AWS:CloudTrail` | AWS IAM: ListUsers, ListRoles |
| `gcp:workspaceaudit` | Token Generation via Domain Delegation |
| `m365:signinlogs` | Unusual sign-in from service principal to user mailbox |
| `macos:unifiedlog` | User credential prompt events without associated trusted installer package |
| `linux:auth` | sshd login |
| `saas:googleworkspace` | Accessed third-party credential management service |
| `azure:signinlogs` | Reset password or download key from portal |
| `linux:syslog` | SSH failed login |
| `macos:unifiedlog` | Login failure / authorization denied |
| `azure:signinlogs` | status = failure |
| `Okta:authn` | authentication_failure |
| `saas-app:auth` | login_failure |
| `networkdevice:syslog` | AAA, RADIUS, or TACACS authentication |
| `kubernetes:apiserver` | authentication.k8s.io/v1beta1 |
| `m365:exchange` | Logon failure |
| `AWS:CloudTrail` | eventName=ConsoleLogin \| eventType=AwsConsoleSignIn |
| `auditd:USER_LOGIN` | USER_AUTH |
| `azure:signinlogs` | Sign-in logs |
| `macos:unifiedlog` | auth |
| `m365:unified` | Sign-in logs |
| `AWS:CloudTrail` | ConsoleLogin or AssumeRole |
| `esxi:auth` | /var/log/auth.log |
| `networkdevice:syslog` | authentication logs |
| `azure:signinlogs` | SigninSuccess |
| `WinEventLog:Security` | EventCode=4625, 4771, 4648 |
| `linux:syslog` | Failed password for invalid user |
| `macos:unifiedlog` | Login Window and Authd errors |
| `azure:signinlogs` | Failure Reason + UserPrincipalName |
| `saas:okta` | authentication_failure |
| `networkdevice:syslog` | AAA or TACACS authentication failures |
| `kubernetes:audit` | Failed login |
| `m365:exchange` | FailedLogin |
| `saas:auth` | signin_failed |
| `saas:googleworkspace` | login with reused session token and mismatched user agent or IP |
| `saas:googleworkspace` | Access via OAuth credentials with unusual scopes or from anomalous IPs |
| `networkdevice:syslog` | authentication & authorization |
| `azure:signinlogs` | Sign-in activity |
| `AWS:CloudTrail` | ConsoleLogin, AssumeRole, ListAccessKeys, CreateUser |
| `gcp:audit` | drive.activity |
| `gcp:audit` | login.event |
| `linux:syslog` | sshd[pid]: Failed password |
| `macos:unifiedlog` | authd |
| `networkdevice:syslog` | login failed |
| `GCPAuditLogs:login.googleapis.com` | Failed sign-in events |
| `esxi:auth` | SSH session/login |
| `NSM:Connections` | sshd or PAM logins |
| `saas:okta` | Sign-in logs / audit events |
| `gcp:audit` | Sign-in logs / audit events |
| `azure:signinlogs` | Sign-in logs / audit events |
| `kubernetes:audit` | authentication.k8s.io |
| `WinEventLog:Security` | EventCode=4648 |
| `linux:syslog` | authentication and authorization events during environmental validation phase |
