# DC0010 - User Account Modification

## Description

Changes made to an existing user, service, or machine account, including alterations to attributes, permissions, roles, authentication methods, or group memberships.

## Log Sources

| Log Source | Channel |
|------------|---------|
| `azure:audit` | Operation IN ("Add device", "Add registered users to device", "Add registered owner to device") |
| `linux:syslog` | sudo or su access prior to content change |
| `WinEventLog:Security` | EventCode=4738, 4728, 4670 |
| `auditd:SYSCALL` | usermod, groupmod, passwd |
| `macos:unifiedlog` | com.apple.accountsd, com.apple.opendirectoryd |
| `saas:okta` | User Attribute Modified / Role Assignment Changed |
| `m365:unified` | Admin Activity > Role Change or Sharing Change |
| `gcp:audit` | Admin Activity > Role Change or Sharing Change |
| `m365:unified` | Set-ADUser OR Set-ADAccountControl |
| `AWS:CloudTrail` | UpdateLoginProfile |
| `WinEventLog:Security` | EventCode=4723, 4724, 4740 |
| `saas:okta` | user.lifecycle.delete, user.account.lock |
| `m365:unified` | User excluded from MFA or MFA method registered |
| `saas:zoom` | DisableMFA or RegisterNewFactor |
| `AWS:CloudTrail` | AttachUserPolicy, CreatePolicyVersion, PutRolePolicy |
| `gcp:audit` | google.iam.admin.v1.RoleAssignment |
| `m365:audit` | Add member to role, Add app role assignment |
| `Okta:SystemLog` | user.account.privilege.grant |
| `m365:unified` | Add member to role, Set-Mailbox |
| `m365:unified` | Set-MailboxAuditBypassAssociation or disabling Advanced Auditing |
| `m365:unified` | New agent registration by non-admin user |
| `WinEventLog:Security` | EventCode=4704 |
| `WinEventLog:Security` | EventCode=4728, 4729, 4732, 4733, 4756, 4757 |
| `auditd:SYSCALL` | SYSCALL for usermod or /etc/group file modification |
| `macos:unifiedlog` | Process execution or directory service changes |
| `azure:policy` | DisableMfaPolicy or change to ConditionalAccess rules |
| `azure:audit` | Add member to role |
| `AWS:CloudTrail` | AttachUserPolicy |
| `AWS:CloudTrail` | CreateAccessKey |
| `azure:signinlogs` | unusual role assumption or elevation path |
| `saas:okta` | admin role granted outside approved workflows |
| `AWS:CloudTrail` | role privilege expansion detected |
| `m365:unified` | Add-MailboxPermission, UpdateFolderPermissions |
| `gcp:audit` | Set Gmail Delegation |
| `auditd:SYSCALL` | usermod, or account rename system calls |
| `azure:audit` | Rename user |
| `m365:unified` | Set-Mailbox, Set-InboxRule, Set-MailboxFolderPermission |
| `azure:audit` | Add service principal credentials, app password added, app role assignment |
| `gcp:audit` | iam.serviceAccounts.keys.create, os-login.sshPublicKeys.add |
| `gcp:audit` | API Key Created, OAuth Client Registered |
| `kubernetes:audit` | create or update events for RoleBinding or ClusterRoleBinding objects |
