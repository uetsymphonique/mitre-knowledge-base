# DC0013 - User Account Metadata

## Description

Contextual data about an account, which may include a username, user ID, environmental data, etc.

## Log Sources

| Log Source | Channel |
|------------|---------|
| `WinEventLog:Security` | EventCode=4720, 4738 |
| `WinEventLog:Security` | EventCode=4673 |
| `AWS:CloudTrail` | AssumeRole |
| `auditd:SYSCALL` | open,openat,read |
| `macos:MDM` | profiles -P\|getaccountpolicies |
| `AWS:CloudTrail` | GetAccountPasswordPolicy |
| `azure:audit` | operation contains 'Get*Password*Policy' OR 'List*Authentication*Policy' OR 'Get-ADDefaultDomainPasswordPolicy' |
| `m365:unified` | Workload=AzureActiveDirectory OR Exchange AND (Operation=Cmdlet AND Parameters contains 'Password' AND (CmdletName='Get-*' OR CmdletName='Get-OrganizationConfig')) |
| `saas:auth` | Refresh token issuance or refresh token usage from new IPs or user agents |
| `gcp:audit` | Directory API Access: users.list or groups.list |
| `CloudTrail:GetCallerIdentity` | GetCallerIdentity |
| `vpxd.log` | vCenter Management |
| `macos:unifiedlog` | Creation of user account with UID <500 |
| `WinEventLog:Security` | EventCode=4674 |
| `windows:osquery` | User enumeration with creation/last modified timestamps |
| `linux:osquery` | Listing of /etc/passwd and /etc/shadow metadata |
| `saas:okta` | User lifecycle events |
| `Microsoft Entra ID Audit Logs` | RoleManagement.Read.Directory or Directory.Read.All |
| `azure:activity` | Azure CLI Operation: Microsoft.Graph/users/read |
| `gcp:audit` | IAM API call: serviceAccounts.list or projects.getIamPolicy |
| `Microsoft Graph API Logs` | users.list, directoryObjects.getByIds |
| `Defender for Identity` | Suspicious Enumeration of Cloud Directory |
| `Google Admin Audit` | users.list, groups.list |
| `AWS:CloudTrail` | PassRole |
| `gcp:iam` | PrincipalEmail with serviceAccountTokenCreator impersonating new identity |
| `AWS:CloudTrail` | AssumeRole: Discovery actions tied to assumed identities outside of normal context |
| `saas:okta` | User Enumeration Events |
| `gcp:audit` | Directory API Access |
