# azure

78 unique events

| Log Source | Channel | Data Components |
|------------|---------|-----------------|
| `azure:activity` | Add role assignment / ElevateAccess / Create service principal | Application Log Content |
| `azure:activity` | Azure CLI Operation: Microsoft.Graph/users/read | User Account Metadata |
| `azure:activity` | CollectGuestLogs: Unexpected collection of guest logs by Azure VM Agent outside normal maintenance windows | File Access |
| `azure:activity` | Intune PowerShell Scripts | Command Execution |
| `azure:activity` | List Blobs | Cloud Storage Enumeration |
| `azure:activity` | MICROSOFT.AUTHORIZATION/POLICIES/WRITE | Cloud Service Modification |
| `azure:activity` | MICROSOFT.COMPUTE/SNAPSHOTS/WRITE | Snapshot Creation |
| `azure:activity` | MICROSOFT.COMPUTE/VIRTUALMACHINES/DELETE | Instance Deletion |
| `azure:activity` | MICROSOFT.COMPUTE/VIRTUALMACHINES/LIST | Instance Enumeration |
| `azure:activity` | MICROSOFT.COMPUTE/VIRTUALMACHINES/RESTORE | Instance Modification |
| `azure:activity` | MICROSOFT.COMPUTE/VIRTUALMACHINES/WRITE | Instance Creation |
| `azure:activity` | Microsoft.Compute/virtualMachines/read | Instance Enumeration |
| `azure:activity` | Microsoft.Compute/virtualMachines/runCommand/action: Abnormal initiation of Azure RunCommand jobs or PowerShell/Bash payloads | Script Execution |
| `azure:activity` | Microsoft.Compute/virtualMachines/write: imageReference publisher NOT IN allowlist OR plan is new/unknown | Instance Creation |
| `azure:activity` | Microsoft.Network/networkWatchers/flowLogSettings/write | Cloud Service Modification |
| `azure:activity` | Update conditionalAccessPolicy | Active Directory Object Modification |
| `azure:activity` | az monitor diagnostic-settings delete | Cloud Service Disable |
| `azure:activity` | networkInsightsLogs | Network Traffic Content |
| `azure:activity` | operationName: Write, Access Review, RoleAssignment | Cloud Service Modification |
| `azure:ad` | SecretGet | Cloud Service Enumeration |
| `azure:ad` | SignInEvents | Logon Session Creation |
| `azure:audit` | Add delegated admin / Assign admin roles / Update application consent | Logon Session Metadata |
| `azure:audit` | Add member to role | User Account Modification |
| `azure:audit` | Add service principal credentials, app password added, app role assignment | User Account Modification |
| `azure:audit` | Add user | User Account Creation |
| `azure:audit` | App registrations or consent grants by abnormal users or at unusual times | Application Log Content |
| `azure:audit` | Consent to application: OAuth application consent granted to service principal | Cloud Service Modification |
| `azure:audit` | ListApplications, ListServicePrincipals: Large-scale queries against identity or application objects | Cloud Service Enumeration |
| `azure:audit` | New device object creation | Active Directory Object Creation |
| `azure:audit` | Operation IN ("Add device", "Add registered users to device", "Add registered owner to device") | User Account Modification |
| `azure:audit` | Rename user | User Account Modification |
| `azure:audit` | Tenant subscription transfers or new management group creation | Cloud Service Modification |
| `azure:audit` | az ad user get-member-groups, Get-AzRoleAssignment | Group Enumeration |
| `azure:audit` | operation contains 'Get*Password*Policy' OR 'List*Authentication*Policy' OR 'Get-ADDefaultDomainPasswordPolicy' | User Account Metadata |
| `azure:policy` | DisableAuditLogs or ConditionalAccess logging changes | Cloud Service Modification |
| `azure:policy` | DisableMfaPolicy or change to ConditionalAccess rules | User Account Modification |
| `azure:policy` | UpdatePolicy | Cloud Service Modification |
| `azure:resource` | PATCH vm/authorized_keys | File Modification |
| `azure:signin` | Microsoft.Compute/virtualMachines/serialConsole/connect/action | Logon Session Creation |
| `azure:signin` | UserLoginSuccess, TokenIssued | Logon Session Creation |
| `azure:signinlogs` | Abnormal sign-in from scripting tools (PowerShell, AADInternals) | Logon Session Creation |
| `azure:signinlogs` | Add certificate credential, Update certificate credential | Active Directory Object Modification |
| `azure:signinlogs` | ConsentGrant: Suspicious consent grants to non-approved or unknown applications | Application Log Content |
| `azure:signinlogs` | Failed MFA attempts, unusual conditional access triggers, login attempts from unexpected IP ranges | Logon Session Creation |
| `azure:signinlogs` | Failure Reason + UserPrincipalName | User Account Authentication |
| `azure:signinlogs` | Graph API Query | Cloud Service Enumeration |
| `azure:signinlogs` | Interactive/Non-Interactive Sign-In | User Account Authentication |
| `azure:signinlogs` | InteractiveUser, NonInteractiveUser | Logon Session Creation |
| `azure:signinlogs` | InteractiveUser, ServicePrincipalSignIn | Logon Session Creation |
| `azure:signinlogs` | InteractiveUserLogin: Discovery behavior linked to privileged logins from atypical IP ranges | Logon Session Creation |
| `azure:signinlogs` | Login from newly created account | User Account Authentication |
| `azure:signinlogs` | Modify Conditional Access Policy | Application Log Content |
| `azure:signinlogs` | Multiple MFA challenge requests without successful primary login | User Account Authentication |
| `azure:signinlogs` | Operation=UserLogin | User Account Authentication |
| `azure:signinlogs` | OperationName=SetDomainAuthentication OR Set-FederatedDomain | User Account Authentication |
| `azure:signinlogs` | OperationName=SetDomainAuthentication OR Update-MsolFederatedDomain | Command Execution |
| `azure:signinlogs` | Register PTA Agent or Modify AD FS trust | Application Log Content |
| `azure:signinlogs` | Reset password or download key from portal | User Account Authentication |
| `azure:signinlogs` | Resource access initiated using application credentials, not user accounts | Application Log Content |
| `azure:signinlogs` | SAML-based login with anomalous issuer or NotOnOrAfter lifetime | Logon Session Metadata |
| `azure:signinlogs` | SAML/OIDC tokens issued without corresponding MFA or password validation | Web Credential Creation |
| `azure:signinlogs` | Sign-in activity | User Account Authentication |
| `azure:signinlogs` | Sign-in logs | User Account Authentication |
| `azure:signinlogs` | Sign-in logs / audit events | User Account Authentication |
| `azure:signinlogs` | Sign-in with unfamiliar location/device + portal navigation | User Account Authentication |
| `azure:signinlogs` | SignIn: Sign-ins flagged as atypical (new geographic region, unfamiliar device id) shortly after correlated endpoint/browser compromise times | User Account Authentication |
| `azure:signinlogs` | SigninSuccess | User Account Authentication |
| `azure:signinlogs` | Success logs from high-risk accounts | User Account Authentication |
| `azure:signinlogs` | Suspicious login to cloud mailbox system | Logon Session Creation |
| `azure:signinlogs` | TokenIssuanceStart, TokenIssuanceSuccess | Web Credential Usage |
| `azure:signinlogs` | TokenIssued, RefreshTokenUsed | Web Credential Usage |
| `azure:signinlogs` | TokenIssued, TokenRenewed: Unexpected or anomalous token issuance events | User Account Authentication |
| `azure:signinlogs` | Unusual Token Usage or Application Consent | User Account Authentication |
| `azure:signinlogs` | UserLogin, ConditionalAccessPolicyEvaluated | Logon Session Creation |
| `azure:signinlogs` | status = failure | User Account Authentication |
| `azure:signinlogs` | unusual role assumption or elevation path | User Account Modification |
| `azure:vmguest` | Unexpected execution of cloud agent processes (e.g., WindowsAzureGuestAgent.exe, ssm-agent) followed by arbitrary script or binary execution | Process Creation |
| `azure:vpcflow` | HTTP requests to 169.254.169.254 or Azure Metadata endpoints | Network Traffic Content |
