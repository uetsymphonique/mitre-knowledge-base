# DC0069 - Cloud Service Modification

## Description

Cloud service modification refers to changes made to the configuration, settings, or data of a cloud service. These modifications can include administrative changes such as enabling or disabling features, altering permissions, or deleting critical components. Monitoring these changes is critical to detect potential misconfigurations or malicious activity. Examples: 

- AWS Cloud Service Modifications: A user disables AWS CloudTrail logging (StopLogging) or deletes a CloudWatch configuration rule (DeleteConfigRule).
- Azure Cloud Service Modifications: Changes to Azure Role-Based Access Control (RBAC) roles, such as adding a new Contributor role to a sensitive resource.
- Google Cloud Service Modifications: Deletion of a Google Cloud Storage bucket or disabling a Google Cloud Function.
- Office 365 Cloud Service Modifications: Altering mailbox permissions or disabling auditing in Microsoft 365.

## Log Sources

| Log Source | Channel |
|------------|---------|
| `AWS:CloudTrail` | CreateFunction |
| `m365:unified` | Creation of Power Automate flow triggered by OneDrive or Exchange event |
| `AWS:CloudTrail` | PutUserPolicy, PutGroupPolicy, PutRolePolicy, CreatePolicyVersion |
| `AWS:CloudTrail` | Condition block updated in IAM policy (e.g., aws:SourceIp, aws:RequestedRegion) |
| `azure:activity` | operationName: Write, Access Review, RoleAssignment |
| `azure:policy` | UpdatePolicy |
| `AWS:CloudTrail` | UpdateAccountPasswordPolicy |
| `AWS:CloudTrail` | PutIdentityPolicy |
| `AWS:CloudTrail` | LeaveOrganization: API calls severing accounts from AWS Organizations |
| `AWS:CloudTrail` | CreateAccount: API calls creating new accounts in AWS Organizations |
| `azure:audit` | Tenant subscription transfers or new management group creation |
| `AWS:CloudTrail` | UpdateIdentityPolicy or DisableMFA |
| `m365:unified` | SendMessage |
| `gcp:config` | UpdateSink request modifying log export destinations |
| `azure:policy` | DisableAuditLogs or ConditionalAccess logging changes |
| `AWS:CloudTrail` | UpdateFederationSettings or RegisterHybridConnector |
| `AWS:CloudTrail` | CreateTrafficMirrorSession / ModifyTrafficMirrorTarget |
| `azure:activity` | Microsoft.Network/networkWatchers/flowLogSettings/write |
| `gcp:audit` | compute.packetMirroring.insert |
| `AWS:CloudTrail` | CreateFunction / UpdateFunctionConfiguration: Function creation, role assignment, or configuration change events |
| `m365:unified` | AddFlow / UpdateFlow: New automation or workflow creation events |
| `saas:appsscript` | Create / Update: Deployment of scripts with event-driven triggers |
| `saas:slack` | Exported file or accessed admin API |
| `AWS:CloudTrail` | RequestServiceQuotaIncrease |
| `azure:activity` | MICROSOFT.AUTHORIZATION/POLICIES/WRITE |
| `gcp:audit` | projects.updateQuota or orgPolicies.updatePolicy |
| `AWS:CloudTrail` | Delete* / Stop*: DeleteAlarms, StopLogging, or DisableMonitoring API calls |
| `AWS:CloudTrail` | Use of temporary credentials issued from IMDS access |
| `saas:github` | Workflow triggered via pull_request_target from forked repo |
| `azure:audit` | Consent to application: OAuth application consent granted to service principal |
| `saas:integration` | New or modified third-party application integrations with elevated permissions |
