# DC0099 - Group Enumeration

## Description

Extracting group lists from identity systems identifies permissions, roles, or configurations. Adversaries may exploit high-privilege groups or misconfigurations. Examples:

- AWS CLI: `aws iam list-groups`
- PowerShell: `Get-ADGroup -Filter *`
- (Saas) Google Workspace: Admin SDK Directory API
- Azure: `Get-AzureADGroup`
- Microsoft 365:  Graph API `GET https://graph.microsoft.com/v1.0/groups`

*Data Collection Measures:*

- Cloud Logging: Enable AWS CloudTrail, Azure Activity Logs, and Google Workspace Admin Logs for group-related actions.
- Directory Monitoring: Track logs like AD Event ID 4662 (object operations).
- API Monitoring: Log API activity like AWS IAM queries.
- SaaS Monitoring: Use platform logs (e.g., Office 365 Unified Audit Logs).
- SIEM Integration: Centralize group query tracking.

## Log Sources

| Log Source | Channel |
|------------|---------|
| `AWS:CloudTrail` | ListGroups, ListAttachedRolePolicies |
| `azure:audit` | az ad user get-member-groups, Get-AzRoleAssignment |
| `gcp:audit` | cloudidentity.groups.list |
| `saas:salesforce` | GET /services/data/vXX.X/groups |
| `saas:github` | GET /orgs/:org/teams, GET /teams/:team/members |
