# DC0070 - Cloud Service Metadata

## Description

Cloud service metadata refers to the contextual and descriptive information about cloud services, including their name, type, purpose, configuration, and activity around them. This metadata is essential for understanding the roles and functions of cloud services, their operational status, and their potential misuse. Examples: 

- Azure Service Metadata: Metadata describing a resource in Azure, such as an Azure Storage Account or a Virtual Machine.
- AWS Cloud Service Metadata: Metadata for an AWS EC2 instance collected using the `DescribeInstances` API call.
- Google Cloud Service Metadata: Metadata for a Google Compute Engine instance collected using `gcloud compute instances describe`.
- Office 365 Metadata: Metadata about an Office 365 SharePoint site.

## Log Sources

| Log Source | Channel |
|------------|---------|
| `AWS:CloudTrail` | GetInstanceIdentityDocument |
| `AWS:CloudTrail` | rds:ExecuteStatement: Large data access via RDS or Aurora with unknown session context |
| `saas:github` | repo.download, repo.clone, oauth.authorize, repo.getContent |
| `AWS:CloudWatch` | unexpected IAM user or role assuming privileges for instance/snapshot operations |
| `AWS:CloudTrail` | GetSecretValue |
| `AWS:CloudTrail` | InvokeFunction |
| `m365:sharepoint` | Multiple file download operations on a site by a privileged account in a short time window |
| `saas:github` | CI/CD secret accessed or exported |
| `m365:exchange` | Cmdlet - New-InboxRule |
| `m365:unified` | New-InboxRule, Set-InboxRule |
