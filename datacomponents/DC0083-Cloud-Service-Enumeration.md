# DC0083 - Cloud Service Enumeration

## Description

Cloud service enumeration involves listing or querying available cloud services in a cloud control plane. This activity is often performed to identify resources such as virtual machines, storage buckets, compute clusters, or other services within a cloud environment. Examples include API calls like `AWS ECS ListServices`, `Azure ListAllResources`, or `Google Cloud ListInstances`. Examples: 

AWS Cloud Service Enumeration: The adversary gathers details about existing ECS services to identify opportunities for privilege escalation or exfiltration.
- Azure Resource Enumeration: The adversary collects information about virtual machines, resource groups, and other Azure assets for reconnaissance purposes.
- Google Cloud Resource Enumeration: The attacker seeks to map the environment and find misconfigured or underutilized resources for exploitation.
- Office 365 Service Enumeration: The attacker may look for data repositories or collaboration tools to exfiltrate sensitive information.

## Log Sources

| Log Source | Channel |
|------------|---------|
| `AWS:CloudTrail` | GetSecretValue |
| `gcp:secrets` | accessSecretVersion |
| `azure:ad` | SecretGet |
| `AWS:CloudTrail` | ssm:ListInventoryEntries |
| `AWS:CloudTrail` | DescribeInstances, DescribeServices, ListFunctions: High frequency enumeration calls or unusual user agents performing discovery |
| `azure:audit` | ListApplications, ListServicePrincipals: Large-scale queries against identity or application objects |
| `m365:unified` | Get-MsolServicePrincipal, ListAppRoles: Service discovery operations executed by accounts not normally performing administrative tasks |
| `saas:adminapi` | ListIntegrations, ListServices: Repeated service discovery requests from accounts without administrative responsibilities |
| `AWS:CloudTrail` | GetInstanceIdentityDocument or IMDSv2 token requests |
| `AWS:CloudTrail` | DescribeUsers / ListUsers / GetUser |
| `azure:signinlogs` | Graph API Query |
