# CloudTrail

4 unique events

| Log Source | Channel | Data Components |
|------------|---------|-----------------|
| `CloudTrail:GetCallerIdentity` | GetCallerIdentity | User Account Metadata |
| `CloudTrail:GetObject` | sensitive credential files in buckets or local image storage | File Access |
| `CloudTrail:PutObject` | PutObject | File Creation |
| `CloudTrail:Signin` | SAML login without corresponding IdP authentication log | Logon Session Creation |
