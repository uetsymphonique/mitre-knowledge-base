# DC0006 - Web Credential Creation

## Description

Initial construction of new web credential material (ex: Windows EID 1200 or 4769)

## Log Sources

| Log Source | Channel |
|------------|---------|
| `WinEventLog:ADFS` | Token issuance events showing anomalous claims or issuers |
| `AWS:CloudTrail` | AssumeRole, GetFederationToken API calls by unusual or new entities |
| `azure:signinlogs` | SAML/OIDC tokens issued without corresponding MFA or password validation |
| `m365:unified` | Session creation without MFA or login event |
| `m365:oauth` | OAuth grants or tokens issued without expected user consent |
