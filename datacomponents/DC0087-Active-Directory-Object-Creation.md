# DC0087 - Active Directory Object Creation

## Description

Creating new objects in AD, such as user accounts, groups, organizational units (OUs), or trust relationships. Logged as Event ID 5137. Examples:

- User Account Creation: New user account.
- Group Creation: New security/distribution group.
- OU Creation: New organizational unit.
- Service Account Creation: New service account for automation or malicious tasks.
- Trust Object Creation: Trust relationship with another domain.

## Log Sources

| Log Source | Channel |
|------------|---------|
| `azure:audit` | New device object creation |
| `WinEventLog:Security` | Device Object Creation |
| `WinEventLog:Security` | EventCode=4928 |
| `AWS:CloudTrail` | CreateAccessKey, ImportKeyPair, CreateLoginProfile, CreateKeyPair |
