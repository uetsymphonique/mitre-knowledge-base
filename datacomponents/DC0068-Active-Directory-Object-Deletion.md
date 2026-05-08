# DC0068 - Active Directory Object Deletion

## Description

Object deletion in AD (e.g., user accounts, groups, OUs) is logged as Event ID 5141. Examples:

- User Account: Deleted user.
- Group: Deleted security/distribution group.
- Organizational Unit (OU): Loss of configurations or policies.
- Service Account: Disrupted operations or cover tracks.
- Trust Object: Removed domain trust, disrupting connectivity.

*Data Collection Measures:*

- Audit Policy:
    - Enable "Audit Directory Service Changes" (Success and Failure).
    - Path: `Computer Configuration > Policies > Windows Settings > Security Settings > Advanced Audit Policy Configuration > Audit Policies > Directory Service Changes`.
    - Key Event: Event ID 5141.
- Log Forwarding: Use WEF to centralize logs for SIEM tools (e.g., Splunk).
- Enable EDR Monitoring:
    - Detect processes or users that initiate unauthorized object deletions.
    - Monitor tools and scripts that may delete key directory objects.

## Log Sources

| Log Source | Channel |
|------------|---------|
| `WinEventLog:Security` | EventCode=4929 |
