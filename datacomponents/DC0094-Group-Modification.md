# DC0094 - Group Modification

## Description

Changes made to a group, such as membership, name, or permissions (ex: Windows EID 4728 or 4732, AWS IAM UpdateGroup). Examples: 

- Active Directory:
    - Event ID 4728: Member added to a global group.
    - Event ID 4732: Member added to a local group.
- Azure AD: `Set-AzureADGroup -ObjectId <GroupId> -DisplayName "New Name"`
- AWS IAM: `aws iam update-group --group-name <GroupName> --new-path "/admin/"`
- Google Workspace: Modify permissions via Admin SDK API: `PATCH https://admin.googleapis.com/admin/directory/v1/groups/<groupKey>`
- Office 365: Modify groups via Graph API: `PATCH https://graph.microsoft.com/v1.0/groups/<groupId>`

*Data Collection Measures:*

- Directory Logging:
    - Windows: Log EIDs 4728 (add), 4729 (remove).
    - Azure AD: Enable "Audit logs."
    - Google Workspace: Enable Admin Activity logs.
    - Office 365: Use Unified Audit Logs.
- Cloud Monitoring:
    - AWS: Log `UpdateGroup`, `AttachGroupPolicy`, `RemoveUserFromGroup`.
    - Azure: Track modifications via Audit logs.
- API Monitoring: Log Google Admin SDK and Microsoft Graph API calls.
- SIEM Integration: Centralize and monitor group modification logs.

## Log Sources

| Log Source | Channel |
|------------|---------|
| `m365:unified` | Add member to group |
