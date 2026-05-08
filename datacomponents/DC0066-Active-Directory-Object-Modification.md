# DC0066 - Active Directory Object Modification

## Description

Changes to AD objects (e.g., users, groups, OUs) are logged as Event ID 5136 (Object Modification) or 5163 (Attribute Changes). Examples:

- User Account: Modifying attributes (e.g., group membership, enabling/disabling accounts).
- Group Membership: Adding/removing members.
- OU: Changing properties/permissions (e.g., delegation).
- Service Account: Modifying SPNs or other attributes.
- Object Attributes: Changes to passwords, logon hours, or control flags.

## Log Sources

| Log Source | Channel |
|------------|---------|
| `azure:activity` | Update conditionalAccessPolicy |
| `esxi:vpxa` | vim.SessionManager.login / vim.AccountManager.createUser |
| `WinEventLog:Security` | EventCode=5163 |
| `WinEventLog:Security` | EventCode=4739 |
| `azure:signinlogs` | Add certificate credential, Update certificate credential |
| `m365:dirsync` | Replication cookie changes involving Configuration partition with new server/nTDSDSA objects. |
| `WinEventLog:Security` | EventCode=5136 |
| `WinEventLog:Security` | EventCode=4663, 4670, 4656 |
| `esxi:vpxd` | permission change operations on datastores or VMs |
| `m365:unified` | Set-Mailbox, Set-AppPassword, Add-MailboxPermission |
| `m365:unified` | Add app role assignment grant to user: Consent to application by privileged or unexpected accounts |
