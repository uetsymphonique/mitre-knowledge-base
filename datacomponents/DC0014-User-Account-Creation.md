# DC0014 - User Account Creation

## Description

The initial establishment of a new user, service, or machine account within an operating system, cloud environment, or identity management system.

## Log Sources

| Log Source | Channel |
|------------|---------|
| `WinEventLog:Security` | EventCode=4720 |
| `azure:audit` | Add user |
| `AWS:CloudTrail` | CreateUser |
| `saas:zoom` | New user created |
| `saas:slack` | admin.user.create |
| `m365:unified` | Add user |
| `auditd:SYSCALL` | adduser |
| `docker:daemon` | ExecCreate + usermod or useradd |
| `auditd:SYSCALL` | useradd or adduser executed |
| `networkdevice:syslog` | username <user> privilege <level> |
| `saas:okta` | user.lifecycle.create |
