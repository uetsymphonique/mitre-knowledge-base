# journald

8 unique events

| Log Source | Channel | Data Components |
|------------|---------|-----------------|
| `journald:Application` | Segfault or crash log entry associated with specific application binary | Application Log Content |
| `journald:boot` | Secure Boot failure, firmware version change | Host Status |
| `journald:package` | dpkg/apt install, remove, upgrade events | File Metadata |
| `journald:package` | dpkg/apt or yum/dnf transaction logs (install/update of build tools) | File Metadata |
| `journald:package` | dpkg/apt/yum/dnf transaction logs; vendor updaters in systemd journals | File Metadata |
| `journald:package` | yum/dnf install or update transactions | File Metadata |
| `journald:systemd` | Repeated service restart attempts or unit failures | Application Log Content |
| `journald:systemd` | udisks2 or udevd logs | Drive Creation |
