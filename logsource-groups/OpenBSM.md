# OpenBSM

4 unique events

| Log Source | Channel | Data Components |
|------------|---------|-----------------|
| `OpenBSM:AuditTrail` | BSM audit events for file permission modifications | File Metadata |
| `OpenBSM:AuditTrail` | BSM audit events for file permission, ownership, and attribute modifications with user context | File Metadata |
| `OpenBSM:AuditTrail` | BSM audit events for process execution and system call monitoring during reconnaissance | Process Creation |
| `OpenBSM:AuditTrail` | open/openat of /dev/bpf*; ioctl BIOCSETF-like operations. | Process Creation |
