# ebpf

10 unique events

| Log Source | Channel | Data Components |
|------------|---------|-----------------|
| `ebpf:syscalls` | Process within container accesses link-local address 169.254.169.254 | Network Traffic Content |
| `ebpf:syscalls` | Unexpected container volume unmount + file deletion | File Metadata |
| `ebpf:syscalls` | container_file_activity | File Access |
| `ebpf:syscalls` | execve | Process Creation |
| `ebpf:syscalls` | file_write | File Modification |
| `ebpf:syscalls` | open/read on secret mount paths | File Access |
| `ebpf:syscalls` | process execution or network connect from just-created container PID namespace | Process Creation |
| `ebpf:syscalls` | socket connect | Network Connection Creation |
| `ebpf:syscalls` | useradd or /etc/passwd modified inside container | Command Execution |
| `ebpf:tracepoints` | Runtime memory overwrite of argv[] memory region | Process Modification |
