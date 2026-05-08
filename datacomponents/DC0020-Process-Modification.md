# DC0020 - Process Modification

## Description

Changes made to a running process, such as writing data into memory, modifying execution behavior, or injecting code into an existing process. Adversaries frequently modify processes to execute malicious payloads, evade detection, or gain escalated privileges.

## Log Sources

| Log Source | Channel |
|------------|---------|
| `auditd:SYSCALL` | rename, chmod |
| `auditd:SYSCALL` | mprotect |
| `macos:endpointsecurity` | ES_EVENT_MMAP |
| `auditd:SYSCALL` | kill syscalls targeting auditd process |
| `macos:unifiedlog` | memory mapping |
| `WinEventLog:Sysmon` | EventCode=8 |
| `macos:osquery` | Memory Mappings |
| `ebpf:tracepoints` | Runtime memory overwrite of argv[] memory region |
| `etw:Microsoft-Windows-Kernel-Process` | Memory Modification / Unmapped module load or suspicious RWX allocations in the process space of a browser process |
| `macos:unifiedlog` | Anomalous dyld dynamic library loads or RWX memory mappings in browser process |
| `auditd:SYSCALL` | open, rename |
| `auditd:SYSCALL` | SYSCALL ptrace/mprotect |
| `macos:endpointsecurity` | ES_EVENT_TYPE_NOTIFY_MMAP |
| `macos:unifiedlog` | process, library load, memory operations |
| `auditd:SYSCALL` | rename |
| `linux:osquery` | Detection of bitwise operations or custom encryption functions in memory traces |
| `macos:unifiedlog` | Abnormal memory operations (XOR/bitwise loops) during archive generation |
| `auditd:memprotect` | change from PROT_READ\|PROT_WRITE to PROT_EXEC |
| `linux:procfs` | /proc/[pid]/maps, /proc/[pid]/mem |
