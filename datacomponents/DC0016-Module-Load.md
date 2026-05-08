# DC0016 - Module Load

## Description

When a process or program dynamically attaches a shared library, module, or plugin into its memory space. This action is typically performed to extend the functionality of an application, access shared system resources, or interact with kernel-mode components.

## Log Sources

| Log Source | Channel |
|------------|---------|
| `Module` | None |
| `WinEventLog:Sysmon` | EventCode=7 |
| `ETW:LoadImage` | provider: ETW LoadImage events for images from user-writable/UNC paths |
| `auditd:SYSCALL` | openat/read/mmap: Open/mmap .so files from non-standard paths |
| `linux:osquery` | select: Open files path LIKE '/tmp/%.so' OR '/dev/shm/%.so' |
| `macos:unifiedlog` | dyld/unified log entries indicating image load from non-system paths |
| `macos:osquery` | select: path LIKE '%/Library/%/*.dylib' OR '/tmp/*.dylib' |
| `macos:unifiedlog` | dynamic loading of sleep-related functions or sandbox detection libraries |
| `auditd:SYSCALL` | LD_PRELOAD Logging |
| `linux:osquery` | Dynamic Linking State |
| `macos:unifiedlog` | DYLD event subsystem |
| `linux:osquery` | Process linked with libcrypto.so making external connections |
| `macos:unifiedlog` | process execution events with dylib load activity |
| `linux:Sysmon` | EventCode=7 |
| `WinEventLog:Application` | CLR Assembly creation, loading, or modification logs via MSSQL CLR integration |
| `macos:unifiedlog` | Process memory maps new dylib (dylib_load event) |
| `macos:unifiedlog` | Dylib loaded from abnormal location |
| `WinEventLog:Security` | EventCode=3033 |
| `WinEventLog:Security` | EventCode=3063 |
| `auditd:MMAP` | load: Loading of libzip.so, libz.so, or libbz2.so by processes not normally associated with archiving |
| `macos:unifiedlog` | Loading of libz.dylib, libarchive.dylib by non-standard applications |
| `macos:unifiedlog` | suspicious dlopen/dlsym usage in non-development processes |
| `m365:unified` | Non-standard Office startup component detected (e.g., unexpected DLL path) |
| `auditd:SYSCALL` | mmap |
| `esxi:vmkernel` | unexpected module load |
| `snmp:status` | Status change in cryptographic hardware modules (enabled -> disabled) |
| `esxi:vmkernel` | module load |
| `macos:unifiedlog` | delay/sleep library usage in user context |
| `linux:syslog` | kmod |
| `macos:unifiedlog` | subsystem=com.apple.kextd |
| `macos:unifiedlog` | loading of unexpected dylibs compared to historical baselines |
| `auditd:file-events` | open of suspicious .so from non-standard paths |
| `macos:syslog` | DYLD_INSERT_LIBRARIES anomalies |
| `auditd:SYSCALL` | dmesg |
| `macos:endpointsecurity` | ES_EVENT_TYPE_NOTIFY_KEXTLOAD |
| `auditd:SYSCALL` | module load or memory map path |
| `macos:unifiedlog` | launch and dylib load |
| `linux:osquery` | Processes linked with libssl/libcrypto performing network activity |
| `etw:Microsoft-Windows-Kernel-ImageLoad` | provider: Unsigned/user-writable image loads into msbuild.exe |
