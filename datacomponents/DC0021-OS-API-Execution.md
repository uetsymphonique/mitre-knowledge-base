# DC0021 - OS API Execution

## Description

Calls made by a process to operating system-provided Application Programming Interfaces (APIs). These calls are essential for interacting with system resources such as memory, files, and hardware, or for performing system-level tasks. Monitoring these calls can provide insight into a process's intent, especially if the process is malicious.

## Log Sources

| Log Source | Channel |
|------------|---------|
| `Process` | None |
| `etw:Microsoft-Windows-Kernel-Base` | GetLocaleInfoW, GetTimeZoneInformation API calls |
| `AWS:CloudTrail` | GetMetadata, DescribeInstanceIdentity |
| `macos:osquery` | open, execve: Unexpected processes accessing or modifying critical files |
| `auditd:SYSCALL` | ptrace, ioctl |
| `etw:Microsoft-Windows-Kernel-Process` | API tracing / stack tracing via ETW or telemetry-based EDR |
| `EDR:memory` | Behavioral API telemetry (GetProcAddress, LoadLibrary, VirtualAlloc) |
| `networkdevice:syslog` | aaa privilege_exec |
| `macos:unifiedlog` | None |
| `etw:Microsoft-Windows-Kernel-Process` | APCQueueOperations |
| `macos:unifiedlog` | Invocation of SMLoginItemSetEnabled by non-system or recently installed application |
| `macos:unifiedlog` | flock\|NSDistributedLock\|FileHandle.*lockForWriting |
| `etw:Microsoft-Windows-Directory-Services-SAM` | api_call: Calls to DsAddSidHistory or related RPC operations |
| `macos:unifiedlog` | application logs referencing NSTimer, sleep, or launchd delays |
| `etw:Microsoft-Windows-Kernel-Process` | High-frequency or suspicious sequence of QueryPerformanceCounter/GetTickCount API calls from a non-standard process lineage |
| `auditd:SYSCALL` | Rules capturing clock_gettime, time, gettimeofday syscalls when enabled |
| `networkdevice:syslog` | Unexpected reload, crashinfo, or boot message not tied to scheduled maintenance |
| `etw:Microsoft-Windows-RPC` | rpc_call: srvsvc.NetShareEnum / NetShareEnumAll from non-admin or unusual processes |
| `NSM:Flow` | smb_command: TreeConnectAndX to \\*\IPC$ / srvsvc or Trans2/NT_CREATE for listing shares |
| `WinEventLog:Security` | EventCode=4663, 4670, 4656 |
| `EDR:memory` | API usage MFCreateDeviceSource, IAMStreamConfig, ICaptureGraphBuilder2, DirectShow filter graph creation from uncommon callers |
| `auditd:SYSCALL` | openat/read/ioctl: openat/read/ioctl on /dev/video* by uncommon user/process |
| `macos:unifiedlog` | Access decisions to kTCCServiceCamera for unexpected binaries |
| `EDR:memory` | Objective‑C/Swift calls to AVCaptureDevice/AVCaptureSession by non-whitelisted processes |
| `auditd:SYSCALL` | mmap, ptrace, process_vm_writev or direct memory ops |
| `WinEventLog:Application` | API call to AddMonitor invoked by non-installer process |
| `etw:Microsoft-Windows-Win32k` | SetWindowLong, SetClassLong, NtUserMessageCall, SendNotifyMessage, PostMessage |
| `auditd:SYSCALL` | unshare, mount, keyctl, setns syscalls executed by containerized processes |
| `macos:unifiedlog` | audio APIs |
| `WinEventLog:Microsoft-Windows-COM/Operational` | CLSID activation events where ProcessName=mmc.exe and CLSID not in allowed baseline |
| `macos:unifiedlog` | com.apple.securityd, com.apple.tccd |
| `auditd:SYSCALL` | send, recv, write: Abnormal interception or alteration of transmitted data |
| `macos:osquery` | CALCULATE: Integrity validation of transmitted data via hash checks |
| `ETW:Token` | token_analysis: API calls such as DuplicateTokenEx or ImpersonateLoggedOnUser |
| `etw:Microsoft-Windows-Kernel-Process` | API Calls |
| `etw:Microsoft-Windows-DotNETRuntime` | AssemblyLoad/ModuleLoad (Loader keyword) from Microsoft-Windows-DotNETRuntime |
| `EDR:memory` | VirtualAlloc/VirtualProtect/MapViewOfFile indicators via stack/heap activity and ImageLoad |
| `auditd:MMAP` | memory region with RWX permissions allocated |
| `snmp:trap` | management queries |
| `AWS:CloudTrail` | Describe* or List* API calls |
| `etw:Microsoft-Windows-Win32k` | SendMessage, PostMessage, LVM_* |
| `auditd:SYSCALL` | sudo or pkexec invocation |
| `macos:unifiedlog` | authorization execute privilege requests |
| `etw:Microsoft-Windows-Kernel-Process` | NtQueryInformationProcess |
| `macos:unifiedlog` | ptrace: Processes invoking ptrace with PTRACE_TRACEME flag |
| `esxi:hostd` | Remote access API calls and file uploads |
| `etw:Microsoft-Windows-Kernel-Process` | NtUnmapViewOfSection, VirtualAllocEx, WriteProcessMemory, SetThreadContext, ResumeThread |
| `linux:syslog` | Execution of modified binaries or abnormal library load sequences |
| `macos:unifiedlog` | Calls to AuthorizationExecuteWithPrivileges() observed via Apple System Logger or security_auditing tools |
| `macos:unifiedlog` | access or unlock attempt to keychain database |
| `macos:unifiedlog` | Execution of input detection APIs (e.g., CGEventSourceKeyState) |
| `auditd:SYSCALL` | mount system call with bind or remap flags |
| `AWS:CloudTrail` | Decrypt |
| `etw:Microsoft-Windows-Kernel-File` | ZwSetEaFile or ZwQueryEaFile function calls |
| `auditd:SYSCALL` | fork/clone/daemon syscall tracing |
| `fs:fsusage` | Detached process execution with no associated parent |
| `auditd:SYSCALL` | ptrace, mmap, mprotect, open, dlopen |
| `ETW:ProcThread` | api_call: CreateProcessWithTokenW, CreateProcessAsUserW |
| `EDR:memory` | MemoryWriteToExecutable |
| `ETW:Token` | api_call: DuplicateTokenEx, ImpersonateLoggedOnUser, SetThreadToken |
| `etw:Microsoft-Windows-Kernel-Process` | api_call: UpdateProcThreadAttribute (PROC_THREAD_ATTRIBUTE_PARENT_PROCESS) and CreateProcess* with EXTENDED_STARTUPINFO_PRESENT / StartupInfoEx |
| `etw:Microsoft-Windows-Security-Auditing` | api_call: LogonUser(A\|W), LsaLogonUser, SetThreadToken, ImpersonateLoggedOnUser |
| `etw:Microsoft-Windows-Kernel-Process` | API calls |
| `auditd:SYSCALL` | ptrace, mmap, process_vm_writev |
| `auditd:SYSCALL` | execve of dd or sed targeting /proc/*/mem |
| `etw:Microsoft-Windows-Kernel-Process` | CreateTransaction, CreateFileTransacted, RollbackTransaction, NtCreateProcessEx, NtCreateThreadEx |
| `ETW` | Calls to GetUserDefaultUILanguage, GetSystemDefaultUILanguage, GetKeyboardLayoutList |
| `etw:Microsoft-Windows-Kernel-Process` | WriteProcessMemory: WriteProcessMemory targeting regions containing KernelCallbackTable addresses |
| `EDR:file` | SetFileTime |
