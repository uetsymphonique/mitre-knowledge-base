# etw

28 unique events

| Log Source | Channel | Data Components |
|------------|---------|-----------------|
| `etw:Microsoft-Antimalware-Scan-Interface` | Amsi/Script content + API verdicts during in-memory staging | Script Execution |
| `etw:Microsoft-Windows-ClickOnce` | provider: Event Tracing for Windows (ETW) events associated with ClickOnce deployment (dfsvc.exe activity) | Process Metadata |
| `etw:Microsoft-Windows-Directory-Services-SAM` | api_call: Calls to DsAddSidHistory or related RPC operations | OS API Execution |
| `etw:Microsoft-Windows-DotNETRuntime` | AssemblyLoad/ModuleLoad (Loader keyword) from Microsoft-Windows-DotNETRuntime | OS API Execution |
| `etw:Microsoft-Windows-Kernel-Base` | GetLocaleInfoW, GetTimeZoneInformation API calls | OS API Execution |
| `etw:Microsoft-Windows-Kernel-File` | ZwSetEaFile or ZwQueryEaFile function calls | OS API Execution |
| `etw:Microsoft-Windows-Kernel-ImageLoad` | provider: Unsigned/user-writable image loads into msbuild.exe | Module Load |
| `etw:Microsoft-Windows-Kernel-Process` | APCQueueOperations | OS API Execution |
| `etw:Microsoft-Windows-Kernel-Process` | API Calls | OS API Execution |
| `etw:Microsoft-Windows-Kernel-Process` | API calls | OS API Execution |
| `etw:Microsoft-Windows-Kernel-Process` | API tracing / stack tracing via ETW or telemetry-based EDR | OS API Execution |
| `etw:Microsoft-Windows-Kernel-Process` | CreateTransaction, CreateFileTransacted, RollbackTransaction, NtCreateProcessEx, NtCreateThreadEx | OS API Execution |
| `etw:Microsoft-Windows-Kernel-Process` | High-frequency or suspicious sequence of QueryPerformanceCounter/GetTickCount API calls from a non-standard process lineage | OS API Execution |
| `etw:Microsoft-Windows-Kernel-Process` | Memory Modification / Unmapped module load or suspicious RWX allocations in the process space of a browser process | Process Modification |
| `etw:Microsoft-Windows-Kernel-Process` | NtQueryInformationProcess | OS API Execution |
| `etw:Microsoft-Windows-Kernel-Process` | NtUnmapViewOfSection, VirtualAllocEx, WriteProcessMemory, SetThreadContext, ResumeThread | OS API Execution |
| `etw:Microsoft-Windows-Kernel-Process` | WriteProcessMemory: WriteProcessMemory targeting regions containing KernelCallbackTable addresses | OS API Execution |
| `etw:Microsoft-Windows-Kernel-Process` | api_call: UpdateProcThreadAttribute (PROC_THREAD_ATTRIBUTE_PARENT_PROCESS) and CreateProcess* with EXTENDED_STARTUPINFO_PRESENT / StartupInfoEx | OS API Execution |
| `etw:Microsoft-Windows-Kernel-Process` | process_start: EventHeader.ProcessId true parent vs reported PPID mismatch | Process Metadata |
| `etw:Microsoft-Windows-Kernel-Process` | provider: ETW CreateProcess events linking msbuild.exe to suspicious children where standard logs are incomplete | Process Creation |
| `etw:Microsoft-Windows-Kernel-Storage` | Raw disk I/O operations bypassing NTFS APIs | Firmware Modification |
| `etw:Microsoft-Windows-NDIS-PacketCapture` | TLS Handshake/Network Flow | Network Traffic Content |
| `etw:Microsoft-Windows-RPC` | rpc_call: srvsvc.NetShareEnum / NetShareEnumAll from non-admin or unusual processes | OS API Execution |
| `etw:Microsoft-Windows-Security-Auditing` | api_call: LogonUser(A\|W), LsaLogonUser, SetThreadToken, ImpersonateLoggedOnUser | OS API Execution |
| `etw:Microsoft-Windows-Win32k` | SendMessage, PostMessage, LVM_* | OS API Execution |
| `etw:Microsoft-Windows-Win32k` | SetWindowLong, SetClassLong, NtUserMessageCall, SendNotifyMessage, PostMessage | OS API Execution |
| `etw:Microsoft-Windows-WinINet` | HTTPS Inspection | Network Traffic Content |
| `etw:Microsoft-Windows-WinINet` | WinINet API telemetry | Network Traffic Content |
