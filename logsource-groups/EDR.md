# EDR

19 unique events

| Log Source | Channel | Data Components |
|------------|---------|-----------------|
| `EDR:AMSI` | Malicious inline C#/script blobs embedded in MSBuild projects if intercepted by AMSI-aware loaders (rare but possible via chained LOLBins) | Script Execution |
| `EDR:AMSI` | None | Command Execution |
| `EDR:Telemetry` | Process lineage and API usage enrichment (GetSystemTime, GetTimeZoneInformation, NtQuerySystemTime) | Process Metadata |
| `EDR:cli` | Command Line Telemetry | Command Execution |
| `EDR:detection` | App reputation telemetry | File Metadata |
| `EDR:detection` | ThreatDetected, QuarantineLog | Application Log Content |
| `EDR:detection` | ThreatLog | Application Log Content |
| `EDR:file` | File Metadata Analysis (PE overlays, entropy) | File Metadata |
| `EDR:file` | File Metadata Inspection (Low String Entropy, Missing PDB) | File Metadata |
| `EDR:file` | SetFileTime | OS API Execution |
| `EDR:hunting` | Advanced Hunting: DeviceProcessEvents + DeviceNetworkEvents | Network Traffic Content |
| `EDR:hunting` | Behavioral rule for registry enumeration under credential-related paths | Windows Registry Key Access |
| `EDR:hunting` | Correlation of signer info, parent-child lineage, rare invocation context (user host role), and API surfaces (CreateProcess*, LoadLibrary*) | Process Metadata |
| `EDR:memory` | API usage MFCreateDeviceSource, IAMStreamConfig, ICaptureGraphBuilder2, DirectShow filter graph creation from uncommon callers | OS API Execution |
| `EDR:memory` | Behavioral API telemetry (GetProcAddress, LoadLibrary, VirtualAlloc) | OS API Execution |
| `EDR:memory` | MemoryWriteToExecutable | OS API Execution |
| `EDR:memory` | Objective‑C/Swift calls to AVCaptureDevice/AVCaptureSession by non-whitelisted processes | OS API Execution |
| `EDR:memory` | VirtualAlloc/VirtualProtect/MapViewOfFile indicators via stack/heap activity and ImageLoad | OS API Execution |
| `EDR:scriptblock` | Process Tree + Script Block Logging | Script Execution |
