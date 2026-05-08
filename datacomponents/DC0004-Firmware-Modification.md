# DC0004 - Firmware Modification

## Description

Changes made to firmware, which may include its settings, configurations, or underlying data. This can encompass alterations to the Master Boot Record (MBR), Volume Boot Record (VBR), or other firmware components critical to system boot and functionality. Such modifications are often indicators of adversary activity, including malware persistence and system compromise. Examples: 

- Changes to Master Boot Record (MBR): Modifying the MBR to load malicious code during the boot process.
- Changes to Volume Boot Record (VBR): Altering the VBR to redirect boot processes to malicious locations.
- Firmware Configuration Changes: Modifying BIOS/UEFI settings such as disabling Secure Boot.
- Firmware Image Tampering: Updating firmware with a malicious or unauthorized image.
- Logs or Errors Indicating Firmware Changes: Logs showing unauthorized firmware updates or checksum mismatches.

This data component can be collected through the following measures:

- BIOS/UEFI Logs: Enable and monitor BIOS/UEFI logs to capture settings changes or firmware updates.
- Firmware Integrity Monitoring: Use tools or firmware security features to detect changes to firmware components.
- Endpoint Detection and Response (EDR) Solutions: Many EDR platforms can detect abnormal firmware activity, such as changes to MBR/VBR or unauthorized firmware updates.
- File System Monitoring: Monitor changes to MBR/VBR-related files using tools like Sysmon or auditd.
    - Windows Example (Sysmon): Monitor Event ID 7 (Raw disk access).
    - Linux Example (auditd): `auditctl -w /dev/sda -p wa -k firmware_modification`
- Network Traffic Analysis: Capture firmware updates downloaded over the network, particularly from untrusted sources. Use network monitoring tools like Zeek or Wireshark to analyze firmware-related traffic.
- Secure Boot Logs: Collect and analyze Secure Boot logs for signs of tampering or unauthorized configurations. Example: Use PowerShell to retrieve Secure Boot settings on Windows: `Confirm-SecureBootUEFI`
- Vendor-Specific Firmware Tools: Many hardware vendors provide tools for firmware integrity checks.Examples:
    - Intel Platform Firmware Resilience (PFR).
    - Lenovo UEFI diagnostics.

## Log Sources

| Log Source | Channel |
|------------|---------|
| `Firmware` | None |
| `networkdevice:syslog` | Image Upgrade / Configuration Change |
| `networkdevice:config` | Boot image path or firmware configuration variable modified outside of maintenance windows |
| `WinEventLog:Microsoft-Windows-Kernel-Boot` | Firmware integrity validation failed or boot configuration tampered |
| `auditd:SYSCALL` | write access to /dev/mem or /sys/firmware/efi/efivars |
| `macos:unifiedlog` | boot failure events or SMC validation errors |
| `networkdevice:firmware` | Firmware update initiated or bootloader tampering detected |
| `networkdevice:config` | Log entries indicating ROMMON image upgrade commands (boot system, upgrade rom-monitor) |
| `networkdevice:config` | Boot variable modified to point to non-standard or unsigned image |
| `firmware:integrity ` | Firmware integrity verification failures or mismatches against expected UEFI/firmware image baselines |
| `auditd:SYSCALL` | ioctl/write: Direct firmware update or device memory manipulation syscalls |
| `firmware:smart` | Unexpected firmware-level errors or abnormal S.M.A.R.T. log entries |
| `macos:unifiedlog` | Firmware update events or kernel extension (kext) loads not signed by Apple |
| `firmware:integrity` | Baseline mismatch or unexpected EFI module detected during integrity checks |
| `macos:osquery` | Unexpected changes in EFI or NVRAM variables controlling hardware boot state |
| `networkdevice:syslog` | Custom firmware or routing changes |
| `etw:Microsoft-Windows-Kernel-Storage` | Raw disk I/O operations bypassing NTFS APIs |
| `firmware:runtime` | Debug or memory access commands indicating attempts to alter OS instructions in memory |
| `networkdevice:syslog` | Boot information log showing image loaded from TFTP server instead of local storage |
