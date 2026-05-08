# DC0042 - Drive Creation

## Description

The activity of assigning a new drive letter or creating a mount point for a data storage device, such as a USB, network share, or external hard drive, enabling access to its content on a host system. Examples: 

- USB Drive Insertion: A USB drive is plugged in and automatically assigned the letter `E:\` on a Windows machine.
- Network Drive Mapping: A network share `\\server\share` is mapped to the drive `Z:\`.
- Virtual Drive Creation: A virtual disk is mounted on `/mnt/virtualdrive` using an ISO image or a virtual hard disk (VHD).
- Cloud Storage Mounting: Google Drive is mounted as `G:\` on a Windows machine using a cloud sync tool.
- External Storage Integration: An external HDD or SSD is connected and assigned `/mnt/external` on a Linux system..

## Log Sources

| Log Source | Channel |
|------------|---------|
| `Drive` | None |
| `WinEventLog:System` | Kernel-PnP 410/400 device install, disk added |
| `auditd:SYSCALL` | mknod,open,openat |
| `macos:unifiedlog` | mounted\|appeared\|DA: disk* attached |
| `WinEventLog:System` | EventCode=1006 |
| `auditd:SYSCALL` | Removable media mount notification |
| `macos:unifiedlog` | com.apple.diskarbitration |
| `WinEventLog:System` | EventCode=1006, 10001 |
| `auditd:SYSCALL` | device event logs |
| `linux:osquery` | mount_events |
| `macos:unifiedlog` | Volume Mount + File Read |
| `WinEventLog:System` | EventCode=2003 |
| `auditd:SYSCALL` | udev events or drive enumeration involving TinyPilot paths or device classes |
| `linux:syslog` | Device attach logs containing TinyPilot/PiKVM identifiers |
| `macos:unifiedlog` | Hardware enumeration events via IOKit or USBMuxd showing TinyPilot or unknown keyboard/mouse |
| `auditd:SYSCALL` | Kernel Device Events - USB Block Devices |
| `maos:osquery` | mount_events |
| `macos:unifiedlog` | Volume Mount + Process Trace + File Read |
| `journald:systemd` | udisks2 or udevd logs |
| `macos:unifiedlog` | log stream --predicate 'eventMessage contains "USBMSC"' |
| `linux:syslog` | New HID device enumeration with type 'keyboard' followed by immediate input injection |
| `macos:unifiedlog` | New IOUSB keyboard/HID device enumerated with suspicious attributes |
