# DC0054 - Drive Access

## Description

Refers to the act of accessing a data storage device, such as a hard drive, SSD, USB, or network-mounted drive. This data component logs the opening or mounting of drives, capturing activities such as reading, writing, or executing files within an assigned drive letter (e.g., `C:\`, `/mnt/drive`) or mount point. Examples: 

- Removable Drive Insertion: A USB drive is inserted, assigned the letter `F:\`, and files are accessed.
- Network Drive Mounting: A network share `\\server\share` is mapped to the drive `Z:\`.
- External Hard Drive Access: An external drive is connected, mounted at `/mnt/backup`, and accessed for copying files.
- System Volume Access: The system volume `C:\` is accessed for modifications to critical files.
- Cloud-Synced Drives: Cloud storage drives like OneDrive or Google Drive are accessed via local mounts.

## Log Sources

| Log Source | Channel |
|------------|---------|
| `WinEventLog:Sysmon` | EventCode=9 |
| `auditd:SYSCALL` | open/write syscalls on /dev/sd* or /dev/nvme* |
| `auditd:SYSCALL` | write syscalls to /dev/sd* targeting offset 0 |
| `auditd:SYSCALL` | open/write syscalls to block devices (/dev/sd*, /dev/nvme*) |
| `linux:syslog` | mount/umount or file copy logs |
| `fs:fsusage` | open/read/mount operations |
| `linux:osquery` | hardware_events |
| `macos:osquery` | usb_devices |
