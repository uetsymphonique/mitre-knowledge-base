# DC0098 - Volume Deletion

## Description

The removal of a cloud-based or on-premise block storage volume. This action permanently deletes the allocated storage and may result in data loss if not backed up.

*Data Collection Measures:*

- Cloud Logging & APIs
    - AWS CloudTrail Logs
        - `eventName: DeleteVolume` (tracks volume deletions)
    - Azure Monitor Logs
        - `operationName: Microsoft.Compute/disks/delete`
        - `status: Success | Failure` (flag unauthorized delete attempts)
    - Google Cloud Audit Logs
        - `protoPayload.methodName: "v1.compute.disks.delete"`
        - `authenticationInfo.principalEmail` (identifies the user deleting the volume)
- System & Host-Based Logging
    - Linux & macOS Logs:
        - `/var/log/syslog` or `/var/log/messages` for volume detach/deletion actions
    - Windows Event Logs:
        - Event ID 98 (Storage Class Memory)
        - Event ID 225 (Volume Removal Detected)
        - Event ID 12 (Disk Removal Notification)

## Log Sources

| Log Source | Channel |
|------------|---------|
| `esxi:vmkernel` | file delete\|datastore purge |
| `AWS:CloudTrail` | DeleteVolume |
