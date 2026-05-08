# DC0049 - Snapshot Deletion

## Description

The removal of a point-in-time backup of a cloud storage volume, virtual machine (VM), or database.

*Data Collection Measures:*

- AWS CloudTrail
    - Logs `DeleteSnapshot` API calls in EC2, RDS, and EBS services.
- Azure Monitor Logs
    - Tracks snapshot deletions via `Microsoft.Compute/snapshots/delete` API calls.
- Google Cloud Logging
    - Detects snapshot removal through `compute.disks.deleteSnapshot` events.

## Log Sources

| Log Source | Channel |
|------------|---------|
| `AWS:CloudTrail` | DeleteSnapshot |
| `esxi:hostd` | snapshot.removeall or snapshot file deletion |
