# DC0047 - Snapshot Enumeration

## Description

The process of listing or retrieving metadata about existing snapshots in a cloud environment.

*Data Collection Measures:*

- AWS CloudTrail
    - Logs API calls such as `DescribeSnapshots`, `ListSnapshots`, and `GetSnapshotAttributes`.
- Azure Monitor Logs
    - Tracks snapshot enumeration via `Microsoft.Compute/snapshots/read`.
- Google Cloud Logging
    - Detects snapshot listing through `compute.disks.listSnapshots`.
