# DC0058 - Snapshot Modification

## Description

Changes made to a cloud snapshot's metadata, attributes, or control settings. These modifications may involve adjusting access permissions, changing retention policies, or altering encryption settings. 

*Data Collection Measures:*

- AWS CloudTrail
    - Tracks API calls such as `ModifySnapshotAttribute`, `ResetSnapshotAttribute`, and `ModifySnapshotTier`.
- Azure Monitor Logs
    - Logs changes via `Microsoft.Compute/snapshots/write`.
- Google Cloud Logging
    - Captures modifications through `compute.snapshots.setIamPolicy` and `compute.snapshots.patch`.

## Log Sources

| Log Source | Channel |
|------------|---------|
| `AWS:CloudTrail` | ModifySnapshotAttribute |
