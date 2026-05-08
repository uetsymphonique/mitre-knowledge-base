# DC0062 - Snapshot Metadata

## Description

Contextual data about a snapshot, which may include information such as ID, type, and status

## Log Sources

| Log Source | Channel |
|------------|---------|
| `AWS:CloudTrail` | DescribeSnapshots |
| `gcp:audit` | compute.disks.insert with sourceSnapshot parameter |
| `AWS:CloudTrail` | CopySnapshot |
