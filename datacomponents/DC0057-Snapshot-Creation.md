# DC0057 - Snapshot Creation

## Description

The process of taking a point-in-time copy of a cloud storage volume (files, settings, configurations, etc.), virtual machine (VM), or database that can be created and deployed in cloud environments.

## Log Sources

| Log Source | Channel |
|------------|---------|
| `esxi:vmkernel` | snapshot create/write events |
| `AWS:CloudTrail` | CreateSnapshot |
| `azure:activity` | MICROSOFT.COMPUTE/SNAPSHOTS/WRITE |
