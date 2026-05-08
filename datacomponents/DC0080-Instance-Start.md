# DC0080 - Instance Start

## Description

The initiation or activation of a virtual machine instance within a cloud infrastructure. This action typically involves starting an existing instance that had been stopped or paused, allowing it to resume operation. Examples: 

- Google Cloud Platform (GCP): Starting an instance through `instance.start` API activity.
- AWS: Logging of `StartInstances` in AWS CloudTrail for EC2 instances.
- Azure: `Microsoft.Compute/virtualMachines/start` entries indicate a VM instance being started.

## Log Sources

| Log Source | Channel |
|------------|---------|
| `AWS:CloudTrail` | StartInstances |
| `AWS:CloudTrail` | RunInstances |
