# DC0076 - Instance Creation

## Description

The initial provisioning and construction of a virtual machine (VM) or compute instance within a cloud infrastructure environment. This activity involves defining and allocating resources such as CPU, memory, storage, and networking to spin up a new compute instance. Examples:

- AWS: creating an EC2 instance using RunInstances API calls.
- Azure, creating a VM through the Azure Resource Manager (ARM).
- GCP, an `instance.insert` action recorded.

## Log Sources

| Log Source | Channel |
|------------|---------|
| `azure:activity` | Microsoft.Compute/virtualMachines/write: imageReference publisher NOT IN allowlist OR plan is new/unknown |
| `gcp:audit` | compute.instances.insert: sourceImage not in approved projects OR has external image link |
| `azure:activity` | MICROSOFT.COMPUTE/VIRTUALMACHINES/WRITE |
| `gcp:audit` | compute.instances.insert |
| `AWS:CloudTrail` | RunInstances,CreateImage |
