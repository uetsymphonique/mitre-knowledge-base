# DC0081 - Instance Deletion

## Description

Removal of a virtual machine (VM) or compute instance within a cloud infrastructure. This activity results in the termination and deletion of the allocated resources (e.g., CPU, memory, storage), making the instance unavailable for future use. Examples:

- AWS: instance deletion involves the `TerminateInstances` API call, which is recorded in CloudTrail logs.
- Azure: VM deletion can be monitored via Azure Activity Logs, showing the `Microsoft.Compute/virtualMachines/delete` operation.
- GCP: instance deletion is logged as an instance.delete operation within GCP Audit Logs.

## Log Sources

| Log Source | Channel |
|------------|---------|
| `azure:activity` | MICROSOFT.COMPUTE/VIRTUALMACHINES/DELETE |
| `gcp:audit` | compute.instances.delete |
