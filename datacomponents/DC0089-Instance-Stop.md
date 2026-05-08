# DC0089 - Instance Stop

## Description

The deactivation or shutdown of a virtual machine instance within a cloud infrastructure. This action typically involves stopping a running instance, which halts its operation and releases certain associated resources, such as CPU and memory. Examples: 

- Google Cloud Platform (GCP): `instance.stop` events recorded in GCP Audit Logs indicate the deactivation of an instance.
- Amazon Web Services (AWS): `StopInstances` actions in AWS CloudTrail indicate EC2 instances being stopped.
- Microsoft Azure: `Microsoft.Compute/virtualMachines/deallocate` or `stop` events in Azure Activity Logs represent a virtual machine being stopped or deallocated.

## Log Sources

| Log Source | Channel |
|------------|---------|
| `AWS:CloudTrail` | TerminateInstances |
| `AWS:CloudTrail` | StopInstances |
