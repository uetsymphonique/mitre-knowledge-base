# DC0075 - Instance Enumeration

## Description

The process of retrieving or querying a list of virtual machine instances or compute instances within a cloud infrastructure. This activity provides a view of all available or running instances, typically including their associated metadata such as instance ID, name, state, and configuration details. Examples:

- AWS: instance enumeration involves the `DescribeInstances` API call, which retrieves information about running or stopped EC2 instances.
- Azure: VM enumeration can be monitored via the `Microsoft.Compute/virtualMachines/read` operation.
- GCP: instance enumeration is logged as an `instance.list` operation within GCP Audit Logs.

*Data Collection Measures:*

- AWS CloudTrail: CloudTrail logs stored in S3 or forwarded to CloudWatch.
- Azure Activity Logs: Accessible via Azure Monitor or exported to a storage account.
- GCP Audit Logs: Logs Explorer or BigQuery.

## Log Sources

| Log Source | Channel |
|------------|---------|
| `AWS:CloudTrail` | DescribeDBInstances |
| `azure:activity` | MICROSOFT.COMPUTE/VIRTUALMACHINES/LIST |
| `gcp:audit` | compute.instances.list OR storage.buckets.list |
| `AWS:CloudTrail` | DescribeInstances, GetConsoleOutput, DescribeImages |
| `azure:activity` | Microsoft.Compute/virtualMachines/read |
