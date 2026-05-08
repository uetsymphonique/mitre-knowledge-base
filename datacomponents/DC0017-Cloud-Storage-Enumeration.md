# DC0017 - Cloud Storage Enumeration

## Description

Cloud Storage Enumeration involves retrieving a list of available cloud storage infrastructure, such as buckets, containers, or objects, within a cloud environment. This activity may be performed for legitimate administrative purposes or malicious reconnaissance by adversaries seeking to identify accessible storage resources.Examples:

- AWS S3 Bucket Enumeration: An AWS user lists all buckets using the `ListBuckets` API call.
- Azure Blob Storage Container Enumeration: A user retrieves a list of all containers within a storage account using the Azure Storage SDK or API.
- Google Cloud Storage Bucket Enumeration: A Google Cloud user lists all buckets within a project using the `storage.buckets.list` API.
- OpenStack Swift Container Enumeration: A user retrieves a list of containers in OpenStack Swift using the `GET` method on the storage endpoint.

## Log Sources

| Log Source | Channel |
|------------|---------|
| `AWS:CloudTrail` | ListBuckets |
| `AWS:CloudTrail` | ListObjectsV2 |
| `azure:activity` | List Blobs |
| `gcp:storage` | storage.objects.list |
