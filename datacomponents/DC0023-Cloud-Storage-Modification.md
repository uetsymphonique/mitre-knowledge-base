# DC0023 - Cloud Storage Modification

## Description

Cloud Storage Modification involves tracking changes made to cloud storage infrastructure, including updates to settings, permissions, or stored data. Examples include modifying object access control lists (ACLs), uploading new objects, or updating bucket policies. Examples: 

AWS S3: An object is uploaded or its ACL is modified.
- Azure Blob Storage: A blob's metadata or permissions are updated.
- Google Cloud Storage: An object's lifecycle policy is updated, or a bucket policy is changed.
- OpenStack Swift: Modifications to container settings or uploading of new objects.

## Log Sources

| Log Source | Channel |
|------------|---------|
| `AWS:CloudTrail` | PutBucketLifecycle, PutLifecycleConfiguration, SetBucketLifecycle, storage.buckets.update |
| `AWS:CloudTrail` | PutObject (with SSE-C), UploadPart (SSE-C) |
| `AWS:CloudTrail` | PutBucketPolicy |
| `m365:unified` | SharingSet |
| `saas:googledrive` | drive.permission.add |
