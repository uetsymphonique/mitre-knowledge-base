# DC0027 - Cloud Storage Metadata

## Description

Cloud Storage Metadata provides contextual information about cloud storage infrastructure and its associated activity. This data may include attributes such as storage name, size, owner, permissions, creation date, region, and activity metadata. It is essential for monitoring, auditing, and identifying anomalies in cloud storage environments. Examples: 

- AWS S3 Bucket Metadata: Metadata about an S3 bucket includes the bucket name, region, creation date, owner, storage class, and permissions.
- Azure Blob Storage Metadata: Metadata for an Azure Blob container includes container name, access level (e.g., private or public), size, and tags.
- Google Cloud Storage Metadata: Metadata includes bucket name, storage class, location, labels, lifecycle policies, and versioning status.
- OpenStack Swift Metadata: Metadata for a Swift container includes name, access level, quota, and custom attributes.

## Log Sources

| Log Source | Channel |
|------------|---------|
| `AWS:CloudTrail` | Post-authentication metadata enumeration from GUI session |
| `m365:unified` | AnonymousLinkCreated |
| `saas:box` | collaboration.invite |
| `saas:dropbox` | Shared link created to external account |
