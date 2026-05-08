# DC0025 - Cloud Storage Access

## Description

Cloud storage access refers to the retrieval or interaction with data stored in cloud infrastructure. This data component includes activities such as reading, downloading, or accessing files and objects within cloud storage systems. Common examples include API calls like GetObject in AWS S3, which retrieves objects from cloud buckets. Examples: 

- AWS S3 Access: An adversary uses the `GetObject` API to retrieve sensitive data from an AWS S3 bucket.
- Azure Blob Storage Access: A user accesses a blob in Azure Storage using `Get Blob` or `Get Blob Properties`.
- Google Cloud Storage Access: An adversary uses `storage.objects.get` to download objects from - OpenStack Swift Storage Access: A user retrieves an object from OpenStack Swift using the `GET` method.

## Log Sources

| Log Source | Channel |
|------------|---------|
| `AWS:CloudTrail` | GetObject, CopyObject |
| `AWS:CloudTrail` | PutObject: S3 writes with .sql/.csv extension by same identity or within 5 min of DB access |
| `m365:unified` | Accessed SharePoint files or pages |
| `m365:unified` | FileAccessed, FileDownloaded, ConsentGranted |
| `gcp:workspaceaudit` | download, authorization_grant |
| `m365:sharepoint` | AnonymousLinkCreated, FileDownloaded |
| `m365:unified` | App-only or delegated access patterns where client_id != known enterprise apps |
| `saas:github` | Artifact generated includes base64/encoded exfil payload or URL |
