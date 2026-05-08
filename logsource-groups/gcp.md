# gcp

38 unique events

| Log Source | Channel | Data Components |
|------------|---------|-----------------|
| `gcp:audit` | API Key Created, OAuth Client Registered | User Account Modification |
| `gcp:audit` | Admin Activity > Role Change or Sharing Change | User Account Modification |
| `gcp:audit` | Directory API Access | User Account Metadata |
| `gcp:audit` | Directory API Access: users.list or groups.list | User Account Metadata |
| `gcp:audit` | IAM API call: serviceAccounts.list or projects.getIamPolicy | User Account Metadata |
| `gcp:audit` | LoginAudit, DriveAudit | Logon Session Creation |
| `gcp:audit` | None | Command Execution |
| `gcp:audit` | Set Gmail Delegation | User Account Modification |
| `gcp:audit` | Sign-in logs / audit events | User Account Authentication |
| `gcp:audit` | Write operations to storage | File Access |
| `gcp:audit` | admin.googleapis.com | Logon Session Creation |
| `gcp:audit` | cloud.ssh.publicKey.inserted, compute.instances.osLogin | Logon Session Creation |
| `gcp:audit` | cloudidentity.groups.list | Group Enumeration |
| `gcp:audit` | compute.disks.insert with sourceSnapshot parameter | Snapshot Metadata |
| `gcp:audit` | compute.instances.delete | Instance Deletion |
| `gcp:audit` | compute.instances.insert | Instance Creation |
| `gcp:audit` | compute.instances.insert: sourceImage not in approved projects OR has external image link | Instance Creation |
| `gcp:audit` | compute.instances.list OR storage.buckets.list | Instance Enumeration |
| `gcp:audit` | compute.instances.restore | Instance Modification |
| `gcp:audit` | compute.instances.setMetadata | File Modification |
| `gcp:audit` | compute.packetMirroring.insert | Cloud Service Modification |
| `gcp:audit` | drive.activity | User Account Authentication |
| `gcp:audit` | google.iam.admin.v1.RoleAssignment | User Account Modification |
| `gcp:audit` | google.iam.credentials.generateAccessToken / serviceAccountTokenCreator | Logon Session Metadata |
| `gcp:audit` | iam.serviceAccounts.keys.create, os-login.sshPublicKeys.add | User Account Modification |
| `gcp:audit` | login.event | User Account Authentication |
| `gcp:audit` | methodName: setIamPolicy, startInstance, createServiceAccount | Command Execution |
| `gcp:audit` | network.query* | Network Traffic Content |
| `gcp:audit` | projects.updateQuota or orgPolicies.updatePolicy | Cloud Service Modification |
| `gcp:config` | UpdateSink request modifying log export destinations | Cloud Service Modification |
| `gcp:iam` | PrincipalEmail with serviceAccountTokenCreator impersonating new identity | User Account Metadata |
| `gcp:secrets` | accessSecretVersion | Cloud Service Enumeration |
| `gcp:storage` | storage.objects.list | Cloud Storage Enumeration |
| `gcp:vpcflow` | first 5m egress to unknown ASNs | Network Traffic Content |
| `gcp:workspaceaudit` | SendAs: Outbound messages with alias identities that differ from primary account | Application Log Content |
| `gcp:workspaceaudit` | Token Generation via Domain Delegation | User Account Authentication |
| `gcp:workspaceaudit` | download, authorization_grant | Cloud Storage Access |
| `gcp:workspaceaudit` | drive.activity logs | File Creation |
