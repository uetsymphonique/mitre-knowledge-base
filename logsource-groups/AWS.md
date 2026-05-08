# AWS

139 unique events

| Log Source | Channel | Data Components |
|------------|---------|-----------------|
| `AWS:CloudMetrics` | Autoscaling, memory/cpu alarms, or instance unhealthiness | Host Status |
| `AWS:CloudTrail` | AWS ConsoleLogin, StartSession | Logon Session Creation |
| `AWS:CloudTrail` | AWS IAM: ListUsers, ListRoles | User Account Authentication |
| `AWS:CloudTrail` | AssumeRole | User Account Metadata |
| `AWS:CloudTrail` | AssumeRole or ConsoleLogin with repeated MFA failures followed by repeated MFA requests | User Account Authentication |
| `AWS:CloudTrail` | AssumeRole, GetFederationToken API calls by unusual or new entities | Web Credential Creation |
| `AWS:CloudTrail` | AssumeRole, GetFederationToken, GetSessionToken | Web Credential Usage |
| `AWS:CloudTrail` | AssumeRole,AssumeRoleWithSAML,AssumeRoleWithWebIdentity | Logon Session Creation |
| `AWS:CloudTrail` | AssumeRole: Discovery actions tied to assumed identities outside of normal context | User Account Metadata |
| `AWS:CloudTrail` | AssumeRoleWithSAML | Web Credential Usage |
| `AWS:CloudTrail` | AssumeRoleWithWebIdentity | User Account Authentication |
| `AWS:CloudTrail` | AttachUserPolicy | User Account Modification |
| `AWS:CloudTrail` | AttachUserPolicy, CreatePolicyVersion, PutRolePolicy | User Account Modification |
| `AWS:CloudTrail` | AuthorizeSecurityGroupIngress | Firewall Rule Modification |
| `AWS:CloudTrail` | Condition block updated in IAM policy (e.g., aws:SourceIp, aws:RequestedRegion) | Cloud Service Modification |
| `AWS:CloudTrail` | ConsoleLogin | Logon Session Creation |
| `AWS:CloudTrail` | ConsoleLogin or AssumeRole | User Account Authentication |
| `AWS:CloudTrail` | ConsoleLogin, AssumeRole, ListAccessKeys, CreateUser | User Account Authentication |
| `AWS:CloudTrail` | ConsoleLogin, AssumeRole, ListResources | Logon Session Creation |
| `AWS:CloudTrail` | ConsoleLogin: If IdP backed by cloud provider, Console login from new IP/agent after correlated endpoint compromise | Logon Session Creation |
| `AWS:CloudTrail` | CopySnapshot | Snapshot Metadata |
| `AWS:CloudTrail` | Create egress rule allowing UDP to port 53, 123, 11211 | Firewall Rule Modification |
| `AWS:CloudTrail` | CreateAccessKey | User Account Modification |
| `AWS:CloudTrail` | CreateAccessKey, ImportKeyPair, CreateLoginProfile, CreateKeyPair | Active Directory Object Creation |
| `AWS:CloudTrail` | CreateAccount: API calls creating new accounts in AWS Organizations | Cloud Service Modification |
| `AWS:CloudTrail` | CreateBucket | Cloud Storage Creation |
| `AWS:CloudTrail` | CreateFunction | Cloud Service Modification |
| `AWS:CloudTrail` | CreateFunction / UpdateFunctionConfiguration: Function creation, role assignment, or configuration change events | Cloud Service Modification |
| `AWS:CloudTrail` | CreatePod: Programmatic creation of new pod resources using container images not seen before in the environment | Pod Creation |
| `AWS:CloudTrail` | CreateSnapshot | Snapshot Creation |
| `AWS:CloudTrail` | CreateTrafficMirrorSession / ModifyTrafficMirrorTarget | Cloud Service Modification |
| `AWS:CloudTrail` | CreateTrafficMirrorSession or ModifyTrafficMirrorTarget | Network Traffic Flow |
| `AWS:CloudTrail` | CreateUser | User Account Creation |
| `AWS:CloudTrail` | CreateUser\|AttachRolePolicy\|CreateAccessKey\|UpdateAssumeRolePolicy\|CreateLoginProfile | Application Log Content |
| `AWS:CloudTrail` | CreateVolume | Volume Creation |
| `AWS:CloudTrail` | Decrypt | OS API Execution |
| `AWS:CloudTrail` | Delete* / Stop*: DeleteAlarms, StopLogging, or DisableMonitoring API calls | Cloud Service Modification |
| `AWS:CloudTrail` | DeleteBucket, DeleteDBCluster, DeleteSnapshot, TerminateInstances | Cloud Storage Deletion |
| `AWS:CloudTrail` | DeleteSnapshot | Snapshot Deletion |
| `AWS:CloudTrail` | DeleteVolume | Volume Deletion |
| `AWS:CloudTrail` | Describe* or List* API calls | OS API Execution |
| `AWS:CloudTrail` | DescribeCluster, ListClusters, ListNodegroups | Container Enumeration |
| `AWS:CloudTrail` | DescribeDBInstances | Instance Enumeration |
| `AWS:CloudTrail` | DescribeInstances | Instance Metadata |
| `AWS:CloudTrail` | DescribeInstances, DescribeServices, ListFunctions: High frequency enumeration calls or unusual user agents performing discovery | Cloud Service Enumeration |
| `AWS:CloudTrail` | DescribeInstances, GetConsoleOutput, DescribeImages | Instance Enumeration |
| `AWS:CloudTrail` | DescribeSnapshots | Snapshot Metadata |
| `AWS:CloudTrail` | DescribeUsers / ListUsers / GetUser | Cloud Service Enumeration |
| `AWS:CloudTrail` | GetAccountPasswordPolicy | User Account Metadata |
| `AWS:CloudTrail` | GetCallerIdentity | Web Credential Usage |
| `AWS:CloudTrail` | GetConsoleOutput | Logon Session Creation |
| `AWS:CloudTrail` | GetInstanceIdentityDocument | Cloud Service Metadata |
| `AWS:CloudTrail` | GetInstanceIdentityDocument or IMDSv2 token requests | Cloud Service Enumeration |
| `AWS:CloudTrail` | GetLogEvents: High frequency log exports from CloudWatch or equivalent services | Command Execution |
| `AWS:CloudTrail` | GetMetadata, DescribeInstanceIdentity | OS API Execution |
| `AWS:CloudTrail` | GetObject, CopyObject | Cloud Storage Access |
| `AWS:CloudTrail` | GetSecretValue | Cloud Service Enumeration, Cloud Service Metadata |
| `AWS:CloudTrail` | GetSessionToken, AssumeRoleWithWebIdentity | Web Credential Usage |
| `AWS:CloudTrail` | Ingress rule creation or modification for security group | Firewall Rule Modification |
| `AWS:CloudTrail` | InvokeFunction | Cloud Service Metadata, Command Execution |
| `AWS:CloudTrail` | InvokeFunction: Unexpected or repeated invocation of functions not tied to known workflows | Application Log Content |
| `AWS:CloudTrail` | InvokeModel | Application Log Content |
| `AWS:CloudTrail` | LeaveOrganization: API calls severing accounts from AWS Organizations | Cloud Service Modification |
| `AWS:CloudTrail` | ListBuckets | Cloud Storage Enumeration |
| `AWS:CloudTrail` | ListGroups, ListAttachedRolePolicies | Group Enumeration |
| `AWS:CloudTrail` | ListObjectsV2 | Cloud Storage Enumeration |
| `AWS:CloudTrail` | ModifyImageAttribute | Image Modification |
| `AWS:CloudTrail` | ModifySnapshotAttribute | Snapshot Modification |
| `AWS:CloudTrail` | ModifyVolume | Volume Modification |
| `AWS:CloudTrail` | New security group created with permissive rules | Firewall Rule Modification |
| `AWS:CloudTrail` | PassRole | User Account Metadata |
| `AWS:CloudTrail` | Post-authentication metadata enumeration from GUI session | Cloud Storage Metadata |
| `AWS:CloudTrail` | PutBucketLifecycle, PutLifecycleConfiguration, SetBucketLifecycle, storage.buckets.update | Cloud Storage Modification |
| `AWS:CloudTrail` | PutBucketPolicy | Cloud Storage Modification |
| `AWS:CloudTrail` | PutIdentityPolicy | Cloud Service Modification |
| `AWS:CloudTrail` | PutObject | File Creation |
| `AWS:CloudTrail` | PutObject (with SSE-C), UploadPart (SSE-C) | Cloud Storage Modification |
| `AWS:CloudTrail` | PutObject: S3 writes with .sql/.csv extension by same identity or within 5 min of DB access | Cloud Storage Access |
| `AWS:CloudTrail` | PutUserPolicy, PutGroupPolicy, PutRolePolicy, CreatePolicyVersion | Cloud Service Modification |
| `AWS:CloudTrail` | RegisterImage | Image Creation |
| `AWS:CloudTrail` | Removal of CloudTrail trail | Cloud Service Disable |
| `AWS:CloudTrail` | Removal of restrictive egress rules from a security group | Firewall Disable |
| `AWS:CloudTrail` | RequestServiceQuotaIncrease | Cloud Service Modification |
| `AWS:CloudTrail` | RevertSnapshot | Instance Modification |
| `AWS:CloudTrail` | RunInstances | Instance Start |
| `AWS:CloudTrail` | RunInstances,CreateImage | Instance Creation |
| `AWS:CloudTrail` | SSM RunCommand | Command Execution |
| `AWS:CloudTrail` | SendCommand, StartSession, ExecuteCommand: Unexpected AWS Systems Manager command execution targeting EC2 instances | Command Execution |
| `AWS:CloudTrail` | SendEmail | Application Log Content |
| `AWS:CloudTrail` | SendSSHPublicKey, StartSession (SSM), EC2InstanceConnect | Logon Session Creation |
| `AWS:CloudTrail` | SessionToken used without preceding MFA or login event | Web Credential Usage |
| `AWS:CloudTrail` | StartInstances | Instance Start |
| `AWS:CloudTrail` | Stop logging for an existing CloudTrail | Cloud Service Disable |
| `AWS:CloudTrail` | StopInstances | Instance Stop |
| `AWS:CloudTrail` | StopLogging, DeleteTrail, UpdateTrail: API calls that disable or modify logging services | Application Log Content |
| `AWS:CloudTrail` | StopLogging, DeleteTrail, or DisableSecurityService | Cloud Service Disable |
| `AWS:CloudTrail` | Temporary security credentials used to authenticate into management console or APIs | Logon Session Creation |
| `AWS:CloudTrail` | TerminateInstances | Instance Stop |
| `AWS:CloudTrail` | UpdateAccountPasswordPolicy | Cloud Service Modification |
| `AWS:CloudTrail` | UpdateFederationSettings or RegisterHybridConnector | Cloud Service Modification |
| `AWS:CloudTrail` | UpdateIdentityPolicy or DisableMFA | Cloud Service Modification |
| `AWS:CloudTrail` | UpdateLoginProfile | User Account Modification |
| `AWS:CloudTrail` | Use of temporary credentials issued from IMDS access | Cloud Service Modification |
| `AWS:CloudTrail` | Web console logins using session cookies without corresponding MFA event | Logon Session Creation |
| `AWS:CloudTrail` | command-line execution invoking credential enumeration | Command Execution |
| `AWS:CloudTrail` | cross-account or unexpected assume role | Process Metadata |
| `AWS:CloudTrail` | eventName: RunInstances, CreateUser, PutRolePolicy, InvokeCommand | Command Execution |
| `AWS:CloudTrail` | eventName=ConsoleLogin \| eventType=AwsConsoleSignIn | User Account Authentication |
| `AWS:CloudTrail` | rds:ExecuteStatement: Large data access via RDS or Aurora with unknown session context | Cloud Service Metadata |
| `AWS:CloudTrail` | role privilege expansion detected | User Account Modification |
| `AWS:CloudTrail` | ssm:GetCommandInvocation | Command Execution |
| `AWS:CloudTrail` | ssm:ListInventoryEntries | Cloud Service Enumeration |
| `AWS:CloudTrail` | sts:GetFederationToken | User Account Authentication |
| `AWS:CloudTrail` | sudden role assumption after credential file access | Logon Session Creation |
| `AWS:CloudWatch` | Elevated 5xx response rates in application logs or gateway layer | Application Log Content |
| `AWS:CloudWatch` | NetworkOut spike beyond baseline | Host Status |
| `AWS:CloudWatch` | Repeated crash pattern within container or instance logs | Application Log Content |
| `AWS:CloudWatch` | StatusCheckFailed or StatusCheckFailed_System for burstable instances (t2/t3) | Host Status |
| `AWS:CloudWatch` | Sudden spike in network output without a corresponding inbound request ratio | Host Status |
| `AWS:CloudWatch` | Sustained EC2 CPU usage above normal baseline | Host Status |
| `AWS:CloudWatch` | Sustained spike in CPU usage on EC2 instance with web service role | Host Status |
| `AWS:CloudWatch` | Unusual CPU burst or metric anomalies | Host Status |
| `AWS:CloudWatch` | unexpected IAM user or role assuming privileges for instance/snapshot operations | Cloud Service Metadata |
| `AWS:VPCFlowLogs` | High outbound traffic from new region resource | Network Connection Creation |
| `AWS:VPCFlowLogs` | High volume internal-to-internal IP transfer or cross-account cloud transfer | Network Traffic Content |
| `AWS:VPCFlowLogs` | Large outbound UDP traffic to multiple public reflector IPs | Network Traffic Flow |
| `AWS:VPCFlowLogs` | Large transfer volume (>20MB) from RDS IP range to external public IPs | Network Connection Creation |
| `AWS:VPCFlowLogs` | Large volume of malformed or synthetic payloads to application endpoints prior to failure | Network Traffic Content |
| `AWS:VPCFlowLogs` | Outbound connection to 169.254.169.254 from EC2 workload | Network Connection Creation |
| `AWS:VPCFlowLogs` | Outbound connections to port 22, 3389 | Network Connection Creation |
| `AWS:VPCFlowLogs` | Outbound data flows | Network Traffic Flow |
| `AWS:VPCFlowLogs` | Outbound flow logs to known mining pools | Network Traffic Flow |
| `AWS:VPCFlowLogs` | Traffic between instances | Network Traffic Content |
| `AWS:VPCFlowLogs` | Traffic observed on mirror destination instance | Network Connection Creation |
| `AWS:VPCFlowLogs` | Unusual volume of data transferred from S3 storage endpoints to non-corporate IPs | Network Traffic Content |
| `AWS:VPCFlowLogs` | Unusual volume of inbound packets from single source across short time interval | Network Traffic Flow |
| `AWS:VPCFlowLogs` | VPC/NSG flow logs for pod/instance egress to Internet or metadata | Network Traffic Flow |
| `AWS:VPCFlowLogs` | egress > 90th percentile or frequent connection reuse | Network Traffic Flow |
| `AWS:VPCFlowLogs` | source instance sends large volume of traffic in short window | Network Traffic Flow |
