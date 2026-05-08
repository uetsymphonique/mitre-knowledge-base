# kubernetes

26 unique events

| Log Source | Channel | Data Components |
|------------|---------|-----------------|
| `kubernetes:apiserver` | Pod spec triggering build or custom controller activity invoking image builds | Image Creation |
| `kubernetes:apiserver` | Pod spec with hostPath or privileged securityContext | Volume Modification |
| `kubernetes:apiserver` | Resource creation and update logs | Image Metadata |
| `kubernetes:apiserver` | authentication.k8s.io/v1beta1 | User Account Authentication |
| `kubernetes:apiserver` | create/exec: Kubernetes API calls to exec into containers or create pods from curl, kubectl, or SDK clients | Container Creation |
| `kubernetes:apiserver` | exec into pod followed by secret retrieval via API | Process Creation |
| `kubernetes:apiserver` | get/list requests to /api/v1/secrets or /api/v1/namespaces/*/serviceaccounts | User Account Authentication |
| `kubernetes:apiserver` | kubectl exec or kubelet API calls targeting running pods | Process Creation |
| `kubernetes:apiserver` | list or get requests against pods, deployments, or nodes | Pod Enumeration |
| `kubernetes:apiserver` | serviceAccount token used in API requests not tied to workload identity | Web Credential Usage |
| `kubernetes:apiserver` | verb=create, resource=cronjobs, group=batch | Scheduled Job Creation |
| `kubernetes:audit` | Failed login | User Account Authentication |
| `kubernetes:audit` | GET or LIST requests to /var/run/secrets/kubernetes.io/serviceaccount/ followed by access to the Kubernetes API server | File Access |
| `kubernetes:audit` | Shell process (e.g., /bin/sh, /bin/bash) spawned in a container without an interactive session attached (i.e., automation anomaly) | Command Execution |
| `kubernetes:audit` | Unauthorized container creation or kubelet exec logs | Logon Session Metadata |
| `kubernetes:audit` | authentication.k8s.io | User Account Authentication |
| `kubernetes:audit` | create | Image Creation, Pod Creation, Service Creation |
| `kubernetes:audit` | create or update events for RoleBinding or ClusterRoleBinding objects | User Account Modification |
| `kubernetes:audit` | create: Pod/Container created with image tag 'latest' or mutable tag; imagePullPolicy=Always; noDigest=true | Container Creation |
| `kubernetes:audit` | kubectl delete or patch of security pods/admission controllers | Service Metadata |
| `kubernetes:audit` | process execution involving curl, grep, or awk on secrets | Command Execution |
| `kubernetes:audit` | seccomp or AppArmor profile changes | Service Metadata |
| `kubernetes:events` | CrashLoopBackOff, OOMKilled, container restart count exceeds threshold | Host Status |
| `kubernetes:events` | container start/stop activity via Docker, containerd, or CRI-O | Container Creation |
| `kubernetes:events` | start: ContainerStarted or Pulling image → Started container | Container Start |
| `kubernetes:orchestrator` | Access to orchestrator logs containing credentials (Docker/Kubernetes logs) | Application Log Content |
