# DC0072 - Container Creation

## Description

"Container Creation" data component captures details about the initial construction of a container in a containerized environment. This includes events where a new container is instantiated, such as through Docker, Kubernetes, or other container orchestration platforms. Monitoring these events helps detect unauthorized or potentially malicious container creation. Examples:

- Docker Example: `docker create my-container`, `docker run --name=my-container nginx:latest`
- Kubernetes Example: `kubectl run my-pod --image=nginx`, `kubectl create deployment my-deployment --image=nginx`
- Cloud Container Services Example
    - AWS ECS: Task or service creation (`RunTask` or `CreateService`).
    - Azure Container Instances: Deployment of a container group.
    - Google Kubernetes Engine (GKE): Creation of new pods via GCP APIs.

## Log Sources

| Log Source | Channel |
|------------|---------|
| `kubernetes:apiserver` | create/exec: Kubernetes API calls to exec into containers or create pods from curl, kubectl, or SDK clients |
| `kubernetes:events` | container start/stop activity via Docker, containerd, or CRI-O |
| `docker:daemon` | container create/start with privileged flag or host volume mount |
| `kubernetes:audit` | create: Pod/Container created with image tag 'latest' or mutable tag; imagePullPolicy=Always; noDigest=true |
| `systemd:unit` | container run with restart policy set to 'always' or 'unless-stopped' |
| `docker:events` | created,started: new container from untrusted registry or unexpected entrypoint |
| `containerd:events` | create |
| `docker:events` | docker run with restart=always or modifying init |
