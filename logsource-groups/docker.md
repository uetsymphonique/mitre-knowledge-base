# docker

23 unique events

| Log Source | Channel | Data Components |
|------------|---------|-----------------|
| `docker:api` | docker logs access or container inspect commands from non-administrative users | Command Execution |
| `docker:audit` | Process execution events within container namespace context | Process Creation |
| `docker:daemon` | ExecCreate + usermod or useradd | User Account Creation |
| `docker:daemon` | container create/start with privileged flag or host volume mount | Container Creation |
| `docker:daemon` | container file operations | File Deletion |
| `docker:daemon` | container_create,container_start | Application Log Content |
| `docker:daemon` | docker build or POST /build API request | Image Creation |
| `docker:daemon` | docker build or docker commit commands followed by docker push to internal registry | Image Creation |
| `docker:daemon` | docker exec or docker run with unexpected command/entrypoint | Command Execution |
| `docker:daemon` | docker ps, docker inspect, or docker images commands | Container Enumeration |
| `docker:events` | Container exited with non-zero code repeatedly in short period | Application Log Content |
| `docker:events` | Docker/Kubernetes audit of exec/attach (kubectl exec) or unexpected child processes inside container | Process Creation |
| `docker:events` | container exec rm\|container stop --force | Command Execution |
| `docker:events` | created,started: new container from untrusted registry or unexpected entrypoint | Container Creation |
| `docker:events` | docker run with restart=always or modifying init | Container Creation |
| `docker:events` | docker.events.json | Image Metadata |
| `docker:events` | exec_create: docker exec events targeting running containers from non-CI sources | Container Start |
| `docker:events` | remote API calls to /containers/create or /containers/{id}/start | Network Traffic Content |
| `docker:events` | start | Container Start |
| `docker:registry` | push event of new image version from unrecognized user or context | Image Modification |
| `docker:runtime` | Termination of monitoring sidecar or security container | Process Termination |
| `docker:runtime` | execution of cloud CLI tool (e.g., aws, az) inside container | Application Log Content |
| `docker:stats` | unusual network TX/RX byte deltas | Network Traffic Content |
