# containerd

10 unique events

| Log Source | Channel | Data Components |
|------------|---------|-----------------|
| `containerd:Events` | unusual process spawned from container image context | Process Creation |
| `containerd:events` | Docker or containerd image pulls and process executions | Process Metadata |
| `containerd:events` | Image pull from untrusted registry (name NOT IN allowlist) or new digest never seen before | Image Creation |
| `containerd:events` | New container with suspicious image name or high resource usage | Process Creation |
| `containerd:events` | create | Container Creation |
| `containerd:runtime` | /var/log/containers/*.log | Process Creation |
| `containerd:runtime` | CRI CreateContainer/StartContainer with privileged=true OR added capabilities OR host* namespaces | Container Start |
| `containerd:runtime` | container-level outbound traffic events | Network Traffic Flow |
| `containerd:runtime` | e.g., containerd, Docker events | Container Enumeration |
| `containerd:runtime` | file change monitoring within /etc/cron.*, /tmp, or mounted volumes | File Modification |
