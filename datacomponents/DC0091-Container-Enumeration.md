# DC0091 - Container Enumeration

## Description

"Container Enumeration" data component captures events and actions related to listing and identifying active or available containers within a containerized environment. This includes information about running, stopped, or configured containers, such as their names, IDs, statuses, or associated images. Monitoring this activity is crucial for detecting unauthorized discovery or reconnaissance efforts. Examples: 

- Docker Example: `docker ps`, `docker ps -a`
- Kubernetes Example: `kubectl get pods`, `kubectl get deployments`
- Cloud Container Services Example
    - AWS ECS: API Call: ListTasks or ListContainers
    - Azure Kubernetes Service: API Call: List pod or container instances.
    - Google Kubernetes Engine (GKE): API Call: Retrieve deployments and their associated containers.

## Log Sources

| Log Source | Channel |
|------------|---------|
| `docker:daemon` | docker ps, docker inspect, or docker images commands |
| `AWS:CloudTrail` | DescribeCluster, ListClusters, ListNodegroups |
| `containerd:runtime` | e.g., containerd, Docker events |
