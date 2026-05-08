# DC0015 - Image Creation

## Description

Initial construction of a virtual machine image within a cloud environment. Virtual machine images are templates containing an operating system and installed applications, which can be deployed to create new virtual machines. Monitoring the creation of these images is important because adversaries may create custom images to include malicious software or misconfigurations for later exploitation. Examples: 

- Azure Compute Service Image Creation
    - Example: Creating a virtual machine image in Azure using Azure CLI: `az image create --resource-group MyResourceGroup --name MyImage --source MyVM`
- AWS EC2 AMI (Amazon Machine Image) Creation
    - Example: Creating an AMI from an EC2 instance: `aws ec2 create-image --instance-id i-1234567890abcdef0 --name "MyAMI" --description "An AMI for my app"`
- Google Cloud Compute Engine Image Creation
    - Example: Creating a custom image using gcloud: `gcloud compute images create my-custom-image --source-disk my-disk --source-disk-zone us-central1-a`
- VMware vSphere
    - Example: Exporting a VM to create an OVF (Open Virtualization Format) template: This could later be imported into other environments with potential tampering.

## Log Sources

| Log Source | Channel |
|------------|---------|
| `containerd:events` | Image pull from untrusted registry (name NOT IN allowlist) or new digest never seen before |
| `docker:daemon` | docker build or docker commit commands followed by docker push to internal registry |
| `kubernetes:audit` | create |
| `AWS:CloudTrail` | RegisterImage |
| `docker:daemon` | docker build or POST /build API request |
| `kubernetes:apiserver` | Pod spec triggering build or custom controller activity invoking image builds |
