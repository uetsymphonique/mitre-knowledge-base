# DC0092 - Volume Modification

## Description

Changes made to a cloud volume, including its settings and control data (ex: AWS modify-volume)

## Log Sources

| Log Source | Channel |
|------------|---------|
| `kubernetes:apiserver` | Pod spec with hostPath or privileged securityContext |
| `AWS:CloudTrail` | ModifyVolume |
