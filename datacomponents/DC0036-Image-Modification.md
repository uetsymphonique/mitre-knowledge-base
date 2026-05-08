# DC0036 - Image Modification

## Description

Changes made to a virtual machine image, including setting and/or control data (ex: Azure Compute Service Images PATCH)

## Log Sources

| Log Source | Channel |
|------------|---------|
| `docker:registry` | push event of new image version from unrecognized user or context |
| `AWS:CloudTrail` | ModifyImageAttribute |
