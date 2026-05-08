# firmware

5 unique events

| Log Source | Channel | Data Components |
|------------|---------|-----------------|
| `firmware:integrity` | Baseline mismatch or unexpected EFI module detected during integrity checks | Firmware Modification |
| `firmware:integrity` | Firmware integrity verification failures or mismatches against expected UEFI/firmware image baselines | Firmware Modification |
| `firmware:runtime` | Debug or memory access commands indicating attempts to alter OS instructions in memory | Firmware Modification |
| `firmware:smart` | Unexpected firmware-level errors or abnormal S.M.A.R.T. log entries | Firmware Modification |
| `firmware:update` | Unexpected or unscheduled firmware updates, image overwrites, or failed signature validation | File Modification |
