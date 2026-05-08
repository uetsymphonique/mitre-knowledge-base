# DC0001 - Scheduled Job Creation

## Description

The establishment of a task or job that will execute at a predefined time or based on specific triggers.

## Log Sources

| Log Source | Channel |
|------------|---------|
| `Scheduled Job` | None |
| `WinEventLog:Security` | EventCode=4698 |
| `linux:syslog` | Execution of non-standard script or binary by cron |
| `WinEventLog:TaskScheduler` | EventCode=106 |
| `linux:osquery` | crontab, systemd_timers |
| `macos:osquery` | launchd_jobs |
| `esxi:vmkernel` | Startup script and task execution logs |
| `kubernetes:apiserver` | verb=create, resource=cronjobs, group=batch |
| `linux:osquery` | file_events |
| `macos:unifiedlog` | process: crontab edits, launch of cron job |
| `macos:osquery` | file_events - cron, launchd |
| `esxi:cron` | execution of scheduled job |
| `esxi:hostd` | task creation events |
| `macos:cron` | cron/launchd |
| `WinEventLog:Security` | EventCode=4699 |
| `linux:cron` | Scheduled execution of unknown or unusual script/binary |
