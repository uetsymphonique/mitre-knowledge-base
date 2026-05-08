# DC0005 - Scheduled Job Metadata

## Description

Contextual data about a scheduled job, which may include information such as name, timing, command(s), etc.

## Log Sources

| Log Source | Channel |
|------------|---------|
| `Scheduled Job` | None |
| `linux:cron` | cron activity |
| `fs:fileevents` | /Library/LaunchDaemons/*.plist, ~/Library/LaunchAgents/*.plist |
| `WinEventLog:TaskScheduler` | Task registration/execution shortly after a time discovery event |
| `macos:unifiedlog` | New/modified launchd plist (persistence/scheduling) within TimeWindow after time query |
| `esxi:syslog` | /var/log/vpxa.log task invocations tied to time configuration |
| `WinEventLog:System` | EventCode=106, 200 |
| `macos:launchd` | launchd.plist and logs |
