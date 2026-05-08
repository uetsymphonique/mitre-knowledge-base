# snmp

5 unique events

| Log Source | Channel | Data Components |
|------------|---------|-----------------|
| `snmp:access` | GETBULK/GETNEXT requests for OIDs associated with configuration parameters | Network Connection Creation |
| `snmp:config` | Configuration change traps or policy enforcement failures | Network Traffic Flow |
| `snmp:status` | Status change in cryptographic hardware modules (enabled -> disabled) | Module Load |
| `snmp:syslog` | firmware write/log event | File Creation |
| `snmp:trap` | management queries | OS API Execution |
