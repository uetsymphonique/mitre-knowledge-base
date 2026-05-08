# ApplicationLog

9 unique events

| Log Source | Channel | Data Components |
|------------|---------|-----------------|
| `ApplicationLog:API` | Docker/Kubernetes API access from external sources | Application Log Content |
| `ApplicationLog:CallRecords` | Outbound or inbound calls to high-risk or blocklisted numbers | Application Log Content |
| `ApplicationLog:EntraIDPortal` | DeviceRegistration events | Application Log Content |
| `ApplicationLog:IIS` | IIS W3C logs in C:\inetpub\logs\LogFiles\W3SVC* (spikes in 5xx, RCE/SQLi/path traversal/JNDI patterns) | Application Log Content |
| `ApplicationLog:Ingress` | Kubernetes NGINX/Envoy ingress controller logs with anomalous payloads and 5xx spikes | Application Log Content |
| `ApplicationLog:Intune/MDM Logs` | Enrollment events (e.g., MDMDeviceRegistration) | Application Log Content |
| `ApplicationLog:MailServer` | Unexpected additions of sieve rules or filtering directives | Application Log Content |
| `ApplicationLog:Outlook` | Outlook client-level rule creation actions not consistent with normal user activity | Application Log Content |
| `ApplicationLog:WebServer` | /var/log/httpd/access_log, /var/log/apache2/access.log, /var/log/nginx/access.log with exploit indicators and burst errors | Application Log Content |
