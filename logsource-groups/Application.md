# Application

6 unique events

| Log Source | Channel | Data Components |
|------------|---------|-----------------|
| `Application:Mail` | High-frequency inbound mail activity to a specific recipient address | Application Log Content |
| `Application:Mail` | Inbound email attachments logged from MTAs with suspicious metadata | Application Log Content |
| `Application:Mail` | Inbound emails containing hyperlinks from suspicious sources | Application Log Content |
| `Application:Mail` | Inbound messages with anomalous headers, spoofed SPF/DKIM failures | Application Log Content |
| `Application:Mail` | Mismatch between authenticated username and From header in email | Application Log Content |
| `Application:Mail` | smtpd$.*$: .*from=[.*@internaldomain.com](mailto:.*@internaldomain.com) to=[.*@internaldomain.com](mailto:.*@internaldomain.com) | Application Log Content |
