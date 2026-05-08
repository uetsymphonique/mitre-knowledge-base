# saas

85 unique events

| Log Source | Channel | Data Components |
|------------|---------|-----------------|
| `saas:Airtable` | EXPORT: User-triggered data export via GUI or API | Application Log Content |
| `saas:PRMetadata` | Commit message or branch name contains encoded strings or payload indicators | Command Execution |
| `saas:RepoEvents` | New file added or modified in PR targeting CI/CD or build config (e.g., `gitlab-ci.yml`, `build.gradle`, `pom.xml`, `.github/workflows/*.yml`) | File Metadata |
| `saas:Snowflake` | QUERY: Large or repeated SELECT * queries to sensitive tables | Application Log Content |
| `saas:access` | Multiple concurrent logins using same cookie from different locations | Logon Session Creation |
| `saas:access` | SAML token accepted without preceding login challenge | Web Credential Usage |
| `saas:adminapi` | ListIntegrations, ListServices: Repeated service discovery requests from accounts without administrative responsibilities | Cloud Service Enumeration |
| `saas:api` | Webhook registrations or repeated POST activity | Network Traffic Flow |
| `saas:application` | High-frequency invocation of SMS-related API endpoints from publicly accessible OTP or verification forms (e.g., Twilio: SendMessage, Cognito: AdminCreateUser) with irregular destination patterns. | Application Log Content |
| `saas:application` | High-volume API calls or traffic via messaging or webhook service | Application Log Content |
| `saas:appsscript` | Create / Update: Deployment of scripts with event-driven triggers | Cloud Service Modification |
| `saas:audit` | Application added or consent granted: Integration persisting after original user disabled | Application Log Content |
| `saas:audit` | Log export integration removed or disabled | Cloud Service Disable |
| `saas:audit` | Repeated requests to SMS-generating endpoints using anomalous or new user agents, IP ranges, or geographies. | User Account Authentication |
| `saas:audit` | Rule/ConfigChange: Auto-forward rules, delegate assignments, or changes to financial approval workflows | Application Log Content |
| `saas:auth` | API requests made with tokens not associated with expected user logins | Web Credential Usage |
| `saas:auth` | Login, TokenGranted: Discovery actions tied to anomalous login sessions or tokens | Logon Session Creation |
| `saas:auth` | LoginSuccess, APIKeyUse, AdminAction | Logon Session Creation |
| `saas:auth` | Refresh token issuance or refresh token usage from new IPs or user agents | User Account Metadata |
| `saas:auth` | signin_failed | User Account Authentication |
| `saas:box` | API calls exceeding baseline thresholds | Network Traffic Content |
| `saas:box` | User navigated to admin interface | Application Log Content |
| `saas:box` | collaboration.invite | Cloud Storage Metadata |
| `saas:collaboration` | MessagePosted: Suspicious links or attachment delivery via collaboration tools (Slack, Teams, Zoom) | Application Log Content |
| `saas:confluence` | REST API access from non-browser agents | Network Traffic Content |
| `saas:confluence` | access.content | Application Log Content |
| `saas:confluence` | logon | Logon Session Creation |
| `saas:dropbox` | Shared link created to external account | Cloud Storage Metadata |
| `saas:email` | AuthenticationFailures (SPF/DKIM/DMARC) OR Domain Mismatch | Application Log Content |
| `saas:finance` | Transaction/Transfer: Unusual or large transactions initiated outside business hours or by unusual accounts | Application Log Content |
| `saas:github` | Artifact generated includes base64/encoded exfil payload or URL | Cloud Storage Access |
| `saas:github` | Bulk access to multiple files or large volume of repo requests within short time window | Application Log Content |
| `saas:github` | CI/CD secret accessed or exported | Cloud Service Metadata |
| `saas:github` | GET /orgs/:org/teams, GET /teams/:team/members | Group Enumeration |
| `saas:github` | Login from unusual IP, device fingerprint, or location; access token creation from new client | Logon Session Creation |
| `saas:github` | Workflow triggered via pull_request_target from forked repo | Cloud Service Modification |
| `saas:github` | repo.download, repo.clone, oauth.authorize, repo.getContent | Cloud Service Metadata |
| `saas:gmail` | SendEmail, OpenAttachment, ClickLink | Application Log Content |
| `saas:googledrive` | FileOpen / FileAccess: Event-driven script triggering on user file actions | Application Log Content |
| `saas:googledrive` | drive.permission.add | Cloud Storage Modification |
| `saas:googleworkspace` | API access without user login | User Account Authentication |
| `saas:googleworkspace` | Access via OAuth credentials with unusual scopes or from anomalous IPs | User Account Authentication |
| `saas:googleworkspace` | Accessed third-party credential management service | User Account Authentication |
| `saas:googleworkspace` | OAuth2 authorization grants / Admin role assignments | Application Log Content |
| `saas:googleworkspace` | OAuthTokenGranted, APIRequest | Web Credential Usage |
| `saas:googleworkspace` | access_token issued | Web Credential Usage |
| `saas:googleworkspace` | login with reused session token and mismatched user agent or IP | User Account Authentication |
| `saas:hubspot` | contact_viewed, contact_exported, login | Application Log Content |
| `saas:integration` | New or modified third-party application integrations with elevated permissions | Cloud Service Modification |
| `saas:okta` | Conditional Access policy rule modified or MFA requirement disabled | Application Log Content |
| `saas:okta` | Federation configuration update or signing certificate change | Application Log Content |
| `saas:okta` | MFAChallengeIssued | Application Log Content |
| `saas:okta` | Sign-in logs / audit events | User Account Authentication |
| `saas:okta` | System API Call: user.read, group.read | Application Log Content |
| `saas:okta` | Unusual OAuth app requesting message-read scopes for Slack/Teams/Jira | User Account Authentication |
| `saas:okta` | User Attribute Modified / Role Assignment Changed | User Account Modification |
| `saas:okta` | User Enumeration Events | User Account Metadata |
| `saas:okta` | User lifecycle events | User Account Metadata |
| `saas:okta` | WebUI access to administrator dashboard | Application Log Content |
| `saas:okta` | admin role granted outside approved workflows | User Account Modification |
| `saas:okta` | authentication_failure | User Account Authentication |
| `saas:okta` | session.impersonation.start | User Account Authentication |
| `saas:okta` | session.token.reuse | Logon Session Creation |
| `saas:okta` | user.authentication.sso | Logon Session Metadata |
| `saas:okta` | user.lifecycle.create | User Account Creation |
| `saas:okta` | user.lifecycle.delete, user.account.lock | User Account Modification |
| `saas:okta` | user.session.start | Logon Session Creation |
| `saas:okta` | user.session.start, app.oauth2.as.authorize, policy.mfa.bypass | Logon Session Metadata |
| `saas:openai` | High volume of requests to /v1/chat/completions or /v1/images/generations | Application Log Content |
| `saas:salesforce` | API login using access_token without login history | User Account Authentication |
| `saas:salesforce` | ConnectedApp OAuth policy change / Login as user | Logon Session Metadata |
| `saas:salesforce` | DataExport, RestAPI, Login, ReportExport | Application Log Content |
| `saas:salesforce` | GET /services/data/vXX.X/groups | Group Enumeration |
| `saas:salesforce` | Login | User Account Authentication |
| `saas:slack` | Exported file or accessed admin API | Cloud Service Modification |
| `saas:slack` | OAuth token use by unknown app client_id accessing private channels or files | Application Log Content |
| `saas:slack` | admin.user.create | User Account Creation |
| `saas:slack` | chat.postMessage, files.upload, or discovery API calls involving token/credential regex | Application Log Content |
| `saas:slack` | conversations.history, files.list, users.info, audit_logs | Application Log Content |
| `saas:slack` | file_upload, message_send, message_click | Application Log Content |
| `saas:teams` | ChatMessageSent, ChatMessageEdited, LinkClick | Application Log Content |
| `saas:zoom` | DisableMFA or RegisterNewFactor | User Account Modification |
| `saas:zoom` | New user created | User Account Creation |
| `saas:zoom` | Zoom Admin Dashboard accessed from unfamiliar IP/device | Logon Session Creation |
| `saas:zoom` | unusual web session tokens and automation patterns during login | Application Log Content |
