# DC0007 - Web Credential Usage

## Description

An attempt by a user to gain access to a network or computing resource by providing web credentials (ex: Windows EID 1202)

## Log Sources

| Log Source | Channel |
|------------|---------|
| `AWS:CloudTrail` | SessionToken used without preceding MFA or login event |
| `m365:unified` | SessionId reused from different device/browser fingerprint |
| `AWS:CloudTrail` | AssumeRoleWithSAML |
| `saas:access` | SAML token accepted without preceding login challenge |
| `m365:exchange` | Mailbox access using SAML token without corresponding MFA event |
| `AWS:CloudTrail` | GetSessionToken, AssumeRoleWithWebIdentity |
| `macos:unifiedlog` | New session initiated using cookies without normal MFA or password validation |
| `m365:unified` | Session activity without correlated login event |
| `AWS:CloudTrail` | AssumeRole, GetFederationToken, GetSessionToken |
| `azure:signinlogs` | TokenIssued, RefreshTokenUsed |
| `saas:googleworkspace` | OAuthTokenGranted, APIRequest |
| `m365:unified` | OAuthTokenIssued, FileAccessed, MailItemsAccessed |
| `kubernetes:apiserver` | serviceAccount token used in API requests not tied to workload identity |
| `NSM:Connections` | Pre-authentication keys generated or token signing anomalies |
| `macos:unifiedlog` | Web sessions initiated with newly forged tokens |
| `saas:auth` | API requests made with tokens not associated with expected user logins |
| `azure:signinlogs` | TokenIssuanceStart, TokenIssuanceSuccess |
| `saas:googleworkspace` | access_token issued |
| `m365:unified` | TokenIssued, FileAccessed |
| `AWS:CloudTrail` | GetCallerIdentity |
