# DC0104 - Response Content

## Description

Captured network traffic that provides details about responses received during an internet scan. This data includes both protocol header values (e.g., HTTP status codes, IP headers, or DNS response codes) and response body content (e.g., HTML, JSON, or raw data). Examples:

- HTTP Scan: A web server responds to a probe with an HTTP 200 status code and an HTML body indicating the default page is accessible.
- DNS Scan: A DNS server replies to a query with a resolved IP address for a domain, along with details like Time-To-Live (TTL) and authoritative information.
- TCP Banner Grab: A service listening on a port (e.g., SSH or FTP) responds with a banner containing service name, version, or other metadata.

## Log Sources

| Log Source | Channel |
|------------|---------|
| `Internet Scan` | None |
| `NSM:Flow` | Suspicious changes in TLS certificate responses or redirected domains |
