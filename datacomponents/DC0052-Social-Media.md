# DC0052 - Social Media

## Description

Established, compromised, or otherwise acquired by adversaries to conduct reconnaissance, influence operations, social engineering, or other cyber threats.

*Data Collection Measures:*

- API Monitoring	
    - Social media APIs (e.g., Twitter API, Facebook Graph API) can extract behavioral patterns of accounts.
- Web Scraping
    - Extracts public profile data, friend lists, or interactions to identify impersonation attempts.
- Threat Intelligence Feeds	
    - External feeds track malicious personas linked to disinformation campaigns or phishing.
- OSINT Tools
    - Maltego, SpiderFoot, and OpenCTI can map social media persona relationships.
- Endpoint Detection	
    - EDR logs user behavior and alerts on suspicious social media interactions.
- SIEM Logging
    - Detects access to known phishing pages or social media abuse via proxy logs.
- Dark Web Monitoring	
    - Identifies compromised social media credentials being sold.

## Log Sources

| Log Source | Channel |
|------------|---------|
| `Persona` | None |
