# SOAR Active Directory Enrichment Service

Automatically enriches incidents in **IBM QRadar SOAR** with data from **Active Directory** via LDAP. Runs as a systemd service, polling SOAR every 30 seconds.

## What it does

- Finds new SOAR incidents that have not yet been enriched with AD data
- Extracts the username or IP address from incident fields
- Performs an LDAP query against the domain controller (port 389)
- Writes results back into custom incident fields in SOAR

## Data Added to Each Incident

| SOAR Field | Description |
|------------|-------------|
| `ad_username` | SAMAccountName of the user or computer name |
| `ad_display_name` | Display name (full name or Computer Account) |
| `ad_title` | Job title (users) or OS version (computers) |
| `ad_department` | Department |
| `ad_manager` | Manager |
| `ad_groups` | AD group membership (comma-separated) |
| `ad_account_status` | Account status (Enabled / Disabled / Locked) |
| `ad_last_logon` | Date and time of last logon |
| `ad_source_ip` | Source IP from the incident |
| `ad_email` | Email address or FQDN (for computers) |

## Architecture

```
IBM QRadar SOAR          Active Directory
(192.168.2.80)    --->   DC (192.168.3.1:389)
  /rest/orgs/{id}/incidents    LDAP query
  Update incident properties
```

## Installation

### Requirements

- Python 3.6+
- Standard library only (socket for raw LDAP, urllib, ssl)
- Network access to DC on port 389 (LDAP)
- RHEL/CentOS/Debian with systemd

### 1. Copy the script

```bash
mkdir -p /opt/soar-ad-enrichment
cp enrichment.py /opt/soar-ad-enrichment/
chmod +x /opt/soar-ad-enrichment/enrichment.py
```

### 2. Configure

Edit the variables at the top of `enrichment.py`:

```python
SOAR_HOST  = '192.168.2.80'         # IBM SOAR IP address
SOAR_EMAIL = 'admin@example.com'     # SOAR login
SOAR_PASS  = 'password'              # SOAR password
SOAR_ORG   = 201                     # SOAR organization ID

AD_HOST    = '192.168.3.1'          # Domain controller IP
AD_PORT    = 389                     # LDAP port (389 or 636 for LDAPS)
AD_USER    = 'DOMAIN\\Administrator' # AD user (with domain prefix)
AD_PASS    = 'password'              # AD password
AD_BASE_DN = 'DC=example,DC=com'    # Domain base DN

POLL_INTERVAL = 30    # Poll interval in seconds
STATE_FILE = '/opt/soar-ad-enrichment/processed.json'
```

### 3. Install systemd service

```bash
cp soar-ad-enrichment.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable soar-ad-enrichment.service
systemctl start soar-ad-enrichment.service
```

### 4. Verify

```bash
systemctl status soar-ad-enrichment.service
tail -f /opt/soar-ad-enrichment/enrichment.log
```

## Log Example

```
2026-06-08 10:13:01 [INFO] Processing incident #2185 - source: JUMPHOST / 192.168.2.252
2026-06-08 10:13:01 [INFO] AD lookup: found computer JUMPHOST
2026-06-08 10:13:01 [INFO] Enriched incident #2185 (department=Computers, status=Enabled)
```

## State Files

| File | Purpose |
|------|---------|
| `processed.json` | List of already-enriched incident IDs |
| `enrichment.log` | Service log |

## Notes

- Supports both user accounts and computer accounts in AD
- If the user is not found by username, tries a PTR lookup by IP
- LDAP connection without TLS (port 389) with NTLM authentication
- For LDAPS (port 636): change `AD_PORT = 636`

## Stack

- **IBM QRadar SOAR** 51.x
- **Active Directory** / Windows Server 2016+
- **Python** 3.6+
- **RHEL** 8.x / systemd

<img width="1382" height="826" alt="image" src="https://github.com/user-attachments/assets/e02fa95b-143f-497d-8997-2d0fa2cf15ce" />
<img width="1151" height="886" alt="image" src="https://github.com/user-attachments/assets/c55006a3-44a8-44fc-84ef-025952e2b393" />

