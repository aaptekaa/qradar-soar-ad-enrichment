#!/usr/bin/env python3
"""
QRadar SOAR - Active Directory Enrichment Service
Watches for new QRadar SIEM incidents and enriches them with AD user info.
"""

import json
import re
import time
import logging
import urllib.request
import urllib.parse
import ssl
import socket
from datetime import datetime, timezone

# --- Config ---
SOAR_HOST    = "192.168.2.80"
SOAR_EMAIL   = "administrator@test.com"
SOAR_PASS    = "AdminPass"
SOAR_ORG     = 201

SIEM_HOST    = "192.168.2.70"
SIEM_USER    = "admin"
SIEM_PASS    = "AdminPass"

AD_HOST      = "192.168.3.1"
AD_PORT      = 389
AD_USER      = "Domain\\Administrator"
AD_PASS      = "AdminPass"
AD_BASE_DN   = "DC=test,DC=com"

POLL_INTERVAL = 30  # seconds
STATE_FILE    = "/opt/soar-ad-enrichment/processed.json"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler("/opt/soar-ad-enrichment/enrichment.log"),
        logging.StreamHandler()
    ],

)
log = logging.getLogger(__name__)

# ── SSL context (skip verify for self-signed certs) ──────────────────────────
SSL_CTX = ssl.create_default_context()
SSL_CTX.check_hostname = False
SSL_CTX.verify_mode = ssl.CERT_NONE


# ══════════════════════════════════════════════════════════════════════════════
# SOAR API helpers
# ══════════════════════════════════════════════════════════════════════════════

class SOARClient:
    def __init__(self):
        self.base = f"https://{SOAR_HOST}"
        self.csrf = None
        self.cookie_jar = urllib.request.HTTPCookieProcessor()
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPSHandler(context=SSL_CTX),
            self.cookie_jar
        )
        self._login()

    def _login(self):
        body = json.dumps({"email": SOAR_EMAIL, "password": SOAR_PASS}).encode()
        req = urllib.request.Request(
            self.base + "/rest/session", data=body,
            headers={"Content-Type": "application/json", "Accept": "application/json"},
            method="POST"
        )
        with self.opener.open(req, timeout=15) as r:
            resp = json.loads(r.read())
        self.csrf = resp.get("csrf_token")
        log.info("SOAR login OK, csrf=%s", self.csrf)

    def _req(self, method, path, body=None):
        url = self.base + path
        data = json.dumps(body).encode() if body is not None else None
        headers = {"Content-Type": "application/json", "Accept": "application/json"}
        if self.csrf:
            headers["X-sess-id"] = self.csrf
        req = urllib.request.Request(url, data=data, headers=headers, method=method)
        try:
            with self.opener.open(req, timeout=15) as r:
                return json.loads(r.read())
        except Exception as e:
            log.error("SOAR %s %s failed: %s", method, path, e)
            return {}

    def _post(self, path, body):
        return self._req("POST", path, body)

    def _get(self, path):
        return self._req("GET", path)

    def _put(self, path, body):
        return self._req("PUT", path, body)

    def get_incidents(self):
        return self._get(f"/rest/orgs/{SOAR_ORG}/incidents") or []

    def get_incident(self, inc_id):
        return self._get(f"/rest/orgs/{SOAR_ORG}/incidents/{inc_id}")

    def update_incident(self, inc_id, changes):
        return self._put(f"/rest/orgs/{SOAR_ORG}/incidents/{inc_id}", changes)

    def add_note(self, inc_id, text):
        return self._post(
            f"/rest/orgs/{SOAR_ORG}/incidents/{inc_id}/comments",
            {"text": {"format": "html", "content": text}}
        )


# ══════════════════════════════════════════════════════════════════════════════
# QRadar SIEM API helpers
# ══════════════════════════════════════════════════════════════════════════════

class SIEMClient:
    def __init__(self):
        import base64
        creds = base64.b64encode(f"{SIEM_USER}:{SIEM_PASS}".encode()).decode()
        self.headers = {
            "Authorization": f"Basic {creds}",
            "Accept": "application/json",
            "Version": "16.0"
        }
        self.base = f"https://{SIEM_HOST}"

    def _get(self, path):
        url = self.base + path
        req = urllib.request.Request(url, headers=self.headers)
        try:
            with urllib.request.urlopen(req, context=SSL_CTX, timeout=15) as r:
                return json.loads(r.read())
        except Exception as e:
            log.error("SIEM GET %s failed: %s", path, e)
            return {}

    def get_offense(self, offense_id):
        return self._get(f"/api/siem/offenses/{offense_id}")

    def get_source_addresses(self, ids):
        """Get IPs for source_address_ids list."""
        results = []
        for sid in ids[:3]:
            data = self._get(f"/api/siem/source_addresses/{sid}")
            if data.get("source_ip"):
                results.append(data["source_ip"])
        return results


# ══════════════════════════════════════════════════════════════════════════════
# Active Directory LDAP query
# ══════════════════════════════════════════════════════════════════════════════

def _ldap_safe(entry, attr):
    val = getattr(entry, attr, None)
    if val is None:
        return ""
    v = str(val)
    return "" if v in ("[]", "None") else v


def _decode_uac(uac_str):
    try:
        uac = int(uac_str) if uac_str else 0
    except Exception:
        return "Unknown"
    parts = []
    parts.append("DISABLED" if uac & 0x2 else "Enabled")
    if uac & 0x10:
        parts.append("LOCKED")
    if uac & 0x10000:
        parts.append("pwd-never-expires")
    if uac & 0x1000:
        parts.append("Workstation/Server")
    return " | ".join(parts)


def _extract_cn(dn_str):
    m = re.match(r"CN=([^,]+)", dn_str.strip())
    return m.group(1) if m else ""


def _ldap_connect():
    from ldap3 import Server, Connection, ALL, NTLM
    server = Server(AD_HOST, port=AD_PORT, get_info=ALL)
    return Connection(server, user=AD_USER, password=AD_PASS,
                      authentication=NTLM, auto_bind=True)


def query_ad_user(username):
    """Query AD for a user account. Returns dict or None."""
    try:
        from ldap3 import SUBTREE
        conn = _ldap_connect()
        attrs = ['displayName', 'mail', 'department', 'title', 'telephoneNumber',
                 'manager', 'memberOf', 'lastLogon', 'userAccountControl',
                 'whenCreated', 'description', 'sAMAccountName',
                 'distinguishedName', 'badPwdCount', 'lockoutTime']
        conn.search(AD_BASE_DN, f"(&(objectClass=user)(sAMAccountName={username}))",
                    SUBTREE, attributes=attrs)
        if not conn.entries:
            conn.unbind()
            return None
        e = conn.entries[0]
        conn.unbind()

        groups = [_extract_cn(g) for g in _ldap_safe(e, "memberOf").split("\n") if g.strip()]

        return {
            "type":           "user",
            "username":       _ldap_safe(e, "sAMAccountName") or username,
            "display_name":   _ldap_safe(e, "displayName") or username,
            "email":          _ldap_safe(e, "mail"),
            "department":     _ldap_safe(e, "department"),
            "title":          _ldap_safe(e, "title"),
            "manager":        _extract_cn(_ldap_safe(e, "manager")),
            "account_status": _decode_uac(_ldap_safe(e, "userAccountControl")),
            "last_logon":     _ldap_safe(e, "lastLogon"),
            "groups":         "\n".join(g for g in groups if g),
            "bad_pwd_count":  _ldap_safe(e, "badPwdCount"),
            "when_created":   _ldap_safe(e, "whenCreated"),
            "description":    _ldap_safe(e, "description"),
        }
    except ImportError:
        log.error("ldap3 not available")
        return None
    except Exception as e:
        log.error("AD user query failed for %s: %s", username, e)
        return None


def query_ad_computer(hostname):
    """Query AD for a computer account. Returns dict or None."""
    try:
        from ldap3 import SUBTREE
        conn = _ldap_connect()
        # Try both with and without trailing $
        sam = hostname.rstrip("$") + "$"
        attrs = ['cn', 'dNSHostName', 'operatingSystem', 'operatingSystemVersion',
                 'description', 'lastLogon', 'managedBy', 'location',
                 'distinguishedName', 'whenCreated', 'userAccountControl',
                 'memberOf', 'sAMAccountName']
        conn.search(AD_BASE_DN,
                    f"(&(objectClass=computer)(|(sAMAccountName={sam})(cn={hostname})))",
                    SUBTREE, attributes=attrs)
        if not conn.entries:
            conn.unbind()
            return None
        e = conn.entries[0]
        conn.unbind()

        os_name = _ldap_safe(e, "operatingSystem")
        os_ver  = _ldap_safe(e, "operatingSystemVersion")
        managed = _extract_cn(_ldap_safe(e, "managedBy"))

        return {
            "type":           "computer",
            "username":       _ldap_safe(e, "cn") or hostname,
            "display_name":   f"{hostname} (Computer Account)",
            "email":          _ldap_safe(e, "dNSHostName"),
            "department":     _ldap_safe(e, "location") or "Computers",
            "title":          f"{os_name} {os_ver}".strip() if os_name else "Unknown OS",
            "manager":        managed,
            "account_status": _decode_uac(_ldap_safe(e, "userAccountControl")),
            "last_logon":     _ldap_safe(e, "lastLogon"),
            "groups":         "",
            "bad_pwd_count":  "",
            "when_created":   _ldap_safe(e, "whenCreated"),
            "description":    _ldap_safe(e, "description"),
        }
    except Exception as e:
        log.error("AD computer query failed for %s: %s", hostname, e)
        return None


def query_ad_object(name):
    """Try user first, then computer. Returns ad_info dict or None."""
    info = query_ad_user(name)
    if info:
        log.info("Found AD user: %s", name)
        return info
    info = query_ad_computer(name)
    if info:
        log.info("Found AD computer: %s", name)
        return info
    log.warning("AD object not found for: %s", name)
    return None


def _find_similar_ad_users(username, max_results=3):
    """Return list of AD sAMAccountNames similar to the given name (fuzzy match)."""
    try:
        import difflib
        from ldap3 import SUBTREE
        conn = _ldap_connect()
        conn.search(AD_BASE_DN, "(objectClass=user)", SUBTREE,
                    attributes=["sAMAccountName"])
        all_names = [str(e.sAMAccountName) for e in conn.entries
                     if str(e.sAMAccountName) not in ("[]", "None")]
        conn.unbind()
        matches = difflib.get_close_matches(username, all_names,
                                            n=max_results, cutoff=0.6)
        return matches
    except Exception:
        return []


# ══════════════════════════════════════════════════════════════════════════════
# Username extraction
# ══════════════════════════════════════════════════════════════════════════════

def extract_username_from_offense(siem, offense_id):
    """Try to extract username from QRadar offense."""
    offense = siem.get_offense(offense_id)
    if not offense:
        return None, []

    # Get source IPs
    src_ids = offense.get("source_address_ids", [])
    src_ips = siem.get_source_addresses(src_ids)

    # QRadar offense sometimes has username in the description/name
    # Pattern: "from the same Username" -> look for common account names
    name = offense.get("description", "")

    # Try to get username from offense categories
    categories = offense.get("categories", [])
    log.info("Offense %s categories: %s", offense_id, categories)

    return None, src_ips


def _is_ip(s):
    """Return True if the string looks like an IP address."""
    return bool(re.match(r'^[\d\.:a-fA-F]+$', s) and (':' in s or re.match(r'^\d+\.\d+\.\d+\.\d+$', s)))

def extract_username_from_incident_name(incident_name):
    """Extract username from QRadar SOAR incident name patterns.

    QRadar SOAR names end with '- <username>' or '- <source_ip>'.
    We want username-like tokens (letters/digits/backslash) and skip IPs.
    """
    # Try the tail after the last " - "
    parts = incident_name.rsplit(" - ", 1)
    if len(parts) == 2:
        candidate = parts[1].strip()
        # Strip domain prefix if present (e.g. "Domain\\Administrator" → "Administrator")
        if "\\" in candidate:
            candidate = candidate.split("\\")[-1]
        # Only accept if it looks like a username (no colons, not pure digits/dots)
        if candidate and not _is_ip(candidate) and re.match(r'^[A-Za-z][A-Za-z0-9_.$-]*$', candidate):
            return candidate

    # Fallback: look for well-known Windows account patterns in the name
    for kw in ["Administrator", "SYSTEM", "Guest"]:
        if kw.lower() in incident_name.lower():
            return kw

    return None


# ══════════════════════════════════════════════════════════════════════════════
# State management
# ══════════════════════════════════════════════════════════════════════════════

def load_state():
    try:
        with open(STATE_FILE) as f:
            return set(json.load(f))
    except Exception:
        return set()

def save_state(processed):
    with open(STATE_FILE, "w") as f:
        json.dump(list(processed), f)


# ══════════════════════════════════════════════════════════════════════════════
# Core enrichment logic
# ══════════════════════════════════════════════════════════════════════════════

def build_note_html(username, ad_info, src_ips, qradar_id):
    """Build formatted HTML note for SOAR incident."""
    ts  = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    obj_type = ad_info.get("type", "user")
    is_computer = (obj_type == "computer")

    status = ad_info.get("account_status", "")
    status_color = "#c00" if ("DISABLED" in status or "LOCKED" in status) else "#060"

    ips_str = ", ".join(src_ips) if src_ips else "N/A"
    title_icon = "🖥️ AD Enrichment (Computer)" if is_computer else "👤 AD Enrichment (User)"

    if is_computer:
        rows = [
            ("Hostname",        ad_info.get("username", "N/A"),        False),
            ("DNS Name",        ad_info.get("email", "N/A"),           True),
            ("Operating System",ad_info.get("title", "N/A"),           False),
            ("Location",        ad_info.get("department", "N/A"),      True),
            ("Managed By",      ad_info.get("manager", "N/A"),         False),
            ("Account Status",  status,                                  True),
            ("Last Logon",      ad_info.get("last_logon", "N/A"),      False),
            ("Source IP(s)",    ips_str,                                True),
            ("Created",         ad_info.get("when_created", "N/A"),    False),
            ("Description",     ad_info.get("description", "N/A"),     True),
        ]
    else:
        groups = ad_info.get("groups", "")
        groups_html = ("".join(f"<li>{g}</li>" for g in groups.split("\n") if g)
                       if groups else "<li><i>none</i></li>")
        groups_html = f"<ul style='margin:2px 0;padding-left:16px;'>{groups_html}</ul>"
        rows = [
            ("Username",        f"<b>{ad_info.get('username','N/A')}</b>",  False),
            ("Full Name",       ad_info.get("display_name", "N/A"),          True),
            ("Email",           ad_info.get("email", "N/A"),                 False),
            ("Department",      ad_info.get("department", "N/A"),            True),
            ("Job Title",       ad_info.get("title", "N/A"),                 False),
            ("Manager",         ad_info.get("manager", "N/A"),               True),
            ("Account Status",  f"<b style='color:{status_color};'>{status}</b>", False),
            ("Last Logon",      ad_info.get("last_logon", "N/A"),            True),
            ("Bad Pwd Count",   ad_info.get("bad_pwd_count", "N/A"),         False),
            ("Source IP(s)",    ips_str,                                      True),
            ("Created",         ad_info.get("when_created", "N/A"),          False),
            ("Groups",          groups_html,                                   True),
        ]

    shade_style = "style=\"background:#f9f9f9;\""
    rows_html = "".join(
        f"<tr {shade_style if shade else ''}>"
        f"<td style='padding:3px 10px;color:#555;width:150px;white-space:nowrap;'><b>{label}</b></td>"
        f"<td style='padding:3px 10px;'>{value}</td></tr>"
        for label, value, shade in rows
    )

    return (
        f"<div style='font-family:sans-serif;border:1px solid #ccc;"
        f"padding:12px;border-radius:4px;max-width:700px;'>"
        f"<h3 style='margin:0 0 6px 0;color:#003580;'>{title_icon} — QRadar Offense #{qradar_id}</h3>"
        f"<p style='color:#888;margin:0 0 10px 0;font-size:11px;'>Auto-enriched at {ts}</p>"
        f"<table style='border-collapse:collapse;width:100%;'>{rows_html}</table>"
        f"</div>"
    )


def enrich_incident(soar, siem, incident):
    inc_id = incident["id"]
    qradar_id = incident.get("properties", {}).get("qradar_id")
    if not qradar_id:
        return

    log.info("Enriching incident %s (QRadar offense %s)", inc_id, qradar_id)

    # Try to get username from incident name
    inc_name = incident.get("name", "")
    username = extract_username_from_incident_name(inc_name)

    # Also try from SIEM offense
    _, src_ips = extract_username_from_offense(siem, qradar_id)

    if not username:
        log.warning("Could not extract username from incident %s", inc_id)
        # Add a note anyway with source IPs
        if src_ips:
            soar.add_note(inc_id, f"<b>[AD Enrichment]</b> Could not extract username. Source IPs: {', '.join(src_ips)}")
        return

    log.info("Extracted username: %s", username)

    # Query AD — try user first, then computer account
    ad_info = query_ad_object(username)
    if not ad_info:
        # Still write username + "NOT FOUND" into the fields so tab isn't blank
        similar = _find_similar_ad_users(username)
        hint = f" (похожие в AD: {', '.join(similar)})" if similar else ""
        status_msg = f"NOT FOUND IN AD{hint}"

        full_incident = soar.get_incident(inc_id)
        if full_incident:
            full_incident["properties"].update({
                "ad_username":       username,
                "ad_display_name":   f"[Не найден в AD]",
                "ad_account_status": status_msg,
                "ad_source_ip":      ", ".join(src_ips) if src_ips else "",
            })
            soar.update_incident(inc_id, full_incident)

        note = (
            f"<div style='border:1px solid #f5a623;padding:10px;border-radius:4px;'>"
            f"<b style='color:#c07000;'>⚠️ AD Enrichment — QRadar Offense #{qradar_id}</b><br/>"
            f"Пользователь <b>{username}</b> <b>не найден</b> в Active Directory (test.com).<br/>"
            f"Возможно опечатка в имени или несуществующий аккаунт (атака на случайные имена)."
            f"{('<br/>Похожие аккаунты в AD: <b>' + ', '.join(similar) + '</b>') if similar else ''}"
            f"<br/>Source IP(s): {', '.join(src_ips) if src_ips else 'N/A'}"
            f"</div>"
        )
        soar.add_note(inc_id, note)
        log.info("Incident %s: username '%s' not in AD%s", inc_id, username,
                 f", similar: {similar}" if similar else "")
        return

    # Update custom incident fields
    full_incident = soar.get_incident(inc_id)
    if full_incident:
        full_incident["properties"].update({
            "ad_username":       ad_info.get("username", username),
            "ad_display_name":   ad_info.get("display_name", ""),
            "ad_email":          ad_info.get("email", ""),
            "ad_department":     ad_info.get("department", ""),
            "ad_title":          ad_info.get("title", ""),
            "ad_manager":        ad_info.get("manager", ""),
            "ad_account_status": ad_info.get("account_status", ""),
            "ad_last_logon":     ad_info.get("last_logon", ""),
            "ad_source_ip":      ", ".join(src_ips) if src_ips else "",
            "ad_groups":         ad_info.get("groups", ""),
        })
        soar.update_incident(inc_id, full_incident)
        log.info("Updated incident %s properties with AD info", inc_id)

    # Add formatted HTML note
    note_html = build_note_html(username, ad_info, src_ips, qradar_id)
    soar.add_note(inc_id, note_html)
    log.info("Added AD enrichment note to incident %s", inc_id)


# ══════════════════════════════════════════════════════════════════════════════
# Main loop
# ══════════════════════════════════════════════════════════════════════════════

def main():
    log.info("=== SOAR AD Enrichment Service starting ===")
    soar = SOARClient()
    siem = SIEMClient()
    processed = load_state()

    while True:
        try:
            incidents = soar.get_incidents()
            if isinstance(incidents, list):
                for inc in incidents:
                    inc_id = str(inc.get("id"))
                    qradar_id = inc.get("properties", {}).get("qradar_id")
                    status = inc.get("plan_status")

                    # Process any QRadar incident not yet enriched
                    if inc_id not in processed and qradar_id:
                        try:
                            enrich_incident(soar, siem, inc)
                        except Exception as e:
                            log.error("Error enriching incident %s: %s", inc_id, e)
                        processed.add(inc_id)
                        save_state(processed)
        except Exception as e:
            log.error("Main loop error: %s", e)
            try:
                soar = SOARClient()
            except Exception:
                pass

        time.sleep(POLL_INTERVAL)


if __name__ == "__main__":
    main()
