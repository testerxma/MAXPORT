"""Building a profile of the other party in a connection.

Hard technical limits worth stating plainly:
  - A MAC address does not cross a router. It is obtainable only for an
    address inside your own LAN (via ARP). For an internet address there is
    no path to it at all. What can be learned about a remote IP: the network
    owner, the provider, an approximate location, the reverse name and its
    reputation. That is enough for a formal report and does not identify a
    person. Behind a VPN, Tor or a compromised relay, it describes the relay.
"""

from __future__ import annotations

import ipaddress
import json
import socket
import urllib.error
import urllib.request
from dataclasses import dataclass, asdict, field

from .netcheck import arp_table

_cache: dict[str, "PeerProfile"] = {}
UA = {"User-Agent": "MaxPort/1.0 (host security audit)"}


@dataclass
class PeerProfile:
    ip: str = ""
    scope: str = ""              # local | internet | loopback
    mac: str = ""                # only available for devices on the same LAN
    vendor: str = ""             # manufacturer, derived from the MAC prefix
    hostname: str = ""           # reverse DNS name
    country: str = ""
    region: str = ""
    city: str = ""
    isp: str = ""
    org: str = ""
    asn: str = ""
    is_proxy: bool = False       # VPN / proxy / hosting
    is_hosting: bool = False
    abuse_email: str = ""
    abuse_score: int = -1        # AbuseIPDB score (0-100), -1 = not checked
    reports: int = 0
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)

    @property
    def summary(self) -> str:
        if self.scope == "loopback":
            return "Internal connection to this machine itself"
        if self.scope == "local":
            bits = ["A device inside your local network"]
            if self.mac:
                bits.append(f"MAC: {self.mac}")
            if self.vendor:
                bits.append(self.vendor)
            return " — ".join(bits)
        bits = []
        if self.city or self.country:
            bits.append(", ".join(x for x in (self.city, self.country) if x))
        if self.isp:
            bits.append(self.isp)
        if self.asn:
            bits.append(self.asn)
        return " — ".join(bits) or "An address on the internet"


def classify(ip: str) -> str:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return "unknown"
    if addr.is_loopback:
        return "loopback"
    if addr.is_private or addr.is_link_local:
        return "local"
    return "internet"


def _get_json(url: str, timeout: int = 8) -> dict | None:
    try:
        req = urllib.request.Request(url, headers=UA)
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read().decode("utf-8", "replace"))
    except Exception:
        return None


def reverse_dns(ip: str) -> str:
    """Reverse name of an address, or empty if it has none.

    The timeout is passed per call. setdefaulttimeout() would change the
    default for every socket in the process, including the API requests
    below, which is a side effect no lookup helper should be imposing.
    """
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ""


def forward_confirmed(ip: str, hostname: str) -> bool:
    """Does the reverse name resolve forward to the same address?

    A PTR record is controlled by whoever owns the address block, so an
    operator running from a VPS can name theirs anything they like, including
    a vendor's domain. Resolving the name forward closes that gap: they would
    also have to control the vendor's zone.
    """
    if not ip or not hostname:
        return False
    try:
        infos = socket.getaddrinfo(hostname, None)
    except Exception:
        return False
    return any(info[4][0] == ip for info in infos)


def mac_for_local_ip(ip: str) -> tuple[str, str]:
    """Looks up a MAC in the ARP table — LAN devices only."""
    for entry in arp_table():
        if entry["ip"] == ip:
            return entry["mac"], entry.get("vendor", "")
    return "", ""


def geo_asn(ip: str) -> dict | None:
    """Network owner and rough location for an address.

    HTTPS first. The previous version used ip-api over plain HTTP, so the
    answer about a suspected attacker's address arrived unauthenticated and
    modifiable in transit — poor form anywhere, worse in a tool whose whole
    job is deciding whom to trust. It also asked for Arabic replies, which
    stayed behind after the interface moved to English and produced a report
    in two languages.

    The plaintext service remains as a last resort, and when it is used the
    result says so rather than presenting it as equally reliable.
    """
    data = _get_json(f"https://ipwho.is/{ip}")
    if data and data.get("success"):
        conn = data.get("connection") or {}
        return {
            "status": "success",
            "country": data.get("country", ""),
            "regionName": data.get("region", ""),
            "city": data.get("city", ""),
            "isp": conn.get("isp", "") or conn.get("org", ""),
            "org": conn.get("org", ""),
            "as": (f"AS{conn['asn']}" if conn.get("asn") else ""),
            "proxy": bool((data.get("security") or {}).get("proxy")),
            "hosting": bool((data.get("security") or {}).get("hosting")),
            "transport": "https",
        }

    fields = "status,country,regionName,city,isp,org,as,proxy,hosting,query"
    data = _get_json(f"http://ip-api.com/json/{ip}?fields={fields}")
    if data and data.get("status") == "success":
        data["transport"] = "http"
    return data


def rdap_abuse(ip: str) -> str:
    """Pulls the abuse contact from RDAP, for filing a formal report."""
    data = _get_json(f"https://rdap.org/ip/{ip}", timeout=10)
    if not data:
        return ""
    for ent in data.get("entities", []) or []:
        roles = ent.get("roles") or []
        if "abuse" not in roles:
            continue
        vcard = (ent.get("vcardArray") or [None, []])[1]
        for item in vcard:
            if item and item[0] == "email":
                return item[3]
    return ""


def abuseipdb(ip: str, api_key: str) -> dict | None:
    if not api_key:
        return None
    try:
        req = urllib.request.Request(
            f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90",
            headers={**UA, "Key": api_key, "Accept": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=10) as r:
            return json.loads(r.read().decode()).get("data")
    except Exception:
        return None


_vt_cache: dict[str, dict] = {}


def virustotal(sha256: str, api_key: str) -> dict | None:
    """Asks VirusTotal about a file hash. The file itself is never uploaded.

    Only the hash is sent, so no data leaves the machine. If the file is
    unknown to them, that is itself a signal: widely used legitimate software
    is always already known.
    """
    if not sha256 or not api_key:
        return None
    if sha256 in _vt_cache:
        return _vt_cache[sha256]
    try:
        req = urllib.request.Request(
            f"https://www.virustotal.com/api/v3/files/{sha256}",
            headers={**UA, "x-apikey": api_key})
        with urllib.request.urlopen(req, timeout=12) as r:
            data = json.loads(r.read().decode("utf-8", "replace"))
        stats = (data.get("data", {}).get("attributes", {})
                 .get("last_analysis_stats", {}))
        attrs = data.get("data", {}).get("attributes", {})
        res = {
            "known": True,
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "total": sum(v for v in stats.values() if isinstance(v, int)),
            "name": (attrs.get("meaningful_name") or ""),
            "first_seen": attrs.get("first_submission_date", 0),
            "reputation": attrs.get("reputation", 0),
        }
    except urllib.error.HTTPError as e:
        if e.code == 404:
            res = {"known": False, "malicious": 0, "total": 0,
                   "note": "Unknown to VirusTotal — this file has not been seen before"}
        elif e.code == 429:
            return {"error": "Free query limit exceeded (4 per minute)"}
        elif e.code == 401:
            return {"error": "VirusTotal key is not valid"}
        else:
            return {"error": f"HTTP error {e.code}"}
    except Exception as e:
        return {"error": str(e)[:120]}

    _vt_cache[sha256] = res
    return res


def vt_summary(res: dict | None) -> tuple[str, str]:
    """Turns a VirusTotal result into a displayable (text, severity)."""
    if not res:
        return "", "info"
    if "error" in res:
        return res["error"], "info"
    if not res.get("known"):
        return res.get("note", "Unknown to VirusTotal"), "warn"
    mal = res.get("malicious", 0) + res.get("suspicious", 0)
    total = res.get("total", 0)
    if mal >= 5:
        return f"{mal} of {total} engines flag it as malicious", "critical"
    if mal >= 1:
        return f"{mal} of {total} engines flag it — may be a false positive", "warn"
    return f"Clean across {total} engines", "info"


def profile_peer(ip: str, online: bool = True, abuse_key: str = "") -> PeerProfile:
    """Builds a full profile of the other party."""
    if ip in _cache:
        return _cache[ip]

    p = PeerProfile(ip=ip, scope=classify(ip))

    if p.scope == "local":
        # this is the only case where a MAC is obtainable
        p.mac, p.vendor = mac_for_local_ip(ip)
        p.hostname = reverse_dns(ip)
        if not p.mac:
            p.errors.append("Not in the ARP table — may be behind another router")
        _cache[ip] = p
        return p

    if p.scope != "internet":
        _cache[ip] = p
        return p

    p.hostname = reverse_dns(ip)

    if online:
        g = geo_asn(ip)
        if g and g.get("status") == "success":
            p.country = g.get("country", "")
            p.region = g.get("regionName", "")
            p.city = g.get("city", "")
            p.isp = g.get("isp", "")
            p.org = g.get("org", "")
            p.asn = g.get("as", "")
            p.is_proxy = bool(g.get("proxy"))
            p.is_hosting = bool(g.get("hosting"))
            if g.get("transport") == "http":
                p.errors.append("Location data came over plain HTTP and was "
                                "not authenticated in transit")
        else:
            p.errors.append("Could not fetch location and provider data")

        p.abuse_email = rdap_abuse(ip)

        a = abuseipdb(ip, abuse_key)
        if a:
            p.abuse_score = a.get("abuseConfidenceScore", -1)
            p.reports = a.get("totalReports", 0)

    _cache[ip] = p
    return p


def clear_cache() -> None:
    _cache.clear()
