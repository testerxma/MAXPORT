"""Inspecting the network itself: ARP table, DNS servers, hosts file."""

from __future__ import annotations

import os
import platform
import re
import subprocess
from collections import defaultdict

IS_WINDOWS = platform.system() == "Windows"

_OUI = {
    "00:50:56": "VMware", "00:0c:29": "VMware", "08:00:27": "VirtualBox",
    "52:54:00": "QEMU/KVM", "00:15:5d": "Hyper-V", "00:1a:11": "Google",
    "3c:5a:b4": "Google", "b8:27:eb": "Raspberry Pi", "dc:a6:32": "Raspberry Pi",
    "d8:3a:dd": "Raspberry Pi", "00:1b:63": "Apple", "ac:de:48": "Apple",
    "f0:18:98": "Apple", "00:23:ae": "Dell", "00:1e:c9": "Dell",
    "00:24:e8": "Dell", "00:e0:4c": "Realtek", "00:16:3e": "Xen",
}

MAC_RE = re.compile(r"([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}")
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def _run(cmd: list[str], timeout: int = 10) -> str:
    try:
        r = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout, errors="replace",
            creationflags=subprocess.CREATE_NO_WINDOW if IS_WINDOWS else 0,
        )
        return r.stdout or ""
    except Exception:
        return ""


def vendor_of(mac: str) -> str:
    return _OUI.get(mac.lower()[:8].replace("-", ":"), "")


def arp_table() -> list[dict]:
    """ARP table — every device this machine has spoken to on the LAN."""
    entries: list[dict] = []

    if not IS_WINDOWS and os.path.exists("/proc/net/arp"):
        try:
            with open("/proc/net/arp") as f:
                for line in f.readlines()[1:]:
                    parts = line.split()
                    if len(parts) >= 6 and parts[3] != "00:00:00:00:00:00":
                        entries.append({
                            "ip": parts[0], "mac": parts[3].lower(),
                            "iface": parts[5], "vendor": vendor_of(parts[3]),
                        })
        except Exception:
            pass
        if entries:
            return entries

    out = _run(["arp", "-a"])
    for line in out.splitlines():
        m_ip, m_mac = IP_RE.search(line), MAC_RE.search(line)
        if m_ip and m_mac:
            mac = m_mac.group(0).lower().replace("-", ":")
            if mac == "ff:ff:ff:ff:ff:ff":
                continue
            entries.append({
                "ip": m_ip.group(0), "mac": mac, "iface": "",
                "vendor": vendor_of(mac),
            })
    return entries


def _own_addresses() -> set[str]:
    """This machine's own addresses, which are not evidence of anything."""
    own: set[str] = set()
    try:
        import psutil
        for addrs in psutil.net_if_addrs().values():
            for a in addrs:
                if a.address:
                    own.add(a.address.split("%")[0])
    except Exception:
        pass
    return own


def neighbour_table() -> list[dict]:
    """IPv6 neighbours. ARP is IPv4-only, so NDP was a blind spot.

    An attacker on a dual-stack network can poison NDP and intercept traffic
    without touching ARP at all, which the previous version could not see.
    """
    entries: list[dict] = []
    if IS_WINDOWS:
        out = _run(["netsh", "interface", "ipv6", "show", "neighbors"])
    else:
        out = _run(["ip", "-6", "neigh", "show"])
    for line in out.splitlines():
        m_mac = MAC_RE.search(line)
        if not m_mac:
            continue
        token = line.split()[0] if line.split() else ""
        if ":" not in token or token.count(":") < 2:
            continue
        mac = m_mac.group(0).lower().replace("-", ":")
        if mac in ("ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"):
            continue
        entries.append({"ip": token.split("%")[0], "mac": mac,
                        "iface": "", "vendor": vendor_of(mac), "family": "ipv6"})
    return entries


def detect_arp_spoof(entries: list[dict] | None = None) -> list[dict]:
    """One MAC on several IPs is a strong sign of a man-in-the-middle.

    It is also what a router with a second address, a host with two
    interfaces on one subnet, a virtualisation bridge, and a stale cache
    entry after a DHCP renewal all look like. Reporting every duplicate as a
    man-in-the-middle produced a critical alert on ordinary networks, so the
    ordinary causes are excluded first and the remainder is annotated with
    what makes it suspicious.
    """
    entries = entries if entries is not None else arp_table()
    own = _own_addresses()

    by_mac: dict[str, set[str]] = defaultdict(set)
    for e in entries:
        ip = e.get("ip", "")
        mac = e.get("mac", "")
        if not ip or not mac or ip in own:
            continue
        if mac in ("00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff"):
            continue
        # Multicast and broadcast MACs map to many addresses by design
        try:
            if int(mac.split(":")[0], 16) & 1:
                continue
        except ValueError:
            continue
        by_mac[mac].add(ip)

    alerts = []
    for mac, ips in by_mac.items():
        if len(ips) < 2:
            continue
        # Addresses on different subnets behind one MAC is the router doing
        # its job; the interesting case is one MAC answering for several
        # hosts on the same subnet.
        same_subnet = defaultdict(set)
        for ip in ips:
            same_subnet[".".join(ip.split(".")[:3])].add(ip)
        clustered = {k: v for k, v in same_subnet.items() if len(v) > 1}
        if not clustered:
            continue
        alerts.append({"mac": mac, "ips": sorted(ips),
                       "vendor": vendor_of(mac),
                       "count": max(len(v) for v in clustered.values())})
    return alerts


def dns_servers() -> list[str]:
    """DNS servers in use. Silent changes are a classic sign of compromise."""
    servers: list[str] = []
    if IS_WINDOWS:
        out = _run([
            "powershell", "-NoProfile", "-Command",
            "Get-DnsClientServerAddress -AddressFamily IPv4 "
            "| Select-Object -ExpandProperty ServerAddresses",
        ])
        servers = [s.strip() for s in out.splitlines() if s.strip()]
    else:
        for path in ("/etc/resolv.conf",):
            try:
                with open(path) as f:
                    for line in f:
                        if line.strip().startswith("nameserver"):
                            servers.append(line.split()[1])
            except Exception:
                pass
        out = _run(["resolvectl", "dns"])
        servers += IP_RE.findall(out)
    seen, uniq = set(), []
    for s in servers:
        if s not in seen:
            seen.add(s)
            uniq.append(s)
    return uniq


def hosts_entries() -> list[dict]:
    """hosts entries — used to redirect sites or block update servers."""
    path = (r"C:\Windows\System32\drivers\etc\hosts" if IS_WINDOWS
            else "/etc/hosts")
    out = []
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            for i, line in enumerate(f, 1):
                s = line.strip()
                if not s or s.startswith("#"):
                    continue
                parts = s.split()
                if len(parts) < 2:
                    continue
                ip, names = parts[0], parts[1:]
                loopback = ip.startswith("127.") or ip in ("::1", "0.0.0.0")
                out.append({
                    "line": i, "ip": ip, "names": " ".join(names),
                    "redirect": not loopback,
                    "blocks_security": any(
                        k in " ".join(names).lower()
                        for k in ("microsoft", "windowsupdate", "sophos", "kaspersky",
                                  "avast", "mcafee", "malwarebytes", "clamav",
                                  "defender", "virustotal", "ubuntu.com")
                    ),
                })
    except Exception:
        pass
    return out


def proxy_settings() -> dict:
    """Proxy settings. A planted proxy routes all browsing through others."""
    res = {"enabled": False, "server": "", "source": ""}
    if IS_WINDOWS:
        out = _run([
            "reg", "query",
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings",
        ])
        for line in out.splitlines():
            if "ProxyEnable" in line and line.strip().endswith("0x1"):
                res["enabled"] = True
            if "ProxyServer" in line:
                res["server"] = line.split()[-1]
        res["source"] = "Windows settings"
    else:
        for var in ("http_proxy", "https_proxy", "all_proxy",
                    "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY"):
            if os.environ.get(var):
                res["enabled"] = True
                res["server"] = os.environ[var]
                res["source"] = f"environment variable {var}"
                break
    return res


def interfaces() -> list[dict]:
    """Network adapters — an unfamiliar VPN or bridge deserves a look."""
    import psutil
    out = []
    addrs = psutil.net_if_addrs()
    stats = psutil.net_if_stats()
    for name, addr_list in addrs.items():
        mac = next((a.address for a in addr_list
                    if MAC_RE.fullmatch((a.address or "").replace("-", ":"))), "")
        ips = [a.address for a in addr_list
               if a.address and not MAC_RE.fullmatch(a.address.replace("-", ":"))]
        st = stats.get(name)
        out.append({
            "name": name,
            "up": bool(st and st.isup),
            "mac": mac.lower().replace("-", ":"),
            "vendor": vendor_of(mac) if mac else "",
            "ips": ips,
        })
    return out
