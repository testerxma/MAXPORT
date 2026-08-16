"""Signatures for remote-control tools and the ports tied to them.

Split into three confidence tiers:
  - REMOTE_TOOLS: remote-control tools known by name (high confidence)
  - ADMIN_PORTS: legitimate admin ports that are also entry points (medium)
  - ABUSED_PORTS: ports common in malware (low confidence, hint only)
"""

# process name (lowercase, no extension) -> display name
REMOTE_TOOLS = {
    "anydesk": "AnyDesk",
    "teamviewer": "TeamViewer",
    "tv_w32": "TeamViewer",
    "tv_x64": "TeamViewer",
    "teamviewer_service": "TeamViewer Service",
    "rustdesk": "RustDesk",
    "winvnc": "VNC Server",
    "winvnc4": "VNC Server",
    "tvnserver": "TightVNC",
    "vncserver": "VNC Server",
    "x11vnc": "x11vnc",
    "screenconnect": "ScreenConnect",
    "connectwisecontrol": "ConnectWise Control",
    "screenconnect.clientservice": "ScreenConnect Client",
    "aa_v3": "Ammyy Admin",
    "ammyy": "Ammyy Admin",
    "supremosystem": "Supremo",
    "supremo": "Supremo",
    "rserver3": "Radmin Server",
    "radmin": "Radmin",
    "dwagent": "DWService Agent",
    "dwagsvc": "DWService",
    "g2comm": "GoToMyPC",
    "lmiguardiansvc": "LogMeIn",
    "logmein": "LogMeIn",
    "sragent": "Splashtop",
    "srserver": "Splashtop",
    "splashtop": "Splashtop",
    "parsecd": "Parsec",
    "atera": "Atera Agent",
    "syncrosetup": "Syncro RMM",
    "nomachine": "NoMachine",
    "remoteutilities": "Remote Utilities",
    "rutserv": "Remote Utilities Host",
    "quickassist": "Windows Quick Assist",
    "mstsc": "RDP Client (outbound)",
    "chrome_remote_desktop": "Chrome Remote Desktop",
    "remoting_host": "Chrome Remote Desktop Host",
}

# Legitimate admin ports — one listening is a way into the machine
ADMIN_PORTS = {
    22: "SSH",
    23: "Telnet (unencrypted — dangerous)",
    3389: "RDP — Remote Desktop",
    5900: "VNC",
    5901: "VNC",
    5902: "VNC",
    5903: "VNC",
    5938: "TeamViewer",
    5985: "WinRM (HTTP)",
    5986: "WinRM (HTTPS)",
    4899: "Radmin",
    5222: "Chrome Remote Desktop",
    7070: "AnyDesk",
    8040: "ScreenConnect",
    6568: "AnyDesk",
    3283: "Apple Remote Desktop",
}

# Ports common in malicious control tools — low-confidence hint
ABUSED_PORTS = {
    1177: "njRAT",
    1604: "DarkComet",
    4444: "Metasploit / common in backdoors",
    5552: "njRAT",
    6666: "common in backdoors",
    6667: "IRC — used by botnets",
    7777: "common in backdoors",
    31337: "Back Orifice",
}

# Ports that malware sometimes uses and ordinary software uses constantly.
# Keeping them in ABUSED_PORTS meant a Jupyter notebook on 8888 or a
# supervisord on 9001 produced a "common in backdoors" warning on every
# scan, which is exactly the kind of alert that teaches people to stop
# reading alerts. They are still named, at informational level only.
NOISY_PORTS = {
    8000: "development web server",
    8080: "development or proxy web server",
    8888: "Jupyter or a development server",
    9001: "supervisord or Tor control",
    9050: "Tor SOCKS proxy",
}

# Paths where legitimate software is expected to live
TRUSTED_DIR_PREFIXES_WIN = (
    r"c:\windows",
    r"c:\program files",
    r"c:\program files (x86)",
)

TRUSTED_DIR_PREFIXES_NIX = (
    "/usr/bin",
    "/usr/sbin",
    "/usr/lib",
    "/usr/libexec",
    "/bin",
    "/sbin",
    "/opt",
    "/snap",
)

# Paths it is suspicious to run a program from
SUSPICIOUS_DIR_HINTS = (
    "\\appdata\\local\\temp",
    "\\appdata\\roaming",
    "\\windows\\temp",
    "\\downloads",
    "\\public",
    "/tmp/",
    "/dev/shm/",
    "/var/tmp/",
)


def identify_tool(proc_name: str) -> str | None:
    """Which remote-control product this process belongs to, if any.

    The hand-written table wins: it is curated, it carries the vendor
    domains used to tell a real session from a hijacked one, and its
    entries reflect decisions about severity. The generated catalogue is a
    wider net cast behind it, so a product released after these signatures
    were written is still recognised instead of passing as an unknown
    binary — the way this tool would otherwise go stale.
    """
    if not proc_name:
        return None
    key = proc_name.lower().removesuffix(".exe")
    if key in REMOTE_TOOLS:
        return REMOTE_TOOLS[key]
    try:
        from .rmm_catalogue import CATALOGUE_EXECUTABLES
    except ImportError:
        return None
    return CATALOGUE_EXECUTABLES.get(key)


def describe_port(port: int) -> tuple[str, str] | None:
    """Returns (description, confidence) for a port, or None if unknown."""
    if port in ADMIN_PORTS:
        return ADMIN_PORTS[port], "admin"
    if port in ABUSED_PORTS:
        return ABUSED_PORTS[port], "abused"
    if port in NOISY_PORTS:
        return NOISY_PORTS[port], "noisy"
    return None


# ───────────────────────────────────────────────────────────────────
# Vendor domains for remote-control tools
# ───────────────────────────────────────────────────────────────────
# A legitimate control tool talks to its vendor's servers. When the tool
# itself reaches a raw address belonging to no known domain, it is most
# likely driven from an attacker's own server rather than official
VENDOR_DOMAINS = {
    "AnyDesk": ("anydesk.com", "net.anydesk.com"),
    "TeamViewer": ("teamviewer.com", "dyngate.com"),
    "TeamViewer Service": ("teamviewer.com", "dyngate.com"),
    "RustDesk": ("rustdesk.com",),
    "ScreenConnect": ("screenconnect.com", "connectwise.com", "hostedrmm.com"),
    "ScreenConnect Client": ("screenconnect.com", "connectwise.com", "hostedrmm.com"),
    "ConnectWise Control": ("screenconnect.com", "connectwise.com"),
    "Splashtop": ("splashtop.com", "splashtop.eu"),
    "LogMeIn": ("logmein.com", "logme.in"),
    "GoToMyPC": ("gotomypc.com", "logmein.com"),
    "Atera Agent": ("atera.com", "servicedesk.atera.com"),
    "Syncro RMM": ("syncromsp.com", "syncroapi.com"),
    "DWService Agent": ("dwservice.net",),
    "DWService": ("dwservice.net",),
    "Supremo": ("supremocontrol.com", "nanosystems.it"),
    "Parsec": ("parsec.app", "parsecgaming.com"),
    "NoMachine": ("nomachine.com",),
    "Chrome Remote Desktop": ("google.com", "gvt1.com", "googleusercontent.com"),
    "Chrome Remote Desktop Host": ("google.com", "gvt1.com", "googleusercontent.com"),
    "Windows Quick Assist": ("microsoft.com", "msftconnecttest.com", "azure.com"),
    "Remote Utilities Host": ("remoteutilities.com",),
    "Remote Utilities": ("remoteutilities.com",),
    "Radmin": ("radmin.com", "famatech.com"),
    "Radmin Server": ("radmin.com", "famatech.com"),
}


# ───────────────────────────────────────────────────────────────────
# Tunnelling tools
# ───────────────────────────────────────────────────────────────────
# A tunnel inverts the direction of the connection: the machine dials out,
# passing the firewall and router without opening a port. And because the
# session appears aimed at the tunnel provider, the visible address is not
TUNNEL_TOOLS = {
    "cloudflared": "Cloudflare Tunnel",
    "ngrok": "ngrok",
    "frpc": "frp (client)",
    "frps": "frp (server)",
    "chisel": "chisel",
    "zrok": "zrok",
    "playit": "playit.gg",
    "playit-agent": "playit.gg",
    "localtunnel": "localtunnel",
    "nps": "nps",
    "npc": "nps (client)",
    "gost": "gost",
    "iodine": "DNS tunnel (iodine)",
    "dnscat2": "DNS tunnel (dnscat2)",
    "pagekite": "PageKite",
    "bore": "bore",
}

# Mesh VPNs. They do invert the connection, but they are mainstream products
# a great many people install deliberately, and calling a running Tailscale
# a critical finding trains the user to dismiss the tunnel category
# altogether. Reported, at a lower severity, as something to recognise
# rather than something to fear.
MESH_VPNS = {
    "tailscaled": "Tailscale",
    "tailscale": "Tailscale",
    "zerotier-one": "ZeroTier",
    "zerotier": "ZeroTier",
    "nebula": "Nebula",
    "netbird": "NetBird",
    "headscale": "Headscale",
}

# Tunnels running inside signed, legitimate programs. Neither the file hash
# nor its signature reveals these: the program is sound and the feature is
# built in. Each entry maps a process name to the argument fragments that
# turn it into a tunnel; an empty tuple means the name alone is enough.
TUNNEL_ARGS = {
    "code": ("tunnel",),
    "code-tunnel": ("tunnel",),
    "codium": ("tunnel",),
    "ssh": ("-r", "-l", "-d", "-w"),
    "autossh": ("-r", "-l", "-d"),
    "socat": ("exec:", "system:"),
    "powershell": ("-encodedcommand", "-enc "),
    "pwsh": ("-encodedcommand", "-enc "),
}

TUNNEL_ARG_LABEL = {
    "code": "VS Code tunnel",
    "code-tunnel": "VS Code tunnel",
    "codium": "VS Codium tunnel",
    "ssh": "SSH port forward",
    "autossh": "persistent SSH port forward",
    "socat": "socat relay",
    "powershell": "encoded PowerShell command",
    "pwsh": "encoded PowerShell command",
}

TUNNEL_DOMAINS = (
    "trycloudflare.com", "argotunnel.com", "cfargotunnel.com",
    "ngrok.io", "ngrok-free.app", "ngrok.app", "ngrok.dev",
    "devtunnels.ms", "tunnels.api.visualstudio.com",
    "loca.lt", "lhr.life", "localhost.run", "serveo.net",
    "pinggy.io", "telebit.cloud", "pagekite.me", "bore.pub",
    "playit.gg", "zrok.io", "ts.net",
)

# Dynamic DNS lets an attacker change address without changing the malware
DDNS_DOMAINS = (
    "duckdns.org", "dyndns.org", "no-ip.com", "no-ip.org", "noip.com",
    "ddns.net", "hopto.org", "zapto.org", "sytes.net", "myftp.biz",
    "myftp.org", "serveminecraft.net", "servegame.com", "redirectme.net",
    "chickenkiller.com", "freedns.afraid.org", "dynu.com", "3utilities.com",
)


def identify_tunnel(proc_name: str, cmdline: str = "") -> str | None:
    """Identifies a tunnel, whether a dedicated tool or a feature of a legit one.

    Names are matched exactly. startswith() on keys as short as "nps", "bore"
    and "gost" claimed any process whose name merely began with those
    letters.
    """
    n = (proc_name or "").lower().removesuffix(".exe")
    if n in TUNNEL_TOOLS:
        return TUNNEL_TOOLS[n]

    low = f" {(cmdline or '').lower()} "
    args = TUNNEL_ARGS.get(n)
    if args is not None:
        if not args:
            return TUNNEL_ARG_LABEL.get(n, n)
        for frag in args:
            # Flags are matched as separate words so "-d" does not fire on a
            # path fragment; substrings such as "exec:" are matched directly.
            hit = (f" {frag} " in low or f" {frag}" in low.rstrip()
                   if frag.startswith("-") else frag in low)
            if hit:
                return TUNNEL_ARG_LABEL.get(n, n)
    return None


def identify_mesh_vpn(proc_name: str) -> str | None:
    """A mainstream mesh VPN, reported but not treated as a covert channel."""
    n = (proc_name or "").lower().removesuffix(".exe")
    return MESH_VPNS.get(n)


def domain_flags(hostname: str) -> tuple[str, str] | None:
    """Classifies a hostname: tunnel, dynamic DNS, or neither."""
    h = (hostname or "").lower().rstrip(".")
    if not h:
        return None
    for d in TUNNEL_DOMAINS:
        if h == d or h.endswith("." + d):
            return "tunnel", d
    for d in DDNS_DOMAINS:
        if h == d or h.endswith("." + d):
            return "ddns", d
    return None


def vendor_match(tool: str, hostname: str) -> bool | None:
    """Is this control program talking to its own vendor's servers?

    None means "unknown" — either no domain is on record for the tool, or the
    address has no reverse name. Both are cases of not knowing, and not
    knowing must not be converted into an accusation. Most cloud addresses
    carry no PTR record at all, so treating a missing name as a mismatch
    accused every legitimate session running on ordinary hosting.

    A caller acting on True should confirm the name forward as well (see
    intel.forward_confirmed): a PTR record is set by whoever owns the address
    block, so an operator on a VPS can point theirs at a vendor domain and
    pass a reverse-only check.
    """
    domains = VENDOR_DOMAINS.get(tool)
    if not domains:
        try:
            from .rmm_catalogue import CATALOGUE_DOMAINS
            domains = CATALOGUE_DOMAINS.get(tool)
        except ImportError:
            domains = None
    if not domains:
        return None
    h = (hostname or "").lower().rstrip(".")
    if not h:
        return None           # raw address with no reverse name — unknown
    return any(h == d or h.endswith("." + d) for d in domains)
