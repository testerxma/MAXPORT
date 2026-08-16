"""Living-off-the-land binaries: signed by the vendor, abused by attackers.

This module exists to correct a blind spot in our own trust model. Elsewhere
we treat a valid digital signature as evidence of trustworthiness, which is
usually right and here is exactly wrong. certutil.exe, mshta.exe and
bitsadmin.exe are all genuinely signed by Microsoft and all can download a
file from the internet and run it. An attacker using them brings no malware
of their own, so there is no unsigned file to catch and nothing for a
signature check to object to.

The signal is therefore never the binary itself, which is present on every
Windows machine and usually idle. It is the binary doing something outside
its purpose: a certificate utility opening a network connection, or a
script host spawned by a document. So nothing here fires on presence alone.

Curated from the LOLBAS project's catalogue, narrowed to binaries that can
fetch remote content, execute arbitrary code, or carry a session — the
capabilities that matter for remote control specifically.
"""

from __future__ import annotations

# Binary -> (what it is for, how it gets abused)
NETWORK_CAPABLE = {
    "certutil.exe": ("certificate utility",
                     "downloads arbitrary files and decodes base64 payloads"),
    "bitsadmin.exe": ("background transfer service",
                      "downloads files and can run one on completion"),
    "curl.exe": ("HTTP client",
                 "downloads payloads while looking like normal traffic"),
    "esentutl.exe": ("database utility",
                     "copies files from remote shares"),
    "finger.exe": ("user lookup utility",
                   "used as a covert download and exfiltration channel"),
    "expand.exe": ("archive expander", "fetches files from remote paths"),
    "makecab.exe": ("cabinet packer", "packs data for exfiltration"),
    "replace.exe": ("file replacement tool", "copies files from remote shares"),
    "hh.exe": ("help viewer", "opens remote help files containing script"),
    "msiexec.exe": ("installer",
                    "installs a package straight from a remote URL"),
    "wget.exe": ("HTTP client", "downloads payloads"),
}

EXECUTION_CAPABLE = {
    "mshta.exe": ("HTML application host",
                  "runs script from a file or a remote URL"),
    "rundll32.exe": ("DLL entry point runner",
                     "runs code inside a signed, trusted process"),
    "regsvr32.exe": ("COM registration tool",
                     "runs remote script without writing to disk"),
    "wscript.exe": ("script host", "runs VBScript and JScript"),
    "cscript.exe": ("console script host", "runs scripts without a window"),
    "installutil.exe": (".NET installer", "runs .NET code bypassing controls"),
    "regasm.exe": (".NET assembly registration", "runs .NET code"),
    "regsvcs.exe": (".NET services tool", "runs .NET code"),
    "msbuild.exe": ("build tool", "compiles and runs code from a project file"),
    "cmstp.exe": ("connection manager profile installer",
                  "runs script from an INF file, bypassing prompts"),
    "forfiles.exe": ("file iteration tool", "runs a command per matched file"),
    "pcalua.exe": ("compatibility assistant", "launches another program"),
    "conhost.exe": ("console host", "used to launch a hidden process"),
    "scriptrunner.exe": ("script runner", "runs an arbitrary command"),
    "wmic.exe": ("WMI command line",
                 "runs commands locally or on a remote machine"),
    "odbcconf.exe": ("ODBC configuration tool", "loads and runs a DLL"),
    "xwizard.exe": ("wizard host", "loads a remote COM object"),
}

# A parent that has no business launching a network program at all
NEVER_A_PARENT = (
    "winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe",
    "acrord32.exe", "acrobat.exe", "onenote.exe", "msaccess.exe",
)

ALL = {**NETWORK_CAPABLE, **EXECUTION_CAPABLE}


def identify(proc_name: str) -> tuple[str, str] | None:
    """Returns (purpose, abuse) if this is a known abusable system binary."""
    n = (proc_name or "").lower()
    if not n.endswith(".exe"):
        n += ".exe"
    return ALL.get(n)


def is_network_capable(proc_name: str) -> bool:
    n = (proc_name or "").lower()
    if not n.endswith(".exe"):
        n += ".exe"
    return n in NETWORK_CAPABLE


def assess(proc_name: str, cmdline: str, ancestry: str,
           has_connection: bool) -> dict | None:
    """Judges whether this binary is being used outside its purpose.

    Presence is never the finding. What matters is context: is it holding a
    network connection it has no reason to hold, was it launched by a
    document, or is its command line carrying a URL?
    """
    info = identify(proc_name)
    if not info:
        return None
    purpose, abuse = info

    low = (cmdline or "").lower()
    anc = (ancestry or "").lower()
    reasons, severity = [], "warn"

    if any(p in anc for p in NEVER_A_PARENT):
        parent = next(p for p in NEVER_A_PARENT if p in anc)
        reasons.append(f"launched by {parent}, which never legitimately "
                       "starts a system utility")
        severity = "critical"

    if has_connection and is_network_capable(proc_name):
        reasons.append("holding a live network connection, which is how this "
                       "binary is used to fetch a payload")
        severity = "critical"
    elif has_connection:
        reasons.append("holding a network connection, which is outside its purpose")

    if any(u in low for u in ("http://", "https://", "ftp://", "\\\\")):
        reasons.append("a remote address appears in its command line")
        severity = "critical"

    if any(f in low for f in ("-decode", "/decode", "-urlcache", "/urlcache",
                              "frombase64", "-enc", "-encodedcommand")):
        reasons.append("using flags associated with fetching or decoding payloads")
        severity = "critical"

    if not reasons:
        return None      # present and idle is normal, not a finding

    return {
        "binary": proc_name,
        "purpose": purpose,
        "abuse": abuse,
        "reasons": reasons,
        "severity": severity,
    }
