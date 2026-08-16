"""Browser extensions: what they are allowed to do, and who allowed it.

The browser holds the sessions. An extension with permission to read cookies
on every site does not need to steal a password — it takes the session
itself, and a stolen session walks past multi-factor authentication because
the authentication already happened. That makes an extension a quieter route
to an account than any malware on disk, and one this tool could not see at
all.

Behaviour is the wrong thing to look for here. Malicious extensions are
built to survive review: they fetch their payload from a server after
install, wait days between check-ins, and act on a fraction of visits. What
they cannot hide is the permission set, because the browser enforces it and
it sits in a file. So this module reads what each extension is *able* to do
and how it got installed, and leaves what it *did* to the network checks.

Nothing here is an accusation. A password manager legitimately reads every
page; a proxy switcher legitimately controls the proxy. The finding is
always "this can read every session you have — did you install it, and does
it need that?", which is a question the person can actually answer.
"""

from __future__ import annotations

import glob
import json
import os
import platform
import time

IS_WINDOWS = platform.system() == "Windows"

# Permissions that matter, and what each one actually grants. Written as
# consequences rather than API names, because "can read the cookies that
# keep you signed in" is a question the owner can answer and
# "cookies permission" is not.
PERMISSION_MEANING = {
    "cookies": "read the cookies that keep you signed in",
    "webRequest": "watch and alter every network request",
    "webRequestBlocking": "intercept requests before they are sent",
    "declarativeNetRequest": "rewrite or block network requests",
    "declarativeNetRequestWithHostAccess": "rewrite requests on any site",
    "debugger": "attach to pages as a debugger and read everything in them",
    "nativeMessaging": "talk to a program installed on this computer",
    "management": "disable or remove your other extensions",
    "proxy": "route your traffic through a server of its choosing",
    "clipboardRead": "read what you copy",
    "downloads": "download files without asking",
    "history": "read your full browsing history",
    "tabs": "see every page you open",
    "scripting": "run its own code inside pages",
    "privacy": "change your privacy settings",
    "desktopCapture": "capture your screen",
    "tabCapture": "capture the contents of tabs",
    "identity": "obtain authentication tokens",
    "browsingData": "erase browsing data",
}

# The permissions whose harm depends on where they apply
BROAD_HOSTS = ("<all_urls>", "*://*/*", "http://*/*", "https://*/*",
               "*://*/", "file:///*")

# Combinations that add up to session theft. Individually ordinary; together
# they are the whole capability an attacker needs and nothing more.
DANGEROUS_COMBOS = [
    ({"cookies"}, True,
     "can read the session cookies for every site you visit — enough to sign "
     "in as you without ever needing your password or second factor"),
    ({"debugger"}, False,
     "can attach to pages as a debugger, which reads everything in them "
     "including what you type"),
    ({"webRequest", "webRequestBlocking"}, True,
     "can intercept every request before it is sent, including "
     "authentication headers"),
    ({"nativeMessaging"}, False,
     "can pass messages to a program installed on this computer, which is "
     "how a browser extension reaches outside the browser"),
    ({"proxy"}, False,
     "can send your traffic through a server of its choosing"),
    ({"management"}, False,
     "can disable your other extensions, including security ones"),
]


def _home_dirs() -> list[str]:
    """Home directories to search, including the real user's under sudo."""
    homes = []
    for var in ("SUDO_USER", "PKEXEC_UID"):
        val = os.environ.get(var)
        if not val:
            continue
        try:
            import pwd
            rec = (pwd.getpwuid(int(val)) if var == "PKEXEC_UID"
                   else pwd.getpwnam(val))
            if rec.pw_dir:
                homes.append(rec.pw_dir)
        except Exception:
            pass
    homes.append(os.path.expanduser("~"))
    return list(dict.fromkeys(h for h in homes if h and os.path.isdir(h)))


def _chromium_roots() -> list[tuple[str, str]]:
    """(browser name, user-data directory) for every Chromium browser found."""
    roots = []
    for home in _home_dirs():
        if IS_WINDOWS:
            local = os.environ.get("LOCALAPPDATA") or os.path.join(
                home, "AppData", "Local")
            candidates = [
                ("Chrome", os.path.join(local, "Google", "Chrome", "User Data")),
                ("Edge", os.path.join(local, "Microsoft", "Edge", "User Data")),
                ("Brave", os.path.join(local, "BraveSoftware",
                                       "Brave-Browser", "User Data")),
                ("Vivaldi", os.path.join(local, "Vivaldi", "User Data")),
                ("Opera", os.path.join(
                    os.environ.get("APPDATA") or home,
                    "Opera Software", "Opera Stable")),
            ]
        else:
            cfg = os.path.join(home, ".config")
            candidates = [
                ("Chrome", os.path.join(cfg, "google-chrome")),
                ("Chromium", os.path.join(cfg, "chromium")),
                ("Edge", os.path.join(cfg, "microsoft-edge")),
                ("Brave", os.path.join(cfg, "BraveSoftware", "Brave-Browser")),
                ("Vivaldi", os.path.join(cfg, "vivaldi")),
                ("Opera", os.path.join(cfg, "opera")),
            ]
        roots += [(name, path) for name, path in candidates
                  if os.path.isdir(path)]
    return roots


def _firefox_profiles() -> list[str]:
    out = []
    for home in _home_dirs():
        if IS_WINDOWS:
            base = os.path.join(os.environ.get("APPDATA") or home,
                                "Mozilla", "Firefox", "Profiles")
        else:
            base = os.path.join(home, ".mozilla", "firefox")
        if os.path.isdir(base):
            out += [p for p in glob.glob(os.path.join(base, "*"))
                    if os.path.isdir(p)]
    return out


def _read_json(path: str) -> dict | None:
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            return json.load(f)
    except Exception:
        return None


def _localise(manifest: dict, ext_dir: str, value: str) -> str:
    """Resolves a __MSG_name__ placeholder to the real display name.

    Extensions may declare their name in a message catalogue rather than the
    manifest. Reporting "__MSG_extName__" to someone trying to decide whether
    they installed a thing is no help at all.
    """
    if not value.startswith("__MSG_"):
        return value
    key = value[6:-2] if value.endswith("__") else value[6:]
    default = manifest.get("default_locale") or "en"
    for locale in (default, "en", "en_US"):
        msgs = _read_json(os.path.join(ext_dir, "_locales", locale,
                                       "messages.json"))
        if msgs and key in msgs:
            got = (msgs[key] or {}).get("message")
            if got:
                return got
    return value


def _assess(permissions: list, hosts: list) -> tuple[list, bool]:
    """What this permission set amounts to, and whether hosts are unrestricted."""
    perms = {str(p) for p in permissions}
    all_hosts = {str(h) for h in hosts}
    # Host permissions can also appear in the permissions array (MV2)
    broad = any(h in BROAD_HOSTS or h.startswith("*://*")
                for h in all_hosts | perms)

    concerns = []
    for needed, needs_broad, meaning in DANGEROUS_COMBOS:
        if not needed.issubset(perms):
            continue
        if needs_broad and not broad:
            continue
        concerns.append(meaning)
    return concerns, broad


def _chromium_extensions() -> list[dict]:
    items = []
    for browser, root in _chromium_roots():
        pattern = os.path.join(root, "*", "Extensions", "*", "*",
                               "manifest.json")
        for manifest_path in glob.glob(pattern):
            manifest = _read_json(manifest_path)
            if not manifest:
                continue
            ext_dir = os.path.dirname(manifest_path)
            parts = manifest_path.split(os.sep)
            try:
                ext_id = parts[-3]
                profile = parts[-5]
            except IndexError:
                ext_id, profile = "", ""

            perms = list(manifest.get("permissions") or [])
            optional = list(manifest.get("optional_permissions") or [])
            hosts = list(manifest.get("host_permissions") or [])
            # Manifest V2 puts host patterns in with the permissions
            hosts += [p for p in perms if isinstance(p, str) and "://" in p]

            concerns, broad = _assess(perms, hosts)

            # An extension from the store carries the store's update URL.
            # Its absence means it was placed here by something else — a
            # policy, an installer, or by hand.
            update_url = str(manifest.get("update_url") or "")
            from_store = "clients2.google.com" in update_url or bool(update_url)

            try:
                installed = os.path.getmtime(ext_dir)
            except OSError:
                installed = 0.0

            items.append({
                "browser": browser,
                "profile": profile,
                "id": ext_id,
                "name": _localise(manifest, ext_dir,
                                  str(manifest.get("name") or ext_id)),
                "version": str(manifest.get("version") or ""),
                "path": ext_dir,
                "permissions": sorted(str(p) for p in perms),
                "optional_permissions": sorted(str(p) for p in optional),
                "hosts": sorted(set(hosts)),
                "broad_host_access": broad,
                "concerns": concerns,
                "from_store": from_store,
                "installed": installed,
                "manifest_version": manifest.get("manifest_version", 0),
            })
    return items


def _firefox_extensions() -> list[dict]:
    items = []
    for profile in _firefox_profiles():
        data = _read_json(os.path.join(profile, "extensions.json"))
        if not data:
            continue
        for addon in data.get("addons") or []:
            if addon.get("type") not in (None, "extension"):
                continue
            if not addon.get("active", True) and addon.get("userDisabled"):
                continue
            manifest = addon.get("defaultLocale") or {}
            perms_all = ((addon.get("userPermissions") or {}) or {})
            perms = list(perms_all.get("permissions") or [])
            hosts = list(perms_all.get("origins") or [])
            concerns, broad = _assess(perms, hosts)

            # Firefox records where an add-on came from. Anything other than
            # the store was placed here by something else.
            source = str(addon.get("sourceURI") or "")
            location = str(addon.get("location") or "")
            from_store = ("addons.mozilla.org" in source
                          or location == "app-profile" and bool(source))

            items.append({
                "browser": "Firefox",
                "profile": os.path.basename(profile),
                "id": str(addon.get("id") or ""),
                "name": str(manifest.get("name") or addon.get("id") or ""),
                "version": str(addon.get("version") or ""),
                "path": str(addon.get("path") or ""),
                "permissions": sorted(str(p) for p in perms),
                "optional_permissions": [],
                "hosts": sorted(set(str(h) for h in hosts)),
                "broad_host_access": broad,
                "concerns": concerns,
                "from_store": from_store,
                "installed": (addon.get("installDate") or 0) / 1000.0,
                "manifest_version": 2,
            })
    return items


def scan_extensions(errors: list[str] | None = None) -> list[dict]:
    """Every browser extension we can read, with what it is able to do."""
    def sub(label, fn):
        try:
            return fn()
        except Exception as e:
            if errors is not None:
                errors.append(f"{label}: {type(e).__name__}: {str(e)[:120]}")
            return []

    items = sub("Chromium extensions", _chromium_extensions)
    items += sub("Firefox extensions", _firefox_extensions)
    return items


def describe_permissions(ext: dict) -> list[str]:
    """The extension's permissions in plain terms, for the evidence panel."""
    out = []
    for perm in ext.get("permissions", []):
        meaning = PERMISSION_MEANING.get(perm)
        if meaning:
            out.append(meaning)
    if ext.get("broad_host_access"):
        out.append("act on every website, not a specific list")
    return out
