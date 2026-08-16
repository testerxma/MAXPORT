"""What was within reach, and what to do in the next hour.

Most tools stop at telling someone they are compromised. That is the least
useful moment to stop. The person is frightened, the clock is running, and
the single question they need answered is what to do first.

This module answers it by inventorying what an infostealer running as this
user could actually have reached — the browser profiles, the SSH keys, the
cloud credentials, the wallet files that are on *this* machine — and turning
that into an ordered list of things to revoke.

The order matters more than the list. Changing a password does nothing about
a stolen session cookie, because the session was already authenticated and
carries no password with it; the attacker stays signed in through the reset
and past multi-factor authentication. So session revocation comes before
password changes, and both come before anything cosmetic.

Two deliberate limits. Nothing here reads the contents of a credential
store: the file's existence is the finding, and opening it would put the
secrets somewhere new. And nothing claims theft occurred — this is what was
*exposed* if something ran, which is a different and honest claim.
"""

from __future__ import annotations

import glob
import os
import platform

IS_WINDOWS = platform.system() == "Windows"

# Ordered by how quickly the loss becomes irreversible, not by how common
# the item is. A drained wallet cannot be undone; a stolen password can.
CATEGORY_ORDER = ["wallet", "session", "cloud", "ssh", "password", "messaging"]

URGENCY = {
    "wallet": "immediately — a transfer cannot be reversed",
    "session": "first — a stolen session survives a password change",
    "cloud": "within the hour — keys can create new access silently",
    "ssh": "within the hour — a key needs no password and may be trusted "
           "by other machines",
    "password": "today — after sessions are revoked, or the reset is undone",
    "messaging": "today — an account takeover here is used to reach others",
}


def _triage_entry(category: str, name: str, where: str, action: str,
           found: bool = True) -> dict:
    return {"category": category, "name": name, "path": where,
            "action": action, "urgency": URGENCY.get(category, ""),
            "found": found}


def _home() -> str:
    for var in ("SUDO_USER", "PKEXEC_UID"):
        val = os.environ.get(var)
        if not val:
            continue
        try:
            import pwd
            rec = (pwd.getpwuid(int(val)) if var == "PKEXEC_UID"
                   else pwd.getpwnam(val))
            if rec.pw_dir and os.path.isdir(rec.pw_dir):
                return rec.pw_dir
        except Exception:
            pass
    return os.path.expanduser("~")


def _exists_any(patterns: list[str]) -> str:
    for pattern in patterns:
        hits = glob.glob(pattern)
        if hits:
            return hits[0]
    return ""


def browser_sessions() -> list[dict]:
    """Cookie stores hold the sessions that outlive a password change."""
    home = _home()
    out = []
    if IS_WINDOWS:
        local = os.environ.get("LOCALAPPDATA") or os.path.join(
            home, "AppData", "Local")
        roots = {
            "Chrome": os.path.join(local, "Google", "Chrome", "User Data"),
            "Edge": os.path.join(local, "Microsoft", "Edge", "User Data"),
            "Brave": os.path.join(local, "BraveSoftware", "Brave-Browser",
                                  "User Data"),
        }
        firefox = os.path.join(os.environ.get("APPDATA") or home,
                               "Mozilla", "Firefox", "Profiles")
    else:
        cfg = os.path.join(home, ".config")
        roots = {
            "Chrome": os.path.join(cfg, "google-chrome"),
            "Chromium": os.path.join(cfg, "chromium"),
            "Edge": os.path.join(cfg, "microsoft-edge"),
            "Brave": os.path.join(cfg, "BraveSoftware", "Brave-Browser"),
        }
        firefox = os.path.join(home, ".mozilla", "firefox")

    for name, root in roots.items():
        if not os.path.isdir(root):
            continue
        out.append(_triage_entry(
            "session", f"{name} signed-in sessions", root,
            f"Sign out of every device in each account you use in {name}. "
            "Look for a 'sign out everywhere' or 'active sessions' control — "
            "that is what invalidates a stolen cookie."))
        if _exists_any([os.path.join(root, "*", "Login Data")]):
            out.append(_triage_entry(
                "password", f"{name} saved passwords", root,
                f"Change the passwords saved in {name}, starting with email "
                "and banking. Do this after revoking sessions."))

    if os.path.isdir(firefox):
        out.append(_triage_entry(
            "session", "Firefox signed-in sessions", firefox,
            "Sign out everywhere in the accounts you use in Firefox."))
        if _exists_any([os.path.join(firefox, "*", "logins.json")]):
            out.append(_triage_entry(
                "password", "Firefox saved passwords", firefox,
                "Change the passwords stored in Firefox."))
    return out


def ssh_and_cloud() -> list[dict]:
    """Keys and tokens: no password, and often trusted elsewhere."""
    home = _home()
    out = []

    ssh_dir = os.path.join(home, ".ssh")
    if os.path.isdir(ssh_dir):
        keys = [os.path.basename(p) for p in glob.glob(os.path.join(ssh_dir, "*"))
                if os.path.basename(p).startswith("id_")
                and not p.endswith(".pub")]
        if keys:
            out.append(_triage_entry(
                "ssh", f"SSH private keys ({', '.join(keys[:4])})", ssh_dir,
                "Generate new keys and remove the old public keys from every "
                "server and from GitHub, GitLab and any other service. A key "
                "with no passphrase is usable immediately."))

    checks = [
        ("cloud", "AWS credentials", [os.path.join(home, ".aws", "credentials")],
         "Deactivate the access keys in the AWS console and issue new ones."),
        ("cloud", "Google Cloud credentials",
         [os.path.join(home, ".config", "gcloud", "credentials.db")],
         "Revoke with 'gcloud auth revoke --all' and sign in again."),
        ("cloud", "Azure credentials",
         [os.path.join(home, ".azure", "*.json")],
         "Run 'az logout' and review sign-in activity in the portal."),
        ("cloud", "Kubernetes config", [os.path.join(home, ".kube", "config")],
         "Rotate the cluster credentials this file holds."),
        ("cloud", "Docker registry login",
         [os.path.join(home, ".docker", "config.json")],
         "Log out and issue a new registry token."),
        ("cloud", "npm token", [os.path.join(home, ".npmrc")],
         "Revoke the npm token and create a new one."),
        ("cloud", "PyPI token", [os.path.join(home, ".pypirc")],
         "Revoke the PyPI token."),
        ("cloud", "Git credential store",
         [os.path.join(home, ".git-credentials")],
         "This file holds tokens in plain text. Revoke every token in it."),
        ("cloud", "GitHub CLI token",
         [os.path.join(home, ".config", "gh", "hosts.yml")],
         "Run 'gh auth logout' and revoke the token on GitHub."),
    ]
    for category, name, patterns, action in checks:
        hit = _exists_any(patterns)
        if hit:
            out.append(_triage_entry(category, name, hit, action))
    return out


def wallets_and_messaging() -> list[dict]:
    """Where a loss is immediate and cannot be undone."""
    home = _home()
    out = []
    if IS_WINDOWS:
        appdata = os.environ.get("APPDATA") or os.path.join(
            home, "AppData", "Roaming")
        local = os.environ.get("LOCALAPPDATA") or os.path.join(
            home, "AppData", "Local")
    else:
        appdata = os.path.join(home, ".config")
        local = os.path.join(home, ".local", "share")

    wallets = [
        ("Electrum", [os.path.join(appdata, "Electrum", "wallets", "*"),
                      os.path.join(home, ".electrum", "wallets", "*")]),
        ("Exodus", [os.path.join(appdata, "Exodus", "exodus.wallet"),
                    os.path.join(home, ".config", "Exodus", "exodus.wallet")]),
        ("Bitcoin Core", [os.path.join(appdata, "Bitcoin", "wallet.dat"),
                          os.path.join(home, ".bitcoin", "wallet.dat")]),
        ("Ethereum keystore", [os.path.join(home, ".ethereum", "keystore", "*")]),
        ("Monero", [os.path.join(home, "Monero", "wallets", "*")]),
    ]
    for name, patterns in wallets:
        hit = _exists_any(patterns)
        if hit:
            out.append(_triage_entry(
                "wallet", f"{name} wallet file", hit,
                "Move the funds to a wallet created on a machine you trust. "
                "Do not simply change the password: the file itself may "
                "already be gone, and the passphrase can be broken offline."))

    messaging = [
        ("Telegram", [os.path.join(appdata, "Telegram Desktop", "tdata"),
                      os.path.join(home, ".local", "share",
                                   "TelegramDesktop", "tdata")]),
        ("Discord", [os.path.join(appdata, "discord", "Local Storage"),
                     os.path.join(home, ".config", "discord",
                                  "Local Storage")]),
        ("Signal", [os.path.join(appdata, "Signal"),
                    os.path.join(home, ".config", "Signal")]),
    ]
    for name, patterns in messaging:
        hit = _exists_any(patterns)
        if hit:
            out.append(_triage_entry(
                "messaging", f"{name} session data", hit,
                f"Terminate all other sessions in {name}'s settings. These "
                "files can sign someone in as you without a code."))
    return out


def build_checklist(errors: list[str] | None = None) -> list[dict]:
    """Everything on this machine worth revoking, ordered by urgency."""
    def sub(label, fn):
        try:
            return fn()
        except Exception as e:
            if errors is not None:
                errors.append(f"{label}: {type(e).__name__}: {str(e)[:120]}")
            return []

    items = sub("browser sessions", browser_sessions)
    items += sub("keys and cloud credentials", ssh_and_cloud)
    items += sub("wallets and messaging", wallets_and_messaging)

    order = {c: i for i, c in enumerate(CATEGORY_ORDER)}
    items.sort(key=lambda i: order.get(i["category"], 99))
    return items


def summary(items: list[dict]) -> str:
    """One sentence naming what is at stake, for the top of a report."""
    if not items:
        return ("Nothing obvious to revoke was found on this machine, which "
                "is not the same as nothing being at risk.")
    counts: dict[str, int] = {}
    for i in items:
        counts[i["category"]] = counts.get(i["category"], 0) + 1
    parts = []
    for cat in CATEGORY_ORDER:
        if counts.get(cat):
            parts.append(f"{counts[cat]} {cat}")
    return ("If something did run as you, these were within reach: "
            + ", ".join(parts)
            + ". Revoke sessions before changing passwords — a password "
              "change does not end a session that is already signed in.")
