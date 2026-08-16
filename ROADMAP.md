# Roadmap

Decisions and research that shaped what comes next, written down so the
reasoning survives the conversation it came from.

---

## 1. Android application

**Status: planned, not started. Android only — iOS is deliberately excluded.**

### Why Android is the right target

The desktop question — *is someone controlling this machine right now?* —
translates directly. On Android the answer is almost always the same
mechanism: an accessibility service the owner was talked into enabling.
Google's own analysis ranks observing and interacting with apps through an
accessibility service as its second most impactful malware abuse vector, and
the families that use it (SpyNote, SOVA, ToxicPanda, Cerberus, Anubis,
SharkBot) follow one recipe: socially engineer the victim into granting
`BIND_ACCESSIBILITY_SERVICE`, then inject synthetic gestures to automate
anything the operator wants.

That is the same scam this project already addresses on the desktop — a
support call, an install, a permission — except the device also holds the
banking app.

### Why iOS is excluded

The sandbox prevents process enumeration, inspection of other applications
and access to system network state. Any "scanner" for iOS would be a guided
checklist wearing a scanner's clothes, and that is worse than nothing: it
would produce a reassuring result having checked nothing. If iOS is ever
addressed, it must be presented honestly as a manual checklist.

### What an Android application can and cannot do

Cannot, without root:

- See other applications' network connections (`/proc/net` restricted since
  Android 10)
- Terminate another process
- Read another application's files
- Enumerate installed packages without `QUERY_ALL_PACKAGES`, which Google
  Play restricts to a small set of categories

Can:

- Read `Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES` — the single most
  valuable signal available, and the one that answers the actual question
- List device administrators, notification listeners and overlay permission
  holders
- Determine the installer of a package, separating sideloaded from store
- See all traffic through the VPN service API — but **only one application
  may hold it**, so this competes with the user's real VPN, and it is also
  what the unrelated NetGuard firewall already does

### Timing that constrains the design

Android 17 removes accessibility service access from applications not
categorised as accessibility tools, and 17.2 restricts the API further under
Advanced Protection Mode. Google is closing this vector itself.

That does not remove the need — the enormous installed base of older devices
will never receive those changes, and those are the devices victims are
using — but it does mean the application should be built for older Android
first, and should not assume the vector stays open on new devices.

### Recommended sequence

**Phase 1 — scan a phone from the desktop over ADB.** Reuses this codebase
entirely: a new collector module, no new language, no store approval, no
sandbox limits, and ADB sees what no in-app scanner can. Works today.

```
adb shell settings get secure enabled_accessibility_services
adb shell dumpsys device_policy
adb shell pm list packages -i          # installer, catches sideloading
adb shell appops get <pkg> SYSTEM_ALERT_WINDOW
adb shell dumpsys notification
```

**Phase 2 — a native Android application.** A separate product in a
different language. It reaches the people who have no computer, which is
most victims of phone scams, but it should not be confused with this
codebase.

**Open question that decides the order:** do the intended users own a
computer at all? If phone-scam victims in the target region are
phone-only, Phase 1 serves very few and Phase 2 becomes the real work
despite its cost.

---

## 2. Development-tool supply chain

**Status: researched, not started. Strongest candidate for the next build.**

This project's users skew toward developers and security workstations —
exactly the population now being targeted directly.

### Editor extensions

In May 2026 a compromised Nx Console extension was published to the official
Visual Studio Code marketplace, was live for roughly eleven to eighteen
minutes, and was used to clone approximately 3,800 of GitHub's internal
repositories from a single compromised employee device. The payload
harvested cloud, CI/CD and AI coding assistant credentials. In January 2026
two AI-branded marketplace extensions with about 1.5 million combined
installs were found exfiltrating developer files.

The architecture is identical to the browser extension scanner already
built: manifests on disk, permissions and provenance, no behavioural
analysis. Targets are VS Code, Cursor, Windsurf and JetBrains.

**The heuristic that matters most is age.** These compromises are caught in
minutes to hours; the exposure window is the gap between publication and
removal. An extension installed or updated within the last few days is worth
surfacing on its own, independent of what it contains — a signal available
from the filesystem timestamp and from nothing else.

### MCP servers

Roughly 86% of MCP servers run locally on developer machines. Recurring
failures worth detecting:

- **Bound to `0.0.0.0` instead of loopback** — anyone on the same café or
  office network can reach it. This project already enumerates listening
  ports, so identifying which of them are MCP servers is a short step.
- **No authentication.** Thousands of exposed servers, with only a small
  fraction using OAuth.
- **Repository-controlled configuration.** Check Point reported that a
  malicious hook in a repository's `.claude/settings.json` executes when the
  project is opened, before any trust prompt appears, and that settings in
  `.mcp.json` could auto-approve every MCP server at launch. A file in a
  cloned repository is therefore an execution vector, which is squarely a
  persistence-and-execution question this project already asks elsewhere.
- **Shadow servers** — configurations added outside any review.

Where to look: `~/.claude.json`, `.mcp.json` and `.claude/settings.json` in
project directories, and the equivalent editor settings.

**A note on our own position.** This project now ships an MCP server, so it
has to meet the standard it checks: loopback only, bearer token per session,
origin validation, actions off by default. If that ever stops being true,
this section becomes hypocrisy rather than a feature.

---

## 3. Smaller items, ranked

1. **Baseline comparison** — "what changed since last week". The history
   database already exists; this is mostly presentation, and it answers a
   question a single scan structurally cannot.
2. **Signed evidence export** — a report that can be handed to a bank or the
   police. The README already claims the tool supports a formal report; this
   would make that true.
3. **Router-side inspection** — the only honest answer to the limit stated
   in the README, that a scanner running inside a possibly compromised
   machine can be lied to by anything at kernel level. Watching the traffic
   from outside is the check that cannot be faked from inside.
4. **npm and PyPI install-time compromise.** The axios compromise in March
   2026 and the Mastra package incident show the pattern; recently installed
   packages are the same age heuristic as extensions. Lower priority because
   the noise is high and the tooling in this space is already crowded.
