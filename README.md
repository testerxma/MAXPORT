# MaxPort

**Answers one question about the machine it runs on: is anyone controlling
this computer right now?** Then shows the evidence, and gives you the means
to cut the connection.

[![tests](https://github.com/YOUR-USERNAME/maxport/actions/workflows/tests.yml/badge.svg)](https://github.com/testerxma/maxport/actions/workflows/tests.yml)
[![licence: MIT](https://img.shields.io/badge/licence-MIT-blue.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)
[![platforms](https://img.shields.io/badge/platforms-Windows%20%7C%20Linux-lightgrey.svg)](#running-it)

Built for the situation where someone took a support call, installed
something, and now cannot tell whether the stranger is gone. Most tools
answer *what is on this machine*. MaxPort answers *is someone on it now* —
and if so, what they reached, and what to revoke first.

---

## What it looks for

- **Remote-control software with a live session** — AnyDesk, TeamViewer,
  ScreenConnect, RustDesk, VNC, Splashtop, plus a generated catalogue of
  over two hundred more
- **Hijacked legitimate tools** — a real remote-access product whose session
  does not route through its vendor's own infrastructure
- **Several remote-access tools at once** — one is ordinary; three is a
  pattern operators create so that removing the obvious one changes nothing
- **Tools configured for unattended access** — the difference between "ran
  once" and "set up to let someone back in silently"
- **Known-exploited versions** of remote-access software
- **Tunnels and covert channels** — ngrok, cloudflared, chisel, reverse SSH,
  encoded PowerShell, DNS tunnelling
- **Browser extensions** whose permissions amount to session theft — an
  add-on that reads cookies on every site can sign in as you with no
  password and no second factor
- **Persistence** — autostart entries, services, cron, authorised SSH keys
- **What recently executed** — the Run box and shell history still hold a
  paste-and-run payload after the process has exited, including commands
  padded with whitespace to hide themselves in the dialog
- **Abuse of signed system binaries** — certutil, mshta, regsvr32 and others
- **Programs using their own DNS server**, going around the resolver the
  machine was configured with
- **Network interference** — ARP and IPv6 neighbour spoofing, hosts file
  redirects, unexpected DNS servers and proxies

## Running it

```bash
pip install psutil PySide6-Essentials

# Linux
sudo -E python3 run.py

# Windows: open PowerShell as Administrator
python run.py
```

Or download the single file from [Releases](../../releases) and run
`python maxport.py`.

Without administrator or root the scan is half-blind: connections show no
owning process and several checks return nothing. MaxPort offers to relaunch
itself with privileges; `--no-elevate` declines.

```bash
python maxport.py doctor       # what this machine lets MaxPort do, and why not
python maxport.py scan         # full scan
python maxport.py scan --json  # structured output for scripts
python maxport.py --watch      # keep monitoring after the scan
python maxport.py --cli        # text report, needs only psutil
```

Exit codes: `0` clear · `1` findings · `2` remote session active ·
`3` incomplete · `4` needs privileges · `5` usage · `6` refused · `7` error.

## Response actions

Every action is reversible and logged. Nothing is ever deleted, because you
may need the evidence later.

- Stop or freeze a process — freezing preserves its memory for analysis, and
  identity is verified first so a recycled PID cannot be killed by mistake
- Block an address at the firewall, both directions, IPv4 and IPv6
- Close a port
- **Isolate the machine** — cuts external traffic while keeping the LAN
  reachable, with a dead-man's switch scheduled *outside* the process, so it
  still reverts if MaxPort crashes or is closed

## After a finding: what to revoke

When a scan finds something, MaxPort inventories what an infostealer running
as you could have reached on *this* machine — browser sessions, SSH keys,
cloud tokens, wallet files, messaging sessions — and orders them by how
quickly the loss becomes permanent.

The order is the point. **Revoke sessions before changing passwords**: a
stolen session cookie is already authenticated, so the attacker stays signed
in straight through a password reset and past multi-factor authentication.
Wallets come first because a transfer cannot be undone.

Nothing reads the contents of a credential store. The file's existence is
the finding; opening it would only put the secrets somewhere new.

## Agent access (MCP)

The **Agent (MCP)** page starts a local server a coding agent such as Claude
Code can drive. Press *Start server*, then paste the generated command:

```bash
claude mcp add --transport http maxport http://127.0.0.1:8787/mcp \
  --header "Authorization: Bearer <token shown in the window>"
```

The agent gets five read-only tools: `maxport_scan`, `maxport_status`,
`maxport_doctor`, `maxport_exposure` and `maxport_history`.

How it is contained:

- **Loopback only** — binds `127.0.0.1`, never `0.0.0.0`
- **Bearer token**, regenerated every time the server starts
- **Origin validated**, as the specification requires for local servers
- **Actions off by default** — blocking and stopping appear only after you
  tick the box in the window
- **Isolation is never exposed to an agent** — cutting the network removes
  the channel it would use to observe the result
- **Everything is logged in the window as it happens**
- The server stops when you close the program

## Keeping signatures current

```bash
python3 tools/sync_signatures.py            # refresh from LOLRMM
python3 tools/sync_signatures.py --dry-run  # preview the change
```

Regenerates `maxport/rmm_catalogue.py` from the public
[LOLRMM](https://github.com/magicsword-io/LOLRMM) catalogue. Hand-written
signatures always win; the catalogue is a wider net cast behind them.

Run it deliberately, never during a scan. A security tool that fetches code
from the internet and rewrites its own detection logic on a possibly
compromised machine has built the problem it exists to find. The output is
source, reviewed in a diff like anything else.

## Limits worth knowing before you trust the result

**MaxPort runs inside the machine it is examining.** It asks the operating
system what is running and what is connected. An implant at kernel level can
answer those questions falsely, and no program in user space can tell. A
clean result means *nothing was found by these checks* — never *this machine
is clean*.

It is effective against the common cases: remote-access software installed
during a scam call, an off-the-shelf RAT, a hijacked management agent, a
paste-and-run payload. It is not an answer to a targeted intrusion.

If you seriously suspect compromise, examine the machine from **outside** —
watch its traffic at the router, or boot it from external media — and treat
this report as one input among several.

Two further limits:

- A MAC address does not cross a router. For an address on the internet you
  can learn the provider, rough location and reputation. That is enough for
  a report and does not identify a person.
- Signature and CVE lists are static and age. Every report states the date
  the vulnerability data was compiled.

## Use it on machines you are responsible for

MaxPort can stop processes, change firewall rules and cut a machine off the
network. Run it on hardware you own or administer with permission. Scanning
or isolating machines belonging to other people may be a criminal offence
regardless of intent.

## Development

```bash
cd src
python3 tests/test_regressions.py     # 92 tests
python3 build_single.py               # regenerate dist/maxport.py
```

The split source under `maxport/` is the source of truth; the single file is
generated from it. See [CONTRIBUTING.md](CONTRIBUTING.md) for the
conventions used when writing a detection, and [ROADMAP.md](ROADMAP.md) for
what is planned — including an Android application, and why iOS is
deliberately excluded.

| Module | Role |
| --- | --- |
| `engine.py` | Runs every check, produces the verdict |
| `collectors.py` | Connections and listening ports, tied to processes |
| `signatures.py` | Tool, port, tunnel and vendor-domain signatures |
| `rmm_catalogue.py` | Generated from LOLRMM — do not edit by hand |
| `extensions.py` | Browser extensions and their permissions |
| `rmmconfig.py` | Remote-access tools set up for unattended entry |
| `triage.py` | What to revoke after a compromise, in order |
| `netcheck.py` | ARP, IPv6 neighbours, DNS, hosts file, interfaces |
| `persistence.py` | Autostart points |
| `exectrace.py` | What recently executed |
| `hardening.py` | Dormant doors and protection settings |
| `vulncheck.py` | Known-exploited versions |
| `lolbins.py` | Signed system binaries used outside their purpose |
| `profiles.py` | Machine profile — desktop or security workstation |
| `intel.py` | Profiling the other party in a connection |
| `respond.py` | Response actions |
| `monitor.py` | Continuous monitoring |
| `store.py` | History and known-good list |
| `mcpserver.py` | MCP server for agent access |
| `cmdline.py` | Terminal and structured output |
| `ui/` | Qt interface |

## Licence

MIT — see [LICENSE](LICENSE).

Not affiliated with the unrelated Android firewall that previously shared
this project's former name.
