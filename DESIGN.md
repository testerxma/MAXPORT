# Design decisions

Why MaxPort behaves the way it does. Everything here describes code that
exists; nothing is a plan.

---

## The question the tool answers

Most scanners answer *what is on this machine*. MaxPort answers *is someone
on it now*, because that is the question people actually arrive with after a
support call went wrong.

That choice runs through everything. The verdict has three states — a
control session is live, something needs review, or nothing was found — and
a live session outranks every other finding regardless of how many there
are. A machine with fourteen warnings and no active session is in less
trouble than a machine with one active session, and the report says so.

## Not knowing is a separate answer from "safe"

Several early bugs were the same mistake in different places: a check that
could not reach a conclusion returned a negative one.

- A missing reverse DNS record was read as "does not match the vendor", so
  every legitimate remote-access session running on ordinary hosting was
  reported as hijacked. Most cloud addresses have no PTR record.
- An unverifiable signature was reported as trusted.
- A check that raised an exception contributed nothing, and nothing looks
  exactly like "found nothing".

So trust has three values, not two. `vendor_match` returns `None`.
`check_trust` returns `unknown` as its own state. And `engine._safely` turns
a failed check into a visible **Incomplete scan** finding — the verdict
refuses to say "clear" when part of the scan did not run.

This is the difference between a report and a false reassurance, and a false
reassurance from a tool people consult when frightened is worse than no tool.

## Severity is a promise

Reserved for what is happening now. A live commercial remote-control session
is critical. A port that could be used is not.

The corollary is that a check firing on ordinary machines costs more than it
gains, because it teaches people to ignore the whole category. Tailscale is
a mesh VPN people install deliberately, not a covert tunnel. Jupyter on 8888
is not a backdoor. Both were reported as critical once; both were moved to
tiers that name them without alarming.

## Machine profiles downgrade, they never hide

A security workstation legitimately runs tools that would be alarming
elsewhere. `profiles.py` lowers the severity of offensive tooling on such a
machine and always says it did, with a count in the report.

Certain categories are exempt entirely — `NEVER_DOWNGRADED` covers remote
control, hijacked tools, vulnerable versions and silent installs. "The owner
runs security tools" explains a copy of `chisel`. It does not explain a live
ScreenConnect session.

The original implementation matched tool names as substrings. The list
contains `nc`, so any finding whose title or path contained those two
letters was demoted — ScreenConnect, VNC, "unencrypted", a path containing
"Sync". Matching is now on whole tokens, and there are tests pinning each
case, because the failure silenced exactly what the tool exists to find.

## Every action is reversible, and nothing is deleted

Blocking, freezing, closing and isolating can all be undone. Nothing is
removed from disk, because the person may need the evidence later — for a
bank, an employer, or the police.

Freezing a process is offered alongside stopping it, since a suspended
process keeps its memory for analysis while a killed one does not.

Actions verify identity before acting. A finding carries the PID *and* the
process start time and name, because the user may act minutes later, by
which point the kernel can have handed that number to something the system
needs.

## Isolation carries a switch that outlives the program

Isolation may be triggered on a machine reached over the network, so it
reverts automatically unless confirmed.

The revert is scheduled **outside the process** — `systemd-run`, `schtasks`
or `at` — because an in-process timer dies with the program. If MaxPort
crashes or is closed while isolated, the firewall rules stay and nothing
lifts them. When no scheduler is available the interface says so plainly
instead of promising a guarantee it cannot keep.

State is written to disk, and startup checks for isolation left behind by a
previous run. The rename from the project's former name kept the old names
as read-only constants for exactly this reason: firewall rules and state
files do not rename themselves, and a machine isolated by an older release
would otherwise have been sealed with no way back.

## Signatures update by running a script, never at scan time

`tools/sync_signatures.py` regenerates the catalogue from LOLRMM. It is run
deliberately and produces source code, reviewed in a diff.

A security tool that fetches code from the internet and rewrites its own
detection logic — on a machine that may already be compromised — has built
the supply-chain problem it exists to find.

Hand-written signatures in `signatures.py` always take precedence. The
generated catalogue is a wider net cast behind them, so a product released
after the curated list was written is still recognised.

## Findings are written for the person, not the analyst

Evidence panels say what a capability *means*. "This can read the cookies
that keep you signed in" is actionable. "Holds the cookies permission" is
not.

The timeline exists for the same reason. A list of findings answers what is
wrong; ordering them by time answers what happened. Three findings within
four minutes on a Tuesday afternoon is often the moment someone recognises
the call they took.

## The revocation list is ordered by permanence, not likelihood

After a finding, MaxPort inventories what an infostealer running as the user
could have reached and orders it by how quickly the loss becomes
irreversible.

Sessions come before passwords. A stolen session cookie is already
authenticated, so the attacker remains signed in through a password reset
and past multi-factor authentication — changing the password first wastes
the window. Wallets come before everything, because a transfer cannot be
undone.

Nothing reads the contents of a credential store. The file's existence is
the finding; opening it would put the secrets somewhere new.

The list only appears when something was actually found. Presenting it after
a clean scan teaches people to ignore it on the day it matters.

## Agent access is opt-in at every layer

MaxPort ships an MCP server so a coding agent can run scans. It is started
from the interface rather than spawned by the client, which is why the
transport is Streamable HTTP rather than stdio — a button cannot control a
process the agent launches.

- Binds `127.0.0.1`, never `0.0.0.0`. A scanner that can stop processes must
  not be reachable from the network it is watching.
- A bearer token, regenerated on every start, compared in constant time.
- `Origin` is validated, as the specification requires for local servers,
  because a page open in the user's browser can otherwise reach a loopback
  server through them.
- Read-only by default. Blocking and stopping appear only after a separate
  switch in the window.
- Isolation is never exposed. Cutting the network removes the channel the
  agent would use to observe the result.
- Every call is logged in the window as it happens, so a sequence of agent
  actions is watched rather than reconstructed afterwards.

The same reasoning governs the terminal interface: without an interactive
terminal, MaxPort refuses to attempt privilege elevation rather than opening
a consent dialog nobody will see and exiting successfully — which would
report a clean machine that was never examined.

## The tool states what it cannot do

MaxPort runs inside the machine it examines and asks the operating system
what is running. A kernel-level implant can answer falsely and no user-space
program can tell.

This is in the README, in the security policy, and in the report itself.
Every scan carries the compilation date of the vulnerability data, and a
clean result is described as "no match in this list" rather than as safety.

A tool that overstates its reach in this domain does more damage than one
that admits its limits, because the person stops looking.

## Both platforms are first-class

Windows and Linux are supported and tested in CI on both. Where a capability
exists on only one, `maxport.py doctor` reports which checks can run on this
machine and why the others cannot — so the absence of a finding can be told
apart from the absence of a check.

## Comments record decisions

The code says what it does. A comment earns its place by recording why —
a constraint, a trap, or a bug that a plausible-looking change would
reintroduce. The regression suite serves the same purpose in executable
form: every test in it failed against an earlier version.
