# Contributing

Thank you for looking. This is a small project with strong opinions about a
few things; the rest is open.

## Getting set up

```bash
git clone https://github.com/YOUR-USERNAME/maxport
cd maxport/src
pip install psutil PySide6-Essentials
python3 tests/test_regressions.py        # or: python -m pytest tests/ -q
```

The split source under `maxport/` is the source of truth. The portable
single file is generated:

```bash
cd src && python3 build_single.py        # must run from inside src/
```

`build_single.py` will refuse to build on a name collision between modules
and tells you which one. If you add a module, add it to `ORDER` and to the
alias line in the header, or the merged build will fail at import.

## Before you open a pull request

1. `python3 tests/test_regressions.py` passes.
2. `python3 build_single.py` succeeds and `dist/maxport.py` runs.
3. New behaviour has a test. If you fixed a bug, the test should fail
   against the old code — that is what makes it a regression test rather
   than a description.

## Writing a detection

This is where the project has opinions.

**Say what it means, not what it is.** "This can read the cookies that keep
you signed in" is something the owner can act on. "Extension holds the
cookies permission" is not.

**Not knowing is its own answer.** Where a check cannot reach a conclusion,
return unknown. Do not convert an absent signature, a missing reverse DNS
record or an unreadable file into an accusation. Several bugs in this
project's history were exactly that.

**A failed check is a finding.** Silence and "found nothing" look identical
from outside, and the difference matters enormously when someone is
deciding whether they are safe. Wrap sub-checks so a failure surfaces.

**Match whole tokens, not substrings.** A two-letter tool name matched as a
substring once downgraded live remote-control sessions because a file path
contained those letters. There are tests pinning this; please leave them.

**Assume the finding will be read by someone frightened.** Severity is a
promise. Reserve critical for things that are happening now.

**Weigh the false positive.** A check that fires on ordinary machines
teaches people to ignore the whole category, which costs more than the
detection gains. Tailscale is not a covert tunnel; Jupyter on 8888 is not a
backdoor.

## Comments

Explain *why*, not *what*. The code says what it does. A comment earns its
place by recording a decision, a constraint or a trap — something a reader
would otherwise have to rediscover.

## Adding a remote-access tool

Two options:

- **Curated** — add it to `REMOTE_TOOLS` and `VENDOR_DOMAINS` in
  `signatures.py`. Do this when you know the vendor domains, since that is
  what separates a real session from a hijacked one.
- **Catalogue** — if it is in [LOLRMM](https://github.com/magicsword-io/LOLRMM),
  run `python3 tools/sync_signatures.py`. Do not edit
  `maxport/rmm_catalogue.py` by hand; it is generated.

Hand-written signatures always take precedence over the catalogue.

## Platforms

Windows and Linux are both supported and neither is an afterthought. If you
can only test one, say so in the pull request — that is useful information,
not a failing. `python3 maxport.py doctor` reports what a given machine can
and cannot do.

## Things that will be declined

- Fetching and executing code at scan time. Signature updates happen by
  running a script and reviewing a diff. A security tool that rewrites its
  own detection logic from the internet, on a machine that may already be
  compromised, has built the problem it exists to find.
- Exposing isolation to an automated caller. Cutting the network removes the
  channel the caller would use to observe the result.
- Anything that deletes rather than blocks, disables or quarantines.
  Evidence may be needed later.
- Silent `except: pass` around a check.

## Reporting a security problem in MaxPort itself

See [SECURITY.md](SECURITY.md). Please do not open a public issue.
