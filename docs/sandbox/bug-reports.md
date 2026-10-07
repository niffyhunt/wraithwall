# Reproducible bug reports

Sandbox bugs should be reproducible by construction: the environment is
deterministic, the telemetry is fixed-seed, and the tooling already collects
the evidence. This page explains what to capture and why it is safe to
attach.

## What to collect, in order

### 1. The exact commands and their full output

Not a paraphrase. The E-code lines are designed to be complete: cause, fix,
and code. Copy them whole.

### 2. The state + gate record

```bash
./sandbox.sh status --json
```

Includes the sandbox state file contents: profile, tier, ports, image
digests, and the gate results recorded at `up` time. This tells maintainers
exactly what was verified on your host before the failure.

### 3. The platform report

```bash
./sandbox.sh platform --json
```

The tri-state isolation-control report for your host. Most "works on my
machine" bugs are one control flipping ACTIVE/UNAVAILABLE/UNKNOWN — this
names it.

### 4. The service logs that matter

```bash
./sandbox.sh logs sb-app --tail 200
./sandbox.sh logs sb-postgres --tail 100
```

…or whichever service the failure names. Full output, not excerpts.

### 5. Only if asked: an export bundle

```bash
./sandbox.sh export --out /tmp/ww-bug-bundle
```

The bundle contains the synthetic corpus, tty logs, and pipeline session
records — the deterministic inputs a maintainer can replay locally.

## Redaction guarantees (why this is safe)

- **Everything in the sandbox is synthetic by construction.** The corpus is
  repo-shipped, fixed-seed, LOCAL-marked; there are no real credentials in
  the data path.
- **The export gate enforces it**: before `export` keeps a bundle it scans
  for secret-shaped strings; anything found ⇒ bundle deleted, exit 2,
  code E307. If you ever see E307, do not share anything — report the
  generator bug.
- **The status/platform reports carry no secret values** — they are
  digests, booleans, and tri-state summaries by design.

What is *never* safe to attach: your host's `.env`, Docker daemon config,
other projects' logs, or anything from outside the sandbox. Nobody needs it
and nobody should get it.

## The determinism promise (for "can't reproduce" cases)

Because the corpus is a pure function of `seed_version`, a maintainer
running the same release gets **byte-identical telemetry**. If your bug
involves pipeline behavior, say which release/commit you ran
(`status --json` includes it) — the maintainer can replay the exact inputs.
Any nondeterminism you can demonstrate in the corpus itself is a **severe**
bug; report it with that label.

## Where to file

Repository issues, with the `sandbox` label. Security-sensitive findings
(things that look like escape, refusal bypass, or secret leakage) do **not**
go in public issues — see root `SECURITY.md` for the disclosure path and
scope.
