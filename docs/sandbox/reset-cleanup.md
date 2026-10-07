# Reset & cleanup

Three levels of "make it clean again", from cheapest to most destructive.
All are idempotent; the destructive one says so in its own name.

## `reset` — telemetry back to the known baseline

```bash
./sandbox.sh reset
```

Clears pipeline/telemetry state and re-seeds **deterministically**: the
corpus is a fixed-seed function (`seed_version` + ASCII seed string), so a
reset always converges to byte-identical data. Use it to re-run an
experiment, clear accumulated inspect-state, or get dashboards back to the
clean baseline. Images, config, and the state file survive.

Idempotency note: resetting twice in a row is the same as resetting once —
the baseline is computed, not accumulated.

## `destroy --yes` — the real delete

```bash
./sandbox.sh destroy --yes
```

Stops services and **deletes** sandbox-owned state: containers, volumes, and
the state file. Refuses without `--yes`. After it completes:

- nothing sandbox-owned is running (verified against the daemon, not assumed),
- the state file is gone, so `status` reports nothing,
- images are kept — they're rebuildable artifacts, not state; clean them
  separately if you want the disk space.

Destroyed-inventory example (what a clean destroy reports/leaves):

```text
removed containers: sb-app, sb-redis, sb-postgres, (uplink proxy if present)
removed networks:   sb_internal, (sb_uplink if present)
removed volumes:    sb_seed, sb_pgdata, sb_ttylog
kept images:        wraithwall/sb-app:<digest>, redis:<digest>, postgres:<digest>
```

## Manual nuke — when even `destroy` can't run

If the CLI itself is broken (partial upgrade, corrupted state), the daemon is
the source of truth. Project names are namespaced (`ww-sb-*`), so:

```bash
docker ps -a --filter "name=ww-sb-"        # find everything
docker compose -p <project> down -v        # preferred: compose-aware teardown
```

…or, last resort, `docker rm -f` / `docker network rm` / `docker volume rm`
each `ww-sb-*` object by name. Then remove the sandbox state directory
(path is printed by `status` when a state file exists) and start fresh.

The E107 host-firewall rule (see `network.md`) is a **host** prerequisite, not
sandbox state — removing it is a host-firewall change you make deliberately.

## What reset/destroy deliberately do NOT touch

- Your repository checkout and any uncommitted work.
- Other Docker projects on the host (filtering by `ww-sb-*` namespace is how
  the anti-collateral guarantee works — same mechanism `destroy` uses).
- Images unless you explicitly remove them.
- Any file outside the sandbox state directory and Docker objects.

## Secure-deletion honesty

Sandbox data is synthetic by construction (LOCAL-marked, fixed-seed, no real
credentials — enforced by the export gate), so "secure deletion" here means
*gone from the daemon and the state directory*, not *forensically unrecoverable
from disk*. If you need forensic-grade erasure on real hardware, that is an
OS-level concern outside this tool's scope — and if your data needs it, it
should never have entered the sandbox anyway (see `data-policy.md`).
