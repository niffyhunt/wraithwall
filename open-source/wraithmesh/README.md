# WraithMesh

Distributed deception sensor mesh — **Phase 1**.

Nodes collapse honeypot noise locally and uplink **signed equivalence-class observations**. The TIE aggregator corroborates across nodes, scores contributor reputation, and exposes a read API — without raw commands, IPs, or customer identifiers.

## Phase 1 additions

- **Canary sensor** — watch a JSONL beacon inbox (`canary-kit` integration path)
- **Reputation engine** — per-node trust scoring; canary observations weigh 2×
- **Persistent TIE store** — SQLite-backed campaigns + reputation
- **TIE read API** — `/v1/stats`, `/v1/campaigns`, `/v1/nodes/{id}/reputation`
- **Sensor metrics** — `wraithmesh sensor status`

## Install

```bash
cd honeypot-mitre && pip install .
cd ../wraithmesh && pip install .
```

## Cowrie sensor

```bash
export WRAITHMESH_KEY="change-me"
wraithmesh init-manifest --output mesh.json --sensor-class cowrie
wraithmesh sensor run --config mesh.json --once
```

## Canary sensor

External systems append beacon events (package + version only — no token, no IP):

```json
{"package_name": "internal-sdk", "version": "2.4.1", "timestamp": "2026-07-12T00:00:00Z"}
```

```bash
wraithmesh init-manifest --output mesh-canary.json --sensor-class canary --beacon-inbox ./beacons.jsonl
wraithmesh sensor run --config mesh-canary.json --once
```

## TIE aggregator

```bash
wraithmesh aggregator serve --port 8787 --db .wraithmesh/tie.db
```

| Endpoint | Purpose |
|----------|---------|
| `POST /v1/observations` | Ingest signed observation batch |
| `GET /v1/equivalence/{key}` | Corroborated campaign record |
| `GET /v1/campaigns` | List recent campaigns |
| `GET /v1/stats` | Exchange stats |
| `GET /v1/nodes/{id}/reputation` | Contributor trust score |

## DML → mesh (signed deception document)

```bash
pip install ../dml-spec   # or: pip install ".[dml]"
export DML_KEY=... WRAITHMESH_KEY=...
wraithmesh manifest from-dml signed_mesh.yaml cowrie-east-1 --output mesh.json
wraithmesh sensor run --config mesh.json --once
```

## Anti-poisoning trap keys

```bash
wraithmesh manifest gen-trap-keys --output trap-keys.json
wraithmesh aggregator serve --trap-keys trap-keys.json
```

Observations matching a trap key are rejected and the node reputation is penalized.

## Multi-node trust

Register node signing keys for the aggregator:

```json
{
  "0f37f3380e0fb940": "node-a-secret",
  "1f20a905d9e47613": "node-b-secret"
}
```

```bash
wraithmesh aggregator serve --trusted-keys trusted-keys.json
```

## Tests

```bash
pip install -e ../honeypot-mitre -e ".[dev]"
pytest
```

MIT — © 2026 niffy_hunt · [wraithwall-toolkit](https://github.com/niffyhunt/wraithwall-toolkit)