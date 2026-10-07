"""CLI: sensor run, manifest init, aggregator ingest/serve (Phase 1 TIE)."""

from __future__ import annotations

import argparse
import json
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from .aggregator import InMemoryAggregatorStore, SqliteAggregatorStore, ingest_batch
from .egress import DEFAULT_ALLOWLIST
from .dml_bridge import write_manifest_from_dml
from .manifest import MeshManifest, load_manifest, write_manifest
from .metrics import SensorMetrics
from .poisoning import generate_trap_keys, load_trap_keys, save_trap_keys
from .sensor import create_sensor
from .signing import load_key, node_id_from_key
from .trust import load_trusted_keys
from .uplink import post_observations


def _resolve_aggregator_key(args: argparse.Namespace) -> str | bytes | dict[str, str]:
    if getattr(args, "trusted_keys", ""):
        return load_trusted_keys(args.trusted_keys)
    return load_key(args.key_env)


def _create_aggregator_store(args: argparse.Namespace) -> Any:
    if getattr(args, "db", ""):
        return SqliteAggregatorStore(args.db)
    return InMemoryAggregatorStore()


def _resolve_trap_keys(args: argparse.Namespace) -> set[str]:
    path = getattr(args, "trap_keys", "") or ""
    if not path:
        return set()
    return load_trap_keys(path)


def _cmd_init_manifest(args: argparse.Namespace) -> int:
    key = load_key(args.key_env)
    node_id = node_id_from_key(key)
    manifest = MeshManifest(
        node_id=node_id,
        sensor_class=args.sensor_class,
        aggregator_url=args.aggregator_url,
        signing_key_env=args.key_env,
        thresholds={
            "uplink_cooldown_seconds": args.cooldown,
            "min_local_count": args.min_count,
            "novel_only": args.novel_only,
        },
        egress_allowlist=DEFAULT_ALLOWLIST,
        cowrie_log_path=args.cowrie_log,
        beacon_inbox_path=args.beacon_inbox,
        state_dir=args.state_dir,
    )
    write_manifest(args.output, manifest, key)
    print(f"wrote {args.output} (node_id={node_id}, sensor={args.sensor_class})")
    return 0


def _emit_obs(obs: Any, *, pretty: bool) -> None:
    payload = obs.to_dict() if hasattr(obs, "to_dict") else obs
    indent = 2 if pretty else None
    sys.stdout.write(json.dumps(payload, indent=indent) + "\n")


def _metrics_path(manifest: MeshManifest) -> Path:
    return Path(manifest.state_dir) / "metrics.json"


def _cmd_sensor_run(args: argparse.Namespace) -> int:
    manifest = load_manifest(args.config)
    sensor = create_sensor(manifest)
    metrics_path = _metrics_path(manifest)
    metrics = SensorMetrics(node_id=manifest.node_id, sensor_class=manifest.sensor_class)
    if metrics_path.exists():
        try:
            metrics = SensorMetrics.load(metrics_path)
        except Exception:
            pass

    source_path = args.log or manifest.cowrie_log_path or manifest.beacon_inbox_path

    def handle(obs: Any) -> None:
        metrics.record_uplink()
        metrics.save(metrics_path)
        payload = obs.to_dict(allowlist=manifest.egress_allowlist)
        _emit_obs(payload, pretty=args.pretty)
        if manifest.aggregator_url:
            post_observations(manifest.aggregator_url, [payload])

    if args.once:
        observations = sensor.run_once(source_path or None)
        for obs in observations:
            handle(obs)
        metrics.save(metrics_path)
        return 0

    sensor.run_forever(source_path or None, on_observation=handle)
    return 0


def _cmd_sensor_status(args: argparse.Namespace) -> int:
    manifest = load_manifest(args.config, verify=False)
    metrics_path = _metrics_path(manifest)
    if not metrics_path.exists():
        print(json.dumps({"status": "no metrics yet", "node_id": manifest.node_id}))
        return 0
    print(metrics_path.read_text(encoding="utf-8"))
    return 0


def _cmd_aggregator_ingest(args: argparse.Namespace) -> int:
    key = _resolve_aggregator_key(args)
    store = _create_aggregator_store(args)
    batch: list[dict[str, Any]] = []
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        batch.append(json.loads(line))
    records = ingest_batch(batch, key=key, store=store, trap_keys=_resolve_trap_keys(args))
    for record in records:
        sys.stdout.write(json.dumps(record.to_dict()) + "\n")
    if hasattr(store, "close"):
        store.close()
    return 0


class _AggregatorHandler(BaseHTTPRequestHandler):
    store: Any
    key: str | bytes | dict[str, str]
    trap_keys: set[str]

    def log_message(self, format: str, *args: Any) -> None:
        return

    def _send_json(self, payload: dict[str, Any], status: int = 200) -> None:
        data = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_POST(self) -> None:
        if self.path != "/v1/observations":
            self.send_error(404)
            return
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length)
        try:
            payload = json.loads(body.decode("utf-8"))
            observations = payload.get("observations") or []
            records = ingest_batch(
                observations, key=self.key, store=self.store, trap_keys=self.trap_keys
            )
            out = {"accepted": len(observations), "records": [r.to_dict() for r in records]}
            self._send_json(out)
        except Exception as exc:
            self._send_json({"error": str(exc)}, status=400)

    def do_GET(self) -> None:
        path = urlparse(self.path).path

        if path == "/v1/stats":
            self._send_json(self.store.stats())
            return

        if path == "/v1/campaigns":
            records = self.store.all_records()
            self._send_json({
                "campaigns": [r.to_dict() for r in records[:50]],
                "count": len(records),
            })
            return

        if path.startswith("/v1/nodes/") and path.endswith("/reputation"):
            node_id = path.removeprefix("/v1/nodes/").removesuffix("/reputation").strip("/")
            rep = self.store.reputation.get(node_id)
            self._send_json(rep.to_dict())
            return

        if path.startswith("/v1/equivalence/"):
            eq = path.split("/v1/equivalence/", 1)[-1].strip("/")
            record = self.store.get(eq)
            if record is None:
                self.send_error(404)
                return
            self._send_json(record.to_dict())
            return

        self.send_error(404)


def _cmd_manifest_from_dml(args: argparse.Namespace) -> int:
    manifest = write_manifest_from_dml(
        args.dml,
        args.sensor_id,
        args.output,
        dml_key_env=args.dml_key_env,
        mesh_key_env=args.mesh_key_env,
        verify_dml=not args.skip_verify,
    )
    print(f"wrote {args.output} from DML sensor {args.sensor_id} (node_id={manifest.node_id})")
    return 0


def _cmd_gen_trap_keys(args: argparse.Namespace) -> int:
    keys = generate_trap_keys(args.count)
    save_trap_keys(args.output, keys)
    print(f"wrote {len(keys)} trap keys to {args.output}")
    return 0


def _cmd_aggregator_serve(args: argparse.Namespace) -> int:
    key = _resolve_aggregator_key(args)
    store = _create_aggregator_store(args)
    trap_keys = _resolve_trap_keys(args)

    class Handler(_AggregatorHandler):
        pass

    Handler.store = store
    Handler.key = key
    Handler.trap_keys = trap_keys
    server = ThreadingHTTPServer((args.host, args.port), Handler)
    print(f"TIE aggregator listening on http://{args.host}:{args.port}")
    print("  GET  /v1/stats")
    print("  GET  /v1/campaigns")
    print("  GET  /v1/equivalence/{key}")
    print("  GET  /v1/nodes/{id}/reputation")
    print("  POST /v1/observations")
    server.serve_forever()
    return 0


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="wraithmesh", description="WraithMesh sensor mesh CLI")
    sub = parser.add_subparsers(dest="command", required=True)

    init_p = sub.add_parser("init-manifest", help="Create a signed sensor manifest")
    init_p.add_argument("--output", default="mesh.json")
    init_p.add_argument("--sensor-class", default="cowrie", choices=["cowrie", "canary"])
    init_p.add_argument("--aggregator-url", default="")
    init_p.add_argument("--cowrie-log", default="/var/log/cowrie/cowrie.json")
    init_p.add_argument("--beacon-inbox", default="", help="JSONL inbox for canary sensor")
    init_p.add_argument("--state-dir", default=".wraithmesh")
    init_p.add_argument("--key-env", default="WRAITHMESH_KEY")
    init_p.add_argument("--cooldown", type=int, default=86400)
    init_p.add_argument("--min-count", type=int, default=1)
    init_p.add_argument("--novel-only", action="store_true")
    init_p.set_defaults(func=_cmd_init_manifest)

    manifest_p = sub.add_parser("manifest", help="Manifest utilities")
    manifest_sub = manifest_p.add_subparsers(dest="manifest_cmd", required=True)

    from_dml_p = manifest_sub.add_parser("from-dml", help="Export signed mesh.json from DML v0.3.0")
    from_dml_p.add_argument("dml", help="signed DML document path")
    from_dml_p.add_argument("sensor_id", help="sensor id inside the DML document")
    from_dml_p.add_argument("--output", default="mesh.json")
    from_dml_p.add_argument("--dml-key-env", default="DML_KEY")
    from_dml_p.add_argument("--mesh-key-env", default="WRAITHMESH_KEY")
    from_dml_p.add_argument("--skip-verify", action="store_true")
    from_dml_p.set_defaults(func=_cmd_manifest_from_dml)

    trap_p = manifest_sub.add_parser("gen-trap-keys", help="Generate TIE poisoning trap keys")
    trap_p.add_argument("--output", default="trap-keys.json")
    trap_p.add_argument("--count", type=int, default=3)
    trap_p.set_defaults(func=_cmd_gen_trap_keys)

    sensor_p = sub.add_parser("sensor", help="Run a sensor")
    sensor_sub = sensor_p.add_subparsers(dest="sensor_cmd", required=True)

    run_p = sensor_sub.add_parser("run", help="Run sensor adapter from manifest")
    run_p.add_argument("--config", required=True)
    run_p.add_argument("--log", default="", help="Override cowrie log or canary inbox path")
    run_p.add_argument("--once", action="store_true")
    run_p.add_argument("--pretty", action="store_true")
    run_p.set_defaults(func=_cmd_sensor_run)

    status_p = sensor_sub.add_parser("status", help="Show local sensor metrics")
    status_p.add_argument("--config", required=True)
    status_p.set_defaults(func=_cmd_sensor_status)

    agg_p = sub.add_parser("aggregator", help="Aggregator / TIE utilities")
    agg_sub = agg_p.add_subparsers(dest="agg_cmd", required=True)

    ingest_p = agg_sub.add_parser("ingest", help="Ingest JSONL observations from stdin")
    ingest_p.add_argument("--key-env", default="WRAITHMESH_KEY")
    ingest_p.add_argument("--trusted-keys", default="")
    ingest_p.add_argument("--db", default="", help="SQLite path for persistent TIE store")
    ingest_p.add_argument("--trap-keys", default="", help="JSON trap keys for feed poisoning detection")
    ingest_p.set_defaults(func=_cmd_aggregator_ingest)

    serve_p = agg_sub.add_parser("serve", help="Start TIE aggregator HTTP server")
    serve_p.add_argument("--host", default="127.0.0.1")
    serve_p.add_argument("--port", type=int, default=8787)
    serve_p.add_argument("--key-env", default="WRAITHMESH_KEY")
    serve_p.add_argument("--trusted-keys", default="")
    serve_p.add_argument("--trap-keys", default="", help="JSON trap keys for feed poisoning detection")
    serve_p.add_argument("--db", default=".wraithmesh/tie.db", help="SQLite path (default persistent)")
    serve_p.set_defaults(func=_cmd_aggregator_serve)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())