"""Loopback UI uplink proxy (Phase 5) — entrypoint of the optional sb-uplink
service.

A minimal asyncio TCP forwarder: host loopback port → this container:8000 →
the WraithWall app's port 8000 by **IP**. Design constraints, all deliberate:

* **No DNS, ever.** The target must be a literal IPv4 address (the launcher
  reads it from ``docker inspect`` after the app is healthy). A hostname is
  refused at startup — this service must not depend on, or exercise, any
  resolver.
* **Refuses to start blind.** Without ``WRAITHWALL_SANDBOX_APP_ADDR`` set to a
  valid address it exits 3 immediately; compose interpolation failures must
  not become silent half-proxies.
* **Bounded.** Concurrent client connections are capped; each direction is
  piped with a fixed buffer and no unbounded buffering.
* **Unprivileged.** Runs as uid 1000 under the standard sandbox hardening
  (cap_drop ALL, no-new-privileges, read-only rootfs).
"""
from __future__ import annotations

import asyncio
import ipaddress
import os
import sys

LISTEN_PORT = 8000
TARGET_PORT = 8000
MAX_CONNECTIONS = 16
BUF_SIZE = 65536


def _target_addr() -> str:
    raw = (os.environ.get("WRAITHWALL_SANDBOX_APP_ADDR") or "").strip()
    if not raw:
        print("uplink: WRAITHWALL_SANDBOX_APP_ADDR is not set; refusing to "
              "start blind", file=sys.stderr)
        raise SystemExit(3)
    try:
        ipaddress.IPv4Address(raw)
    except ValueError:
        print(f"uplink: target {raw!r} is not a literal IPv4 address; "
              "DNS names are refused by design", file=sys.stderr)
        raise SystemExit(3)
    return raw


async def _pipe(reader: asyncio.StreamReader,
                writer: asyncio.StreamWriter) -> None:
    try:
        while True:
            data = await reader.read(BUF_SIZE)
            if not data:
                break
            writer.write(data)
            await writer.drain()
    except Exception:
        pass
    finally:
        try:
            writer.close()
        except Exception:
            pass


async def handle(client_reader: asyncio.StreamReader,
                 client_writer: asyncio.StreamWriter,
                 target: str, sem: asyncio.Semaphore) -> None:
    peer = client_writer.get_extra_info("peername")
    try:
        async with sem:
            try:
                up_reader, up_writer = await asyncio.open_connection(
                    target, TARGET_PORT)
            except Exception as exc:
                print(f"uplink: cannot reach app at {target}:{TARGET_PORT}: "
                      f"{exc}", file=sys.stderr)
                return
            try:
                await asyncio.gather(
                    _pipe(client_reader, up_writer),
                    _pipe(up_reader, client_writer),
                )
            finally:
                try:
                    up_writer.close()
                except Exception:
                    pass
    finally:
        try:
            client_writer.close()
        except Exception:
            pass


async def main() -> None:
    target = _target_addr()
    sem = asyncio.Semaphore(MAX_CONNECTIONS)

    async def _handler(r, w):
        await handle(r, w, target, sem)

    server = await asyncio.start_server(_handler, "0.0.0.0", LISTEN_PORT)
    print(f"uplink: listening on :{LISTEN_PORT} -> {target}:{TARGET_PORT} "
          f"(max {MAX_CONNECTIONS} conns)", flush=True)
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
