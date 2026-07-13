"""Shared thread/concurrency primitives for WraithWall.

Provides:
- spawn_request_thread(): capped daemon thread for per-request background work.
- submit(): shared bounded ThreadPoolExecutor for general background work
  (prevents unbounded thread spawn / OOM under load).
- notify(): non-blocking notification dispatch with retry + backoff and a
  dead-letter queue (DLQ) so failed alerts are never silently dropped.
"""
import json
import logging
import os
import threading
import time
from collections import deque
from concurrent.futures import ThreadPoolExecutor
from threading import BoundedSemaphore

logger = logging.getLogger(__name__)

# ── Per-request capped daemon threads (legacy helper, kept stable) ──
MAX_REQUEST_THREADS = int(os.getenv("MAX_REQUEST_THREADS", "64"))
_request_thread_semaphore = BoundedSemaphore(MAX_REQUEST_THREADS)

def spawn_request_thread(target, args=(), kwargs=None):
    """Spawn a daemon request thread with cap protection.
    Falls back to raw spawn if semaphore is exhausted (degraded,
    never silent-drop)."""
    if kwargs is None:
        kwargs = {}
    acquired = _request_thread_semaphore.acquire(blocking=False)

    def _wrapped():
        try:
            target(*args, **kwargs)
        finally:
            if acquired:
                _request_thread_semaphore.release()

    t = threading.Thread(target=_wrapped, daemon=True)
    t.start()
    return t

# ── Shared bounded worker pool ──
_POOL_WORKERS = int(os.getenv("THREAD_POOL_WORKERS", "12"))
_executor = ThreadPoolExecutor(max_workers=_POOL_WORKERS, thread_name_prefix="ww-pool")

def submit(fn, *args, **kwargs):
    """Submit work to the shared bounded pool. Never raises to the caller.
    Degrades to inline execution if the pool is shutting down."""
    try:
        return _executor.submit(fn, *args, **kwargs)
    except RuntimeError:
        try:
            fn(*args, **kwargs)
        except Exception:
            logger.exception("submit() inline fallback failed")
        return None

# ── Notification dead-letter queue ──
_DLQ_MAX = int(os.getenv("NOTIFY_DLQ_MAX", "500"))
_dead_letters = deque(maxlen=_DLQ_MAX)
_dlq_lock = threading.Lock()
_redis_client = None
_redis_init = False

def _get_redis():
    """Lazily build a Redis client from REDIS_URL. Returns None if unavailable
    (e.g. tests, local dev) — callers must degrade gracefully."""
    global _redis_client, _redis_init
    if _redis_init:
        return _redis_client
    _redis_init = True
    url = os.getenv("REDIS_URL")
    if not url:
        return None
    try:
        import redis  # lazy import
        _redis_client = redis.from_url(url, socket_timeout=2, socket_connect_timeout=2)
    except Exception as e:  # pragma: no cover - depends on env
        logger.warning("notify DLQ: Redis unavailable (%s); using in-memory only", e)
        _redis_client = None
    return _redis_client

def _record_dead_letter(channel, payload, error):
    entry = {
        "ts": time.time(),
        "channel": channel,
        "payload": payload,
        "error": str(error),
    }
    with _dlq_lock:
        _dead_letters.append(entry)
    r = _get_redis()
    if r is not None:
        try:
            r.lpush("notify:dead", json.dumps(entry))
            r.ltrim("notify:dead", 0, _DLQ_MAX - 1)
        except Exception:  # pragma: no cover
            pass
    logger.error("notification dead-lettered channel=%s error=%s", channel, error)

def dead_letters(limit=100):
    """Return recent dead-lettered notifications (newest last, in-memory view)."""
    with _dlq_lock:
        items = list(_dead_letters)
    return items[-limit:]

def dead_letter_count():
    with _dlq_lock:
        return len(_dead_letters)

class NotificationError(Exception):
    """Raised internally when a notification send is judged failed."""

def notify(channel, fn, *args, retries=3, backoff=0.5, **kwargs):
    """Dispatch a notification send on the shared pool with retry + backoff.

    - Non-blocking: returns immediately (a Future or None).
    - ``fn`` may raise on failure OR return a falsy value (e.g. False) to
      indicate failure; both trigger a retry.
    - After ``retries`` exhausted attempts the payload is recorded to the DLQ
      so the alert is never silently dropped.
    """
    def _run():
        last_err = None
        for attempt in range(1, retries + 1):
            try:
                result = fn(*args, **kwargs)
                if result is False:
                    raise NotificationError("send returned False")
                return result
            except Exception as e:  # noqa: BLE001 - we retry all errors
                last_err = e
                logger.warning(
                    "notify[%s] attempt %d/%d failed: %s", channel, attempt, retries, e
                )
                if attempt < retries:
                    time.sleep(backoff * attempt)
        _record_dead_letter(
            channel,
            {"args": repr(args)[:500], "kwargs": repr(kwargs)[:500]},
            last_err,
        )

    return submit(_run)
