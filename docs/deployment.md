# Deployment

WraithWall runs as a Gunicorn-served Flask app behind a reverse proxy in production.

## Main application

```bash
pip install -r requirements.txt
# Provide SECRET_KEY, DATABASE_URL, REDIS_URL, and provider keys via .env
gunicorn main:app --bind 0.0.0.0:$PORT --workers 2 --timeout 120
```

**Required env (minimum):** `SECRET_KEY`, `DATABASE_URL`, `REDIS_URL`

**Development:**

```bash
FLASK_ENV=development SECRET_KEY=dev-secret DATABASE_URL=sqlite:///demo_requests.db \
  gunicorn main:app --bind 0.0.0.0:8000 --workers 1 --timeout 120
```

Set `TESTING=1` for pytest to disable background engines and schedulers.

## Frontend builds

Each Vue app builds into `static/`:

| Source | Output |
| ------ | ------ |
| `frontend/` | `static/app/` |
| `frontend-home/` | `static/home_dist/` |
| `frontend-auth/` | `static/auth_dist/` |
| `frontend-landing/` | `static/landing_dist/` |
| `frontend-blog/` | `static/blog_dist/` |

```bash
cd frontend-landing && npm install && npm run build
```

Commit built bundles if deployment serves committed static assets.

## Standalone subprojects

| Project | Deploy independently |
| ------- | -------------------- |
| `breach-monitor/` | Own Procfile/Dockerfile — `gunicorn app:app` |
| `cowrie-analyzer/` | Docker Compose on honeypot VPS — see `cowrie-analyzer/README.md` |
| `ops-dashboard/` | Separate service — see `ops-dashboard/` |

### Cowrie VPS deploy (verified)

```bash
cowrie-analyzer/scripts/deploy-cowrie.sh
```

Fails fast if Cowrie config mount regresses (`/cowrie/cowrie-git/etc/cowrie.cfg`).

## Production assumptions

- HTTPS termination at reverse proxy (`ProxyFix` / `X-Forwarded-*`)
- PostgreSQL for `DATABASE_URL`
- Redis for rate limits, gateway state, engines
- **Worker count caution:** APScheduler jobs and deception engine threads start per Gunicorn worker unless guarded

## Worker duplication

Long-running engines (`start_cowrie_watcher`, campaign correlator, BGP monitor, etc.) may instantiate per worker. See `docs/architecture/scheduler_graph.json` and `docs/architecture/ARCHITECTURE_VALIDATION.md` before scaling workers.

## More detail

- [AGENTS.md](../AGENTS.md) — environment variable reference
- [cowrie-analyzer/DEPLOYMENT_CHECKLIST.md](../cowrie-analyzer/DEPLOYMENT_CHECKLIST.md)
- [docs/architecture/deployment_notes.md](architecture/deployment_notes.md)