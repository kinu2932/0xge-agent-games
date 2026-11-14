# Deploy — free public HTTPS endpoint (fly.io)

The Agent Games form requires a **public HTTPS endpoint** (the form's own
example is `my-agent.fly.dev/agent`). fly.io's free tier fits: one small
shared-CPU machine, always on (`min_machines_running = 1` so the platform
health check never hits a cold start). No account or money is spent by this
repo itself — the operator runs these steps.

## Steps

```bash
# 1. Install flyctl and log in (creates YOUR fly.io account if needed).
curl -L https://fly.io/install.sh | sh
fly auth login

# 2. From the repo root, launch (uses deploy/fly.toml; do not let it
#    overwrite the config — answer "no" if it asks to tweak settings).
fly launch --no-deploy --copy-config

# 3. Set secrets (never commit these). The HMAC secret comes from the
#    Agent Games dashboard ("Rotate Secret"); the Kurier key + base URL
#    from the Kurier dashboard (linked from the build page).
fly secrets set AGENT_HMAC_SECRET="paste-from-dashboard"
fly secrets set KURIER_API_KEY="paste-from-kurier"
fly secrets set KURIER_BASE_URL="https://<kurier-host>"
fly secrets set PROOF_MODE="off"

# 4. Deploy and check health.
fly deploy
curl https://0xge-agent-games.fly.dev/healthz
# {"status":"ok",...}

# 5. Register the endpoint in Agent Games:
#    https://0xge-agent-games.fly.dev/agent
```

## Notes

- The app listens on `$PORT` (fly sets it automatically); `HOST=0.0.0.0`.
- `auto_stop_machines = "off"` keeps the agent warm — a cold start during a
  round would cost timeouts (−2 each). The free tier includes enough
  always-on hours for one small machine for the rest of the season.
- Logs: `fly logs`. Structured JSON, no secrets.
- If fly.io's free tier is unavailable, any host that gives a public HTTPS
  URL works (Render, Railway, a VPS with Caddy, ...). The only requirement
  is: `POST https://<host>/agent` reachable in <60 s with a valid TLS cert.
- After the season, `fly destroy 0xge-agent-games` removes it.
