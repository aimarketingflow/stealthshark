---
description: Start the Agent Hub dashboard server and open in browser
---

# Dashboard Workflow

Launch the Agent Hub dashboard with live updates.

## Steps

1. Check if hub server is already running:
```bash
lsof -i :9090 | grep LISTEN
```

2. If not running, start the hub server in background:
// turbo
```bash
python3 ~/.agent-hub/server.py &
```

3. Open in browser:
// turbo
```bash
sleep 1 && open http://localhost:9090
```

## Notes

- The hub server watches `.agent/data/*.json` in all registered projects.
- Dashboard auto-updates via SSE when any data file changes.
- Agent workflows (delegate, review) update the data files → dashboard reflects instantly.
- Multiple projects appear in the sidebar with their own views.
- To stop: `kill $(lsof -t -i :9090)`
