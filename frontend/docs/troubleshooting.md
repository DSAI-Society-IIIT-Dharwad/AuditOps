# Troubleshooting

## Backend Connectivity

Check backend health:

```bash
curl http://localhost:8000/health
```

If unreachable:

- ensure API server is running
- verify port `8000` is free
- inspect backend terminal logs

## Empty Snapshot List

If `/snapshots` has no data:

- run at least one analysis from `/graph` or `/ingest`
- then refresh snapshots

## Frontend Build Issues

Reinstall packages and rebuild:

```bash
cd frontend
npm install
npm run build
```

## API Proxy Reminder

Vite dev server proxies `/api/*` requests to `http://localhost:8000`.
No frontend base URL code change is needed for local development.
