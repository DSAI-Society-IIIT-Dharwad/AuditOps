# Hack2Future Frontend

This README is the navigation hub for frontend documentation.

## Quick Links

- Docs index: [docs/README.md](docs/README.md)
- Getting started: [docs/getting-started.md](docs/getting-started.md)
- Pages and features: [docs/pages-and-features.md](docs/pages-and-features.md)
- Troubleshooting: [docs/troubleshooting.md](docs/troubleshooting.md)

## Most Common Commands

Install and run dev server:

```bash
cd frontend
npm install
npm run dev
```

Build production bundle:

```bash
npm run build
```

Preview production build:

```bash
npm run preview
```

## Routes

- `/graph`
- `/ingest`
- `/risks`
- `/snapshots`

## Backend Dependency

Frontend expects backend API at `http://localhost:8000` and uses Vite proxy for `/api/*`.
