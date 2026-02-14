# AreYouSievious

Self-hosted Sieve filter management for people who'd rather not write Sieve by hand.

Visual rule builder + raw editor + ManageSieve protocol. No database, no stored credentials. Your rules live on your mail server where they belong.

## Quick Start

```bash
# Frontend
cd frontend && npm install && npm run build

# Backend
cd backend && pip install -r requirements.txt
python app.py --port 8091 --static ../frontend/dist
```

Open `http://localhost:8091`, log in with your IMAP credentials.

## Stack

- **Frontend:** Svelte + Vite
- **Backend:** Python + FastAPI
- **Protocol:** ManageSieve (RFC 5804) + IMAP
- **Database:** None. State lives on your mail server.

## Docs

- [Architecture](docs/ARCHITECTURE.md)

## License

MIT
