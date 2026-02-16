# Contributing to AreYouSievious

Thanks for wanting to help! Here's how to get started.

## Development Setup

### Prerequisites
- Node.js 22+
- Python 3.12+
- A mail server with ManageSieve (port 4190) and IMAP (port 993) for testing

### Frontend
```bash
cd frontend
npm install
npm run dev    # starts dev server on http://localhost:5173
```

### Backend
```bash
cd backend
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python app.py --port 8091
```

### Docker (full stack)
```bash
docker compose up --build
# App available at http://localhost:8091
```

## Making Changes

1. Fork the repo
2. Create a feature branch from `main` (`feat/my-thing` or `fix/the-bug`)
3. Make your changes
4. Test against a real mail server if touching backend/protocol code
5. Open a PR against `main`

## Code Style

- **Frontend:** Svelte components, no TypeScript (yet)
- **Backend:** Python, type hints appreciated, no frameworks beyond FastAPI
- Keep it simple. This project intentionally has no database and minimal dependencies.

## What We're Looking For

- Bug fixes
- Sieve spec compliance improvements (RFC 5228, 5804)
- UI/UX improvements
- Accessibility fixes
- Documentation

## What We're Not Looking For (right now)

- Adding a database
- User account systems
- Third-party integrations
- Major architecture changes without discussion first

## Reporting Bugs

Open an issue with:
- What you expected
- What happened
- Browser + mail server if relevant

## Questions?

Open an issue. There's no Discord or mailing list (yet).
