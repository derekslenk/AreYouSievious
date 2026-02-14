# AreYouSievious — Architecture

Self-hosted Sieve filter management web UI. Clean Email replacement you own.

## Overview

```
┌─────────────────────────────────┐
│  Browser (Svelte SPA)           │
│  - Visual Rule Builder          │
│  - Script Manager               │
│  - Raw Sieve Editor (Monaco)    │
│  - IMAP Folder Picker           │
│  - Rule Test Runner             │
└──────────┬──────────────────────┘
           │ REST API (JSON)
┌──────────▼──────────────────────┐
│  Python Backend (FastAPI)       │
│  - Session-based IMAP auth      │
│  - Sieve <-> JSON transform     │
│  - ManageSieve client            │
│  - IMAP folder listing           │
│  - Rule test engine              │
└──────────┬──────────────────────┘
           │
    ┌──────┴──────┐
    ▼             ▼
ManageSieve    IMAP
 (4190)        (993)
```

## Stack

| Layer | Tech | Why |
|-------|------|-----|
| Frontend | Svelte + Vite | Component structure for drag-and-drop rule builder, small bundle |
| Editor | Monaco Editor | Sieve syntax highlighting, familiar to devs |
| Backend | Python + FastAPI | sievelib already works, async-friendly |
| ManageSieve | sievelib | Proven — we already use it for the grak script |
| IMAP | imaplib (stdlib) | Folder listing only, no heavy deps |
| Auth | Session cookies + IMAP creds | No stored passwords, authenticate each session |

## Auth Flow

1. User enters: mail server host, username, password
2. Backend validates against IMAP (port 993)
3. On success, creates a session token (httponly cookie)
4. Session holds encrypted creds in memory (never persisted to disk)
5. Session expires after configurable idle timeout (default 30 min)
6. All subsequent API calls use the session to connect to ManageSieve/IMAP on-demand

Why no stored creds:
- Safer for self-hosted single-user tool
- ManageSieve and IMAP accept the same credentials
- One login gets you everything

## Data Model

### Rule (JSON representation)

```json
{
  "id": "r1",
  "enabled": true,
  "name": "GitHub notifications",
  "conditions": {
    "match": "anyof",
    "tests": [
      {"header": "from", "type": "contains", "value": "notifications@github.com"}
    ]
  },
  "actions": [
    {"type": "fileinto", "folder": "Notifications/GitHub"},
    {"type": "stop"}
  ],
  "comment": "Route all GitHub emails"
}
```

### Supported condition types (v1)

| Type | Sieve equivalent |
|------|-----------------|
| header contains | `header :contains` |
| header is | `header :is` |
| header matches | `header :matches` (glob) |
| address is | `address :is` |
| address domain | `address :domain :is` |
| size over/under | `size :over` / `size :under` |
| exists | `exists` |
| allof / anyof | `allof` / `anyof` (nesting) |
| not | `not` (invert any test) |

### Supported actions (v1)

| Action | Sieve equivalent |
|--------|-----------------|
| Move to folder | `fileinto` |
| Copy to folder | `fileinto :copy` |
| Delete | `discard` |
| Redirect | `redirect` |
| Keep | `keep` |
| Flag | `addflag` |
| Mark read | `addflag "\\Seen"` |
| Stop | `stop` |
| Reject | `reject` |
| Vacation | `vacation` (stretch) |

## Sieve <-> JSON Transform

The critical piece. Must be bidirectional and lossless for supported constructs.

### Strategy

1. **Parse**: Use `sievelib.parser` to parse Sieve -> AST
2. **Transform**: Walk AST, convert recognized `if/elsif/else` blocks to JSON rules
3. **Preserve**: Any construct we don't recognize gets stored as a `raw` block (opaque Sieve text)
4. **Generate**: JSON rules -> Sieve text via template rendering
5. **Round-trip**: Raw blocks are emitted in their original position

This means:
- Simple rules are fully editable in the UI
- Complex/exotic Sieve stays as raw text (editable in Monaco)
- We never clobber rules we don't understand

### Required Sieve extensions

Declare based on what actions are used:
- `fileinto` (almost always needed)
- `copy` (for fileinto :copy)
- `imap4flags` (for addflag)
- `reject` / `ereject`
- `vacation`
- `regex` (if user uses regex matching)

## API Endpoints

### Auth
- `POST /api/auth/login` — {host, port, username, password, managesieve_port?}
- `POST /api/auth/logout` — clear session
- `GET /api/auth/status` — check if session is valid

### Scripts
- `GET /api/scripts` — list all scripts {name, active}
- `GET /api/scripts/:name` — get script (returns JSON rules + raw blocks)
- `PUT /api/scripts/:name` — save script (accepts JSON rules, generates Sieve)
- `POST /api/scripts/:name/activate` — set as active script
- `DELETE /api/scripts/:name` — delete script
- `GET /api/scripts/:name/raw` — get raw Sieve text
- `PUT /api/scripts/:name/raw` — save raw Sieve text directly

### Folders
- `GET /api/folders` — IMAP folder tree

### Test
- `POST /api/test` — test rules against a sample email
  - Input: {rules: [...], email: "raw RFC822 text"}
  - Output: {matched_rules: [...], actions: [...]}

## Frontend Pages

### 1. Login
- Server host, username, password
- Optional: ManageSieve port override (default 4190), IMAP port override (default 993)
- Remember server host in localStorage (not creds)

### 2. Dashboard / Script Manager
- List of scripts on server
- Active script highlighted
- Create / rename / delete / activate buttons
- Click script -> opens Rule Editor

### 3. Rule Editor (main view)
- Left panel: list of rules (draggable to reorder)
- Right panel: selected rule detail
  - Name, enabled toggle
  - Condition builder (nested, drag-and-drop)
  - Action builder (ordered list)
- Bottom: raw Sieve preview (live-updating as you edit)
- Save button -> generates Sieve, pushes to server

### 4. Raw Editor
- Full Monaco editor with Sieve syntax
- For power users who want to edit Sieve directly
- Parse button to validate syntax
- Save pushes raw text to server

### 5. Folder Picker (modal/sidebar)
- IMAP folder tree
- Click to select for fileinto actions
- Create new folder option

## File Structure

```
areyousievious/
├── frontend/
│   ├── src/
│   │   ├── App.svelte
│   │   ├── lib/
│   │   │   ├── api.js          # API client
│   │   │   ├── sieve.js        # Client-side Sieve preview
│   │   │   └── stores.js       # Svelte stores
│   │   ├── routes/
│   │   │   ├── Login.svelte
│   │   │   ├── Dashboard.svelte
│   │   │   ├── RuleEditor.svelte
│   │   │   └── RawEditor.svelte
│   │   └── components/
│   │       ├── RuleList.svelte
│   │       ├── ConditionBuilder.svelte
│   │       ├── ActionBuilder.svelte
│   │       ├── FolderPicker.svelte
│   │       └── SievePreview.svelte
│   ├── package.json
│   └── vite.config.js
├── backend/
│   ├── app.py                  # FastAPI app
│   ├── auth.py                 # Session management
│   ├── sieve_transform.py      # Sieve <-> JSON
│   ├── managesieve_client.py   # ManageSieve wrapper
│   ├── imap_client.py          # IMAP folder ops
│   ├── test_engine.py          # Rule test runner
│   └── requirements.txt
├── docs/
│   └── ARCHITECTURE.md
└── README.md
```

## Deployment (bare metal)

```bash
# Build frontend
cd frontend && npm run build

# Backend serves built frontend + API
cd backend && python app.py --port 8091 --static ../frontend/dist
```

Single process. FastAPI serves the Svelte build as static files and handles API routes.

Optionally: launchd plist for auto-start on metastasis.

## Design Principles

1. **No database** — all state lives on the mail server (ManageSieve scripts + IMAP folders)
2. **No stored credentials** — session-only auth, encrypted in memory
3. **Lossless round-trip** — never destroy Sieve constructs we don't understand
4. **Progressive disclosure** — visual builder for simple rules, raw editor for complex ones
5. **Single account focus** — but architecture doesn't prevent multi-account later
6. **Dark mode default** — consistent with Slab aesthetic

## Future (v2+)

- AI rule suggestions (analyze inbox patterns, suggest filters)
- Bulk email analysis ("show me all senders with >10 emails")
- One-click unsubscribe integration
- Import/export rules as JSON
- Multi-account support
- Regex condition support
- Vacation responder UI
