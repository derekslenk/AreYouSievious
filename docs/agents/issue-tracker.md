# Issue tracker: Beads (bd)

Issues and PRDs for this repo live in **beads** — a local Dolt database, synced over
`refs/dolt/data` on the git remote. `.beads/issues.jsonl` is a passive export, **not**
the source of truth. Use the `bd` CLI for all operations.

GitHub Issues on `derekslenk/AreYouSievious` is *not* the tracker for agent work.
`.github/ISSUE_TEMPLATE/` exists for inbound external reports; if you action one, open a
bead for it and work the bead.

## Conventions

- **Create**: `bd create --title="..." --description="..." --type=task|bug|feature|epic|chore --priority=2`
  Priority is `0`–`4` or `P0`–`P4` (0 = critical, 2 = medium) — *not* "high"/"medium"/"low".
  Add `--acceptance="..."`, `--design="..."`, `--notes="..."` for structured sections;
  `--validate` fails the create if required sections are missing.
- **Create a child**: `bd create ... --parent=<id>` (inherits parent labels;
  `--no-inherit-labels` opts out)
- **Read**: `bd show <id>` — details plus dependency edges
- **List**: `bd list --status=open`, `bd ready` (unblocked work), `bd blocked`,
  `bd search <query>`
- **Filter by label**: `bd list --label <a> --label <b>` (AND), `--label-any` (OR),
  `--exclude-label`
- **Comment**: `bd comment <id> "..."`
- **Apply / remove labels**: `bd label add <id> <label>` / `bd label remove <id> <label>`
  (issue id first, label last), `bd label list <id>`
- **Claim**: `bd update <id> --claim`; assign with `--assignee=<name>`
- **Close**: `bd close <id> --reason="..."`; close several with `bd close <id1> <id2> ...`
- **Dependencies**: `bd dep add <issue> <depends-on>` — "issue is blocked by depends-on"

Never use `bd edit` — it opens `$EDITOR` and blocks the agent.

Commit messages in this repo reference beads as `bd:areyousievious-<slug>`.

## Sync

Beads sync is **not** automatic. `bd dolt push` / `bd dolt pull` move issue state to and
from the remote. Per this repo's conservative profile, do not push or sync without
explicit instruction.

## When a skill says "publish to the issue tracker"

Run `bd create`.

## When a skill says "fetch the relevant ticket"

Run `bd show <id>`.

## Wayfinding operations

Used by `/wayfinder`. The **map** is an epic; **child** tickets are its children.

- **Map**: `bd create --type=epic --labels=wayfinder:map` holding the
  Notes / Decisions-so-far / Fog body.
- **Child ticket**: `bd create --parent=<map-id> --labels=wayfinder:<type>` where `<type>`
  is `research` / `prototype` / `grilling` / `task`. Claim with `bd update <id> --claim`.
- **Blocking**: `bd dep add <child> <blocker>`. `bd show <id>` reports what blocks it;
  `bd blocked` lists everything currently gated.
- **Frontier query**: `bd ready --parent=<map-id>` — beads already excludes issues with
  open blockers. Add `--no-assignee` to drop claimed tickets; first in priority order wins.
- **Resolve**: `bd comment <id> "<answer>"`, then `bd close <id>`, then append a context
  pointer to the map's Decisions-so-far via `bd update <map-id> --notes`.
