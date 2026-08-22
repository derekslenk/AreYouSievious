<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-04-08 | Updated: 2026-08-20 -->

# .github

## Purpose
GitHub configuration: issue/PR templates and CI workflows.

## Key Files
| File | Description |
|------|-------------|
| `pull_request_template.md` | PR description template |

## Subdirectories
| Directory | Purpose |
|-----------|---------|
| `ISSUE_TEMPLATE/` | Bug report and feature request templates. Inbound external reports only — agent work is tracked in beads (see `docs/agents/issue-tracker.md`) |
| `workflows/` | GitHub Actions workflows (see below) |

## Workflows
| Workflow | Trigger | What it gates |
|----------|---------|---------------|
| `ci.yml` | push to `main`, **and every PR whatever its base** (`.8su` — a base filter left stacked PRs ungated, their checks reading green because none ran) | Three jobs: **backend** (ruff check, ruff format --check, pytest), **frontend** (vitest, svelte-check, vite build), **contract** (regenerates wire types and fails if the committed artifacts are stale) |
| `release.yml` | tags matching `v*` | Multi-arch image build, push to GHCR, cosign signature |
| `claude.yml` | `@claude` mention in issues/PR comments/reviews | Claude Code action |
| `claude-code-review.yml` | PR opened/synchronized/reopened | Automated PR review |

## For AI Agents

### Working In This Directory
- The `contract` job is the guard that keeps the SPA and the backend DTOs from drifting. If you change a Pydantic model, run `npm run gen:types` in `frontend/` and commit the regenerated `openapi.json` + `api-types.d.ts`, or CI fails
- `ci.yml` pins `permissions: contents: read`; keep new jobs least-privilege
- Workflow changes cannot be verified locally — say so plainly rather than claiming a workflow edit is tested

<!-- MANUAL: -->
