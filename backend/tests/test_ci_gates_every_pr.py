"""CI runs on every pull request, whatever its base (areyousievious-8su).

`ci.yml` was triggered by `pull_request: branches: [main]`. A STACKED pull
request — one whose base is another feature branch, which is how this repo
lands dependent work — matched none of that, so it ran none of the gating
jobs. Observed on PR #54: `gh pr checks` listed exactly one check
(claude-review, the only workflow with no branch filter) against eight on the
PR beside it.

`main` was never actually exposed. Merging a stacked PR pushes to the parent
PR's head branch, which fires `synchronize` on the parent — based on main —
and everything runs before any of it lands. Branch protection held.

What was lost is worse than it sounds: the PR page LOOKED gated. Green
because nothing ran is indistinguishable from green because everything
passed, which is the exact failure `.51`'s review guard was written to
remove, one workflow over. `.51` cannot help here — it only runs inside the
review job, which was the one job that did fire.

Removing the filter is not double work. A `pull_request` run tests the MERGE
of head into base, so the stacked PR tests (child + parent branch) and the
parent afterwards tests (parent + child + main). Different trees, different
answers — the second was never a substitute for the first.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

WORKFLOWS = Path(__file__).resolve().parent.parent.parent / ".github" / "workflows"


def _triggers(workflow: str) -> dict:
    """The `on:` block of a workflow.

    Read under the key `True`, not `"on"`. YAML 1.1 types the bare word `on`
    as a BOOLEAN, so `data["on"]` raises KeyError on a file that plainly
    contains `on:` — a trap worth naming once here rather than rediscovering.
    """
    data = yaml.safe_load((WORKFLOWS / workflow).read_text())
    return data.get("on", data.get(True))


def test_ci_runs_on_a_pull_request_whatever_its_base():
    """ARCHITECTURAL LOCK: no `branches` filter on the pull_request trigger.

    A filter here does not fail loudly — it makes the checks DISAPPEAR, and a
    PR with no checks reads as a PR with no problems. If you are adding one
    back, the stacked PRs this repo uses will silently stop being tested.
    """
    pull_request = _triggers("ci.yml")["pull_request"]
    assert "branches" not in (pull_request or {}), (
        "ci.yml filters pull_request by base branch, so a stacked PR runs no "
        "gating jobs at all and its checks read as green because they never ran."
    )


def test_ci_still_runs_on_pushes_to_main_only():
    """The other half. Dropping the PR filter must not turn into running CI
    on every push to every branch — that IS duplicate work, because the pull
    request for that branch already covers it."""
    assert _triggers("ci.yml")["push"]["branches"] == ["main"]


@pytest.mark.parametrize(
    "job,name",
    [
        ("backend", "backend (pytest + ruff)"),
        ("frontend", "frontend (vitest + vite build)"),
        ("contract", "contract (generated wire types are current)"),
    ],
)
def test_the_gating_jobs_keep_the_names_branch_protection_requires(job, name):
    """Branch protection matches required checks by NAME, and that config
    lives on GitHub rather than in this repo — so a rename here silently
    un-gates main, with nothing in the diff to show for it. Renaming a job
    means updating the protection rule in the same breath."""
    jobs = yaml.safe_load((WORKFLOWS / "ci.yml").read_text())["jobs"]
    assert jobs[job]["name"] == name
