---
name: Workflow & process standing tasks
description: How Claude must conduct work on this project — model selection, issue-per-task, individual commits, handoff docs, no stacked PRs, docs sweep.
type: feedback
---

Standing working agreement for this project (added 2026-07-10 by the owner).
Full text lives in `.claude/CLAUDE.md` → "Standing Tasks & Working Agreement";
this memory is the quick-recall summary.

- **Planning model:** Fable 5 (`claude-fable-5`), run **sequentially, not in
  parallel**. Fall back to Opus if Fable 5 is unavailable, but re-check Fable 5
  availability each subsequent planning round and switch back when available.
- **Implementation model:** most appropriate of Sonnet or Haiku. Opus for
  implementation only when absolutely necessary (and state why). Optimise for
  quota/credit efficiency while getting it right first time.
- **One task = one GitHub issue = one commit.** Create the issue first (high
  detail) if none exists; update it thoroughly if it does; reopen it if closed.
  On completion update the issue and commit individually.
- **Handoff doc** (`.claude/HANDOFF.md`) kept current so a session can resume
  after a crash/restart without re-reading brief/code/chat.
- **All Claude data in the repo `.claude/`** for cross-environment sharing.
- **No stacked PRs.** Wait for an explicit ask before creating any PR; if a
  pending PR targets the requested branch, add to it rather than stacking.
  Monitor PR CI autonomously and fix failures.
- **Docs sweep after queued work:** update .md files, GitHub Issues, Wiki,
  Project, Milestones (create if missing), and the OpenAPI/Swagger spec.
- May loop to propose features and use the `dev-team` plugin skills to steer.

**Why:** the owner wants disciplined, resumable, cost-efficient delivery with a
durable audit trail in GitHub and in-repo Claude state.

**How to apply:** treat every substantive request as a tracked task following
the above; see [[keep-claude-data-in-repo]] for the .claude/ storage rule and
[[domaincheckr-mwwhois-project-overview]] for architecture.
