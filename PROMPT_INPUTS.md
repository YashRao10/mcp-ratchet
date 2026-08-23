# Prompt Inputs

Verbatim log of the prompts that shaped this project's direction, per
standing convention (see finance-projects/agent's own log for precedent).

---

**2026-08-21** — "That's legit go ahead and start going let's make this our
strongest project yet holding most weight in the new AI area"

Preceded by a multi-turn research pass (not verbatim-logged, summarized
here): rejected extending `ai-compliance-crosswalk` into financial
AI-model-risk auditing ("nah I dont want to dive deeper into the crosswalk
leave that as is"); asked what's rising in AI coding-assistant tooling
("what other things should we look at for working figure out what is
rising up these days with more AI cursor and other things"); landed on the
MCP-scanner space specifically ("Yeah the MCP scanner is a good idea that
you had at the end 17,000 new MCPs but no real checkers for them"); then
explicitly widened scope beyond a lightweight linter ("But it doesn't have
to be just lightweight could make it a stronger scanner").

---

**2026-08-23** — "build on the mcppproject", then chose from a menu of
README-flagged gaps: "Python lockfile CVE resolution" (over proxy
blocking/policy mode and trust-tier scoring). Closed the Python side of
the dependency-CVE check's lockfile-resolution gap: `poetry.lock` and
`Pipfile.lock` parsing (transitive deps, same guarantee `package-lock.json`
already gave npm), plus made `requirements.txt` parsing handle real
pip-compile output (`\`-continued lines, `--hash=...` trailers) instead of
only a bare pin list.

Same session, continued after "yeah keep adding and building its weekend
so u dont need to check in as often" (a standing weekend-autonomy grant,
not project-specific): picked up the next README-flagged gap, proxy
blocking/policy mode. Added an opt-in `--block-on-drift` flag — refuses a
call to any tool currently believed drifted from baseline (added, or an
existing tool changed) before it ever reaches the downstream server,
fail-open before the first `tools/list` call this session. New
`blocked_call` audit-log record type, wired into both the dashboard cards
and the per-target detail page. Session ended for the night right after
this landed ("ok actually we are going to log off for the night pick up
tomorrow" / "save and exit") — commit+push only, no further feature work
started.
