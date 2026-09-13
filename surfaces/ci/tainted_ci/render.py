"""Markdown rendering of a report for a PR comment / CI job summary."""

from __future__ import annotations

from tainted.models import FindingStatus
from tainted.report import Report

_EMOJI = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "info": "⚪"}


def render_markdown(report: Report, prove_note: str) -> str:
    s = report.summary
    lines = [
        "## 🩸 Tainted",
        "",
        f"**{report.repo_path}** — {s.total_candidates} candidate(s), "
        f"**{s.proven} proven**, {s.reported} reported, {s.fixed} fixed.",
        "",
        f"_{prove_note}_",
        "",
    ]

    # Applicability — legible skips.
    skipped = report.skipped_planes()
    if skipped:
        lines.append("<sub>skipped planes: " + ", ".join(
            f"{d.plane.value} ({d.provenance.detail})" for d in skipped
        ) + "</sub>\n")

    proven = report.proven_findings
    if proven:
        lines.append("### Proven")
        for f in proven:
            sev = _EMOJI.get(f.severity.value, "")
            lines.append(f"- {sev} **{f.candidate.title}** — `{f.candidate.location}`")
            p = f.proof
            if p and p.exploit and p.exploit.url:
                lines.append(f"  ```\n  {p.exploit.method} {p.exploit.url}\n  ```")
            if p:
                lines.append(f"  > {p.notes}")
        lines.append("")

    candidates = report.unproven_candidates or [f.candidate for f in report.findings]
    if candidates:
        lines.append("### Candidates")
        lines.append("| Sev | Check | Title | Location |")
        lines.append("|---|---|---|---|")
        for c in candidates:
            sev = _EMOJI.get(c.severity.value, "") + " " + c.severity.value
            title = c.title.replace("|", "\\|")
            lines.append(f"| {sev} | {c.check.value} | {title} | `{c.location}` |")
        lines.append("")

    if not proven and not candidates:
        lines.append("✅ No candidates found.")

    m = report.mutation
    if m is not None and m.available and m.total:
        pct = f"{m.score:.0%}" if m.score is not None else "n/a"
        lines += [
            "### Test integrity",
            "",
            f"**{pct} of mutants killed** — {m.survived} of {m.total} changed lines failed no "
            f"test ({m.tool}). Not vulnerabilities: lines nothing is watching.",
            "",
        ]

    # Where the reach ends. A report that only lists what it found reads as a clean bill of
    # health for everything it never tried, so the limits are printed alongside the results.
    if report.coverage:
        lines.append("<details><summary>Coverage — what was proven, and what was not</summary>")
        lines.append("")
        for note in report.coverage:
            mark = "✅ proven" if note.proved else "📄 reported"
            check = note.check.value if note.check else "—"
            lines.append(f"- {mark} **{check}**: {note.detail}")
        lines += ["", "</details>", ""]

    return "\n".join(lines)


# --------------------------------------------------------------------------- #
# Tutorial — the walkthrough, rendered for a job log, and the next-steps block
# --------------------------------------------------------------------------- #
def render_tutorial(topic: str | None = None) -> str:
    """The setup walkthrough as plain text, for `TAINTED_TUTORIAL=1` in a job log.

    Not markdown: this goes to stdout in a CI runner, where nothing renders it.
    """
    from tainted_ci.tutorial import LESSONS

    if topic is None:
        lines = ["Tainted CI — setup walkthrough", ""]
        for lesson in LESSONS:
            lines.append(f"  {lesson['topic']:<20} {lesson['title']}")
            lines.append(f"  {'':<20} {lesson.get('summary', '')}")
            lines.append("")
        lines.append("Set TAINTED_TUTORIAL=<topic> to print one of these in full.")
        return "\n".join(lines)

    lesson = next((l for l in LESSONS if l["topic"] == topic), None)
    if lesson is None:
        return (
            f"No tutorial topic '{topic}'. Choose from: "
            + ", ".join(l["topic"] for l in LESSONS)
        )

    lines = [lesson["title"], "=" * len(lesson["title"]), "", lesson.get("summary", ""), ""]
    for i, step in enumerate(lesson.get("steps", []), start=1):
        lines.append(f"{i}. {step['heading']}")
        lines.append(f"   {step['body']}")
        command = step.get("command")
        if command:
            lines.append("")
            lines += [f"   {line}" for line in str(command).splitlines()]
            lines.append("")
        if step.get("expect"):
            lines.append(f"   -> {step['expect']}")
        lines.append("")
    if lesson.get("next"):
        lines.append(f"Next: {lesson['next']}")
    return "\n".join(lines)


def render_next_steps(gap: str) -> str:
    """The markdown block that says how far this pipeline is configured, and what is next."""
    from tainted_ci.tutorial import NEXT_STEPS

    body = NEXT_STEPS.get(gap) or NEXT_STEPS.get("all_configured", "")
    return (
        "<details><summary>Next steps</summary>\n\n"
        f"{body}\n\n"
        "<sub>Set <code>TAINTED_TUTORIAL=1</code> on this job to print the full "
        "walkthrough.</sub>\n</details>"
    )
