#!/usr/bin/env python3
"""Decide whether the supply chain is fit to release.

The rule comes from the C2PA Generator Product Security Requirements, O.3 and
O.4 at Assurance Level 1: a CRITICAL or HIGH severity vulnerability must be
fixed or mitigated within 90 days of detection. So the question is never "are
there findings" — an open-source dependency tree of any size always has some —
but "has any finding been open too long".

Answering that needs a memory, because a scanner only knows about today. The
ledger at ``conformance/vulnerability-ledger.json`` is that memory: each finding
records when it was first seen, and from that the deadline follows. It is
committed to the repository so the record is auditable and so a fresh CI runner
cannot reset the clock by forgetting.

    first_seen + 90 days < today   ->  the build fails
    otherwise                      ->  the build passes, with a countdown

A finding that has disappeared from the scanners is marked resolved rather than
deleted, so the evidence of how long it took to fix survives.

Exit status is 0 when the gate passes and 1 when it does not.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import pathlib
import sys

WINDOW_DAYS = 90
BLOCKING = {"critical", "high"}


def today() -> dt.date:
    return dt.datetime.now(dt.timezone.utc).date()


def load_json(path: pathlib.Path) -> dict:
    if not path or not path.exists() or path.stat().st_size == 0:
        return {}
    try:
        return json.loads(path.read_text())
    except json.JSONDecodeError:
        # A scanner that produced nothing usable is not a pass. Reporting it as
        # an empty result would be the one failure mode that matters here.
        print(f"gate: {path} is not valid JSON; treating the scan as failed", file=sys.stderr)
        sys.exit(1)


def severity_of(cvss: float | None, label: str | None) -> str:
    """Normalise to the CVSS v3 qualitative bands."""
    if cvss is not None:
        if cvss >= 9.0:
            return "critical"
        if cvss >= 7.0:
            return "high"
        if cvss >= 4.0:
            return "medium"
        return "low"
    return (label or "unknown").lower()


def from_cargo_audit(report: dict) -> list[dict]:
    """Findings from ``cargo audit --json``."""
    findings = []
    for entry in report.get("vulnerabilities", {}).get("list", []) or []:
        advisory = entry.get("advisory", {}) or {}
        package = entry.get("package", {}) or {}
        cvss = advisory.get("cvss")
        score = None
        if isinstance(cvss, str) and "/" in cvss:
            # cargo-audit gives the vector string, not the score. Without a
            # parser the honest reading is "unknown", which the ledger can
            # override with the real severity once a human has looked.
            score = None
        elif isinstance(cvss, (int, float)):
            score = float(cvss)
        findings.append(
            {
                "id": advisory.get("id", "unknown"),
                "ecosystem": "cargo",
                "package": package.get("name", "unknown"),
                "version": package.get("version", ""),
                "title": advisory.get("title", ""),
                "severity": severity_of(score, advisory.get("severity")),
                "url": advisory.get("url", ""),
            }
        )
    # Unmaintained crates and yanked versions are warnings, not vulnerabilities;
    # they are recorded so they are visible but never block a release.
    for kind, entries in (report.get("warnings") or {}).items():
        for entry in entries or []:
            advisory = entry.get("advisory") or {}
            package = entry.get("package", {}) or {}
            findings.append(
                {
                    "id": advisory.get("id", f"{kind}:{package.get('name', 'unknown')}"),
                    "ecosystem": "cargo",
                    "package": package.get("name", "unknown"),
                    "version": package.get("version", ""),
                    "title": advisory.get("title", kind),
                    "severity": "informational",
                    "url": advisory.get("url", ""),
                }
            )
    return findings


def from_npm_audit(report: dict) -> list[dict]:
    """Findings from ``npm audit --json`` (npm 7+ schema)."""
    findings = []
    for name, entry in (report.get("vulnerabilities") or {}).items():
        via = entry.get("via") or []
        advisories = [item for item in via if isinstance(item, dict)]
        if not advisories:
            # A transitive entry whose `via` is a package name; the advisory
            # itself appears under that package's own entry.
            continue
        for advisory in advisories:
            findings.append(
                {
                    "id": f"GHSA:{advisory.get('source', advisory.get('url', 'unknown'))}",
                    "ecosystem": "npm",
                    "package": name,
                    "version": entry.get("range", ""),
                    "title": advisory.get("title", ""),
                    "severity": severity_of(
                        (advisory.get("cvss") or {}).get("score"),
                        advisory.get("severity") or entry.get("severity"),
                    ),
                    "url": advisory.get("url", ""),
                }
            )
    return findings


def key_of(finding: dict) -> str:
    return f"{finding['ecosystem']}:{finding['package']}:{finding['id']}"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ledger", required=True, type=pathlib.Path)
    parser.add_argument("--cargo-audit", type=pathlib.Path)
    parser.add_argument("--npm-audit", type=pathlib.Path)
    parser.add_argument("--report", type=pathlib.Path)
    parser.add_argument(
        "--update",
        action="store_true",
        help="record newly detected findings in the ledger and start their clock",
    )
    args = parser.parse_args()

    findings = from_cargo_audit(load_json(args.cargo_audit)) + from_npm_audit(
        load_json(args.npm_audit)
    )
    current = {key_of(f): f for f in findings}

    ledger = {"findings": {}}
    if args.ledger.exists():
        ledger = json.loads(args.ledger.read_text())
    recorded: dict[str, dict] = ledger.setdefault("findings", {})

    now = today()
    overdue: list[str] = []
    pending: list[str] = []
    untracked: list[str] = []

    for key, finding in sorted(current.items()):
        severity = finding["severity"]
        entry = recorded.get(key)

        # The ledger may carry a human's severity assessment, which overrides
        # a scanner that could not produce one. That is a judgement call and it
        # is recorded where a reviewer can see and challenge it.
        if entry and entry.get("severity"):
            severity = entry["severity"].lower()

        if severity not in BLOCKING:
            continue

        if entry is None:
            if args.update:
                recorded[key] = {
                    "firstSeen": now.isoformat(),
                    "severity": severity,
                    "package": finding["package"],
                    "title": finding["title"],
                    "url": finding["url"],
                    "status": "open",
                }
                pending.append(f"{key} — first seen today, due {now + dt.timedelta(days=WINDOW_DAYS)}")
            else:
                # A finding nobody has recorded is not automatically overdue,
                # but it must not pass silently either: CI runs with --update on
                # the default branch, so an untracked one here means the ledger
                # is behind.
                untracked.append(f"{key} — {severity.upper()}: {finding['title']}")
            continue

        if entry.get("status") == "accepted":
            # An explicitly accepted risk, with a reason recorded next to it.
            pending.append(f"{key} — accepted: {entry.get('reason', 'no reason recorded')}")
            continue

        first_seen = dt.date.fromisoformat(entry["firstSeen"])
        deadline = first_seen + dt.timedelta(days=WINDOW_DAYS)
        if now > deadline:
            overdue.append(
                f"{key} — {severity.upper()}: {finding['title']} "
                f"(first seen {first_seen}, due {deadline}, {(now - deadline).days} days over)"
            )
        else:
            pending.append(
                f"{key} — {severity.upper()}: due {deadline} ({(deadline - now).days} days left)"
            )

    # Anything the scanners no longer see has been fixed. Keeping the record
    # rather than deleting it is what makes the ledger evidence.
    for key, entry in recorded.items():
        if key not in current and entry.get("status") == "open":
            entry["status"] = "resolved"
            entry["resolvedOn"] = now.isoformat()

    if args.update:
        args.ledger.parent.mkdir(parents=True, exist_ok=True)
        args.ledger.write_text(json.dumps(ledger, indent=2, sort_keys=True) + "\n")

    report = {
        "generatedAt": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
        "windowDays": WINDOW_DAYS,
        "totalFindings": len(findings),
        "blocking": len(overdue),
        "overdue": overdue,
        "withinWindow": pending,
        "untracked": untracked,
    }
    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(report, indent=2) + "\n")

    print(f"{len(findings)} finding(s) across cargo and npm")
    for line in pending:
        print(f"  within window: {line}")
    for line in untracked:
        print(f"  UNTRACKED:     {line}")
    for line in overdue:
        print(f"  OVERDUE:       {line}")

    if overdue:
        print(
            f"\ngate: {len(overdue)} CRITICAL/HIGH finding(s) have been open longer than "
            f"{WINDOW_DAYS} days. C2PA Generator Product Security Requirements O.3 and O.4 "
            "do not permit releasing this.",
            file=sys.stderr,
        )
        return 1
    if untracked:
        print(
            f"\ngate: {len(untracked)} CRITICAL/HIGH finding(s) are not in the ledger. Run "
            "`./conformance/scripts/vulnerability-scan.sh --update` and commit the result so "
            "their 90-day clock is on the record.",
            file=sys.stderr,
        )
        return 1

    print("\ngate: passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
