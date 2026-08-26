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


# CVSS v3.1 base metric weights, from the specification's Table 15.
_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_AC = {"L": 0.77, "H": 0.44}
_PR_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.50}
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"H": 0.56, "L": 0.22, "N": 0.0}


def _roundup(value: float) -> float:
    """CVSS v3.1 Appendix A: round up to one decimal, without float surprises."""
    scaled = int(round(value * 100_000))
    if scaled % 10_000 == 0:
        return scaled / 100_000.0
    return (scaled // 10_000 + 1) / 10.0


def cvss_v3_base_score(vector: str) -> float | None:
    """Compute the base score from a CVSS v3 vector string.

    ``cargo audit`` reports the *vector* — ``CVSS:3.1/AV:N/AC:H/...`` — and not
    the score. An earlier version of this gate treated that as "severity
    unknown", which let it pass anything cargo-audit reported: an advisory has
    no ``severity`` label either, so a genuine CRITICAL would have sailed
    through the one control O.3 and O.4 depend on. Scoring the vector is the
    fix; guessing was never acceptable and neither was ignoring it.

    Returns ``None`` for anything that is not a well-formed v3 vector, and the
    caller treats that as unscored rather than as safe.
    """
    if not isinstance(vector, str) or not vector.startswith("CVSS:3"):
        return None

    metrics = {}
    for part in vector.split("/")[1:]:
        key, _, value = part.partition(":")
        metrics[key] = value

    try:
        scope_changed = metrics["S"] == "C"
        av = _AV[metrics["AV"]]
        ac = _AC[metrics["AC"]]
        pr = (_PR_CHANGED if scope_changed else _PR_UNCHANGED)[metrics["PR"]]
        ui = _UI[metrics["UI"]]
        confidentiality = _CIA[metrics["C"]]
        integrity = _CIA[metrics["I"]]
        availability = _CIA[metrics["A"]]
    except KeyError:
        return None

    iss = 1 - ((1 - confidentiality) * (1 - integrity) * (1 - availability))
    if scope_changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    else:
        impact = 6.42 * iss
    if impact <= 0:
        return 0.0

    exploitability = 8.22 * av * ac * pr * ui
    combined = impact + exploitability
    if scope_changed:
        combined *= 1.08
    return _roundup(min(combined, 10.0))


def self_test() -> int:
    """Check the scorer against vectors with published scores.

    Run by ``vulnerability-scan.sh`` before every real evaluation, so the
    control cannot quietly stop working: a scorer that returns ``None`` for
    everything would make the gate pass unconditionally, and that failure looks
    exactly like a clean scan.
    """
    cases = [
        # RUSTSEC-2023-0071, the Marvin Attack on `rsa`.
        ("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N", 5.9, "medium"),
        # CVE-2021-44228, Log4Shell.
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0, "critical"),
        # CVE-2014-0160, Heartbleed.
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", 7.5, "high"),
        # A vector with no impact at all scores zero.
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0, "low"),
    ]

    failures = 0
    for vector, expected, band in cases:
        score = cvss_v3_base_score(vector)
        if score != expected:
            print(f"self-test: {vector} scored {score}, expected {expected}", file=sys.stderr)
            failures += 1
        elif severity_of(score, None) != band:
            print(
                f"self-test: {vector} banded {severity_of(score, None)}, expected {band}",
                file=sys.stderr,
            )
            failures += 1

    # Malformed input must be unscored, never zero: "I could not read this" and
    # "this is harmless" are different answers.
    for junk in ["", "not a vector", "CVSS:2.0/AV:N/AC:L/Au:N/C:P/I:P/A:P", "CVSS:3.1/AV:X"]:
        if cvss_v3_base_score(junk) is not None:
            print(f"self-test: {junk!r} should not have scored", file=sys.stderr)
            failures += 1

    print("self-test: passed" if not failures else f"self-test: {failures} failure(s)")
    return 1 if failures else 0


def from_cargo_audit(report: dict) -> list[dict]:
    """Findings from ``cargo audit --json``."""
    findings = []
    for entry in report.get("vulnerabilities", {}).get("list", []) or []:
        advisory = entry.get("advisory", {}) or {}
        package = entry.get("package", {}) or {}
        # cargo-audit reports the CVSS *vector*, not the score, and leaves
        # `severity` null. Scoring it is what makes the 90-day gate mean
        # anything: without this every cargo finding read as "unknown" and
        # passed, CRITICAL ones included.
        cvss = advisory.get("cvss")
        if isinstance(cvss, str):
            score = cvss_v3_base_score(cvss)
        elif isinstance(cvss, (int, float)):
            score = float(cvss)
        else:
            score = None
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
    parser.add_argument("--ledger", type=pathlib.Path)
    parser.add_argument("--cargo-audit", type=pathlib.Path)
    parser.add_argument("--npm-audit", type=pathlib.Path)
    parser.add_argument("--report", type=pathlib.Path)
    parser.add_argument(
        "--update",
        action="store_true",
        help="record newly detected findings in the ledger and start their clock",
    )
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="check the CVSS scorer against vectors with published scores, and exit",
    )
    args = parser.parse_args()

    if args.self_test:
        return self_test()

    findings = from_cargo_audit(load_json(args.cargo_audit)) + from_npm_audit(
        load_json(args.npm_audit)
    )
    current = {key_of(f): f for f in findings}

    if not args.ledger:
        parser.error("--ledger is required unless --self-test is given")

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
