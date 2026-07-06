from __future__ import annotations

import asyncio
import json
import logging
import sys
from pathlib import Path
from typing import Annotated

import structlog
import typer

from sentinel.application.heuristics.use_cases import (
    QuarantineArchiveFindingsUseCase,
    QuarantineAttempt,
    ScanArchiveUseCase,
)
from sentinel.domain.heuristics.value_objects import HeuristicMatch
from sentinel.domain.shared.value_objects import Severity
from sentinel.infrastructure.filesystem.local_file_remediator import LocalFileRemediator
from sentinel.infrastructure.heuristics.php_malware_scanner import PhpMalwareScanner

app = typer.Typer(help="Kloud101 AI Sentinel command-line tools.")


class _StderrLogger:
    """Minimal structlog-compatible logger that looks up ``sys.stderr``
    fresh on every call rather than caching a reference to it.

    structlog's own ``PrintLogger`` only re-resolves *stdout* dynamically
    (it special-cases ``file=None`` and lets the builtin ``print()`` pick up
    the live ``sys.stdout``); a ``file=sys.stderr`` reference is stored and
    reused as-is. That's fine for a real, single long-lived process, but
    it's a trap under test: tools like Typer's ``CliRunner`` temporarily
    swap and then close ``sys.stderr`` around each invocation, and
    structlog's global config — plus ``cache_logger_on_first_use`` — is
    process-wide, so a later, unrelated test's first log call can end up
    writing to an already-closed stream. Always looking ``sys.stderr`` up
    at print-time sidesteps that entirely.
    """

    def msg(self, message: str) -> None:
        print(message, file=sys.stderr, flush=True)

    log = debug = info = warning = msg
    fatal = failure = err = error = critical = exception = msg


class _StderrLoggerFactory:
    def __call__(self, *args: object) -> _StderrLogger:
        return _StderrLogger()


def _configure_cli_logging() -> None:
    """Routes structlog output to stderr, at WARNING and above only.

    The server (``bootstrap.configure_logging``) deliberately writes JSON
    logs to stdout, since a container's stdout *is* its log stream there.
    A CLI's stdout contract is different — it's the command's actual
    output (a human-readable report or, with ``--json``, a single JSON
    document a script might parse), so routine INFO-level operational logs
    like "file_quarantined" must not land on the same stream, or they'd
    corrupt that output.
    """
    structlog.configure(
        processors=[
            structlog.processors.TimeStamper(fmt="iso", utc=True),
            structlog.processors.format_exc_info,
            structlog.processors.JSONRenderer(),
        ],
        wrapper_class=structlog.make_filtering_bound_logger(logging.WARNING),
        context_class=dict,
        logger_factory=_StderrLoggerFactory(),
        cache_logger_on_first_use=True,
    )


@app.callback()
def _callback() -> None:
    """Kloud101 AI Sentinel command-line tools.

    Registering this no-op callback keeps ``scan-archive`` addressable as an
    explicit subcommand — without it, Typer collapses a single-command app
    so the subcommand name can be omitted, which would silently break as
    soon as a second command (e.g. offline database scanning) is added.
    """
    _configure_cli_logging()


@app.command()
def scan_archive(
    path: Annotated[
        Path, typer.Argument(help="Directory to scan, e.g. an extracted WordPress backup.")
    ],
    quarantine_dir: Annotated[
        Path | None,
        typer.Option(
            "--quarantine-dir",
            help=(
                "Where quarantined files are moved. Defaults to a sibling directory "
                "next to <path>, never inside it — otherwise a rescan would walk into "
                "the quarantine folder and re-flag the files it just moved out."
            ),
        ),
    ] = None,
    min_severity: Annotated[
        str,
        typer.Option(
            "--min-severity",
            help="Minimum severity to report/quarantine: CRITICAL, HIGH, MEDIUM, LOW, INFO.",
        ),
    ] = "LOW",
    apply_quarantine: Annotated[
        bool,
        typer.Option(
            "--apply-quarantine",
            help="Move qualifying files into quarantine. Without this flag, only a report is printed.",
        ),
    ] = False,
    json_output: Annotated[
        bool, typer.Option("--json", help="Print findings as JSON instead of a table.")
    ] = False,
) -> None:
    """Scan a local directory for malware/backdoor indicators.

    Works entirely offline against a downloaded WordPress backup: no
    server, database, or prior baseline is required, unlike the on-host
    agent's integrity monitoring.
    """
    root = path.resolve()
    if not root.is_dir():
        typer.echo(f"Not a directory: {root}", err=True)
        raise typer.Exit(code=1)

    try:
        threshold = Severity(min_severity.upper())
    except ValueError:
        typer.echo(f"Invalid --min-severity: {min_severity!r}", err=True)
        raise typer.Exit(code=1) from None

    result = asyncio.run(ScanArchiveUseCase(scanner=PhpMalwareScanner()).execute(root))
    findings = [match for match in result.findings if match.severity.rank >= threshold.rank]

    quarantine_root: Path | None = None
    attempts: list[QuarantineAttempt] = []
    if apply_quarantine:
        quarantine_root = (
            quarantine_dir.resolve()
            if quarantine_dir
            else root.parent / f"{root.name}.sentinel-quarantine"
        )
        remediator = LocalFileRemediator(root_directory=root, quarantine_directory=quarantine_root)
        attempts = asyncio.run(
            QuarantineArchiveFindingsUseCase(remediator=remediator).execute(
                findings, min_severity=threshold
            )
        )

    # Everything above only computes results — printing happens once, here,
    # so `--json` always emits a single well-formed JSON document on stdout
    # even when combined with `--apply-quarantine`.
    if json_output:
        _print_json(root, findings, quarantine_root=quarantine_root, attempts=attempts)
    else:
        _print_report(root, findings, threshold=threshold)
        if quarantine_root is not None:
            _print_quarantine_results(quarantine_root, attempts)
        elif findings:
            typer.echo("Run again with --apply-quarantine to move these files out of place.")


def _print_json(
    root: Path,
    findings: list[HeuristicMatch],
    *,
    quarantine_root: Path | None,
    attempts: list[QuarantineAttempt],
) -> None:
    payload: dict[str, object] = {
        "root": str(root),
        "affected_files": len({str(match.relative_path) for match in findings}),
        "findings": [
            {
                "relative_path": str(match.relative_path),
                "rule_id": match.rule_id,
                "description": match.description,
                "severity": match.severity.value,
                "line_number": match.line_number,
                "snippet": match.snippet,
            }
            for match in findings
        ],
    }
    if quarantine_root is not None:
        payload["quarantine_directory"] = str(quarantine_root)
        payload["quarantine_attempts"] = [
            {
                "relative_path": attempt.relative_path,
                "succeeded": attempt.succeeded,
                "detail": attempt.detail,
            }
            for attempt in attempts
        ]
    typer.echo(json.dumps(payload, indent=2))


def _print_report(root: Path, findings: list[HeuristicMatch], *, threshold: Severity) -> None:
    if not findings:
        typer.echo(f"No findings at or above {threshold.value} in {root}.")
        return

    affected_files = len({str(match.relative_path) for match in findings})
    typer.echo(f"{len(findings)} finding(s) across {affected_files} file(s) in {root}:\n")
    for match in findings:
        location = str(match.relative_path)
        if match.line_number is not None:
            location += f":{match.line_number}"
        typer.echo(f"[{match.severity.value}] {location} — {match.rule_id}")
        typer.echo(f"    {match.description}")
        typer.echo(f"    {match.snippet}\n")


def _print_quarantine_results(quarantine_root: Path, attempts: list[QuarantineAttempt]) -> None:
    typer.echo(f"\nQuarantine results ({quarantine_root}):")
    for attempt in attempts:
        if attempt.succeeded:
            typer.echo(f"  moved {attempt.relative_path} -> {attempt.detail}")
        else:
            typer.echo(f"  FAILED {attempt.relative_path}: {attempt.detail}")

    typer.echo(
        "\nReview the quarantined files above. To confirm removal, delete the quarantine "
        "folder; to undo a false positive, move the file back to its original path."
    )


def main() -> None:
    app()


if __name__ == "__main__":
    main()
