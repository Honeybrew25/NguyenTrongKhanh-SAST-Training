from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
FINALIZER = ROOT / "scripts" / "finalize_day2_worker.ps1"


def test_finalizer_exit_policy_is_fail_closed_before_pipeline() -> None:
    """Keep terminal scanner outcomes ahead of retry and pipeline control flow."""

    source = FINALIZER.read_text(encoding="utf-8")

    scanner_exit = source.index("$scannerExitCode = $LASTEXITCODE")
    success = source.index("if ($scannerExitCode -eq 0)", scanner_exit)
    quarantined = source.index("if ($scannerExitCode -eq 3)", success)
    busy = source.index("if ($scannerExitCode -eq 4)", quarantined)
    retryable = source.index("elseif ($scannerExitCode -eq 1)", busy)
    terminal_error = source.index('-Status "BLOCKED_SCANNER_ERROR"', retryable)
    retry_backoff = source.index("Start-Sleep -Seconds $retryDelaySeconds", terminal_error)
    pipeline = source.index('-Status "RUNNING_FULL_PIPELINE"', retry_backoff)

    assert (
        scanner_exit
        < success
        < quarantined
        < busy
        < retryable
        < terminal_error
        < retry_backoff
        < pipeline
    )

    quarantined_block = source[quarantined:busy]
    assert '-Status "BLOCKED_QUARANTINED"' in quarantined_block
    assert "exit $scannerExitCode" in quarantined_block

    busy_block = source[busy:retryable]
    assert '-Status "BUSY"' in busy_block
    assert "without consuming the retryable-pass budget" in busy_block
    assert "Start-Sleep -Seconds $busyDelaySeconds" in busy_block
    assert "continue" in busy_block
    assert "$retryablePasses++" not in busy_block

    retryable_block = source[retryable:terminal_error]
    assert "$retryablePasses++" in retryable_block
    assert '-Status "BLOCKED_AFTER_RETRIES"' in retryable_block
    assert '"BLOCKED_BUSY_AFTER_RETRIES"' not in source
    assert source.count('-Status "RUNNING_FULL_PIPELINE"') == 1
