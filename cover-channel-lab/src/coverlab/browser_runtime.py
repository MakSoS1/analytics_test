from __future__ import annotations

import os
import shutil
import signal
import subprocess
import tempfile
import time
from pathlib import Path


def _chrome_binary() -> str:
    configured = os.environ.get("COVERLAB_CHROME", "").strip()
    if configured:
        return configured
    for candidate in ("google-chrome", "google-chrome-stable", "chromium", "chromium-browser"):
        found = shutil.which(candidate)
        if found:
            return found
    raise RuntimeError("Chrome/Chromium not available for browser-native challenge")


def _terminate_group(proc: subprocess.Popen) -> None:
    if proc.poll() is not None:
        return
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    except Exception:
        try:
            proc.kill()
        except ProcessLookupError:
            pass
    try:
        proc.communicate(timeout=5)
    except Exception:
        pass


def browser_run(host: str, scenario_id: str) -> int:
    """Execute the browser fixture with bounded cold-start retries.

    GitHub-hosted Chrome can occasionally spend the entire original 20-second
    budget starting its first headless profile.  Every attempt therefore gets a
    fresh isolated profile and process group.  A timeout/non-zero exit is
    retried a small fixed number of times; a persistently unhealthy browser
    still fails the smoke/shard rather than being converted into success.
    """

    chrome = _chrome_binary()
    url = f"https://{host}:8443/browser-fixture/{scenario_id}"
    attempts = max(1, int(os.environ.get("COVERLAB_BROWSER_ATTEMPTS", "3")))
    timeout = max(5.0, float(os.environ.get("COVERLAB_BROWSER_TIMEOUT", "25")))
    last_error = "browser did not start"

    for attempt in range(1, attempts + 1):
        with tempfile.TemporaryDirectory(prefix="coverlab-chrome-") as profile:
            cmd = [
                chrome,
                "--headless=new",
                "--no-sandbox",
                "--disable-gpu",
                "--disable-dev-shm-usage",
                "--ignore-certificate-errors",
                "--disable-background-networking",
                "--disable-component-update",
                "--disable-sync",
                "--disable-breakpad",
                "--disable-crash-reporter",
                "--metrics-recording-only",
                "--no-first-run",
                "--no-default-browser-check",
                "--disable-features=OptimizationHints,Translate,MediaRouter",
                f"--user-data-dir={profile}",
                "--virtual-time-budget=2500",
                "--dump-dom",
                url,
            ]
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                text=True,
                start_new_session=True,
            )
            try:
                _stdout, stderr = proc.communicate(timeout=timeout)
            except subprocess.TimeoutExpired:
                _terminate_group(proc)
                last_error = f"timeout after {timeout:.1f}s"
            else:
                if proc.returncode == 0:
                    return 200
                tail = (stderr or "").strip().replace("\n", " ")[-800:]
                last_error = f"exit={proc.returncode}" + (f" stderr={tail}" if tail else "")
            finally:
                _terminate_group(proc)

        if attempt < attempts:
            time.sleep(0.5 * attempt)

    raise RuntimeError(
        f"browser fixture {scenario_id} failed after {attempts} attempts: {last_error}"
    )


def install() -> None:
    # run_campaign.run resolves browser_run from its module globals at call time,
    # so replacing this symbol covers ordinary, mixed and trusted-background
    # browser campaigns without duplicating the base runner.
    from . import run_campaign

    run_campaign.browser_run = browser_run
