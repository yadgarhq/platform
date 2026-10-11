"""LEDGER 1437 — ROTATING `valkey-password` MUST HEAL WITHOUT A HUMAN.

WHAT WAS MEASURED, 2026-10-11, AGAINST THIS CHART'S RENDER AND `gateway` v0.12.2.
Before this file, `templates/valkey.yaml` read the password through
`env.VALKEY_PASSWORD.valueFrom.secretKeyRef` — the container's own environment,
fixed once at process start. `gateway` reads the SAME Secret as a mounted file
and exits when that file changes (ADR-0523), so after a rotation the gateway came
back presenting the NEW password to a server still holding the OLD one. The
gateway maps WRONGPASS to `Degrade::Unauthenticated`, which is deliberately
fail-closed (`gateway/src/limit.rs`: a rejected credential "stays wrong until
somebody changes it", so it 503s rather than take the local floor). Net effect:
every rate-limited request 503'd until somebody deleted the valkey pod.

THE FIX IS THE MECHANISM THIS FILE'S TLS HALF ALREADY USES (B-V2). Valkey now
reads its password from the Secret MOUNTED AS A DIRECTORY, the startup script
hashes that file beside the TLS material, and the liveness probe re-hashes on
every check. A rotation changes the file once kubelet refreshes the volume, the
hash stops matching, kubelet restarts the container, and the new process reads
the new password — the same exit-on-change ADR-0523 asks of every process that
reads security material once at boot. Gateway fail-closed stays exactly as it is.

WHAT THESE GATES HOLD, EACH ONE A WAY THE HEAL SILENTLY STOPS WORKING:

  1. THE FILE IS THE ONLY SOURCE. If an env copy survived beside the file, a
     restart could read a stale env value while storing the new hash, and the
     pod would never restart again — healthy, and wrong for ever.
  2. NO `subPath`. A `subPath` mount is never refreshed by kubelet, so the hash
     would never move.
  3. HASH FIRST, READ SECOND. If the file swaps between the two, hash-first
     stores the OLD hash beside the NEW password: one spare restart. Read-first
     would store the NEW hash beside the OLD password: stuck.
  4. FAIL CLOSED ON A MISSING OR EMPTY FILE. `--requirepass ""` is NO AUTH in
     valkey. `set -eu` plus an explicit empty check refuses to start instead of
     serving an open cache that reports Ready. The env form failed closed by
     construction (`CreateContainerConfigError`); the file form has to say so.
  5. THE HASH CLAUSE RENDERS AT EVERY TLS POSTURE, because the password is
     there at every posture.

`test_the_rendered_script_heals_a_rotation_against_a_real_server` runs the
RENDERED startup script and probes against the pinned image, so a path that
disagrees between the script and the probe goes red here and not in a cluster.

NOT PROVED HERE, stated rather than implied: a live rotation on a cluster. The
bound — kubelet's Secret-volume refresh on each pod's node, plus liveness's
3 x 10 s defaults — is the documented Kubernetes behaviour, not a measurement.

NO SKIPS (ADR-0650): helm or docker absent is a failure, not a skip.

Run: python3 -m pytest scripts/tests/test_valkey_password_rotation.py -q
"""

from __future__ import annotations

import subprocess
import time
from pathlib import Path

import pytest
import yaml

from test_valkey_liveness_docker import IMAGE, LiveContainer
from test_render_checks import CHART
from test_valkey_server_tls import DUAL_STACK, OFF, TLS_ONLY, render_valkey

PASSWORD_DIR = "/etc/valkey/auth"
PASSWORD_FILE = f"{PASSWORD_DIR}/password"
WATCHED = "/run/valkey/watched.sha256"
TLS_FILES = "/etc/valkey/tls/tls.crt /etc/valkey/tls/tls.key /etc/valkey/tls/ca.crt"

POSTURES = pytest.mark.parametrize("tls", [OFF, DUAL_STACK, TLS_ONLY], ids=["off", "dual-stack", "tls-only"])


def pod(tmp_path: Path, tls: dict) -> tuple[dict, dict]:
    spec = render_valkey(tmp_path, tls)[("Deployment", "valkey")]["spec"]["template"]["spec"]
    (container,) = spec["containers"]
    return spec, container


@POSTURES
def test_the_password_reaches_valkey_only_as_a_refreshable_file(tmp_path, tls):
    spec, container = pod(tmp_path, tls)

    env_refs = {
        variable["name"]
        for variable in container.get("env", [])
        if "secretKeyRef" in (variable.get("valueFrom") or {})
    }
    assert not env_refs, (
        f"{sorted(env_refs)} still read a Secret into the environment; an env copy "
        f"is fixed at process start and outlives a rotation (gate 1)"
    )

    volumes = {v["name"]: v for v in spec["volumes"]}
    secret = volumes["valkey-password"]["secret"]
    assert secret["secretName"] == "valkey-password", secret
    assert secret["items"] == [{"key": "password", "path": "password"}], secret
    assert not secret.get("optional", False), "an optional mount starts the pod with no password"

    mounts = {m["name"]: m for m in container["volumeMounts"]}
    mount = mounts["valkey-password"]
    assert mount["mountPath"] == PASSWORD_DIR, mount
    assert mount.get("readOnly") is True, mount
    assert "subPath" not in mount, "a subPath mount is never refreshed by kubelet (gate 2)"


@POSTURES
def test_the_startup_script_hashes_first_reads_second_and_refuses_an_empty_file(tmp_path, tls):
    _, container = pod(tmp_path, tls)
    script = container["args"][0]

    lines = [line.strip() for line in script.splitlines() if line.strip()]
    assert lines[0] == "set -eu", f"the script must stop on the first failure: {lines[0]!r}"

    hash_at = script.index(f"> {WATCHED}")
    read_at = script.index(f'VALKEY_PASSWORD="$(cat {PASSWORD_FILE})"')
    assert hash_at < read_at, "the password must be read AFTER it is hashed (gate 3)"
    assert '[ -n "$VALKEY_PASSWORD" ]' in script, "an empty password file must refuse to start (gate 4)"
    assert script.index('[ -n "$VALKEY_PASSWORD" ]') < script.index("exec valkey-server")

    hashed = f"sha256sum {PASSWORD_FILE}"
    if tls["enabled"]:
        hashed += f" {TLS_FILES}"
    assert f"{hashed} > {WATCHED}" in script, script


@POSTURES
def test_liveness_rechecks_the_hash_at_every_posture(tmp_path, tls):
    _, container = pod(tmp_path, tls)
    liveness = container["livenessProbe"]["exec"]["command"][2]
    assert liveness == (
        f"valkey-cli -s /run/valkey/valkey.sock ping >/dev/null && sha256sum -c --status {WATCHED}"
    ), liveness


@POSTURES
def test_readiness_authenticates_with_the_file_not_an_env_copy(tmp_path, tls):
    _, container = pod(tmp_path, tls)
    readiness = container["readinessProbe"]["exec"]["command"][2]
    assert readiness == (
        f'VALKEYCLI_AUTH="$(cat {PASSWORD_FILE})"; '
        'VALKEYCLI_AUTH="${VALKEYCLI_AUTH%"$(printf \'\\r\')"}" '
        "valkey-cli -s /run/valkey/valkey.sock ping | grep -q PONG"
    ), readiness


# ── THE RENDERED SCRIPT AND PROBES AGAINST THE PINNED IMAGE ─────────────────


def rendered(tmp_path: Path) -> tuple[str, str, str]:
    _, container = pod(tmp_path, OFF)
    return (
        container["args"][0],
        container["readinessProbe"]["exec"]["command"][2],
        container["livenessProbe"]["exec"]["command"][2],
    )


def write_password(container: LiveContainer, value: str) -> None:
    # `printf %s`: no trailing newline, the shape the bootstrap Job mints.
    result = container.exec("sh", "-c", f"mkdir -p {PASSWORD_DIR} && printf %s '{value}' > {PASSWORD_FILE}")
    assert result.returncode == 0, result.stderr


def launch(container: LiveContainer, script: str) -> None:
    """Run the RENDERED startup script detached, the way kubelet runs `sh -c`."""
    subprocess.run(
        ["docker", "exec", "-d", container.name, "sh", "-c", script],
        check=True,
        capture_output=True,
        timeout=15,
    )


def probe(container: LiveContainer, command: str) -> int:
    return container.exec("sh", "-c", command).returncode


def wait_ready(container: LiveContainer, readiness: str) -> None:
    for _ in range(40):
        if probe(container, readiness) == 0:
            return
        time.sleep(0.25)
    log = container.exec("sh", "-c", "ps; ls -la /run/valkey")
    raise AssertionError(f"rendered readiness never passed: {log.stdout} {log.stderr}")


def auth_answer(container: LiveContainer, password: str) -> str:
    return container.exec(
        "sh", "-c", f"VALKEYCLI_AUTH='{password}' valkey-cli -s /run/valkey/valkey.sock ping"
    ).stdout.strip()


def test_the_rendered_script_heals_a_rotation_against_a_real_server(tmp_path):
    script, readiness, liveness = rendered(tmp_path)
    old, new = "rotation-old-password", "rotation-new-password"
    with LiveContainer() as container:
        container.exec("mkdir", "-p", "/run/valkey")
        write_password(container, old)
        launch(container, script)
        wait_ready(container, readiness)
        assert probe(container, liveness) == 0, "liveness failed before any rotation"
        assert auth_answer(container, old) == "PONG"

        # THE ROTATION: only the mounted file changes; the server stays up.
        write_password(container, new)
        assert auth_answer(container, old) == "PONG", "the server itself must be unaffected so far"
        assert probe(container, liveness) != 0, "liveness passed after the password file changed"
        assert probe(container, readiness) != 0, "readiness passed with a password the server does not hold"

        # THE RESTART kubelet performs on that failed liveness: same script, new process.
        container.exec(
            "sh", "-c", f"VALKEYCLI_AUTH='{old}' valkey-cli -s /run/valkey/valkey.sock shutdown nosave"
        )
        time.sleep(0.5)
        launch(container, script)
        wait_ready(container, readiness)
        assert probe(container, liveness) == 0, "liveness failed after the restart onto the new file"
        assert auth_answer(container, new) == "PONG"
        assert auth_answer(container, old) != "PONG", "the old password still authenticates after the heal"


def test_a_crlf_password_file_is_trimmed_alike_by_startup_and_readiness(tmp_path):
    """REVIEW OF #42: the startup script strips one trailing `\\r` and
    `gateway` trims trailing `\\n`/`\\r`, so a CRLF file (a hand-made restore)
    must read the same in the readiness probe — else the server holds the
    trimmed password, readiness presents the untrimmed one, and the pod is
    NotReady for ever."""
    script, readiness, liveness = rendered(tmp_path)
    with LiveContainer() as container:
        container.exec("mkdir", "-p", "/run/valkey")
        written = container.exec(
            "sh", "-c", f"mkdir -p {PASSWORD_DIR} && printf 'crlf-password\\r\\n' > {PASSWORD_FILE}"
        )
        assert written.returncode == 0, written.stderr
        launch(container, script)
        for _ in range(40):
            if auth_answer(container, "crlf-password") == "PONG":
                break
            time.sleep(0.25)
        assert auth_answer(container, "crlf-password") == "PONG", "the server did not take the trimmed password"
        assert probe(container, readiness) == 0, "readiness fails on a CRLF password file the server accepted"
        assert probe(container, liveness) == 0


@pytest.mark.parametrize("contents", ["empty", "missing"])
def test_the_rendered_script_refuses_to_start_without_a_password(tmp_path, contents):
    script, _, _ = rendered(tmp_path)
    with LiveContainer() as container:
        container.exec("mkdir", "-p", "/run/valkey")
        if contents == "empty":
            write_password(container, "")
        started = container.exec("sh", "-c", script)
        assert started.returncode != 0, f"the script started valkey with a {contents} password file"
        answered = container.exec("sh", "-c", "valkey-cli -s /run/valkey/valkey.sock ping")
        assert "PONG" not in answered.stdout, "an unauthenticated server is answering"


def test_the_image_under_test_is_the_one_the_chart_pins():
    assert yaml.safe_load((CHART / "values.yaml").read_text())["valkey"]["image"] == IMAGE
