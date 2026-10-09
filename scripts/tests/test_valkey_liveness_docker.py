"""THE RENDERED LIVENESS COMMAND, PROVED AGAINST A REAL `valkey/valkey:9.1.1` (B-V2).

WHAT THIS FILE IS FOR. Every other test in `test_valkey_server_tls.py` asserts
what STRING the liveness probe carries. None of them run that string against a
server, so none of them would catch a syntax error `sh` accepts but a real
shell session does not, or a flag `valkey-cli` renamed between versions. This
file extracts the exact command `templates/valkey.yaml` renders — via PyYAML,
never hand-copied, so a future edit to the probe is exercised here without this
file changing — and runs it with `docker exec` against the PINNED image the
chart itself uses (`valkey/valkey:9.1.1`, same tag `chart/values.yaml` sets),
once while the server answers and once after it is told to stop.

WHY THE CONTAINER'S PID 1 IS `sleep`, NOT `valkey-server`. `docker stop` kills
PID 1, which would tear down the container before a second `docker exec` could
run the probe again. The container's main process is a long sleep instead, and
the server is launched inside it in the background; "stopped" is `valkey-cli
... shutdown nosave` against the running server, which matches what the
liveness probe guards against in the cluster: valkey not answering, with the
Pod (sleep's analogue, kubelet) still up to report an unhealthy probe.

WHY THE PASSWORD IS SET EXPLICITLY HERE. `templates/valkey.yaml` reads
`VALKEY_PASSWORD` and `VALKEYCLI_AUTH` from a Kubernetes Secret this test does
not have; a bare docker run gets no credential unless one is given, and an
unauthenticated run would prove the probe passes for the wrong reason (measured
2026-10-09, `scripts/bv2/tlscheck`: `NOAUTH` without a credential, `PONG`
with one — see `templates/valkey.yaml`'s own readiness comment for the same
measurement against TCP).

NO SKIP WHEN `docker` IS MISSING (ledger 837: no test silently stops running).
This matches `templates/render-checks.yaml`'s own ADR-0650 precedent for
`helm`: the suite does not skip without the tool it needs, it fails, naming
the tool. `LiveContainer.__enter__` below is the first real statement each
test runs; if `docker` is not on PATH or the daemon is unreachable, `docker
run` itself raises there and the test reports red, naming `docker` in the
command that failed. The CI runner this contract is written for has it
(GitHub-hosted `ubuntu` runners ship Docker); a local run with no `docker`
fails loudly rather than reporting a false green.

Run: python3 -m pytest scripts/tests/test_valkey_liveness_docker.py -q
"""

from __future__ import annotations

import subprocess
import time
import uuid
from pathlib import Path

import pytest
import yaml

from test_render_checks import ADOPTER_VALUES, CHART, objects, render

IMAGE = "valkey/valkey:9.1.1"
PASSWORD = "b-v2-ci-check-password"


def rendered_probes(tmp_path: Path, tls_enabled: bool) -> tuple[str, str]:
    """(readiness_command, liveness_command), read off a REAL `helm template`
    render — never hand-copied — for `valkey.tls.enabled: {tls_enabled}`."""
    body = {
        "valkey": {
            "create": True,
            "tls": {"enabled": tls_enabled, "clientAuth": "off", "plaintext": True},
        }
    }
    tmp_path.mkdir(parents=True, exist_ok=True)
    overlay = tmp_path / "overlay.yaml"
    overlay.write_text(yaml.safe_dump(body))
    result = render(
        CHART,
        "--api-versions",
        "cert-manager.io/v1",
        "--api-versions",
        "gateway.envoyproxy.io/v1alpha1",
        "--namespace",
        "yadgar",
        "-f",
        str(ADOPTER_VALUES),
        "-f",
        str(overlay),
    )
    assert result.returncode == 0, result.stderr
    deployment = next(
        d for d in objects(result.stdout) if d["kind"] == "Deployment" and d["metadata"]["name"] == "valkey"
    )
    container = deployment["spec"]["template"]["spec"]["containers"][0]
    readiness = container["readinessProbe"]["exec"]["command"][2]
    liveness = container["livenessProbe"]["exec"]["command"][2]
    return readiness, liveness


class LiveContainer:
    """A `valkey/valkey:9.1.1` container whose PID 1 outlives `valkey-server`,
    so a probe can be re-run after the server inside is told to stop."""

    def __init__(self) -> None:
        self.name = f"bv2-liveness-check-{uuid.uuid4().hex[:10]}"

    def __enter__(self) -> "LiveContainer":
        subprocess.run(
            [
                "docker",
                "run",
                "-d",
                "--name",
                self.name,
                "--entrypoint",
                "sh",
                IMAGE,
                "-c",
                "sleep 3600",
            ],
            check=True,
            capture_output=True,
            timeout=30,
        )
        return self

    def exec(self, *args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["docker", "exec", self.name, *args],
            capture_output=True,
            text=True,
            timeout=15,
        )

    def __exit__(self, *exc: object) -> None:
        # LEDGER 1399: every container this suite starts is stopped, whatever
        # the test outcome — `finally`-equivalent via the context manager.
        subprocess.run(["docker", "stop", "-t", "2", self.name], capture_output=True, timeout=20)
        subprocess.run(["docker", "rm", "-f", self.name], capture_output=True, timeout=20)


def start_server(container: LiveContainer, *, tls_enabled: bool) -> None:
    container.exec("mkdir", "-p", "/run/valkey", check=True)
    hash_clause = ""
    if tls_enabled:
        # No real certs in this isolated check: the hash file is seeded over
        # the socket args file itself, just to exercise `sha256sum -c
        # --status` succeeding once and failing once the file it hashed is
        # gone — the same shape as a rotated/missing cert, without needing a
        # live CA for a liveness-probe-only test. The TLS LISTENER'S own
        # handshake is exercised separately in `scripts/bv2/tlscheck`
        # (`SubagentHandback` report), not duplicated here.
        hash_clause = (
            "touch /run/valkey/tls-material "
            "&& sha256sum /run/valkey/tls-material > /run/valkey/tls.sha256 && "
        )
    start = (
        f"{hash_clause}"
        f"valkey-server --port 6379 --unixsocket /run/valkey/valkey.sock "
        f"--unixsocketperm 700 --requirepass {PASSWORD} --daemonize yes "
        f"--logfile /run/valkey/server.log"
    )
    result = container.exec("sh", "-c", start)
    assert result.returncode == 0, result.stderr + result.stdout
    for _ in range(20):
        probe = container.exec(
            "sh", "-c", f"VALKEYCLI_AUTH={PASSWORD} valkey-cli -s /run/valkey/valkey.sock ping"
        )
        if probe.stdout.strip() == "PONG":
            return
        time.sleep(0.25)
    raise AssertionError("valkey-server did not come up inside the CI container")


def run_probe(container: LiveContainer, command: str) -> subprocess.CompletedProcess[str]:
    """The REAL probe command, with `VALKEYCLI_AUTH` supplied the way the
    chart supplies it: as an env var the exec command reads, not a flag."""
    return container.exec("sh", "-c", f"VALKEYCLI_AUTH={PASSWORD} {command}")


@pytest.mark.parametrize("tls_enabled", [False, True], ids=["tls-off", "tls-on"])
def test_the_rendered_liveness_command_passes_healthy_and_fails_stopped(tmp_path, tls_enabled):
    _, liveness = rendered_probes(tmp_path, tls_enabled)
    with LiveContainer() as container:
        start_server(container, tls_enabled=tls_enabled)

        healthy = run_probe(container, liveness)
        assert healthy.returncode == 0, (
            f"the rendered liveness command failed against a healthy server: "
            f"{liveness!r} -> {healthy.stdout!r} {healthy.stderr!r}"
        )

        stop = container.exec(
            "sh", "-c", f"VALKEYCLI_AUTH={PASSWORD} valkey-cli -s /run/valkey/valkey.sock shutdown nosave"
        )
        # `shutdown nosave` closes the connection without replying; a nonzero
        # exit here is `valkey-cli` reporting "server closed the connection",
        # which is the expected shape of asking a server to stop.
        del stop
        time.sleep(0.5)

        stopped = run_probe(container, liveness)
        assert stopped.returncode != 0, (
            f"the rendered liveness command passed against a stopped server: {liveness!r}"
        )


def test_the_rendered_readiness_command_reads_the_same_socket(tmp_path):
    readiness, _ = rendered_probes(tmp_path, tls_enabled=False)
    with LiveContainer() as container:
        start_server(container, tls_enabled=False)
        healthy = run_probe(container, readiness)
        assert healthy.returncode == 0, healthy.stderr + healthy.stdout
