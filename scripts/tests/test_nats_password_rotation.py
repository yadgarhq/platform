"""LEDGER 1440, ADR-0924 — A ROTATED `nats-auth` / `nats-auth-gateway` RESTARTS THE BROKER.

THE GAP, MEASURED 2026-10-11 (ledger 1425) AND CLOSED HERE. `nats-auth` and
`nats-auth-gateway` are minted by the bootstrap Job's `curl` POST
(`templates/bootstrap-secrets.yaml`), never by a Helm-rendered Secret, so no
checksum can see them. The broker used to read both passwords through
`container.env.NATS_PASSWORD{,_GATEWAY}.valueFrom.secretKeyRef`: its own
environment, fixed at process start. `configChecksumAnnotation` hashes a
ConfigMap that carries the literal text `$NATS_PASSWORD`, and a SIGHUP
re-expands that variable against the same environment. So after a rotation the
broker kept the OLD password until somebody ran `delete pod nats-0`.

THE MECHANISM ADR-0924 RULES, the valkey pattern of `platform#42`:

  1. EACH SECRET IS A DIRECTORY MOUNT OUTSIDE `/etc/`. No `secretKeyRef` env, no
     `subPath` (kubelet never refreshes one), not optional. Outside `/etc/`
     because the upstream chart copies every nats mount under `/etc/` into the
     reloader (`reloader.natsVolumeMountPrefixes`), which needs no password.
  2. THE MOUNTS AND THE PROBE SWAP GO THROUGH THE UPSTREAM JSON-PATCH KEYS.
     `container.merge` and `podTemplate.merge` REPLACE lists, so a mount added
     through `merge` drops the chart's own `config`, `pid` and `nats-tls`. The
     probe swap is a `remove` plus an `add` for the same reason it is not a
     values `null`: the patch runs inside the upstream template, after every
     coalescing step, so its result does not depend on the helm version.
  3. A WRAPPER IN THE NATS CONTAINER hashes both files FIRST, reads them
     SECOND, trims every trailing `\\n` and `\\r` exactly as `iam` and `gateway`
     do (`trim_end_matches(['\\n', '\\r'])`), refuses an empty value, and
     `exec`s nats-server so it stays PID 1 for the lame-duck `preStop`. Not an
     init container: an init container does not run again on a liveness
     restart, so the stored hash would stay stale and the pod would loop.
  4. LIVENESS RE-CHECKS THE HASH BESIDE `/healthz`, at the upstream 30 s x 3.
     The TLS leaf and CA stay OUT of the hash: the reloader reloads them hot,
     and hashing them would restart the broker on every leaf renewal.
  5. THE CHART REFUSES WHAT WOULD SILENTLY BREAK THAT: a broker image with no
     shell (non-alpine), a monitor endpoint the probe cannot reach, and an
     adopter patch list that has lost the wiring.

THE PREMISE LOCK INVERTED. Ledger 1425's `env_secretkeyref_failures` asserted
the password still came from `secretKeyRef`, so that it would go red the day
the password moved to a file. That day is this file. `file_wiring_failures`
locks the new shape instead, and README.md's `delete pod` becomes the fallback.

NOT PROVED HERE: a live rotation on a cluster. The bound (kubelet's
Secret-volume refresh, up to 90 s of liveness checks, the lame-duck drain, and
up to 60 s of client redial under ADR-0893) is derived, not measured.

NO SKIPS (ADR-0650): helm or docker absent is a failure, not a skip.

Run: python3 -m pytest scripts/tests/test_nats_password_rotation.py -q
"""

from __future__ import annotations

import re
import shutil
import subprocess
import time
import uuid
from pathlib import Path

import pytest
import yaml

REPO = Path(__file__).resolve().parents[2]
CHART = REPO / "chart"
ADOPTER_VALUES = REPO / "example" / "values.yaml"
README = REPO / "README.md"

RELEASE_NAMESPACE = "yadgar"

# Same two groups `test_bootstrap.py` and `test_render_checks.py` pass, for the
# same reason: the adopter values this suite renders with turn on the
# certificate and Gateway-listener halves too, and `templates/render-checks.yaml`
# refuses a bare render of either before a single object exists to inspect.
DECLARED_API_VERSIONS = ("cert-manager.io/v1", "gateway.envoyproxy.io/v1alpha1")
API_VERSIONS = tuple(
    part for group in DECLARED_API_VERSIONS for part in ("--api-versions", group)
)

# The live posture `yadgarhq/argocd` runs (B-N2), beside the example's plaintext
# one. `nats-tls` exists only in this one, so the reloader and mount gates must
# hold at both.
TLS_REQUIRED = (
    "nats:\n"
    "  tls: {enabled: true, clientAuth: \"required\"}\n"
    "  config:\n"
    "    nats:\n"
    "      tls:\n"
    "        enabled: true\n"
    "        secretName: nats-tls\n"
    "        merge: {verify: true, ca_file: /etc/nats-certs/nats/ca.crt}\n"
)
POSTURES = pytest.mark.parametrize("posture", ["off", "required"])


def helm(*arguments: str) -> subprocess.CompletedProcess[str]:
    binary = shutil.which("helm")
    assert binary, (
        "helm is not on PATH. This suite renders the chart, and so does the "
        "`helm lint and render` pre-commit hook — install helm rather than "
        "letting either report a pass it did not earn."
    )
    return subprocess.run([binary, *arguments], capture_output=True, text=True)


def documents_of(stdout: str) -> list[dict]:
    return [
        document
        for document in yaml.safe_load_all(stdout)
        if isinstance(document, dict) and document.get("apiVersion")
    ]


def render_result(*arguments: str) -> subprocess.CompletedProcess[str]:
    return helm(
        "template",
        "platform",
        str(CHART),
        "--namespace",
        RELEASE_NAMESPACE,
        *API_VERSIONS,
        "-f",
        str(ADOPTER_VALUES),
        *arguments,
    )


def overlay(tmp_path: Path, name: str, body: str) -> str:
    tmp_path.mkdir(parents=True, exist_ok=True)
    path = tmp_path / name
    path.write_text(body)
    return str(path)


def adopter_render(tmp_path: Path, posture: str = "off", *extra: str) -> list[dict]:
    arguments: list[str] = []
    if posture == "required":
        arguments += ["-f", overlay(tmp_path, "tls-required.yaml", TLS_REQUIRED)]
    result = render_result(*arguments, *extra)
    assert result.returncode == 0, result.stderr
    return documents_of(result.stdout)


def of_kind(documents: list[dict], kind: str) -> list[dict]:
    return [document for document in documents if document.get("kind") == kind]


def name_of(document: dict) -> str:
    return str((document.get("metadata") or {}).get("name"))


# `fullnameOverride: nats` (ADR-0805) is what makes the StatefulSet's name, and
# so the fallback's pod name `nats-0`, the literal below.
BROKER_STATEFULSET_NAME = "nats"
BROKER_CONTAINER_NAME = "nats"
RELOADER_CONTAINER_NAME = "reloader"

SECRET_KEY = "password"
# volume name -> (Secret the bootstrap Job mints, directory it is mounted at)
PASSWORD_VOLUMES = {
    "nats-auth-iam": ("nats-auth", "/var/run/secrets/nats-auth/iam"),
    "nats-auth-gateway": ("nats-auth-gateway", "/var/run/secrets/nats-auth/gateway"),
}
PASSWORD_FILES = tuple(f"{directory}/{SECRET_KEY}" for _, directory in PASSWORD_VOLUMES.values())
IAM_FILE, GATEWAY_FILE = PASSWORD_FILES
HASH_FILE = "/var/run/nats/auth.sha256"
CONFIG_FILE = "/etc/nats-config/nats.conf"
LIVENESS = (
    f"sha256sum -c -s {HASH_FILE} && "
    "wget -q -O /dev/null 'http://127.0.0.1:8222/healthz?js-enabled-only=true'"
)


def nats_statefulset(documents: list[dict]) -> dict:
    statefulsets = [
        document
        for document in of_kind(documents, "StatefulSet")
        if name_of(document) == BROKER_STATEFULSET_NAME
    ]
    assert len(statefulsets) == 1, (
        f"expected exactly 1 StatefulSet named {BROKER_STATEFULSET_NAME!r} "
        f"(ADR-0805's fullnameOverride, and the fallback's `nats-0`), found "
        f"{len(statefulsets)}"
    )
    return statefulsets[0]


def pod_spec(documents: list[dict]) -> dict:
    return nats_statefulset(documents)["spec"]["template"]["spec"]


def container(spec: dict, name: str) -> dict:
    matches = [c for c in spec["containers"] if c.get("name") == name]
    assert len(matches) == 1, f"expected exactly 1 container named {name!r}, found {len(matches)}"
    return matches[0]


def wrapper_script(spec: dict) -> str:
    nats = container(spec, BROKER_CONTAINER_NAME)
    assert nats.get("command") == ["/bin/sh", "-c"], nats.get("command")
    assert len(nats.get("args") or []) == 1, nats.get("args")
    return nats["args"][0]


# ── THE NEW SHAPE, LOCKED (THE INVERTED PREMISE LOCK) ───────────────────────


def file_wiring_failures(documents: list[dict]) -> list[str]:
    """PURE. Both passwords reach the broker only as refreshable directory mounts."""
    failures = []
    spec = pod_spec(documents)
    for c in spec["containers"]:
        for entry in c.get("env") or []:
            if "secretKeyRef" in (entry.get("valueFrom") or {}):
                failures.append(
                    f"container {c['name']!r} still reads {entry['name']} through "
                    f"secretKeyRef: an env copy is fixed at process start and outlives "
                    f"a rotation (ADR-0924)"
                )
    volumes = {v["name"]: v for v in spec.get("volumes") or []}
    mounts = {m["name"]: m for m in container(spec, BROKER_CONTAINER_NAME).get("volumeMounts") or []}
    for volume_name, (secret, directory) in PASSWORD_VOLUMES.items():
        source = (volumes.get(volume_name) or {}).get("secret")
        if not source:
            failures.append(f"no Secret volume named {volume_name!r} (for {secret})")
        else:
            if source.get("secretName") != secret:
                failures.append(f"volume {volume_name!r} reads {source.get('secretName')!r}, not {secret!r}")
            if source.get("items") != [{"key": SECRET_KEY, "path": SECRET_KEY}]:
                failures.append(f"volume {volume_name!r} items are {source.get('items')!r}")
            if source.get("optional", False):
                failures.append(f"volume {volume_name!r} is optional: the broker would start without it")
        mount = mounts.get(volume_name)
        if not mount:
            failures.append(f"the nats container does not mount {volume_name!r}")
            continue
        if mount.get("mountPath") != directory:
            failures.append(f"{volume_name!r} is mounted at {mount.get('mountPath')!r}, not {directory!r}")
        if str(mount.get("mountPath", "")).startswith("/etc/"):
            failures.append(f"{volume_name!r} is under /etc/, so the reloader would get the password too")
        if "subPath" in mount:
            failures.append(f"{volume_name!r} uses subPath, which kubelet never refreshes")
        if mount.get("readOnly") is not True:
            failures.append(f"{volume_name!r} is not mounted readOnly")
    return failures


@POSTURES
def test_the_passwords_reach_the_broker_only_as_refreshable_mounts(tmp_path, posture):
    failures = file_wiring_failures(adopter_render(tmp_path, posture))
    assert failures == [], "\n".join(failures)


def test_a_subpath_mount_reddens_the_wiring_gate(tmp_path):
    """Mutation check: the gate reads the rendered mount, not a string."""
    documents = adopter_render(tmp_path)
    nats = container(pod_spec(documents), BROKER_CONTAINER_NAME)
    for mount in nats["volumeMounts"]:
        if mount["name"] == "nats-auth-iam":
            mount["subPath"] = "password"
    failures = file_wiring_failures(documents)
    assert any("subPath" in failure for failure in failures), failures


@POSTURES
def test_the_chart_keeps_its_own_mounts_and_the_reloader_gets_no_password(tmp_path, posture):
    spec = pod_spec(adopter_render(tmp_path, posture))
    own = {"config", "pid"} | ({"nats-tls"} if posture == "required" else set())

    volumes = {v["name"] for v in spec["volumes"]}
    nats_mounts = {m["name"] for m in container(spec, BROKER_CONTAINER_NAME)["volumeMounts"]}
    assert volumes == own | set(PASSWORD_VOLUMES), volumes
    assert nats_mounts == own | set(PASSWORD_VOLUMES), nats_mounts

    reloader = container(spec, RELOADER_CONTAINER_NAME)
    reloader_mounts = {m["name"] for m in reloader["volumeMounts"]}
    assert reloader_mounts == own, (
        f"the reloader mounts {sorted(reloader_mounts)}; it needs only {sorted(own)} "
        f"and must hold neither password"
    )
    watched = [arg for arg in reloader["args"] if arg.startswith("/")]
    assert not [path for path in watched if "nats-auth" in path], watched


@POSTURES
def test_the_wrapper_hashes_first_reads_second_and_execs_nats_server(tmp_path, posture):
    script = wrapper_script(pod_spec(adopter_render(tmp_path, posture)))
    lines = [line.strip() for line in script.splitlines() if line.strip()]

    assert lines[0] == "set -eu", f"the wrapper must stop on the first failure: {lines[0]!r}"
    assert lines[-1] == f"exec nats-server --config {CONFIG_FILE}", lines[-1]

    hash_line = f"sha256sum {IAM_FILE} {GATEWAY_FILE} > {HASH_FILE}"
    assert hash_line in lines, f"expected the hash line {hash_line!r} in:\n{script}"
    hash_at = script.index(hash_line)
    for path in PASSWORD_FILES:
        assert script.index(f'"{path}"') > hash_at, f"{path} is read before it is hashed"
    assert "/etc/nats-certs" not in script, "the TLS material is the reloader's, never in the hash"

    for variable in ("NATS_PASSWORD", "NATS_PASSWORD_GATEWAY"):
        check = f'[ -n "${variable}" ]'
        assert check in script, f"an empty {variable} must refuse to start"
        assert script.index(check) < script.index("exec nats-server")
    assert "export NATS_PASSWORD NATS_PASSWORD_GATEWAY" in lines, script


@POSTURES
def test_liveness_rechecks_the_hash_beside_healthz_at_upstream_timing(tmp_path, posture):
    spec = pod_spec(adopter_render(tmp_path, posture))
    nats = container(spec, BROKER_CONTAINER_NAME)
    liveness = nats["livenessProbe"]

    handlers = {key for key in ("exec", "httpGet", "tcpSocket", "grpc") if key in liveness}
    assert handlers == {"exec"}, f"liveness must carry one exec handler, found {handlers}"
    assert liveness["exec"]["command"] == ["/bin/sh", "-c", LIVENESS], liveness
    assert (liveness["periodSeconds"], liveness["failureThreshold"]) == (30, 3), liveness
    assert liveness["timeoutSeconds"] == 5, liveness

    # Readiness and startup stay the upstream httpGet probes.
    assert nats["readinessProbe"]["httpGet"]["path"] == "/healthz?js-server-only=true"
    assert nats["startupProbe"]["httpGet"]["path"] == "/healthz"


def test_lame_duck_and_termination_grace_stay_at_chart_defaults(tmp_path):
    documents = adopter_render(tmp_path)
    spec = pod_spec(documents)
    assert spec["terminationGracePeriodSeconds"] == 60, spec["terminationGracePeriodSeconds"]
    assert container(spec, BROKER_CONTAINER_NAME)["lifecycle"]["preStop"]["exec"]["command"] == [
        "nats-server",
        "-sl=ldm=/var/run/nats/nats.pid",
    ]
    conf = nats_conf(documents)
    assert '"lame_duck_duration": "30s"' in conf and '"lame_duck_grace_period": "10s"' in conf, conf


def test_the_broker_stays_a_single_replica_until_clustering_ships(tmp_path):
    """ADR-0924: one replica is a TEMPORARY D55 deviation, until ledger 1519."""
    statefulset = nats_statefulset(adopter_render(tmp_path))
    assert statefulset["spec"]["replicas"] == 1
    values = (CHART / "values.yaml").read_text()
    assert "D55" in values and "1519" in values, "values.yaml must name the deviation and its exit"


# ── THE RENDER-TIME REFUSALS ────────────────────────────────────────────────


def refused(tmp_path: Path, body: str) -> str:
    result = render_result("-f", overlay(tmp_path, "case.yaml", body))
    assert result.returncode != 0, f"the render passed for:\n{body}"
    return result.stderr


@pytest.mark.parametrize(
    "image",
    [
        "{repository: nats, tag: 2.14.6}",
        "{fullImageName: 'nats:2.14.6-scratch'}",
        "{repository: nats, tag: 2.14.6-alpine, digest: 'sha256:" + "0" * 64 + "'}",
    ],
    ids=["scratch-tag", "scratch-full-name", "digest-only"],
)
def test_a_broker_image_without_a_shell_is_refused(tmp_path, image):
    stderr = refused(tmp_path, f"nats:\n  container:\n    image: {image}\n")
    assert "platform: the broker image" in stderr, stderr
    assert "alpine" in stderr, stderr


def test_an_alpine_image_pinned_by_full_name_and_digest_renders(tmp_path):
    body = (
        "nats:\n  container:\n    image:\n"
        "      fullImageName: 'nats:2.14.6-alpine@sha256:" + "0" * 64 + "'\n"
    )
    result = render_result("-f", overlay(tmp_path, "ok.yaml", body))
    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize(
    "monitor",
    ["{enabled: false}", "{port: 9222}", "{tls: {enabled: true}}"],
    ids=["disabled", "other-port", "tls"],
)
def test_a_monitor_the_liveness_probe_cannot_reach_is_refused(tmp_path, monitor):
    stderr = refused(tmp_path, f"nats:\n  config:\n    monitor: {monitor}\n")
    if monitor == "{enabled: false}":
        # MEASURED, helm 3.18.4: helm renders the deeper subchart templates
        # first, and the upstream chart then renders no liveness probe, so the
        # chart's own `remove /livenessProbe/httpGet` fails inside the subchart
        # before the parent's arm runs. Either refusal is a refusal; a pass is not.
        assert (
            "platform: the broker's liveness probe" in stderr
            or "key livenessProbe does not exist" in stderr
        ), stderr
        return
    assert "platform: the broker's liveness probe" in stderr, stderr


@pytest.mark.parametrize(
    "body",
    ["nats:\n  container:\n    patch: []\n", "nats:\n  podTemplate:\n    patch: []\n"],
    ids=["container-patch", "pod-template-patch"],
)
def test_an_adopter_patch_that_drops_the_rotation_wiring_is_refused(tmp_path, body):
    stderr = refused(tmp_path, body)
    assert "platform: the broker's credential-rotation wiring" in stderr, stderr


# ── THE RENDERED WRAPPER AND PROBE AGAINST THE PINNED IMAGE ─────────────────


def nats_conf(documents: list[dict]) -> str:
    (config_map,) = [d for d in of_kind(documents, "ConfigMap") if name_of(d) == "nats-config"]
    return config_map["data"]["nats.conf"]


def rendered_image(documents: list[dict]) -> str:
    return container(pod_spec(documents), BROKER_CONTAINER_NAME)["image"]


class Broker:
    """A broker-image container whose PID 1 is `sleep`, so the rendered wrapper
    can be launched, killed and launched again the way kubelet restarts the
    container on a failed liveness check."""

    def __init__(self, image: str) -> None:
        self.image = image
        self.name = f"nats-rotation-check-{uuid.uuid4().hex[:10]}"

    def __enter__(self) -> "Broker":
        subprocess.run(
            ["docker", "run", "-d", "--name", self.name, "--entrypoint", "sh", self.image, "-c", "sleep 3600"],
            check=True,
            capture_output=True,
            timeout=60,
        )
        return self

    def exec(self, *args: str, detach: bool = False, env: dict | None = None) -> subprocess.CompletedProcess[str]:
        flags = ["-d"] if detach else []
        for key, value in (env or {}).items():
            flags += ["-e", f"{key}={value}"]
        return subprocess.run(
            ["docker", "exec", *flags, self.name, *args], capture_output=True, text=True, timeout=20
        )

    def __exit__(self, *exc: object) -> None:
        # LEDGER 1399: every container this suite starts is removed, whatever
        # the test outcome.
        subprocess.run(["docker", "rm", "-f", self.name], capture_output=True, timeout=30)


# The wrapper exports the two passwords only; every other `$VAR` the rendered
# config names comes from the pod spec's own `env`, which a bare container lacks.
POD_ENV = {"SERVER_NAME": "nats-0"}


def pod_env_covers_the_config(conf: str) -> None:
    referenced = set(re.findall(r"\$([A-Z_][A-Z0-9_]*)", conf))
    missing = referenced - set(POD_ENV) - {"NATS_PASSWORD", "NATS_PASSWORD_GATEWAY"}
    assert not missing, f"the rendered config references {sorted(missing)}, which this gate does not supply"


def seed(broker: Broker, conf: str) -> None:
    result = broker.exec(
        "sh", "-c",
        f"mkdir -p /etc/nats-config /var/run/nats {' '.join(d for _, d in PASSWORD_VOLUMES.values())}"
        f" && cat > {CONFIG_FILE} <<'EOF'\n{conf}\nEOF",
    )
    assert result.returncode == 0, result.stderr


def write_password(broker: Broker, path: str, printf_body: str) -> None:
    """`printf_body` is a printf FORMAT, so a test can write `\\r\\n` endings."""
    result = broker.exec("sh", "-c", f"printf '{printf_body}' > {path}")
    assert result.returncode == 0, result.stderr


def launch(broker: Broker, script: str) -> None:
    started = broker.exec("sh", "-c", script, detach=True, env=POD_ENV)
    assert started.returncode == 0, started.stderr


def stop(broker: Broker) -> None:
    broker.exec("sh", "-c", "kill $(cat /var/run/nats/nats.pid)")
    for _ in range(40):
        if broker.exec("sh", "-c", "pgrep nats-server").returncode != 0:
            return
        time.sleep(0.25)
    raise AssertionError("nats-server did not stop")


def probe(broker: Broker, command: str) -> int:
    return broker.exec("sh", "-c", command).returncode


def connect_answer(broker: Broker, user: str, password: str) -> str:
    """A raw NATS CONNECT over busybox `nc`; the image ships no NATS client."""
    frame = f'CONNECT {{"user":"{user}","pass":"{password}","verbose":false}}\\r\\nPING\\r\\n'
    return broker.exec("sh", "-c", f"(printf '{frame}'; sleep 1) | nc 127.0.0.1 4222").stdout


def wait_live(broker: Broker, liveness: str) -> None:
    for _ in range(60):
        if probe(broker, liveness) == 0:
            return
        time.sleep(0.25)
    log = broker.exec("sh", "-c", "ps; ls -la /var/run/nats")
    raise AssertionError(f"the rendered liveness probe never passed: {log.stdout} {log.stderr}")


def rendered_pieces(tmp_path: Path) -> tuple[str, str, str, str]:
    documents = adopter_render(tmp_path)
    spec = pod_spec(documents)
    liveness = container(spec, BROKER_CONTAINER_NAME)["livenessProbe"]["exec"]["command"][2]
    conf = nats_conf(documents)
    pod_env_covers_the_config(conf)
    return rendered_image(documents), wrapper_script(spec), liveness, conf


def test_the_rendered_wrapper_heals_a_rotation_against_a_real_broker(tmp_path):
    image, script, liveness, conf = rendered_pieces(tmp_path)
    with Broker(image) as broker:
        seed(broker, conf)
        write_password(broker, IAM_FILE, "iam-old")
        write_password(broker, GATEWAY_FILE, "gateway-old")
        launch(broker, script)
        wait_live(broker, liveness)
        assert "PONG" in connect_answer(broker, "gateway", "gateway-old")

        # THE ROTATION: only the mounted file changes; the server stays up.
        write_password(broker, GATEWAY_FILE, "gateway-new")
        assert "PONG" in connect_answer(broker, "gateway", "gateway-old"), "the server moved on its own"
        assert probe(broker, liveness) != 0, "liveness passed after a password file changed"

        # THE RESTART kubelet performs on that failed liveness: same wrapper, new process.
        stop(broker)
        launch(broker, script)
        wait_live(broker, liveness)
        assert "PONG" in connect_answer(broker, "gateway", "gateway-new")
        assert "Authorization Violation" in connect_answer(broker, "gateway", "gateway-old")
        assert "PONG" in connect_answer(broker, "iam", "iam-old"), "the unrotated account broke"


@pytest.mark.parametrize("ending", ["\\r\\n", "\\n\\r\\n", "\\r\\n\\r\\n\\n"], ids=["crlf", "lf-crlf", "mixed-run"])
def test_a_password_file_with_trailing_cr_and_lf_is_trimmed_as_the_clients_trim(tmp_path, ending):
    image, script, liveness, conf = rendered_pieces(tmp_path)
    with Broker(image) as broker:
        seed(broker, conf)
        write_password(broker, IAM_FILE, f"iam-pw{ending}")
        write_password(broker, GATEWAY_FILE, f"gateway-pw{ending}")
        launch(broker, script)
        wait_live(broker, liveness)
        assert "PONG" in connect_answer(broker, "iam", "iam-pw"), "the broker did not take the trimmed value"
        assert "PONG" in connect_answer(broker, "gateway", "gateway-pw")


@pytest.mark.parametrize(
    ("written", "exported"),
    [
        ("pw\\r\\n", "pw"),
        ("pw\\n\\r\\n", "pw"),
        ("pw\\r\\n\\r\\n\\n", "pw"),
        ("pw\\r", "pw"),
        ("p\\rw\\n", "p\rw"),
        ("pw", "pw"),
    ],
    ids=["crlf", "lf-crlf", "mixed-run", "bare-cr", "interior-cr-kept", "no-ending"],
)
def test_the_wrapper_exports_exactly_what_the_clients_send(tmp_path, written, exported):
    """THE TRIM ITSELF, byte for byte. MEASURED while building this gate:
    nats-server's own config parser drops a trailing `\\r` from an expanded
    variable, so the connect test above passes even with the wrapper's `\\r`
    trim deleted. This gate runs the RENDERED wrapper with its `exec` line
    swapped for a print, so it sees the exported value before nats-server can
    hide a difference. `trim_end_matches(['\\n', '\\r'])` keeps an interior
    `\\r`, so the wrapper must too."""
    image, script, _, conf = rendered_pieces(tmp_path)
    exec_line = f"exec nats-server --config {CONFIG_FILE}"
    assert script.count(exec_line) == 1, script
    # Hex, because Python's text mode reads a `\r` in stdout back as `\n`.
    probe_script = script.replace(
        exec_line, 'printf "%s|%s" "$NATS_PASSWORD" "$NATS_PASSWORD_GATEWAY" | od -An -tx1 | tr -d " \\n"'
    )
    with Broker(image) as broker:
        seed(broker, conf)
        write_password(broker, IAM_FILE, written)
        write_password(broker, GATEWAY_FILE, "gateway-pw\\n")
        result = broker.exec("sh", "-c", probe_script)
        assert result.returncode == 0, result.stderr
        got = bytes.fromhex(result.stdout.strip()).decode()
        assert got == f"{exported}|gateway-pw", repr(got)


@pytest.mark.parametrize("contents", ["empty", "missing", "only-newlines"])
def test_the_rendered_wrapper_refuses_to_start_without_a_password(tmp_path, contents):
    image, script, _, conf = rendered_pieces(tmp_path)
    with Broker(image) as broker:
        seed(broker, conf)
        write_password(broker, IAM_FILE, "iam-pw")
        if contents == "empty":
            write_password(broker, GATEWAY_FILE, "")
        elif contents == "only-newlines":
            write_password(broker, GATEWAY_FILE, "\\r\\n\\n")
        started = broker.exec("sh", "-c", script, env=POD_ENV)
        assert started.returncode != 0, f"the wrapper started nats-server with a {contents} password file"
        assert broker.exec("sh", "-c", "pgrep nats-server").returncode != 0, "a broker is running"


def test_the_image_under_test_is_the_one_the_chart_renders(tmp_path):
    image = rendered_image(adopter_render(tmp_path))
    assert image == "nats:2.14.6-alpine", image


# ── THE README: SELF-HEALING FIRST, `delete pod` AS THE FALLBACK ────────────

# The sentence `test_bootstrap.py` already anchors its "rotation" gate on. It
# stays true: the Job still never rotates a value.
ROTATION_MARKER = "Rotation is not provided."
RESTART_COMMAND = "kubectl -n yadgar delete pod nats-0"
ROLLOUT_RESTART_WARNING = "kubectl rollout restart statefulset/nats"
SELF_HEAL_MARKER = "the broker restarts itself"


def broker_runbook_failures(readme: str) -> list[str]:
    """PURE. Scoped to the section `ROTATION_MARKER` already owns."""
    sections = re.split(r"^## ", readme, flags=re.MULTILINE)
    holding = [section for section in sections if ROTATION_MARKER in section]
    if len(holding) != 1:
        return [
            f"expected exactly 1 section of README.md to carry `{ROTATION_MARKER}`, "
            f"found {len(holding)}"
        ]
    section = holding[0]
    failures = []
    if SELF_HEAL_MARKER not in section:
        failures.append(f"missing `{SELF_HEAL_MARKER}`: the broker's own heal is the primary path (ADR-0924)")
    if RESTART_COMMAND not in section:
        failures.append(f"missing the fallback command `{RESTART_COMMAND}` beside `{ROTATION_MARKER}`")
    if ROLLOUT_RESTART_WARNING not in section:
        failures.append(
            f"missing the warning against `{ROLLOUT_RESTART_WARNING}` (Argo's "
            f"selfHeal reverts the `restartedAt` annotation it writes)"
        )
    for secret, _ in PASSWORD_VOLUMES.values():
        if secret not in section:
            failures.append(f"missing `{secret}` beside the fallback command")
    return failures


def test_the_readme_documents_the_self_heal_and_the_fallback():
    failures = broker_runbook_failures(README.read_text())
    assert failures == [], "\n".join(failures)


def test_dropping_the_fallback_command_reddens_the_runbook_gate():
    without = README.read_text().replace(RESTART_COMMAND, "kubectl get pods")
    failures = broker_runbook_failures(without)
    assert any("fallback command" in failure for failure in failures), failures


def test_dropping_the_rollout_restart_warning_reddens_the_runbook_gate():
    without = README.read_text().replace(ROLLOUT_RESTART_WARNING, "kubectl get pods")
    failures = broker_runbook_failures(without)
    assert any("missing the warning against" in failure for failure in failures), failures
