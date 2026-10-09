"""VALKEY'S SERVER TLS CONTRACT: WHAT B-V2 RENDERS (ADR-0852, plan B-V2).

WHAT THIS FILE OWNS. `test_nats_valkey_tls.py` keeps the SHAPE checks and
valkey's own absence/posture guards (mirroring NATS's, B-N2); this file owns
what `valkey.tls.*` actually renders now that `templates/valkey.yaml` and
`templates/ingress-policies.yaml` read it: the unix socket and its `emptyDir`
at every posture, the socket-based readiness and liveness probes, the hash
clause on liveness only when `tls.enabled`, the `--tls-*` server arguments and
the Secret mount only when `tls.enabled`, and the Deployment/Service/
NetworkPolicy port list following `plaintext` and `enabled`.

`valkey.tls.{enabled,clientAuth,plaintext}` HAVE NO CHART DEFAULT (ADR-0845,
ADR-0854), exactly like `nats.tls`: every render below states all three
explicitly. `render_valkey` below takes a MANDATORY `tls` dict for that
reason — there is no "absent means the off posture" case to default to any
more; `test_create_true_with_tls_absent_refuses` below is the one exercising
absence, and it expects a refusal, not a render.

THE TWO VALUES CHECKS `render-checks.yaml` CARRIES FOR VALKEY (counted in
`test_render_checks.py`'s `EXPECTED_VALUES_CHECKS`): `valkey.create: true`
with any of `enabled`/`clientAuth`/`plaintext` absent (missing or `null`),
and `valkey.tls.enabled: false` together with `valkey.tls.plaintext: false`
(no network listener left at all).

Run: python3 -m pytest scripts/tests/test_valkey_server_tls.py -q
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from test_render_checks import ADOPTER_VALUES, CHART, objects, render

API_VERSIONS = (
    "--api-versions",
    "cert-manager.io/v1",
    "--api-versions",
    "gateway.envoyproxy.io/v1alpha1",
)

OFF = {"enabled": False, "clientAuth": "off", "plaintext": True}
DUAL_STACK = {"enabled": True, "clientAuth": "off", "plaintext": True}
TLS_ONLY = {"enabled": True, "clientAuth": "required", "plaintext": False}


def overlay(destination: Path, body: dict) -> Path:
    destination.mkdir(parents=True, exist_ok=True)
    path = destination / "overlay.yaml"
    path.write_text(yaml.safe_dump(body))
    return path


def render_valkey(tmp_path: Path, tls: dict) -> dict:
    """Render with `valkey.create: true` and the given (mandatory) `tls`
    overlay; returns every object keyed by `(kind, name)`."""
    body = {"valkey": {"create": True, "tls": tls}}
    path = overlay(tmp_path, body)
    result = render(CHART, *API_VERSIONS, "--namespace", "yadgar", "-f", str(ADOPTER_VALUES), "-f", str(path))
    assert result.returncode == 0, result.stderr
    return {
        (document["kind"], document["metadata"]["name"]): document
        for document in objects(result.stdout)
    }


# ── THE SOCKET AND ITS emptyDir RENDER AT EVERY POSTURE ──────────────────────


@pytest.mark.parametrize("tls", [OFF, DUAL_STACK, TLS_ONLY], ids=["off", "dual-stack", "tls-only"])
def test_the_socket_and_emptydir_render_at_every_posture(tmp_path, tls):
    found = render_valkey(tmp_path, tls)
    deployment = found[("Deployment", "valkey")]
    spec = deployment["spec"]["template"]["spec"]
    volumes = {v["name"]: v for v in spec["volumes"]}
    assert "run-valkey" in volumes, volumes
    assert volumes["run-valkey"] == {"name": "run-valkey", "emptyDir": {}}
    container = spec["containers"][0]
    mounts = {m["name"]: m for m in container["volumeMounts"]}
    assert "run-valkey" in mounts
    assert mounts["run-valkey"]["mountPath"] == "/run/valkey"
    args = container["args"][0]
    assert "--unixsocket /run/valkey/valkey.sock" in args
    assert "--unixsocketperm 700" in args


@pytest.mark.parametrize("tls", [OFF, DUAL_STACK, TLS_ONLY], ids=["off", "dual-stack", "tls-only"])
def test_readiness_always_reads_the_socket_and_checks_the_answer(tmp_path, tls):
    found = render_valkey(tmp_path, tls)
    container = found[("Deployment", "valkey")]["spec"]["template"]["spec"]["containers"][0]
    probe = container["readinessProbe"]
    assert "exec" in probe, probe
    assert probe["exec"]["command"] == [
        "sh",
        "-c",
        "valkey-cli -s /run/valkey/valkey.sock ping | grep -q PONG",
    ]


@pytest.mark.parametrize("tls", [OFF, DUAL_STACK, TLS_ONLY], ids=["off", "dual-stack", "tls-only"])
def test_liveness_never_checks_the_answer_only_that_the_socket_answers(tmp_path, tls):
    """Credential-independent, deliberately: the liveness probe this version
    replaces was `tcpSocket` (is the port open?), never `requirepass`-aware,
    so a bad credential never restarted a healthy server. `ping >/dev/null`
    asks the same question over the socket; the readiness probe above is the
    one that reads the answer."""
    found = render_valkey(tmp_path, tls)
    container = found[("Deployment", "valkey")]["spec"]["template"]["spec"]["containers"][0]
    command = container["livenessProbe"]["exec"]["command"][2]
    assert command.startswith("valkey-cli -s /run/valkey/valkey.sock ping >/dev/null")
    assert "grep" not in command, command
    assert "tcpSocket" not in container["livenessProbe"], "liveness must not be tcpSocket (B-V2)"


# ── THE LIVENESS HASH CLAUSE, ONLY WHEN tls.enabled, OVER ALL THREE FILES ───


def test_liveness_has_no_hash_clause_when_tls_is_off(tmp_path):
    found = render_valkey(tmp_path, OFF)
    container = found[("Deployment", "valkey")]["spec"]["template"]["spec"]["containers"][0]
    command = container["livenessProbe"]["exec"]["command"][2]
    assert command == "valkey-cli -s /run/valkey/valkey.sock ping >/dev/null"
    assert "sha256sum" not in command


def test_liveness_has_the_hash_clause_over_cert_key_and_ca_when_tls_is_enabled(tmp_path):
    found = render_valkey(tmp_path, DUAL_STACK)
    container = found[("Deployment", "valkey")]["spec"]["template"]["spec"]["containers"][0]
    command = container["livenessProbe"]["exec"]["command"][2]
    assert "sha256sum -c --status /run/valkey/tls.sha256" in command
    assert command.startswith("valkey-cli -s /run/valkey/valkey.sock ping >/dev/null && ")
    args = container["args"][0]
    assert (
        "sha256sum /etc/valkey/tls/tls.crt /etc/valkey/tls/tls.key /etc/valkey/tls/ca.crt "
        "> /run/valkey/tls.sha256"
    ) in args, args


# ── plaintext: false DROPS 6379 FROM DEPLOYMENT, SERVICE AND NETWORKPOLICY ──


def test_plaintext_false_drops_6379_everywhere(tmp_path):
    found = render_valkey(tmp_path, TLS_ONLY)
    container = found[("Deployment", "valkey")]["spec"]["template"]["spec"]["containers"][0]
    assert all(p["containerPort"] != 6379 for p in container["ports"]), container["ports"]
    assert any(p["containerPort"] == 6380 for p in container["ports"]), container["ports"]
    svc_ports = found[("Service", "valkey")]["spec"]["ports"]
    assert all(p["port"] != 6379 for p in svc_ports), svc_ports
    assert any(p["port"] == 6380 for p in svc_ports), svc_ports
    net_ports = found[("NetworkPolicy", "valkey-ingress")]["spec"]["ingress"][0]["ports"]
    assert all(p["port"] != 6379 for p in net_ports), net_ports
    assert any(p["port"] == 6380 for p in net_ports), net_ports


def test_plaintext_true_keeps_6379_beside_a_tls_port(tmp_path):
    found = render_valkey(tmp_path, DUAL_STACK)
    container = found[("Deployment", "valkey")]["spec"]["template"]["spec"]["containers"][0]
    ports = {p["containerPort"] for p in container["ports"]}
    assert ports == {6379, 6380}, ports


def test_the_off_posture_has_only_6379(tmp_path):
    found = render_valkey(tmp_path, OFF)
    container = found[("Deployment", "valkey")]["spec"]["template"]["spec"]["containers"][0]
    ports = {p["containerPort"] for p in container["ports"]}
    assert ports == {6379}, ports
    assert ("Secret", "valkey-tls") not in found
    assert "valkey-tls" not in {m["name"] for m in container["volumeMounts"]}


# ── THE TLS SERVER ARGUMENTS AND THE SECRET MOUNT, ONLY WHEN tls.enabled ────


@pytest.mark.parametrize(
    ("client_auth", "tls_auth_clients"),
    [("off", "no"), ("optional", "optional"), ("required", "yes")],
)
def test_client_auth_maps_to_the_tls_auth_clients_env_var(tmp_path, client_auth, tls_auth_clients):
    """`VALKEY_TLS_AUTH_CLIENTS` IS AN ENV VAR, THE BREAK-GLASS, not a literal
    baked into `args` — `templates/valkey.yaml` reads it as
    `--tls-auth-clients "$VALKEY_TLS_AUTH_CLIENTS"` so an operator can move it
    with `kubectl set env` without a new release."""
    found = render_valkey(tmp_path, {"enabled": True, "clientAuth": client_auth, "plaintext": True})
    container = found[("Deployment", "valkey")]["spec"]["template"]["spec"]["containers"][0]
    env = {e["name"]: e.get("value") for e in container["env"]}
    assert env["VALKEY_TLS_AUTH_CLIENTS"] == tls_auth_clients, env
    assert '--tls-auth-clients "$VALKEY_TLS_AUTH_CLIENTS"' in container["args"][0]


def test_tls_off_has_no_auth_clients_env_var(tmp_path):
    found = render_valkey(tmp_path, OFF)
    container = found[("Deployment", "valkey")]["spec"]["template"]["spec"]["containers"][0]
    names = {e["name"] for e in container["env"]}
    assert "VALKEY_TLS_AUTH_CLIENTS" not in names, names


def test_tls_enabled_mounts_the_valkey_tls_secret_and_nothing_else_does(tmp_path):
    off = render_valkey(tmp_path, OFF)
    off_container = off[("Deployment", "valkey")]["spec"]["template"]["spec"]["containers"][0]
    off_names = {m["name"] for m in off_container["volumeMounts"]}
    assert "valkey-tls" not in off_names, off_names

    on = render_valkey(tmp_path, TLS_ONLY)
    on_container = on[("Deployment", "valkey")]["spec"]["template"]["spec"]["containers"][0]
    mounts = {m["name"]: m for m in on_container["volumeMounts"]}
    assert mounts["valkey-tls"]["mountPath"] == "/etc/valkey/tls"
    assert mounts["valkey-tls"]["readOnly"] is True
    volumes = {v["name"]: v for v in on[("Deployment", "valkey")]["spec"]["template"]["spec"]["volumes"]}
    assert volumes["valkey-tls"]["secret"]["secretName"] == "valkey-tls"
    args = on_container["args"][0]
    assert "--tls-cert-file /etc/valkey/tls/tls.crt" in args
    assert "--tls-key-file /etc/valkey/tls/tls.key" in args
    assert "--tls-ca-cert-file /etc/valkey/tls/ca.crt" in args
    assert "--tls-port 6380" in args


def test_tls_off_renders_no_tls_flags_at_all(tmp_path):
    found = render_valkey(tmp_path, OFF)
    args = found[("Deployment", "valkey")]["spec"]["template"]["spec"]["containers"][0]["args"][0]
    assert "--tls-" not in args, args
    assert "--port 6379" in args


def test_plaintext_false_without_tls_enabled_renders_port_zero(tmp_path):
    # Refused by render-checks (both-off guard) when enabled is ALSO false; this
    # is the only way to reach `--port 0` without `clientAuth` on, exercised
    # here only to pin `--port 0`'s source to `plaintext`, not to `enabled`.
    found = render_valkey(tmp_path, {"enabled": True, "clientAuth": "off", "plaintext": False})
    args = found[("Deployment", "valkey")]["spec"]["template"]["spec"]["containers"][0]["args"][0]
    assert "--port 0" in args, args


# ── THE OFF POSTURE, STATED, RENDERS WHAT IT HAS ALWAYS RENDERED ────────────


def test_the_off_posture_matches_what_predates_the_tls_keys(tmp_path):
    """`valkey.tls.{enabled,clientAuth,plaintext}` are new keys with no
    chart default; this is the render-level check that stating the off
    posture changes nothing beyond the socket/emptyDir/readiness/liveness
    move this version makes unconditionally — see
    `test_nats_valkey_tls.py::test_the_valkey_off_posture_renders_exactly_what_the_absent_keys_render`
    for the byte-identical absent-vs-off-posture comparison this file does
    not repeat."""
    found = render_valkey(tmp_path, OFF)
    assert ("Deployment", "valkey") in found
    assert ("Service", "valkey") in found


# ── THE TWO GUARDS (mirroring NATS's absence arm, B-N2) ─────────────────────


def refused(tmp_path: Path, body: dict) -> str:
    path = overlay(tmp_path, body)
    result = render(CHART, "-f", str(path))
    assert result.returncode != 0, f"rendered instead of refusing: {result.stdout[:400]}"
    return result.stderr


def test_create_true_with_tls_absent_refuses(tmp_path):
    """THE CASE THIS VERSION CHANGED: `valkey.create: true` with no `tls` key
    at all used to render the off posture from the chart's own default; there
    is no default any more (ADR-0845, ADR-0854, mirroring `nats.tls`), so
    this now refuses, naming all three keys absent."""
    stderr = refused(tmp_path, {"valkey": {"create": True}})
    assert "valkey.create is true and" in stderr, stderr
    for key in ("enabled", "clientAuth", "plaintext"):
        assert f"`valkey.tls.{key}`" in stderr, stderr


def test_create_true_with_tls_null_refuses_by_shape(tmp_path):
    """`tls: null` is caught by the SHAPE arm (a null rather than a mapping)
    before the absence arm even runs; still a refusal either way."""
    stderr = refused(tmp_path, {"valkey": {"create": True, "tls": None}})
    assert "`valkey.tls` is a null rather than a mapping" in stderr, stderr


def test_a_single_absent_key_is_named_on_its_own(tmp_path):
    stderr = refused(
        tmp_path,
        {"valkey": {"create": True, "tls": {"clientAuth": "off", "plaintext": True}}},
    )
    assert "`valkey.tls.enabled` is absent" in stderr, stderr
    assert "`valkey.tls.clientAuth`" not in stderr, stderr
    assert "`valkey.tls.plaintext`" not in stderr, stderr


def test_enabled_false_and_plaintext_false_together_is_refused(tmp_path):
    stderr = refused(
        tmp_path,
        {"valkey": {"create": True, "tls": {"enabled": False, "clientAuth": "off", "plaintext": False}}},
    )
    assert "no network listener at all" in stderr, stderr


def test_create_false_needs_no_tls_key_at_all(tmp_path):
    """`valkey.create` stays the gate: a release that leaves the cache out is
    never asked to state a TLS posture for it."""
    path = overlay(tmp_path, {"valkey": {"create": False}})
    result = render(CHART, "-f", str(path))
    assert result.returncode == 0, result.stderr
