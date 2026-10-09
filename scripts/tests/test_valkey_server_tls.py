"""VALKEY'S SERVER TLS CONTRACT: WHAT B-V2 RENDERS (ADR-0852, plan B-V2).

WHAT THIS FILE OWNS. `test_nats_valkey_tls.py` keeps the SHAPE checks and
NATS's own "nothing renders yet" refusal; this file owns what `valkey.tls.*`
actually renders now that `templates/valkey.yaml` and
`templates/ingress-policies.yaml` read it: the unix socket and its `emptyDir`
at every posture, the socket-based readiness and liveness probes, the hash
clause on liveness only when `tls.enabled`, the `--tls-*` server arguments and
the Secret mount only when `tls.enabled`, and the Deployment/Service/
NetworkPolicy port list following `plaintext` and `enabled`.

THE TWO NEW VALUES CHECKS `render-checks.yaml` GAINED (counted in
`test_render_checks.py`'s `EXPECTED_VALUES_CHECKS`): `valkey.create: true`
with no `valkey.tls` key at all, and `valkey.tls.enabled: false` together
with `valkey.tls.plaintext: false` (no network listener left at all).

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


def overlay(destination: Path, body: dict) -> Path:
    destination.mkdir(parents=True, exist_ok=True)
    path = destination / "overlay.yaml"
    path.write_text(yaml.safe_dump(body))
    return path


def render_valkey(tmp_path: Path, tls: dict | None = None) -> dict:
    """Render with `valkey.create: true` and the given `tls` overlay (or the
    chart's own default posture if `tls` is None); returns the Deployment."""
    body: dict = {"valkey": {"create": True}}
    if tls is not None:
        body["valkey"]["tls"] = tls
    path = overlay(tmp_path, body)
    result = render(CHART, *API_VERSIONS, "--namespace", "yadgar", "-f", str(ADOPTER_VALUES), "-f", str(path))
    assert result.returncode == 0, result.stderr
    found = {
        (document["kind"], document["metadata"]["name"]): document
        for document in objects(result.stdout)
    }
    return found


# ── THE SOCKET AND ITS emptyDir RENDER AT EVERY POSTURE ──────────────────────


@pytest.mark.parametrize(
    "tls",
    [
        None,
        {"enabled": False, "clientAuth": "off", "plaintext": True},
        {"enabled": True, "clientAuth": "off", "plaintext": True},
        {"enabled": True, "clientAuth": "required", "plaintext": False},
    ],
    ids=["absent", "off", "dual-stack", "tls-only"],
)
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


@pytest.mark.parametrize(
    "tls",
    [
        None,
        {"enabled": False, "clientAuth": "off", "plaintext": True},
        {"enabled": True, "clientAuth": "off", "plaintext": True},
        {"enabled": True, "clientAuth": "required", "plaintext": False},
    ],
    ids=["absent", "off", "dual-stack", "tls-only"],
)
def test_readiness_always_reads_the_socket(tmp_path, tls):
    found = render_valkey(tmp_path, tls)
    container = found[("Deployment", "valkey")]["spec"]["template"]["spec"]["containers"][0]
    probe = container["readinessProbe"]
    assert "exec" in probe, probe
    assert probe["exec"]["command"] == [
        "sh",
        "-c",
        "valkey-cli -s /run/valkey/valkey.sock ping | grep -q PONG",
    ]
    assert "tcpSocket" not in container["livenessProbe"], "liveness must not be tcpSocket (B-V2)"


# ── THE LIVENESS HASH CLAUSE, ONLY WHEN tls.enabled ──────────────────────────


def test_liveness_has_no_hash_clause_when_tls_is_off(tmp_path):
    found = render_valkey(tmp_path, {"enabled": False, "clientAuth": "off", "plaintext": True})
    container = found[("Deployment", "valkey")]["spec"]["template"]["spec"]["containers"][0]
    command = container["livenessProbe"]["exec"]["command"][2]
    assert command == "valkey-cli -s /run/valkey/valkey.sock ping | grep -q PONG"
    assert "sha256sum" not in command


def test_liveness_has_the_hash_clause_when_tls_is_enabled(tmp_path):
    found = render_valkey(tmp_path, {"enabled": True, "clientAuth": "off", "plaintext": True})
    container = found[("Deployment", "valkey")]["spec"]["template"]["spec"]["containers"][0]
    command = container["livenessProbe"]["exec"]["command"][2]
    assert "sha256sum -c --status /run/valkey/tls.sha256" in command
    assert command.startswith("valkey-cli -s /run/valkey/valkey.sock ping | grep -q PONG && ")
    args = container["args"][0]
    assert "sha256sum /etc/valkey/tls/tls.crt /etc/valkey/tls/tls.key > /run/valkey/tls.sha256" in args


# ── plaintext: false DROPS 6379 FROM DEPLOYMENT, SERVICE AND NETWORKPOLICY ──


def test_plaintext_false_drops_6379_everywhere(tmp_path):
    found = render_valkey(tmp_path, {"enabled": True, "clientAuth": "off", "plaintext": False})
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
    found = render_valkey(tmp_path, {"enabled": True, "clientAuth": "off", "plaintext": True})
    container = found[("Deployment", "valkey")]["spec"]["template"]["spec"]["containers"][0]
    ports = {p["containerPort"] for p in container["ports"]}
    assert ports == {6379, 6380}, ports


def test_the_off_posture_has_only_6379(tmp_path):
    found = render_valkey(tmp_path, {"enabled": False, "clientAuth": "off", "plaintext": True})
    container = found[("Deployment", "valkey")]["spec"]["template"]["spec"]["containers"][0]
    ports = {p["containerPort"] for p in container["ports"]}
    assert ports == {6379}, ports
    assert ("Secret", "valkey-tls") not in found or "volumeMounts" not in found[("Deployment", "valkey")]


# ── THE TLS SERVER ARGUMENTS AND THE SECRET MOUNT, ONLY WHEN tls.enabled ────


@pytest.mark.parametrize(
    ("client_auth", "tls_auth_clients"),
    [("off", "no"), ("optional", "optional"), ("required", "yes")],
)
def test_client_auth_maps_to_tls_auth_clients(tmp_path, client_auth, tls_auth_clients):
    found = render_valkey(tmp_path, {"enabled": True, "clientAuth": client_auth, "plaintext": True})
    args = found[("Deployment", "valkey")]["spec"]["template"]["spec"]["containers"][0]["args"][0]
    assert f"--tls-auth-clients {tls_auth_clients}" in args, args


def test_tls_enabled_mounts_the_valkey_tls_secret_and_nothing_else_does(tmp_path):
    off = render_valkey(tmp_path, {"enabled": False, "clientAuth": "off", "plaintext": True})
    off_container = off[("Deployment", "valkey")]["spec"]["template"]["spec"]["containers"][0]
    off_names = {m["name"] for m in off_container["volumeMounts"]}
    assert "valkey-tls" not in off_names, off_names

    on = render_valkey(tmp_path, {"enabled": True, "clientAuth": "required", "plaintext": True})
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
    found = render_valkey(tmp_path, {"enabled": False, "clientAuth": "off", "plaintext": True})
    args = found[("Deployment", "valkey")]["spec"]["template"]["spec"]["containers"][0]["args"][0]
    assert "--tls-" not in args, args
    assert "--port 6379" in args


def test_plaintext_false_without_tls_renders_port_zero(tmp_path):
    # Refused by render-checks (both-off guard) when enabled is ALSO false; this
    # is the only way to reach `--port 0` without TLS: a transitional state no
    # posture in `example/values.yaml` or the chart default uses, exercised here
    # only to pin `--port 0`'s source to `plaintext`, not to `enabled`.
    found = render_valkey(tmp_path, {"enabled": True, "clientAuth": "off", "plaintext": False})
    args = found[("Deployment", "valkey")]["spec"]["template"]["spec"]["containers"][0]["args"][0]
    assert "--port 0" in args, args


# ── THE TWO NEW GUARDS ───────────────────────────────────────────────────────


def refused(tmp_path: Path, body: dict) -> str:
    path = overlay(tmp_path, body)
    result = render(CHART, "-f", str(path))
    assert result.returncode != 0, f"rendered instead of refusing: {result.stdout[:400]}"
    return result.stderr


def test_create_true_with_tls_null_is_refused(tmp_path):
    stderr = refused(tmp_path, {"valkey": {"create": True, "tls": None}})
    assert "no valkey.tls key at all" in stderr, stderr


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
