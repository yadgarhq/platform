"""NATS AND VALKEY TLS: THE SERVING LEAVES, AND THE EXPAND THAT DECLARES THE KEYS (B-L1).

WHAT THIS CHART VERSION DOES. Two serving leaves join `certificates.leaves` —
`nats-tls` and `valkey-tls`, on the next two free rungs (786h, 792h; ADR-0588) —
and the platform-owned switches B-N2 and B-V2 will render are DECLARED:
`nats.tls.enabled`, `nats.tls.clientAuth`, `valkey.tls.enabled`,
`valkey.tls.clientAuth` and `valkey.tls.plaintext`. Nothing reads them yet.

WHAT IT REFUSES, AND WHY THAT IS THE WHOLE POINT OF AN EXPAND (plan K-8 step 1).
A values file that says `enabled: true` while no template renders a TLS listener
looks encrypted and is not. So every value the contracts have not rendered yet —
`enabled: true`, `plaintext: false`, any `clientAuth` other than `"off"` — is
refused with ONE sentence naming the unit that renders it, and B-N2 / B-V2 lift
that refusal. The off posture renders exactly what an absent key renders.

SHAPES ARE REFUSED TOO, BY NAME, because the schema closes key sets and nothing
else (ADR-0847): a non-map block, a non-bool switch, and a `clientAuth` that is not
a quoted string (YAML reads a bare `off` as false — the B-U5E convention) or not
one of the values its server has. NATS has no `optional` (ADR-0854).

EVERY REFUSAL CASE IS A BARE RENDER of the chart's own defaults plus one overlay:
every `create` toggle is false there, so no capability check can fire and the
refusal is attributable to these checks alone.

Run: python3 -m pytest scripts/tests/test_nats_valkey_tls.py -q
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

# THE ONE SENTENCE every not-yet-rendered value is refused with (plan B-L1).
NOT_RENDERED_YET = "this chart version declares the key; B-N2 / B-V2 renders it"

# THE OFF POSTURE, every key stated. The contracts will make each of these
# required; today each is accepted and changes nothing.
OFF_POSTURE = {
    "nats": {"tls": {"enabled": False, "clientAuth": "off"}},
    "valkey": {"tls": {"enabled": False, "clientAuth": "off", "plaintext": True}},
}

# THE TWO SERVING LEAVES, measured against the names the live Services carry
# (`kubectl --context kind-yadgar -n yadgar get svc nats valkey`, 2026-10-08).
SERVING_LEAVES = {"nats-tls": ("nats", "786h"), "valkey-tls": ("valkey", "792h")}


def overlay(destination: Path, body: dict) -> Path:
    destination.mkdir(parents=True, exist_ok=True)
    path = destination / "overlay.yaml"
    path.write_text(yaml.safe_dump(body))
    return path


def refused(tmp_path: Path, body: dict | str) -> str:
    """A BARE render of the defaults plus `body`; asserts a refusal, returns stderr."""
    tmp_path.mkdir(parents=True, exist_ok=True)
    path = tmp_path / "overlay.yaml"
    path.write_text(body if isinstance(body, str) else yaml.safe_dump(body))
    result = render(CHART, "-f", str(path))
    assert result.returncode != 0, f"rendered instead of refusing: {result.stdout[:400]}"
    assert "--api-versions" not in result.stderr, (
        f"a capability check refused, not the TLS checks: {result.stderr}"
    )
    return result.stderr


# ── THE SERVING LEAVES ───────────────────────────────────────────────────────


def test_the_nats_and_valkey_serving_leaves_name_every_service_form():
    """Each leaf: the Service's four names, `server auth` only, its own rung."""
    # THE NAMESPACE IS STATED, because `helm template` otherwise takes it from
    # whatever kubeconfig context the runner has, and the three long forms carry it.
    result = render(CHART, *API_VERSIONS, "--namespace", "yadgar", "-f", str(ADOPTER_VALUES))
    assert result.returncode == 0, result.stderr
    found = {
        document["metadata"]["name"]: document["spec"]
        for document in objects(result.stdout)
        if document["kind"] == "Certificate"
    }
    for name, (service, rung) in SERVING_LEAVES.items():
        assert name in found, f"{name} is not rendered: {sorted(found)}"
        spec = found[name]
        assert spec["secretName"] == name
        assert spec["commonName"] == service
        assert spec["dnsNames"] == [
            service,
            f"{service}.yadgar",
            f"{service}.yadgar.svc",
            f"{service}.yadgar.svc.cluster.local",
        ], spec["dnsNames"]
        assert spec["usages"] == ["server auth", "digital signature"], spec["usages"]
        assert spec["renewBefore"] == rung, spec["renewBefore"]


# ── THE OFF POSTURE CHANGES NOTHING ──────────────────────────────────────────


def test_the_off_posture_renders_exactly_what_the_absent_keys_render(tmp_path):
    absent = render(CHART, *API_VERSIONS, "-f", str(ADOPTER_VALUES))
    stated = render(
        CHART,
        *API_VERSIONS,
        "-f",
        str(ADOPTER_VALUES),
        "-f",
        str(overlay(tmp_path, OFF_POSTURE)),
    )
    assert absent.returncode == 0, absent.stderr
    assert stated.returncode == 0, stated.stderr
    assert stated.stdout == absent.stdout, "the off posture changed the render"


def test_valkey_client_auth_off_is_accepted_without_the_other_keys(tmp_path):
    """Each key is validated when present; none requires another yet."""
    path = overlay(tmp_path, {"valkey": {"tls": {"clientAuth": "off"}}})
    result = render(CHART, "-f", str(path))
    assert result.returncode == 0, result.stderr


# ── VALUES THE CONTRACTS RENDER, REFUSED UNTIL THEY DO ───────────────────────


@pytest.mark.parametrize(
    ("body", "named"),
    [
        ({"nats": {"tls": {"enabled": True}}}, "nats.tls.enabled: true"),
        ({"valkey": {"tls": {"enabled": True}}}, "valkey.tls.enabled: true"),
        ({"valkey": {"tls": {"plaintext": False}}}, "valkey.tls.plaintext: false"),
        ({"nats": {"tls": {"clientAuth": "required"}}}, 'nats.tls.clientAuth: "required"'),
        ({"valkey": {"tls": {"clientAuth": "optional"}}}, 'valkey.tls.clientAuth: "optional"'),
        ({"valkey": {"tls": {"clientAuth": "required"}}}, 'valkey.tls.clientAuth: "required"'),
    ],
    ids=[
        "nats-enabled",
        "valkey-enabled",
        "valkey-plaintext-false",
        "nats-required",
        "valkey-optional",
        "valkey-required",
    ],
)
def test_a_value_nothing_renders_yet_is_refused_with_the_one_sentence(tmp_path, body, named):
    stderr = refused(tmp_path, body)
    assert NOT_RENDERED_YET in stderr, stderr
    assert named in stderr, stderr


def test_every_unrendered_value_is_named_in_one_refusal(tmp_path):
    stderr = refused(
        tmp_path,
        {
            "nats": {"tls": {"enabled": True, "clientAuth": "required"}},
            "valkey": {"tls": {"enabled": True, "plaintext": False}},
        },
    )
    assert NOT_RENDERED_YET in stderr, stderr
    for named in (
        "nats.tls.enabled: true",
        'nats.tls.clientAuth: "required"',
        "valkey.tls.enabled: true",
        "valkey.tls.plaintext: false",
    ):
        assert named in stderr, (named, stderr)


# ── SHAPES, REFUSED BY NAME ──────────────────────────────────────────────────


def test_a_bare_off_is_refused_as_not_a_quoted_string(tmp_path):
    """`clientAuth: off` unquoted is YAML false (B-U5E convention, item 1)."""
    stderr = refused(tmp_path, "nats:\n  tls:\n    clientAuth: off\n")
    assert "`nats.tls.clientAuth` must be a quoted string" in stderr, stderr
    assert 'write `clientAuth: "off"`' in stderr, stderr
    assert NOT_RENDERED_YET not in stderr, stderr


def test_nats_has_no_optional_mode(tmp_path):
    stderr = refused(tmp_path, {"nats": {"tls": {"clientAuth": "optional"}}})
    assert "`nats.tls.clientAuth` must be `off` or `required`" in stderr, stderr
    assert "NATS has no optional client-certificate mode" in stderr, stderr
    assert NOT_RENDERED_YET not in stderr, stderr


def test_an_unknown_valkey_client_auth_is_refused(tmp_path):
    stderr = refused(tmp_path, {"valkey": {"tls": {"clientAuth": "bogus"}}})
    assert "`valkey.tls.clientAuth` must be `off`, `optional` or `required`" in stderr, stderr


@pytest.mark.parametrize(
    ("body", "named"),
    [
        ('nats:\n  tls:\n    enabled: "false"\n', "`nats.tls.enabled` is a string"),
        ('valkey:\n  tls:\n    enabled: "true"\n', "`valkey.tls.enabled` is a string"),
        # helm reads every YAML number as a float64.
        ("valkey:\n  tls:\n    plaintext: 1\n", "`valkey.tls.plaintext` is a float64"),
    ],
    ids=["nats-enabled-string", "valkey-enabled-string", "valkey-plaintext-int"],
)
def test_a_non_bool_switch_is_refused_by_name(tmp_path, body, named):
    stderr = refused(tmp_path, body)
    assert named in stderr, stderr
    assert "rather than true or false" in stderr, stderr


@pytest.mark.parametrize(
    ("body", "named"),
    [
        ("nats:\n  tls: true\n", "`nats.tls` is a bool rather than a mapping"),
        ('valkey:\n  tls: "on"\n', "`valkey.tls` is a string rather than a mapping"),
        ("nats:\n  tls: null\n", "`nats.tls` is a null rather than a mapping"),
    ],
    ids=["nats-bool", "valkey-string", "nats-null"],
)
def test_a_non_map_tls_block_is_refused_by_name(tmp_path, body, named):
    stderr = refused(tmp_path, body)
    assert named in stderr, stderr
