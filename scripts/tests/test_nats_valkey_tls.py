"""NATS AND VALKEY TLS: THE SERVING LEAVES (B-L1), NATS'S CONTRACT (B-N2), VALKEY'S EXPAND.

THE SERVING LEAVES. `nats-tls` and `valkey-tls` sit in `certificates.leaves` on
the next two free rungs (786h, 792h; ADR-0588).

NATS'S CONTRACT (B-N2, ledger 925, ADR-0852). Two sources describe the broker's
TLS, and the render check makes them agree. The platform-owned switch
`nats.tls.enabled` and mode `nats.tls.clientAuth` ("off" | "required"; NATS has
no optional mode, ADR-0854) are REQUIRED with no default while `nats.create` is
true (ADR-0845) — they exist because the parent always sees the upstream
subchart's own default `false` for `nats.config.nats.tls.enabled`. The upstream
keys do the work: `nats.config.nats.tls.{enabled, secretName: nats-tls}`,
`nats.config.nats.tls.merge.{verify, ca_file}` and, for the transport step only,
`nats.config.merge.allow_non_tls`. `nats.podTemplate.configChecksumAnnotation`
is on, because `allow_non_tls` is not hot-reloadable: every config change is a
pod roll.

VALKEY STAYS AT THE EXPAND until B-V2: its keys are validated when present, and
every value nothing renders yet — `enabled: true`, `plaintext: false`, any
`clientAuth` other than "off" — is refused with ONE sentence naming B-V2.

SHAPES ARE REFUSED BY NAME for both, because the schema closes key sets and
nothing else (ADR-0847): a non-map block, a non-bool switch, and a `clientAuth`
that is not a quoted string (YAML reads a bare `off` as false — the B-U5E
convention) or not one of the values its server has.

EVERY SHAPE AND EXPAND REFUSAL IS A BARE RENDER of the chart's own defaults plus
one overlay: every `create` toggle is false there, so no capability check can
fire and the refusal is attributable to these checks alone. The contract cases
render `example/values.yaml` (`nats.create: true`) with the API groups stated.

Run: python3 -m pytest scripts/tests/test_nats_valkey_tls.py -q
"""

from __future__ import annotations

import difflib
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

# THE ONE SENTENCE every not-yet-rendered valkey value is refused with (B-L1's
# expand, narrowed to valkey by B-N2).
NOT_RENDERED_YET = "this chart version declares the key; B-V2 renders it"

# VALKEY'S OFF POSTURE, every key stated. B-V2 will make each required; today
# each is accepted and changes nothing.
VALKEY_OFF_POSTURE = {
    "valkey": {"tls": {"enabled": False, "clientAuth": "off", "plaintext": True}},
}

# THE NATS POSTURES, ONE PER HOP STEP (plan B-N4.1, B-N4.3, B-N5). `example/values.yaml`
# carries the off posture; each of these is overlaid on it.
NATS_CA_FILE = "/etc/nats-certs/nats/ca.crt"
NATS_TRANSPORT = {  # B-N4.1: TLS on, plaintext clients still accepted
    "nats": {
        "tls": {"enabled": True, "clientAuth": "off"},
        "config": {
            "nats": {"tls": {"enabled": True, "secretName": "nats-tls"}},
            "merge": {"allow_non_tls": True},
        },
    }
}
NATS_TLS_ONLY = {  # B-N4.3: `allow_non_tls` dropped
    "nats": {
        "tls": {"enabled": True, "clientAuth": "off"},
        "config": {"nats": {"tls": {"enabled": True, "secretName": "nats-tls"}}},
    }
}
NATS_VERIFIED = {  # B-N5: every client presents a leaf the internal CA issued
    "nats": {
        "tls": {"enabled": True, "clientAuth": "required"},
        "config": {
            "nats": {
                "tls": {
                    "enabled": True,
                    "secretName": "nats-tls",
                    "merge": {"verify": True, "ca_file": NATS_CA_FILE},
                }
            }
        },
    }
}

# THE ONE SENTENCE the absent-key refusal and the disagreement refusal each open with.
NATS_KEYS_ABSENT = "nats.create is true and"
NATS_DISAGREE = "platform: the NATS TLS keys disagree:"

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


def test_the_valkey_off_posture_renders_exactly_what_the_absent_keys_render(tmp_path):
    absent = render(CHART, *API_VERSIONS, "-f", str(ADOPTER_VALUES))
    stated = render(
        CHART,
        *API_VERSIONS,
        "-f",
        str(ADOPTER_VALUES),
        "-f",
        str(overlay(tmp_path, VALKEY_OFF_POSTURE)),
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
        ({"valkey": {"tls": {"enabled": True}}}, "valkey.tls.enabled: true"),
        ({"valkey": {"tls": {"plaintext": False}}}, "valkey.tls.plaintext: false"),
        ({"valkey": {"tls": {"clientAuth": "optional"}}}, 'valkey.tls.clientAuth: "optional"'),
        ({"valkey": {"tls": {"clientAuth": "required"}}}, 'valkey.tls.clientAuth: "required"'),
    ],
    ids=[
        "valkey-enabled",
        "valkey-plaintext-false",
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
        {"valkey": {"tls": {"enabled": True, "plaintext": False, "clientAuth": "required"}}},
    )
    assert NOT_RENDERED_YET in stderr, stderr
    for named in (
        "valkey.tls.enabled: true",
        "valkey.tls.plaintext: false",
        'valkey.tls.clientAuth: "required"',
    ):
        assert named in stderr, (named, stderr)


def test_nats_values_are_no_longer_refused_as_unrendered(tmp_path):
    """B-N2 LIFTS THE EXPAND REFUSAL FOR NATS: nothing names it in a bare render."""
    path = overlay(tmp_path, {"nats": {"tls": {"enabled": True, "clientAuth": "required"}}})
    result = render(CHART, "-f", str(path))
    assert result.returncode == 0, result.stderr


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


# ── NATS: THE CONTRACT (B-N2) ────────────────────────────────────────────────


def adopter_without_nats_tls(destination: Path, *drop: str) -> Path:
    """`example/values.yaml` with the named `nats.tls` keys deleted (all, if none named)."""
    values = yaml.safe_load(ADOPTER_VALUES.read_text())
    tls = values["nats"]["tls"]
    for key in drop or tuple(tls):
        del tls[key]
    if not tls:
        del values["nats"]["tls"]
    destination.mkdir(parents=True, exist_ok=True)
    path = destination / "adopter-without-nats-tls.yaml"
    path.write_text(yaml.safe_dump(values))
    return path


def contract(tmp_path: Path, body: dict | None = None, *extra: str) -> object:
    """`example/values.yaml` plus `body`, with both API groups stated."""
    arguments = [*API_VERSIONS, "--namespace", "yadgar", "-f", str(ADOPTER_VALUES)]
    if body is not None:
        arguments += ["-f", str(overlay(tmp_path, body))]
    return render(CHART, *arguments, *extra)


def contract_refused(tmp_path: Path, body: dict) -> str:
    result = contract(tmp_path, body)
    assert result.returncode != 0, f"rendered instead of refusing: {result.stdout[:400]}"
    assert "--api-versions" not in result.stderr, result.stderr
    assert NATS_DISAGREE in result.stderr, result.stderr
    return result.stderr


def nats_objects(stdout: str) -> dict[str, dict]:
    return {
        f"{document['kind']}/{document['metadata']['name']}": document
        for document in objects(stdout)
        if document["metadata"]["name"].startswith("nats")
    }


def broker_config(stdout: str) -> dict:
    """The nats-server config the upstream chart renders (JSON, which YAML reads)."""
    config_map = nats_objects(stdout)["ConfigMap/nats-config"]
    return yaml.safe_load(config_map["data"]["nats.conf"])


def reloader_args(stdout: str) -> list[str]:
    pod = nats_objects(stdout)["StatefulSet/nats"]["spec"]["template"]["spec"]
    (reloader,) = [c for c in pod["containers"] if c["name"] == "reloader"]
    return reloader["args"]


# THE REQUIRED KEYS (ADR-0845, ADR-0854).


@pytest.mark.parametrize(
    ("drop", "named"),
    [
        ((), "`nats.tls.enabled` and `nats.tls.clientAuth` are absent"),
        (("enabled",), "`nats.tls.enabled` is absent"),
        (("clientAuth",), "`nats.tls.clientAuth` is absent"),
    ],
    ids=["both", "enabled", "clientAuth"],
)
def test_absent_nats_tls_keys_refuse_while_nats_create_is_true(tmp_path, drop, named):
    values = adopter_without_nats_tls(tmp_path, *drop)
    result = render(CHART, *API_VERSIONS, "-f", str(values))
    assert result.returncode != 0, result.stdout[:400]
    assert "--api-versions" not in result.stderr, result.stderr
    assert NATS_KEYS_ABSENT in result.stderr, result.stderr
    assert named in result.stderr, result.stderr
    assert "ADR-0845" in result.stderr, result.stderr
    assert 'clientAuth: \\"off\\"' in result.stderr or 'clientAuth: "off"' in result.stderr, (
        result.stderr
    )


def test_absent_nats_tls_keys_render_while_nats_create_is_false():
    """THE OPERATOR APPLICATIONS' POSTURE: `nats.create` false, no `nats.tls` at all."""
    result = render(CHART, "--set", "operators.certManager.create=true")
    assert result.returncode == 0, result.stderr


# THE POSTURES RENDER, AND RENDER WHAT THEY SAY.


def test_the_off_posture_renders_a_plaintext_broker_with_the_checksum_annotation(tmp_path):
    result = contract(tmp_path)
    assert result.returncode == 0, result.stderr
    pod = nats_objects(result.stdout)["StatefulSet/nats"]["spec"]["template"]
    assert "checksum/config" in pod["metadata"]["annotations"], pod["metadata"]
    config = broker_config(result.stdout)
    assert "tls" not in config, config
    assert "allow_non_tls" not in config, config


def test_the_off_posture_differs_from_the_annotation_off_only_by_the_checksum(tmp_path):
    """THE ACCEPTANCE (plan B-N2): at the off posture the checksum annotation is the diff.

    With the annotation off the upstream pod template renders `annotations: null`;
    with it on, that line becomes the one-key map. Nothing else moves.
    """
    with_annotation = contract(tmp_path / "on")
    without = contract(tmp_path / "off", {"nats": {"podTemplate": {"configChecksumAnnotation": False}}})
    assert with_annotation.returncode == 0, with_annotation.stderr
    assert without.returncode == 0, without.stderr
    changed = [
        line
        for line in difflib.unified_diff(
            without.stdout.splitlines(), with_annotation.stdout.splitlines(), lineterm="", n=0
        )
        if line[:1] in "+-" and not line.startswith(("+++", "---"))
    ]
    assert changed[0] == "-      annotations: null", changed
    assert changed[1] == "+      annotations:", changed
    assert changed[2].startswith("+        checksum/config: "), changed
    assert len(changed) == 3, changed


def test_the_transport_step_serves_tls_and_accepts_plaintext(tmp_path):
    """B-N4.1: TLS on, `allow_non_tls: true`, `clientAuth: "off"`."""
    result = contract(tmp_path, NATS_TRANSPORT)
    assert result.returncode == 0, result.stderr
    config = broker_config(result.stdout)
    assert config["allow_non_tls"] is True, config
    assert config["tls"]["cert_file"] == "/etc/nats-certs/nats/tls.crt", config["tls"]
    assert "verify" not in config["tls"], config["tls"]
    volumes = nats_objects(result.stdout)["StatefulSet/nats"]["spec"]["template"]["spec"]["volumes"]
    assert {"secretName": "nats-tls"} in [v.get("secret") for v in volumes], volumes


def test_the_tls_only_step_renders(tmp_path):
    """B-N4.3: `allow_non_tls` dropped."""
    result = contract(tmp_path, NATS_TLS_ONLY)
    assert result.returncode == 0, result.stderr
    config = broker_config(result.stdout)
    assert "allow_non_tls" not in config, config
    assert "tls" in config, config


def test_the_verified_step_verifies_against_the_leaf_ca_and_reloads_it(tmp_path):
    """B-N5: `verify` on, `ca_file` the CA cert-manager writes beside the leaf."""
    result = contract(tmp_path, NATS_VERIFIED)
    assert result.returncode == 0, result.stderr
    tls = broker_config(result.stdout)["tls"]
    assert tls["verify"] is True, tls
    assert tls["ca_file"] == NATS_CA_FILE, tls
    args = reloader_args(result.stdout)
    assert ["-config", NATS_CA_FILE] in [args[i : i + 2] for i in range(len(args) - 1)], args


def test_a_custom_tls_dir_moves_the_expected_ca_file(tmp_path):
    body = yaml.safe_load(yaml.safe_dump(NATS_VERIFIED))
    body["nats"]["config"]["nats"]["tls"]["dir"] = "/etc/custom/"
    body["nats"]["config"]["nats"]["tls"]["merge"]["ca_file"] = "/etc/custom/ca.crt"
    result = contract(tmp_path, body)
    assert result.returncode == 0, result.stderr


# THE TWO SOURCES MUST AGREE.


def with_changes(base: dict, *edits: tuple[tuple[str, ...], object]) -> dict:
    """A deep copy of `base` with each `(path, value)` set; value `None` deletes."""
    body = yaml.safe_load(yaml.safe_dump(base))
    for path, value in edits:
        node = body
        for key in path[:-1]:
            node = node.setdefault(key, {})
        if value is None:
            node.pop(path[-1], None)
        else:
            node[path[-1]] = value
    return body


UPSTREAM_TLS = ("nats", "config", "nats", "tls")


@pytest.mark.parametrize(
    ("body", "named"),
    [
        (
            with_changes(NATS_TLS_ONLY, (UPSTREAM_TLS, None)),
            "`nats.tls.enabled` is true and `nats.config.nats.tls.enabled` is false",
        ),
        (
            with_changes(NATS_TLS_ONLY, (("nats", "tls", "enabled"), False)),
            "`nats.tls.enabled` is false and `nats.config.nats.tls.enabled` is true",
        ),
        (
            with_changes(NATS_TLS_ONLY, ((*UPSTREAM_TLS, "secretName"), "nats-other")),
            '`nats.config.nats.tls.secretName` is "nats-other"',
        ),
        (
            with_changes(NATS_TLS_ONLY, ((*UPSTREAM_TLS, "secretName"), None)),
            '`nats.config.nats.tls.secretName` is ""',
        ),
        (
            with_changes(NATS_VERIFIED, ((*UPSTREAM_TLS, "merge", "verify"), None)),
            '`nats.tls.clientAuth` is "required" and `nats.config.nats.tls.merge.verify` is not true',
        ),
        (
            with_changes(NATS_VERIFIED, ((*UPSTREAM_TLS, "merge", "verify"), "true")),
            '`nats.tls.clientAuth` is "required" and `nats.config.nats.tls.merge.verify` is not true',
        ),
        (
            with_changes(
                NATS_VERIFIED,
                ((*UPSTREAM_TLS, "merge", "ca_file"), "/etc/ssl/certs/ca-certificates.crt"),
            ),
            '`nats.config.nats.tls.merge.ca_file` is "/etc/ssl/certs/ca-certificates.crt" '
            'rather than "/etc/nats-certs/nats/ca.crt"',
        ),
        (
            with_changes(NATS_VERIFIED, ((*UPSTREAM_TLS, "merge", "ca_file"), None)),
            '`nats.config.nats.tls.merge.ca_file` is "" rather than "/etc/nats-certs/nats/ca.crt"',
        ),
        (
            with_changes(NATS_VERIFIED, (("nats", "config", "merge", "allow_non_tls"), True)),
            '`nats.tls.clientAuth` is "required" and `nats.config.merge.allow_non_tls` is true',
        ),
        (
            with_changes(
                NATS_TLS_ONLY,
                (("nats", "tls", "clientAuth"), "off"),
                ((*UPSTREAM_TLS, "merge", "verify"), True),
            ),
            '`nats.tls.clientAuth` is "off" and `nats.config.nats.tls.merge.verify` is true',
        ),
        (
            with_changes(
                {"nats": {"tls": {"enabled": False, "clientAuth": "required"}}},
            ),
            '`nats.tls.clientAuth` is "required" and `nats.tls.enabled` is false',
        ),
        (
            with_changes(NATS_TLS_ONLY, (("nats", "tlsCA", "enabled"), True)),
            "`nats.tlsCA.enabled` is true",
        ),
        (
            with_changes(
                NATS_TLS_ONLY,
                (("nats", "config", "patch"), [{"op": "remove", "path": "/tls"}]),
            ),
            "`nats.config.patch` is not empty while `nats.tls.enabled` is true",
        ),
        (
            with_changes(
                NATS_TLS_ONLY,
                ((*UPSTREAM_TLS, "patch"), [{"op": "add", "path": "/verify", "value": False}]),
            ),
            "`nats.config.nats.tls.patch` is not empty while `nats.tls.enabled` is true",
        ),
    ],
    ids=[
        "enabled-upstream-absent",
        "upstream-enabled-platform-off",
        "secret-name-other",
        "secret-name-absent",
        "required-verify-absent",
        "required-verify-string",
        "required-ca-file-public-bundle",
        "required-ca-file-absent",
        "required-allow-non-tls",
        "off-with-verify",
        "required-without-enabled",
        "tls-ca-enabled",
        "config-patch",
        "tls-patch",
    ],
)
def test_a_nats_disagreement_is_refused_by_name(tmp_path, body, named):
    stderr = contract_refused(tmp_path, body)
    assert named in stderr, stderr


def test_every_nats_disagreement_is_named_in_one_refusal(tmp_path):
    body = with_changes(
        NATS_VERIFIED,
        ((*UPSTREAM_TLS, "secretName"), "wrong"),
        ((*UPSTREAM_TLS, "merge", "verify"), None),
        (("nats", "config", "merge", "allow_non_tls"), True),
    )
    stderr = contract_refused(tmp_path, body)
    for named in (
        '`nats.config.nats.tls.secretName` is "wrong"',
        "`nats.config.nats.tls.merge.verify` is not true",
        "`nats.config.merge.allow_non_tls` is true",
    ):
        assert named in stderr, (named, stderr)


def test_tls_ca_enabled_refuses_at_the_off_posture_too(tmp_path):
    stderr = contract_refused(tmp_path, {"nats": {"tlsCA": {"enabled": True}}})
    assert "`nats.tlsCA.enabled` is true" in stderr, stderr
