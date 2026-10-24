"""THE EDGE'S DOWNSTREAM REQUEST-HEADERS TIMEOUT (yaadgaar #218, ADR-1006).

WHAT THE GAP IS. The gateway closes a connection that sends no complete request
head within `server.limits.headerReadTimeoutSeconds` (default 10 s, ADR-1006,
ADR-1016). Envoy never forwards an incomplete request head, so a client that
stalls mid-head through the edge is held by Envoy, not by the gateway. Envoy
Gateway sets no request-headers timeout by default, so the edge held such a
connection open past 45 s (measured on kind at parent 0.46.13).

WHAT THIS CHART OWNS. One `ClientTrafficPolicy` on the edge Gateway, behind
`gatewayListener.create`, that sets
`spec.timeout.http.requestHeadersReceivedTimeout` from
`gatewayListener.requestHeadersTimeoutSeconds` (default 10). That field bounds
the request HEADERS only, from their first byte to their last. (The gateway's
own timer starts at accept, so a connection that sends no byte is not bounded
by this field.)
`requestReceivedTimeout` bounds the whole request with its body, and would cut a
slow valid upload; it is deliberately not set.

WHAT THIS CHART CANNOT CHECK. The gateway's bound is a value of the gateway
chart, which this chart never sees. The companion check in `yadgarhq/chart`
renders both and compares them. This suite holds the shape: the field
exists in the vendored Envoy Gateway CRD, the value renders as a duration the
CRD accepts, and a value outside 1..60 (the gateway's own range) is refused by
name.

Run: python3 -m pytest scripts/tests/ -q
"""

from __future__ import annotations

import re
import tarfile
from pathlib import Path

import pytest
import yaml

from test_render_checks import ADOPTER_VALUES, CHART, helm

# ── WRITTEN DOWN ─────────────────────────────────────────────────────────────
API_VERSION = "gateway.envoyproxy.io/v1alpha1"
KIND = "ClientTrafficPolicy"
FIELD = "requestHeadersReceivedTimeout"
DEFAULT_SECONDS = 10
VALUE_KEY = "gatewayListener.requestHeadersTimeoutSeconds"
VENDORED_ENVOY_GATEWAY = "gateway-helm-v1.9.1.tgz"
CRD_MEMBER = (
    "gateway-helm/charts/crds/crds/generated/"
    "gateway.envoyproxy.io_clienttrafficpolicies.yaml"
)
API_GROUPS = ("cert-manager.io/v1", "gateway.envoyproxy.io/v1alpha1")


def api_version_arguments() -> list[str]:
    return [part for group in API_GROUPS for part in ("--api-versions", group)]


def template(*arguments: str):
    return helm("template", "platform", str(CHART), *arguments)


def documents(stdout: str) -> list[dict]:
    return [
        document
        for document in yaml.safe_load_all(stdout)
        if isinstance(document, dict) and document.get("apiVersion")
    ]


def adopter(tmp_path: Path, overlay: str | None = None):
    arguments = [*api_version_arguments(), "-f", str(ADOPTER_VALUES)]
    if overlay is not None:
        values = tmp_path / "overlay.yaml"
        values.write_text(overlay)
        arguments += ["-f", str(values)]
    return template(*arguments)


def policies(rendered: list[dict]) -> list[dict]:
    return [document for document in rendered if document.get("kind") == KIND]


def one_policy(tmp_path: Path, overlay: str | None = None) -> tuple[dict, list[dict]]:
    result = adopter(tmp_path, overlay)
    assert result.returncode == 0, result.stderr
    rendered = documents(result.stdout)
    found = policies(rendered)
    assert len(found) == 1, f"expected exactly one {KIND}, found {len(found)}"
    return found[0], rendered


def vendored_crd() -> dict:
    archive = CHART / "charts" / VENDORED_ENVOY_GATEWAY
    assert archive.is_file(), (
        f"{archive} is absent: run `helm dependency build chart` first. "
        "Not a skip (ADR-0650)."
    )
    with tarfile.open(archive) as tar:
        member = tar.extractfile(CRD_MEMBER)
        assert member is not None, f"{CRD_MEMBER} is not in {archive.name}"
        return yaml.safe_load(member.read())


def http_timeouts(crd: dict) -> dict:
    (version,) = [v for v in crd["spec"]["versions"] if v["name"] == "v1alpha1"]
    spec = version["schema"]["openAPIV3Schema"]["properties"]["spec"]["properties"]
    return spec["timeout"]["properties"]["http"]["properties"]


# ── THE FIELD IS THE ONE THE VENDORED OPERATOR READS ─────────────────────────


def test_the_vendored_crd_declares_the_request_headers_field():
    """The field is read off the CRD the estate installs, not off documentation."""
    crd = vendored_crd()
    assert crd["spec"]["group"] == "gateway.envoyproxy.io"
    assert crd["spec"]["names"]["kind"] == KIND
    field = http_timeouts(crd)[FIELD]
    assert field["type"] == "string"
    assert "request headers to arrive" in field["description"], (
        "the field's description no longer says it bounds the request headers: "
        "re-read the operator before trusting this policy"
    )


def test_the_rendered_duration_matches_the_crd_pattern(tmp_path):
    policy, _ = one_policy(tmp_path)
    value = policy["spec"]["timeout"]["http"][FIELD]
    pattern = http_timeouts(vendored_crd())[FIELD]["pattern"]
    assert re.fullmatch(pattern, value), f"{value!r} does not match {pattern!r}"


# ── THE POLICY AND WHAT IT ATTACHES TO ───────────────────────────────────────


def test_the_default_render_carries_no_policy():
    """The listener toggle defaults false, so the bare defaults render no policy."""
    result = template()
    assert result.returncode == 0, result.stderr
    assert policies(documents(result.stdout)) == []


def test_the_policy_targets_the_gateway_this_chart_renders(tmp_path):
    policy, rendered = one_policy(tmp_path)
    (gateway,) = [d for d in rendered if d.get("kind") == "Gateway"]
    assert policy["apiVersion"] == API_VERSION
    assert policy["metadata"]["name"] == f"{gateway['metadata']['name']}-request-headers"
    assert policy["spec"]["targetRefs"] == [
        {
            "group": "gateway.networking.k8s.io",
            "kind": "Gateway",
            "name": gateway["metadata"]["name"],
        }
    ]
    assert "namespace" not in policy["metadata"], (
        "a policy attaches only to a target in its own namespace, so it must not "
        "pin one the Gateway does not"
    )


def test_the_default_is_ten_seconds_and_sets_nothing_else(tmp_path):
    """Only the headers bound: no whole-request bound, no idle change."""
    policy, _ = one_policy(tmp_path)
    assert policy["spec"]["timeout"] == {"http": {FIELD: f"{DEFAULT_SECONDS}s"}}
    assert set(policy["spec"]) == {"targetRefs", "timeout"}


def test_a_stated_value_renders(tmp_path):
    policy, _ = one_policy(
        tmp_path, "gatewayListener:\n  requestHeadersTimeoutSeconds: 5\n"
    )
    assert policy["spec"]["timeout"]["http"][FIELD] == "5s"


def test_the_listener_toggle_removes_the_policy(tmp_path):
    result = adopter(tmp_path, "gatewayListener:\n  create: false\n")
    assert result.returncode == 0, result.stderr
    assert policies(documents(result.stdout)) == []


def test_the_policy_is_protected_from_a_prune(tmp_path):
    """A pruned policy silently returns the edge to no headers timeout."""
    policy, _ = one_policy(tmp_path)
    options = policy["metadata"].get("annotations", {}).get(
        "argocd.argoproj.io/sync-options", ""
    )
    assert "Prune=false" in [option.strip() for option in options.split(",")]


# ── A BAD VALUE IS REFUSED BY NAME ───────────────────────────────────────────


@pytest.mark.parametrize(
    "written",
    ["0", "61", "-1", "9.5", '"10"', '"10s"', "null", "true", "[10]"],
)
def test_a_value_outside_the_range_is_refused(tmp_path, written):
    result = adopter(
        tmp_path, f"gatewayListener:\n  requestHeadersTimeoutSeconds: {written}\n"
    )
    assert result.returncode != 0, f"{written} rendered, and it must be refused"
    assert VALUE_KEY in result.stderr, result.stderr


def test_a_misspelt_key_is_refused_by_the_schema(tmp_path):
    """The closed schema (ADR-0850) refuses a key the chart does not read."""
    result = adopter(
        tmp_path, "gatewayListener:\n  requestHeaderTimeoutSeconds: 10\n"
    )
    assert result.returncode != 0, "a misspelt key rendered, and it must be refused"
    assert "requestHeaderTimeoutSeconds" in result.stderr, result.stderr


@pytest.mark.parametrize("written", ["1", "60"])
def test_the_ends_of_the_range_render(tmp_path, written):
    policy, _ = one_policy(
        tmp_path, f"gatewayListener:\n  requestHeadersTimeoutSeconds: {written}\n"
    )
    assert policy["spec"]["timeout"]["http"][FIELD] == f"{written}s"


def test_a_set_flag_integer_renders(tmp_path):
    """`--set` hands helm an int64, not the float64 a values file does."""
    result = template(
        *api_version_arguments(),
        "-f",
        str(ADOPTER_VALUES),
        "--set",
        "gatewayListener.requestHeadersTimeoutSeconds=7",
    )
    assert result.returncode == 0, result.stderr
    (policy,) = policies(documents(result.stdout))
    assert policy["spec"]["timeout"]["http"][FIELD] == "7s"
