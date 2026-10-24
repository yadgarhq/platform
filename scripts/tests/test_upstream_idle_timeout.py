"""THE ENVOY UPSTREAM IDLE TIMEOUT TO THE GATEWAY (ADR-1016).

WHAT THE RACE IS. The gateway edge closes a kept-alive connection that sends no
request head within `server.limits.headerReadTimeoutSeconds` (default 10 s,
gateway chart). Envoy pools its upstream connections and, left at Envoy
Gateway's default, keeps an idle one for about 1 h. So Envoy can reuse a pooled
connection at the moment the gateway closes it, and the client gets a 503 UC.
ADR-1016 closes the race from the Envoy side: Envoy drops an idle upstream
connection strictly before the gateway does.

WHAT THIS CHART OWNS. One `BackendTrafficPolicy` on the edge Gateway, behind
`gatewayListener.create`, that sets `spec.timeout.http.connectionIdleTimeout`
from `gatewayListener.upstreamIdleTimeoutSeconds` (default 8). It targets the
Gateway this chart renders, not the gateway chart's HTTPRoute, so this chart
needs no other chart's object names.

WHAT THIS CHART CANNOT CHECK. The bound it must stay under is a value of the
gateway chart, which this chart never sees. `yadgarhq/chart` renders both and
holds the cross-check. This suite holds the shape: the field exists in the
vendored Envoy Gateway CRD, the value renders as a duration the CRD accepts, and
a value outside 1..59 is refused by name. 59 is the top because the gateway's
own range tops out at 60, so no gateway value could sit above a 60 here.

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
# LITERALS, for the reason every expected value in this estate is one.
API_VERSION = "gateway.envoyproxy.io/v1alpha1"
KIND = "BackendTrafficPolicy"
DEFAULT_SECONDS = 8
VALUE_KEY = "gatewayListener.upstreamIdleTimeoutSeconds"
# The Envoy Gateway chart the estate vendors, and the CRD file inside it that
# defines the policy. Read off `chart/Chart.yaml`'s `gateway-helm` pin.
VENDORED_ENVOY_GATEWAY = "gateway-helm-v1.9.1.tgz"
CRD_MEMBER = (
    "gateway-helm/charts/crds/crds/generated/"
    "gateway.envoyproxy.io_backendtrafficpolicies.yaml"
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


def idle_field(crd: dict) -> dict:
    (version,) = [v for v in crd["spec"]["versions"] if v["name"] == "v1alpha1"]
    spec = version["schema"]["openAPIV3Schema"]["properties"]["spec"]["properties"]
    return spec["timeout"]["properties"]["http"]["properties"]["connectionIdleTimeout"]


# ── THE FIELD IS THE ONE THE VENDORED OPERATOR READS ─────────────────────────


def test_the_vendored_crd_declares_the_upstream_idle_field():
    """The field is read off the CRD the estate installs, not off documentation."""
    crd = vendored_crd()
    assert crd["spec"]["group"] == "gateway.envoyproxy.io"
    assert crd["spec"]["names"]["kind"] == KIND
    field = idle_field(crd)
    assert field["type"] == "string"
    assert "no active requests" in field["description"], (
        "the field's description no longer says it is the connection idle timeout: "
        "re-read the operator before trusting this policy"
    )


def test_the_rendered_duration_matches_the_crd_pattern(tmp_path):
    policy, _ = one_policy(tmp_path)
    value = policy["spec"]["timeout"]["http"]["connectionIdleTimeout"]
    pattern = idle_field(vendored_crd())["pattern"]
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


def test_the_default_is_eight_seconds(tmp_path):
    policy, _ = one_policy(tmp_path)
    assert policy["spec"]["timeout"]["http"] == {
        "connectionIdleTimeout": f"{DEFAULT_SECONDS}s"
    }


def test_a_stated_value_renders(tmp_path):
    policy, _ = one_policy(
        tmp_path, "gatewayListener:\n  upstreamIdleTimeoutSeconds: 5\n"
    )
    assert policy["spec"]["timeout"]["http"]["connectionIdleTimeout"] == "5s"


def test_the_listener_toggle_removes_the_policy(tmp_path):
    result = adopter(tmp_path, "gatewayListener:\n  create: false\n")
    assert result.returncode == 0, result.stderr
    assert policies(documents(result.stdout)) == []


def test_the_policy_is_protected_from_a_prune(tmp_path):
    """A pruned policy silently returns Envoy to its 1 h default, and the race."""
    policy, _ = one_policy(tmp_path)
    options = policy["metadata"].get("annotations", {}).get(
        "argocd.argoproj.io/sync-options", ""
    )
    assert "Prune=false" in [option.strip() for option in options.split(",")]


# ── A VALUE OUTSIDE 1..59 IS REFUSED BY NAME ─────────────────────────────────


@pytest.mark.parametrize(
    "written",
    ["0", "60", "-1", "8.5", '"8"', '"8s"', "null", "true", "[8]"],
)
def test_a_value_outside_the_range_is_refused(tmp_path, written):
    result = adopter(
        tmp_path, f"gatewayListener:\n  upstreamIdleTimeoutSeconds: {written}\n"
    )
    assert result.returncode != 0, f"{written} rendered, and it must be refused"
    assert VALUE_KEY in result.stderr, result.stderr


@pytest.mark.parametrize("written", ["1", "59"])
def test_the_ends_of_the_range_render(tmp_path, written):
    policy, _ = one_policy(
        tmp_path, f"gatewayListener:\n  upstreamIdleTimeoutSeconds: {written}\n"
    )
    assert policy["spec"]["timeout"]["http"]["connectionIdleTimeout"] == f"{written}s"


def test_a_set_flag_integer_renders(tmp_path):
    """`--set` hands helm an int64, not the float64 a values file does."""
    result = template(
        *api_version_arguments(),
        "-f",
        str(ADOPTER_VALUES),
        "--set",
        "gatewayListener.upstreamIdleTimeoutSeconds=7",
    )
    assert result.returncode == 0, result.stderr
    (policy,) = policies(documents(result.stdout))
    assert policy["spec"]["timeout"]["http"]["connectionIdleTimeout"] == "7s"
