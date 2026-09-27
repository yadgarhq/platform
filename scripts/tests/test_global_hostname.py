"""THE ESTATE'S HOSTNAME IS ONE VALUE, `global.hostname` (ADR-0808).

This chart carries three of the five keys that hold the public hostname:
`gatewayListener.hostname`, `edgeTLS.commonName` and `edgeTLS.dnsNames`. Each one
now resolves in the same order, in `templates/_hostname.tpl`:

  1. the chart's own key, when it is set (an explicit per-chart value wins);
  2. `global.hostname`, when the chart's own key is empty;
  3. `gateway.yadgar.internal`, when neither is set — the value `values.yaml`
     shipped before this change, so a render with no hostname anywhere is the
     render it was.

THE THREE CASES ARE (a), (b) AND (c) BELOW, and each has a red case. Only (b) is
red on the chart before this change, because that chart never read `global`. (a)
and (c) were green there by construction, so their red cases are MUTATIONS: a copy
of the chart with `_hostname.tpl` rewritten to lose the property under test, which
the same check must then refuse. A check that cannot be made to fail proves
nothing, and these are the constructions that make each one fail.

EVERY RENDER USES `example/values.yaml`, because the chart's own defaults leave
`edgeTLS.create` and `gatewayListener.create` false and so render none of the
three keys at all. A byte-identity claim over a render that omits the keys would be
true for any template.

Run: python3 -m pytest scripts/tests/ -q
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parents[2]
CHART = REPO / "chart"
ADOPTER_VALUES = REPO / "example" / "values.yaml"
HELPER = "templates/_hostname.tpl"

# The same literal restatement every suite in this directory carries; see
# `test_shared_infrastructure.py` for why it is not derived from the chart.
DECLARED_API_VERSIONS = ("cert-manager.io/v1", "gateway.envoyproxy.io/v1alpha1")

EDGE_CERTIFICATE = yaml.safe_load((CHART / "values.yaml").read_text())["edgeTLS"]["name"]

BUILT_IN = "gateway.yadgar.internal"
GLOBAL = "yadgar.example.com"
LOCAL = "edge.local.example"


def helm(*arguments: str) -> subprocess.CompletedProcess[str]:
    binary = shutil.which("helm")
    # NOT A SKIP (ADR-0650), the same wording as the sibling suites.
    assert binary, (
        "helm is not on PATH. This suite renders the chart — install helm rather "
        "than letting it report a pass it did not earn."
    )
    return subprocess.run([binary, *arguments], capture_output=True, text=True)


def render(chart: Path, *arguments: str) -> list[dict]:
    api_versions = [
        part for group in DECLARED_API_VERSIONS for part in ("--api-versions", group)
    ]
    result = helm(
        "template", "platform", str(chart), *api_versions,
        "-f", str(ADOPTER_VALUES), *arguments,
    )
    assert result.returncode == 0, result.stderr
    return [
        document
        for document in yaml.safe_load_all(result.stdout)
        if isinstance(document, dict) and document.get("apiVersion")
    ]


def the_three_keys(rendered: list[dict]) -> dict[str, object]:
    """The rendered value of each of this chart's three hostname keys. PURE."""
    (gateway,) = [d for d in rendered if d["kind"] == "Gateway"]
    (listener,) = gateway["spec"]["listeners"]
    (edge,) = [
        d
        for d in rendered
        if d["kind"] == "Certificate" and d["metadata"]["name"] == EDGE_CERTIFICATE
    ]
    return {
        "gatewayListener.hostname": listener["hostname"],
        "edgeTLS.commonName": edge["spec"]["commonName"],
        "edgeTLS.dnsNames": edge["spec"]["dnsNames"],
    }


def expected(hostname: str) -> dict[str, object]:
    return {
        "gatewayListener.hostname": hostname,
        "edgeTLS.commonName": hostname,
        "edgeTLS.dnsNames": [hostname],
    }


def values_file(tmp_path: Path, body: str) -> Path:
    path = tmp_path / "overlay.yaml"
    path.write_text(body)
    return path


def chart_with(destination: Path, old: str, new: str) -> Path:
    """A copy of the chart with one string in `_hostname.tpl` replaced. Red cases only.

    The edit is asserted to have landed: a replace whose pattern no longer matches
    leaves the chart unchanged, and the red case would then prove nothing.
    """
    copy = destination / "chart"
    shutil.copytree(CHART, copy)
    target = copy / HELPER
    before = target.read_text()
    assert old in before, f"the red case's edit matched nothing in {HELPER}"
    target.write_text(before.replace(old, new))
    return copy


# ── the three checks, each a function a red case can run against a mutant ──────


def no_hostname_anywhere(chart: Path) -> dict[str, object]:
    return the_three_keys(render(chart))


def global_only(chart: Path) -> dict[str, object]:
    return the_three_keys(render(chart, "--set", f"global.hostname={GLOBAL}"))


def global_and_local(chart: Path) -> dict[str, object]:
    return the_three_keys(
        render(
            chart,
            "--set", f"global.hostname={GLOBAL}",
            "--set", f"gatewayListener.hostname={LOCAL}",
            "--set", f"edgeTLS.commonName={LOCAL}",
            "--set", f"edgeTLS.dnsNames={{{LOCAL}}}",
        )
    )


# ── (a) no global, no local: the render this chart always produced ─────────────


def test_a_no_hostname_anywhere_renders_the_built_in_default():
    assert no_hostname_anywhere(CHART) == expected(BUILT_IN)


def test_a_red_a_changed_built_in_default_is_caught(tmp_path):
    mutant = chart_with(tmp_path, f'"{BUILT_IN}"', '"elsewhere.invalid"')
    assert no_hostname_anywhere(mutant) != expected(BUILT_IN)


def test_a_an_explicit_null_global_is_the_same_as_none(tmp_path):
    overlay = values_file(tmp_path, "global: null\n")
    assert the_three_keys(render(CHART, "-f", str(overlay))) == expected(BUILT_IN)


# ── (b) global set, local empty: every key is the global ───────────────────────


def test_b_global_hostname_reaches_every_key():
    assert global_only(CHART) == expected(GLOBAL)


def test_b_global_hostname_leaves_no_trace_of_the_built_in_default():
    result = helm(
        "template", "platform", str(CHART),
        *[p for g in DECLARED_API_VERSIONS for p in ("--api-versions", g)],
        "-f", str(ADOPTER_VALUES), "--set", f"global.hostname={GLOBAL}",
    )
    assert result.returncode == 0, result.stderr
    assert BUILT_IN not in result.stdout


def test_b_red_a_chart_that_ignores_global_is_caught(tmp_path):
    mutant = chart_with(tmp_path, '(get $global "hostname")', '""')
    assert global_only(mutant) != expected(GLOBAL)


# ── (c) local and global both set: the local key wins ──────────────────────────


def test_c_an_explicit_local_key_wins_over_global():
    assert global_and_local(CHART) == expected(LOCAL)


def test_c_each_local_key_wins_on_its_own():
    """Setting ONE key locally overrides that key alone; the other two follow global."""
    keys = the_three_keys(
        render(
            CHART,
            "--set", f"global.hostname={GLOBAL}",
            "--set", f"gatewayListener.hostname={LOCAL}",
        )
    )
    assert keys == {
        "gatewayListener.hostname": LOCAL,
        "edgeTLS.commonName": GLOBAL,
        "edgeTLS.dnsNames": [GLOBAL],
    }


def test_c_red_a_chart_that_prefers_global_is_caught(tmp_path):
    mutant = chart_with(
        tmp_path,
        '.local | default (get $global "hostname")',
        '(get $global "hostname") | default .local',
    )
    assert global_and_local(mutant) != expected(LOCAL)
