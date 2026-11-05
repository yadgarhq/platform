"""THE BROKER'S MERGE KEYS CANNOT UNDO WHAT THE CHART OWNS (yaadgaar 169, ruled 2026-11-02).

THE GAP. The upstream nats chart mergeOverwrites `nats.container.merge`,
`nats.podTemplate.merge` and `nats.statefulSet.merge` over the objects it
renders, after its own helpers, and a merge replaces a list whole. Before this
file, each of these rendered at rc=0:

  * `nats.container.merge.command` / `.args` replaced the credential-rotation
    wrapper (ADR-0924), so the broker never hashed its passwords and a rotation
    never restarted it;
  * `nats.container.merge.image` replaced the image after the alpine arm read it;
  * `nats.container.merge.volumeMounts`, `nats.podTemplate.merge.spec.volumes` /
    `.containers` and `nats.statefulSet.merge.spec.template` replaced the lists
    that carry `config`, `pid`, `nats-tls` and both password mounts.

THE RULE, in `templates/render-checks.yaml`'s merge-key arms: `command` and
`args` must equal the chart's own; the rest of `container.merge` is an
allowlist; the other two merges are allowlists too (yaadgaar 597): `metadata.labels`,
`metadata.annotations` and an empty `spec`, so every `spec` key is refused. Both
directions are tested at both TLS postures: every refused shape names itself,
and every allowed shape renders.

NO SKIPS (ADR-0650): helm absent is a failure.

Run: python3 -m pytest scripts/tests/test_nats_merge_keys.py -q
"""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

REPO = Path(__file__).resolve().parents[2]
CHART = REPO / "chart"
ADOPTER_VALUES = REPO / "example" / "values.yaml"
RENDER_CHECKS = CHART / "templates" / "render-checks.yaml"
API_VERSIONS = ("--api-versions", "cert-manager.io/v1", "--api-versions", "gateway.envoyproxy.io/v1alpha1")

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
REFUSAL = "platform: the broker's merge keys override what the chart owns"


def helm(*arguments: str) -> subprocess.CompletedProcess[str]:
    binary = shutil.which("helm")
    assert binary, "helm is not on PATH; this suite renders the chart and does not skip (ADR-0650)."
    return subprocess.run([binary, *arguments], capture_output=True, text=True)


def render(tmp_path: Path, posture: str, body: str) -> subprocess.CompletedProcess[str]:
    files = []
    if posture == "required":
        (tmp_path / "tls.yaml").write_text(TLS_REQUIRED)
        files += ["-f", str(tmp_path / "tls.yaml")]
    (tmp_path / "case.yaml").write_text(body)
    files += ["-f", str(tmp_path / "case.yaml")]
    return helm(
        "template", "platform", str(CHART), "--namespace", "yadgar", *API_VERSIONS,
        "-f", str(ADOPTER_VALUES), *files,
    )


# ── THE LITERAL IS PINNED TO ITS SOURCE ─────────────────────────────────────


def wrapper_literal() -> str:
    text = RENDER_CHECKS.read_text()
    found = re.findall(r"\{\{- \$natsWrapper := `(.*?)` \}\}", text, flags=re.DOTALL)
    assert len(found) == 1, f"expected one `$natsWrapper` literal in {RENDER_CHECKS.name}, found {len(found)}"
    return found[0]


def test_the_wrapper_literal_matches_values_yaml():
    merge = yaml.safe_load((CHART / "values.yaml").read_text())["nats"]["container"]["merge"]
    assert merge["command"] == ["/bin/sh", "-c"], merge["command"]
    assert merge["args"] == [wrapper_literal()], (
        "`templates/render-checks.yaml`'s `$natsWrapper` is no longer byte-equal to "
        "`values.yaml`'s `nats.container.merge.args[0]`: change both together"
    )


def test_the_shipped_merges_render_at_both_postures(tmp_path):
    for posture in ("off", "required"):
        result = render(tmp_path, posture, "{}\n")
        assert result.returncode == 0, result.stderr


# ── REFUSED: EACH SHAPE NAMES ITSELF ────────────────────────────────────────

REFUSED = {
    "command-replaced": ("nats:\n  container:\n    merge:\n      command: [nats-server]\n", "`nats.container.merge.command`"),
    "command-extended": ("nats:\n  container:\n    merge:\n      command: [/bin/sh, -c, -x]\n", "`nats.container.merge.command`"),
    "command-null": ("nats:\n  container:\n    merge:\n      command: null\n", "`nats.container.merge.command` is null"),
    "args-replaced": (
        "nats:\n  container:\n    merge:\n      args: ['exec nats-server --config /etc/nats-config/nats.conf']\n",
        "`nats.container.merge.args`",
    ),
    "args-null": ("nats:\n  container:\n    merge:\n      args: null\n", "`nats.container.merge.args`"),
    "image": ("nats:\n  container:\n    merge:\n      image: nats:2.14.6\n", 'sets the key "image"'),
    "volume-mounts": ("nats:\n  container:\n    merge:\n      volumeMounts: []\n", 'sets the key "volumeMounts"'),
    "liveness": ("nats:\n  container:\n    merge:\n      livenessProbe: {tcpSocket: {port: 4222}}\n", 'sets the key "livenessProbe"'),
    "env": ("nats:\n  container:\n    merge:\n      env: []\n", 'sets the key "env"'),
    "case-variant": ("nats:\n  container:\n    merge:\n      Resources: {}\n", 'sets the key "Resources"'),
    "pod-volumes": ("nats:\n  podTemplate:\n    merge:\n      spec:\n        volumes: []\n", "`nats.podTemplate.merge.spec.volumes`"),
    "pod-containers": ("nats:\n  podTemplate:\n    merge:\n      spec:\n        containers: []\n", "`nats.podTemplate.merge.spec.containers`"),
    "pod-init-containers": (
        "nats:\n  podTemplate:\n    merge:\n      spec:\n        initContainers: []\n",
        "`nats.podTemplate.merge.spec.initContainers`",
    ),
    "pod-ephemeral-containers": (
        "nats:\n  podTemplate:\n    merge:\n      spec:\n        ephemeralContainers: []\n",
        "`nats.podTemplate.merge.spec.ephemeralContainers`",
    ),
    # yaadgaar 555: with TLS on the chart's own `podTemplate.patch` adds
    # `hostAliases` after the merge and would replace an adopter's whole list
    # without a word, so the merge key is refused at both postures.
    "pod-host-aliases": (
        "nats:\n  podTemplate:\n    merge:\n      spec:\n        hostAliases: [{ip: 10.0.0.1, hostnames: [x]}]\n",
        "`nats.podTemplate.merge.spec.hostAliases`",
    ),
    "pod-spec-not-a-map": ("nats:\n  podTemplate:\n    merge:\n      spec: [x]\n", "`nats.podTemplate.merge.spec` is not a map"),
    "statefulset-template": (
        "nats:\n  statefulSet:\n    merge:\n      spec:\n        template: {spec: {volumes: []}}\n",
        "`nats.statefulSet.merge.spec.template`",
    ),
    # yaadgaar 597: `spec` is an allowlist with no key on it, so the shapes this
    # file used to render (`nodeSelector`, `minReadySeconds`) are refused too.
    "pod-node-selector": (
        "nats:\n  podTemplate:\n    merge:\n      spec: {nodeSelector: {disk: w169-ssd}}\n",
        "`nats.podTemplate.merge.spec.nodeSelector`",
    ),
    "statefulset-min-ready": (
        "nats:\n  statefulSet:\n    merge:\n      spec: {minReadySeconds: 7}\n",
        "`nats.statefulSet.merge.spec.minReadySeconds`",
    ),
    "statefulset-claims": (
        "nats:\n  statefulSet:\n    merge:\n      spec:\n        volumeClaimTemplates: []\n",
        "`nats.statefulSet.merge.spec.volumeClaimTemplates`",
    ),
}


# MEASURED on helm 3.20.2 and 4.3.0: helm renders the subchart first, and the
# chart's own `add /spec/volumes/-` patch fails inside it on a non-map `spec`
# before the parent's arm runs. Either refusal is a refusal; a pass is not.
SUBCHART_REFUSES_FIRST = {"pod-spec-not-a-map": "key volumes does not exist"}


@POSTURES
@pytest.mark.parametrize("case", sorted(REFUSED))
def test_a_merge_that_overrides_what_the_chart_owns_is_refused(tmp_path, posture, case):
    body, named = REFUSED[case]
    result = render(tmp_path, posture, body)
    assert result.returncode != 0, f"the render passed for:\n{body}"
    if SUBCHART_REFUSES_FIRST.get(case, "\0") in result.stderr:
        return
    assert REFUSAL in result.stderr, result.stderr
    assert named in result.stderr, result.stderr


# ── ALLOWED: EACH SHAPE RENDERS, AND REACHES THE OBJECT ─────────────────────

ALLOWED = {
    "resources": ("nats:\n  container:\n    merge:\n      resources: {limits: {memory: 1Gi}}\n", "1Gi"),
    "security-context": (
        "nats:\n  container:\n    merge:\n      securityContext: {readOnlyRootFilesystem: true}\n",
        "readOnlyRootFilesystem: true",
    ),
    "termination-message": (
        "nats:\n  container:\n    merge:\n      terminationMessagePolicy: FallbackToLogsOnError\n",
        "FallbackToLogsOnError",
    ),
    "pod-labels": ("nats:\n  podTemplate:\n    merge:\n      metadata: {labels: {team: w169}}\n", "team: w169"),
    "statefulset-annotations": (
        "nats:\n  statefulSet:\n    merge:\n      metadata: {annotations: {w169: kept}}\n",
        "w169: kept",
    ),
}


@POSTURES
@pytest.mark.parametrize("case", sorted(ALLOWED))
def test_a_merge_the_chart_allows_renders(tmp_path, posture, case):
    body, marker = ALLOWED[case]
    result = render(tmp_path, posture, body)
    assert result.returncode == 0, result.stderr
    assert marker in result.stdout, f"{marker!r} did not reach the rendered objects"
