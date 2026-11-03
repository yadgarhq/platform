"""EVERY VALUE THE UPSTREAM NATS CHART PRINTS UNQUOTED IS OF ITS KIND (yaadgaar 546).

THE GAP. The upstream nats chart (2.14.6) renders `nats.conf`, the StatefulSet,
its pod and every other object from `files/**.yaml` through `tpl` and then
`fromYaml`, and it prints many values raw (`port: {{ .port }}`). A newline in
such a value ends the scalar and writes a sibling key, which `fromYaml` then
parses as the chart's own. Before this file, `nats.config.nats.port: "4222\\n
allow_non_tls: true"` rendered rc=0 with TLS required and put
`"allow_non_tls": true` into nats.conf, past every key-based check in
`templates/render-checks.yaml`. YAML flow syntax (`{allow_non_tls: true}`) re-types
a value with no newline at all, and `jetstream.yaml` wraps three sizes in its own
`<< >>`, so `maxSize: "1Gi; allow_non_tls: true"` reached nats.conf as raw text.

THE RULE, in `templates/render-checks.yaml`'s unquoted-values arm: each such value
is an ALLOWLIST of its kind, never a denylist of bad characters — a whole number
in range, a bool, a DNS-1123 name, an absolute path, an image reference, a
storage size. `SWEEP` below is the sweep: every unquoted print in the vendored
chart, by file and line, with the values path the arm judges or the reason it
needs none. `test_the_sweep_covers_every_unquoted_print` re-runs the sweep over
the vendored archive, so a chart bump that adds or moves a print reddens here.

NO SKIPS (ADR-0650): helm absent is a failure.

Run: python3 -m pytest scripts/tests/test_nats_unquoted_values.py -q
"""

from __future__ import annotations

import re
import shutil
import subprocess
import tarfile
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
REFUSAL = "platform: a value the upstream nats chart prints unquoted is not of its kind"


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


def nats(path: str, value: str) -> str:
    """A values file setting `nats.<path>` to the YAML scalar `value`."""
    keys = path.split(".")
    lines = ["nats:"]
    for depth, key in enumerate(keys[:-1], start=1):
        lines.append("  " * depth + f"{key}:")
    lines.append("  " * len(keys) + f"{keys[-1]}: {value}")
    return "\n".join(lines) + "\n"


# ── REFUSED: EACH PAYLOAD NAMES ITS PATH ────────────────────────────────────
# `"...\n..."` is a YAML double-quoted scalar, so `\n` reaches the chart as a
# newline. Measured on main 917a50a, every payload here rendered rc=0 except
# four: `port-monitor` and `image-digest`, which an earlier arm refuses (the
# rotation arm's 8222 pin, the alpine arm's digest-only refusal), and
# `name-config-map` and `name-service`, whose flow-syntax name helm's own decode
# of `metadata.name` refuses. The arm refuses all four as well.

INJECT = r'"%s\nallow_non_tls: true"'
POD_INJECT = r'"%s\nhostNetwork: true"'
CONTAINER_INJECT = r'"%s\nlifecycle: {postStart: {exec: {command: [/bin/sh, -c, id]}}}"'

REFUSED = {
    # whole numbers
    "port-nats": (nats("config.nats.port", INJECT % 4222), "`nats.config.nats.port`"),
    "port-nats-flow": (nats("config.nats.port", '"{allow_non_tls: true}"'), "`nats.config.nats.port`"),
    "port-nats-float": (nats("config.nats.port", "4222.5"), "`nats.config.nats.port`"),
    "port-nats-range": (nats("config.nats.port", "70000"), "`nats.config.nats.port`"),
    "port-monitor": (nats("config.monitor.port", INJECT % 8222), "`nats.config.monitor.port`"),
    "port-profiling": (nats("config.profiling.port", INJECT % 65432), "`nats.config.profiling.port`"),
    "port-leafnodes": (nats("config.leafnodes.port", INJECT % 7422), "`nats.config.leafnodes.port`"),
    "port-websocket": (nats("config.websocket.port", INJECT % 8080), "`nats.config.websocket.port`"),
    "port-mqtt": (nats("config.mqtt.port", INJECT % 1883), "`nats.config.mqtt.port`"),
    "port-cluster": (nats("config.cluster.port", INJECT % 6222), "`nats.config.cluster.port`"),
    "port-gateway": (nats("config.gateway.port", INJECT % 7222), "`nats.config.gateway.port`"),
    "port-prom-exporter": (nats("promExporter.port", CONTAINER_INJECT % 7777), "`nats.promExporter.port`"),
    "cluster-replicas": (nats("config.cluster.replicas", POD_INJECT % 3), "`nats.config.cluster.replicas`"),
    "grace-period": (nats("podTemplate.terminationGracePeriodSeconds", POD_INJECT % 60), "`nats.podTemplate.terminationGracePeriodSeconds`"),
    # bool
    "no-advertise": (nats("config.cluster.noAdvertise", INJECT % "true"), "`nats.config.cluster.noAdvertise`"),
    "no-advertise-string": (nats("config.cluster.noAdvertise", '"true"'), "`nats.config.cluster.noAdvertise`"),
    # sizes inside the chart's own `<< >>`
    "size-memory-store": (nats("config.jetstream.memoryStore.maxSize", '"1Gi; allow_non_tls: true"'), "`nats.config.jetstream.memoryStore.maxSize`"),
    "size-file-store": (nats("config.jetstream.fileStore.maxSize", '"1Gi; allow_non_tls: true"'), "`nats.config.jetstream.fileStore.maxSize`"),
    "size-number": (nats("config.jetstream.fileStore.maxSize", "1073741824"), "`nats.config.jetstream.fileStore.maxSize`"),
    "size-number-small": (nats("config.jetstream.fileStore.maxSize", "512"), "`nats.config.jetstream.fileStore.maxSize`"),
    "size-pvc": (nats("config.jetstream.fileStore.pvc.size", '"10Gi; allow_non_tls: true"'), "`nats.config.jetstream.fileStore.pvc.size`"),
    # paths
    "dir-jetstream": (nats("config.jetstream.fileStore.dir", INJECT % "/data"), "`nats.config.jetstream.fileStore.dir`"),
    "dir-resolver-flow": (nats("config.resolver.dir", '"{allow_non_tls: true}"'), "`nats.config.resolver.dir`"),
    "dir-tls": (nats("config.leafnodes.tls.dir", INJECT % "/etc/nats-certs/leafnodes"), "`nats.config.leafnodes.tls.dir`"),
    "dir-tls-relative": (nats("config.gateway.tls.dir", '"-pid"'), "`nats.config.gateway.tls.dir`"),
    "file-tls-cert": (nats("config.nats.tls.cert", INJECT % "tls.crt"), "`nats.config.nats.tls.cert`"),
    "file-tls-key": (nats("config.mqtt.tls.key", '"[tls.key]"'), "`nats.config.mqtt.tls.key`"),
    "dir-tls-ca": (nats("tlsCA.dir", INJECT % "/etc/nats-ca-cert"), "`nats.tlsCA.dir`"),
    "file-tls-ca": (nats("tlsCA.key", INJECT % "ca.crt"), "`nats.tlsCA.key`"),
    # `nats.reloaderConfig` prints every cert_file / key_file / ca_file raw
    "reloader-cert-file": (
        nats("config.nats.tls.merge.cert_file", r'"/x\n- -pid"'),
        "`nats.config` holds a `cert_file`",
    ),
    "reloader-cert-file-not-string": (
        nats("config.nats.tls.merge.key_file", "{a: b}"),
        "`nats.config` holds a `cert_file`, `key_file` or `ca_file` that is not a string",
    ),
    # names
    "name-config-map": (nats("configMap.name", '"[nats-config]"'), "`nats.configMap.name`"),
    "name-stateful-set": (nats("statefulSet.name", INJECT % "nats"), "`nats.statefulSet.name`"),
    "name-headless-service": (nats("headlessService.name", POD_INJECT % "nats-headless"), "`nats.headlessService.name`"),
    "name-service": (nats("service.name", '"{a: b}"'), "`nats.service.name`"),
    "name-service-account": (nats("serviceAccount.name", POD_INJECT % "nats"), "`nats.serviceAccount.name`"),
    "name-pdb": (nats("podDisruptionBudget.name", POD_INJECT % "nats"), "`nats.podDisruptionBudget.name`"),
    "name-pod-monitor": (nats("promExporter.podMonitor.name", POD_INJECT % "nats"), "`nats.promExporter.podMonitor.name`"),
    "name-ws-ingress": (nats("config.websocket.ingress.name", POD_INJECT % "nats-ws"), "`nats.config.websocket.ingress.name`"),
    "name-js-pvc": (nats("config.jetstream.fileStore.pvc.name", CONTAINER_INJECT % "nats-js"), "`nats.config.jetstream.fileStore.pvc.name`"),
    "name-resolver-pvc": (nats("config.resolver.pvc.name", CONTAINER_INJECT % "nats-resolver"), "`nats.config.resolver.pvc.name`"),
    "name-box-contents": (nats("natsBox.contentsSecret.name", POD_INJECT % "nats-box-contents"), "`nats.natsBox.contentsSecret.name`"),
    "name-box-contexts": (nats("natsBox.contextsSecret.name", POD_INJECT % "nats-box-contexts"), "`nats.natsBox.contextsSecret.name`"),
    "name-box-deployment": (nats("natsBox.deployment.name", POD_INJECT % "nats-box"), "`nats.natsBox.deployment.name`"),
    "name-box-service-account": (nats("natsBox.serviceAccount.name", POD_INJECT % "nats-box"), "`nats.natsBox.serviceAccount.name`"),
    "name-override": (nats("nameOverride", POD_INJECT % "nats"), "`nats.nameOverride`"),
    "fullname-override": (nats("fullnameOverride", '"Nats"'), "`nats.fullnameOverride`"),
    "namespace-override": (nats("namespaceOverride", INJECT % "yadgar"), "`nats.namespaceOverride`"),
    "cluster-domain": (nats("config.cluster.routeURLs.k8sClusterDomain", INJECT % "cluster.local"), "`nats.config.cluster.routeURLs.k8sClusterDomain`"),
    "monitor-domain": (nats("promExporter.monitorDomain", CONTAINER_INJECT % "localhost"), "`nats.promExporter.monitorDomain`"),
    "box-context-key": ('nats:\n  natsBox:\n    contexts:\n      "a\\"b": {}\n', "`nats.natsBox.contexts` key"),
    # images: `image: {{ $image }}` sits in the container, beside `lifecycle`
    "image-tag": (nats("container.image.tag", CONTAINER_INJECT.replace("id]}}}", "id]}}}\\nx: y-alpine") % "2.14.6-alpine"), "`nats.container.image.tag`"),
    "image-repository": (nats("container.image.repository", r'"nats:2.14.6-alpine\nlifecycle: {}\nx: y"'), "`nats.container.image.repository`"),
    "image-registry": (nats("container.image.registry", r'"docker.io\nlifecycle: {}\nx: y"'), "`nats.container.image.registry`"),
    "image-digest": (nats("container.image.digest", r'"sha256:x\nlifecycle: {}"'), "`nats.container.image.digest`"),
    "image-full-name": (nats("container.image.fullImageName", r'"nats:2.14.6\nlifecycle: {}\nx: y-alpine"'), "`nats.container.image.fullImageName`"),
    "image-pull-policy": (nats("container.image.pullPolicy", r'"IfNotPresent\nlifecycle: {}"'), "`nats.container.image.pullPolicy`"),
    "image-prom-exporter": (nats("promExporter.image.tag", CONTAINER_INJECT % "0.20.1"), "`nats.promExporter.image.tag`"),
    "image-tag-number": (nats("promExporter.image.tag", "2.14"), "`nats.promExporter.image.tag`"),
    "image-prom-exporter-digest": (nats("promExporter.image.digest", r'"sha256:x\nlifecycle: {}"'), "`nats.promExporter.image.digest`"),
    "image-box": (nats("natsBox.container.image.tag", CONTAINER_INJECT % "0.19.7"), "`nats.natsBox.container.image.tag`"),
    "image-global-registry": ('global:\n  image:\n    registry: "docker.io\\nlifecycle: {}\\nx: y"\n', "`global.image.registry`"),
    "image-global-pull-policy": ('global:\n  image:\n    pullPolicy: "Always\\nlifecycle: {}"\n', "`global.image.pullPolicy`"),
    "image-nats-global-registry": (nats("global.image.registry", r'"docker.io\nlifecycle: {}\nx: y"'), "`nats.global.image.registry`"),
}

# An earlier arm refuses some payloads first, by design: `fail` aborts at the
# first failing check, and this arm is declared after the rotation arms, so the
# alpine-tag arm and the monitor-port arm win where they also apply. Either
# refusal is a refusal; a pass is not. Keyed by case, valued by the marker the
# earlier refusal prints.
EARLIER_ARM_REFUSES_FIRST = {
    "port-monitor": "`nats.config.monitor.port` is",
    "image-digest": "a digest-only pin drops the tag",
}

# The subchart renders before the parent and some garbage stops it there.
# Measured on helm 4.3.0 against nats 2.14.6. Either refusal is a refusal.
SUBCHART_REFUSES_FIRST: dict[str, str] = {}


@POSTURES
@pytest.mark.parametrize("case", sorted(REFUSED))
def test_an_unquoted_value_not_of_its_kind_is_refused(tmp_path, posture, case):
    body, named = REFUSED[case]
    result = render(tmp_path, posture, body)
    assert result.returncode != 0, f"the render passed for:\n{body}"
    for marker in (EARLIER_ARM_REFUSES_FIRST.get(case), SUBCHART_REFUSES_FIRST.get(case)):
        if marker and marker in result.stderr:
            return
    assert REFUSAL in result.stderr, result.stderr
    assert named in result.stderr, result.stderr


# ── ALLOWED: EACH SHAPE RENDERS, AND REACHES THE OBJECT ─────────────────────

DIGEST = "sha256:" + "0" * 64
ALLOWED = {
    "port-int": (nats("config.nats.port", "4223"), '"port": 4223'),
    "port-string": (nats("config.nats.port", '"4223"'), '"port": 4223'),
    "port-prom-exporter": ("nats:\n  promExporter: {enabled: true, port: 7778}\n", "-port=7778"),
    "grace-period": (nats("podTemplate.terminationGracePeriodSeconds", "90"), "terminationGracePeriodSeconds: 90"),
    "replicas": (nats("config.cluster.replicas", "5"), None),
    "no-advertise-false": (nats("config.cluster.noAdvertise", "false"), None),
    "jetstream-sizes": (
        "nats:\n  config:\n    jetstream:\n      enabled: true\n"
        "      memoryStore: {enabled: true, maxSize: 512Mi}\n"
        "      fileStore: {dir: /data/js, maxSize: 2G}\n",
        '"max_memory_store": 512Mi',
    ),
    "jetstream-pvc-size": (
        "nats:\n  config:\n    jetstream:\n      enabled: true\n      fileStore: {pvc: {size: 20Gi}}\n",
        '"max_file_store": 20Gi',
    ),
    "jetstream-size-number": (
        "nats:\n  config:\n    jetstream:\n      enabled: true\n      fileStore: {maxSize: \"1073741824\"}\n",
        '"max_file_store": 1073741824',
    ),
    "name-config-map": (nats("configMap.name", "nats-conf"), "name: nats-conf"),
    "name-dotted": (nats("service.name", "nats.yadgar"), "name: nats.yadgar"),
    "tls-cert-name": (nats("config.nats.tls.cert", "server.crt"), None),
    "image-full-name": (nats("container.image.fullImageName", f"nats:2.14.6-alpine@{DIGEST}"), f"image: nats:2.14.6-alpine@{DIGEST}"),
    "image-registry-port": (nats("container.image.registry", "registry.example.com:5000"), "image: registry.example.com:5000/nats:2.14.6-alpine"),
    "image-pull-policy": (nats("container.image.pullPolicy", "IfNotPresent"), "imagePullPolicy: IfNotPresent"),
    "monitor-domain": (nats("promExporter.monitorDomain", "127.0.0.1"), None),
    "cluster-domain": (nats("config.cluster.routeURLs.k8sClusterDomain", "cluster.example"), None),
}


def test_the_shipped_values_render_at_both_postures(tmp_path):
    for posture in ("off", "required"):
        result = render(tmp_path, posture, "{}\n")
        assert result.returncode == 0, result.stderr


@POSTURES
@pytest.mark.parametrize("case", sorted(ALLOWED))
def test_an_unquoted_value_of_its_kind_renders(tmp_path, posture, case):
    body, marker = ALLOWED[case]
    result = render(tmp_path, posture, body)
    assert result.returncode == 0, result.stderr
    if marker:
        assert marker in result.stdout, f"{marker!r} did not reach the rendered objects"


# ── THE SWEEP IS AN EXECUTABLE CLAIM ────────────────────────────────────────
# Every `{{ }}` in the vendored chart's `files/` and `templates/` that prints a
# value without `quote`, `toYaml` or `toJson`, keyed `file:line` and the action's
# text, valued with the `render-checks.yaml` path(s) that judge it, or with
# `EXCLUDED:` and the reason no value can reach it. An `include` is not listed:
# the helper it calls is swept where it is defined.

SWEEP = {
    ("files/config-map.yaml:5", ".Values.configMap.name"): ["nats.configMap.name"],
    ("files/config/cluster.yaml:2", "$.Values.statefulSet.name"): ["nats.statefulSet.name"],
    ("files/config/cluster.yaml:3", ".port"): ["nats.config.cluster.port"],
    ("files/config/cluster.yaml:4", ".noAdvertise"): ["nats.config.cluster.noAdvertise"],
    ("files/config/cluster.yaml:17", 'printf "%s://%s%s-%d.%s:%d" $proto $auth $.Values.statefulSet.name $i $domain $port'): [
        "nats.statefulSet.name", "nats.headlessService.name", "nats.namespaceOverride",
        "nats.config.cluster.routeURLs.k8sClusterDomain", "nats.config.cluster.port", "nats.config.cluster.replicas",
    ],
    ("files/config/config.yaml:12", ".port"): ["nats.config.nats.port"],
    ("files/config/config.yaml:78", ".port"): ["nats.config.monitor.port"],
    ("files/config/config.yaml:80", ".port"): ["nats.config.monitor.port"],
    ("files/config/config.yaml:90", ".port"): ["nats.config.profiling.port"],
    ("files/config/gateway.yaml:2", "$.Values.statefulSet.name"): ["nats.statefulSet.name"],
    ("files/config/gateway.yaml:3", ".port"): ["nats.config.gateway.port"],
    ("files/config/jetstream.yaml:5", "."): ["nats.config.jetstream.memoryStore.maxSize"],
    ("files/config/jetstream.yaml:13", ".dir"): ["nats.config.jetstream.fileStore.dir"],
    ("files/config/jetstream.yaml:15", ".maxSize"): ["nats.config.jetstream.fileStore.maxSize"],
    ("files/config/jetstream.yaml:17", ".pvc.size"): ["nats.config.jetstream.fileStore.pvc.size"],
    ("files/config/leafnodes.yaml:2", ".port"): ["nats.config.leafnodes.port"],
    ("files/config/mqtt.yaml:2", ".port"): ["nats.config.mqtt.port"],
    ("files/config/protocol.yaml:2", ".port"): "EXCLUDED: no template or file loads config/protocol.yaml",
    ("files/config/resolver.yaml:2", ".dir"): ["nats.config.resolver.dir"],
    ("files/config/websocket.yaml:2", ".port"): ["nats.config.websocket.port"],
    ("files/headless-service.yaml:5", ".Values.headlessService.name"): ["nats.headlessService.name"],
    ("files/ingress.yaml:6", ".name"): ["nats.config.websocket.ingress.name"],
    ("files/ingress.yaml:24", "$.Values.service.name"): ["nats.service.name"],
    ("files/nats-box/contents-secret.yaml:5", ".Values.natsBox.contentsSecret.name"): ["nats.natsBox.contentsSecret.name"],
    ("files/nats-box/contents-secret.yaml:14", "$ctxKey"): ["nats.natsBox.contexts"],
    ("files/nats-box/contents-secret.yaml:14", "$secretVal"): "EXCLUDED: a literal of the chart's own (`creds`, `nkey`)",
    ("files/nats-box/contexts-secret/context.yaml:5", ".Values.service.name"): ["nats.service.name"],
    ("files/nats-box/contexts-secret/context.yaml:7", ".Values.headlessService.name"): ["nats.headlessService.name"],
    ("files/nats-box/contexts-secret/context.yaml:15", "$contextName"): ["nats.natsBox.contexts"],
    ("files/nats-box/contexts-secret/context.yaml:25", "$contextName"): ["nats.natsBox.contexts"],
    ("files/nats-box/contexts-secret/contexts-secret.yaml:5", ".Values.natsBox.contextsSecret.name"): ["nats.natsBox.contextsSecret.name"],
    ("files/nats-box/contexts-secret/contexts-secret.yaml:11", "$ctxKey"): ["nats.natsBox.contexts"],
    ("files/nats-box/deployment/deployment.yaml:5", ".Values.natsBox.deployment.name"): ["nats.natsBox.deployment.name"],
    ("files/nats-box/deployment/pod-template.yaml:30", ".Values.natsBox.contextsSecret.name"): ["nats.natsBox.contextsSecret.name"],
    ("files/nats-box/deployment/pod-template.yaml:35", ".Values.natsBox.contentsSecret.name"): ["nats.natsBox.contentsSecret.name"],
    ("files/nats-box/service-account.yaml:5", ".Values.natsBox.serviceAccount.name"): ["nats.natsBox.serviceAccount.name"],
    ("files/pod-disruption-budget.yaml:5", ".Values.podDisruptionBudget.name"): ["nats.podDisruptionBudget.name"],
    ("files/pod-monitor.yaml:5", ".Values.promExporter.podMonitor.name"): ["nats.promExporter.podMonitor.name"],
    ("files/service-account.yaml:5", ".Values.serviceAccount.name"): ["nats.serviceAccount.name"],
    ("files/service.yaml:5", ".Values.service.name"): ["nats.service.name"],
    ("files/stateful-set/jetstream-pvc.yaml:3", ".name"): ["nats.config.jetstream.fileStore.pvc.name"],
    ("files/stateful-set/nats-container.yaml:62", ".pvc.name"): ["nats.config.jetstream.fileStore.pvc.name"],
    ("files/stateful-set/nats-container.yaml:70", ".pvc.name"): ["nats.config.resolver.pvc.name"],
    ("files/stateful-set/pod-template.yaml:7", "sha256sum $configMap"): "EXCLUDED: a hex digest",
    ("files/stateful-set/pod-template.yaml:53", ".Values.configMap.name"): ["nats.configMap.name"],
    ("files/stateful-set/pod-template.yaml:76", ".Values.podTemplate.terminationGracePeriodSeconds"): ["nats.podTemplate.terminationGracePeriodSeconds"],
    ("files/stateful-set/prom-exporter-container.yaml:6", ".Values.promExporter.port"): ["nats.promExporter.port"],
    ("files/stateful-set/prom-exporter-container.yaml:14", ".Values.promExporter.port"): ["nats.promExporter.port"],
    ("files/stateful-set/prom-exporter-container.yaml:31", "$monitorProto"): "EXCLUDED: a `ternary` of two literals",
    ("files/stateful-set/prom-exporter-container.yaml:31", ".Values.promExporter.monitorDomain"): ["nats.promExporter.monitorDomain"],
    ("files/stateful-set/prom-exporter-container.yaml:31", ".Values.config.monitor.port"): ["nats.config.monitor.port"],
    ("files/stateful-set/resolver-pvc.yaml:3", ".name"): ["nats.config.resolver.pvc.name"],
    ("files/stateful-set/stateful-set.yaml:5", ".Values.statefulSet.name"): ["nats.statefulSet.name"],
    ("files/stateful-set/stateful-set.yaml:13", ".Values.config.cluster.replicas"): ["nats.config.cluster.replicas"],
    ("files/stateful-set/stateful-set.yaml:17", ".Values.headlessService.name"): ["nats.headlessService.name"],
    ("templates/_helpers.tpl:5", 'default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-"'): ["nats.nameOverride"],
    ("templates/_helpers.tpl:15", '.Values.fullnameOverride | trunc 63 | trimSuffix "-"'): ["nats.fullnameOverride"],
    ("templates/_helpers.tpl:19", '.Release.Name | trunc 63 | trimSuffix "-"'): "EXCLUDED: the release name, which helm validates as a DNS-1123 name",
    ("templates/_helpers.tpl:21", 'printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-"'): ["nats.nameOverride"],
    ("templates/_helpers.tpl:30", 'printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-"'): "EXCLUDED: the vendored Chart.yaml",
    ("templates/_helpers.tpl:37", "default .Release.Namespace .Values.namespaceOverride"): ["nats.namespaceOverride"],
    ("templates/_helpers.tpl:110", ".Release.Service"): "EXCLUDED: helm's own literal",
    ("templates/_helpers.tpl:118", ".Release.Name"): "EXCLUDED: the release name, which helm validates as a DNS-1123 name",
    ("templates/_helpers.tpl:134", ".Release.Service"): "EXCLUDED: helm's own literal",
    ("templates/_helpers.tpl:142", ".Release.Name"): "EXCLUDED: the release name, which helm validates as a DNS-1123 name",
    ("templates/_helpers.tpl:162", "$image"): [
        "nats.container.image.repository", "nats.container.image.tag", "nats.container.image.digest",
        "nats.container.image.registry", "nats.container.image.fullImageName",
        "nats.promExporter.image.repository", "nats.natsBox.container.image.repository",
        "global.image.registry", "nats.global.image.registry",
        "nats.reloader.image.repository", "nats.reloader.image.tag", "nats.reloader.image.digest",
        "nats.reloader.image.registry", "nats.reloader.image.fullImageName",
    ],
    ("templates/_helpers.tpl:164", ".pullPolicy | default .global.image.pullPolicy"): [
        "nats.container.image.pullPolicy", "nats.promExporter.image.pullPolicy",
        "nats.natsBox.container.image.pullPolicy", "global.image.pullPolicy", "nats.global.image.pullPolicy",
        "nats.reloader.image.pullPolicy",
    ],
    ("templates/_helpers.tpl:263", "$v"): ["cert_file|key_file|ca_file", "nats.config.nats.tls.dir", "nats.config.nats.tls.cert", "nats.tlsCA.dir", "nats.tlsCA.key"],
    ("templates/_helpers.tpl:266", 'clean (printf "%s/%s" $dir $v)'): "EXCLUDED: an `$include` value; the NATS contract arm refuses every `$include` key under `nats.config`, and the patch arm every JSON patch that could add one (yaadgaar 544)",
    ("templates/_helpers.tpl:284", r'(regexReplaceAll "\"<<\\s+(.*?)\\s+>>\"" (regexReplaceAll "\".*\\$include\": \"(.*)\",?" (include "toPrettyRawJson" .) "include ${1};") "${1}")'): "EXCLUDED: JSON-encoded config; the raw-text and `$include` arms own its two rewrites",
    ("templates/_toPrettyRawJson.tpl:26", "$s"): "EXCLUDED: the JSON-encoded config `nats.formatConfig` formats",
}

ACTION = re.compile(r"\{\{-?\s*(.*?)\s*-?\}\}", re.S)
CONTROL = re.compile(r"^(if|else|end|with|range|define|template|block|/\*|\$[A-Za-z_]*\s*:?=|fail\b)")
ENCODED = re.compile(r"\|\s*(quote|squote|toYaml|toJson|toRawJson|toPrettyJson)\b|^(include|toYaml|toJson|toRawJson)\b")


def vendored_nats() -> Path:
    lock = yaml.safe_load((CHART / "Chart.lock").read_text())
    version = next(d["version"] for d in lock["dependencies"] if d["name"] == "nats")
    archive = CHART / "charts" / f"nats-{version}.tgz"
    assert archive.is_file(), f"{archive} is absent: run `helm dependency build chart` first."
    return archive


def unquoted_prints() -> set[tuple[str, str]]:
    found = set()
    with tarfile.open(vendored_nats()) as archive:
        for member in archive.getmembers():
            relative = member.name.split("/", 1)[1]
            if not member.isfile() or not relative.endswith((".yaml", ".tpl")):
                continue
            if not relative.startswith(("files/", "templates/")) or relative.startswith("templates/tests/"):
                continue
            text = archive.extractfile(member).read().decode()
            for match in ACTION.finditer(text):
                expression = " ".join(match.group(1).split())
                if CONTROL.match(expression) or ENCODED.search(expression):
                    continue
                found.add((f"{relative}:{text.count(chr(10), 0, match.start()) + 1}", expression))
    return found


def test_the_sweep_covers_every_unquoted_print():
    found = unquoted_prints()
    assert found - set(SWEEP) == set(), "an unquoted print in the vendored nats chart is not in SWEEP"
    assert set(SWEEP) - found == set(), "SWEEP lists a print the vendored nats chart no longer has"


def test_every_judged_path_is_in_the_arm():
    text = RENDER_CHECKS.read_text()
    arm = text[text.index("THE SCALARS THE UPSTREAM NATS CHART PRINTS UNQUOTED"):text.index("end of the unquoted-values arm")]
    for key, judged in SWEEP.items():
        if isinstance(judged, str):
            assert judged.startswith("EXCLUDED: "), key
            continue
        for path in judged:
            needle = path if "|" in path else f'"{path}"'
            assert needle in arm, f"{key} names {path!r}, which the unquoted-values arm does not judge"
