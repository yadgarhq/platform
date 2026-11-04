"""THE BROKER'S REMAINING MERGE ROUTES ARE ALLOWLISTS (yaadgaar 553).

THE GAP. The upstream nats chart (2.14.6) runs `nats.loadMergePatch` for every
object it renders: it mergeOverwrites the object's `merge`, then applies its
`patch`. The patch arm refuses every adopter patch, and the merge-key arms hold
`container`, `podTemplate` and `statefulSet` to their lists, but every other
merge reached its object unread. MEASURED rc=0 on main abdbcbb at both TLS
postures: `nats.promExporter.enabled: true` with `merge.command` and a
`volumeMounts` entry for `nats-auth-iam`, which mounts the broker password into a
container that runs any command, in a pod with `shareProcessNamespace: true`.

THE RULE, in `templates/render-checks.yaml`'s object merge arm, while
`nats.create` is true: a container merge (`promExporter`, `natsBox.container`)
holds the `nats.container.merge` allowlist; every other object merge holds
`metadata.labels` and `metadata.annotations` only; a nats-box context merge must
be empty. The `nats.conf` block merges are not judged here, and
`test_every_upstream_merge_is_judged_or_listed` names them.

NO SKIPS (ADR-0650): helm absent is a failure.

Run: python3 -m pytest scripts/tests/test_nats_merge_routes.py -q
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
REFUSAL = "platform: the broker's merge keys reach past what the chart checks"

CONTAINER_MERGES = ["promExporter", "natsBox.container"]
OBJECT_MERGES = [
    "promExporter.podMonitor", "service", "headlessService", "serviceAccount",
    "podDisruptionBudget", "config.websocket.ingress", "config.jetstream.fileStore.pvc",
    "config.resolver.pvc", "natsBox.deployment", "natsBox.podTemplate",
    "natsBox.contextsSecret", "natsBox.contentsSecret", "natsBox.serviceAccount",
]
# Merges another arm judges, each named with the arm.
JUDGED_ELSEWHERE = {
    "config.merge": "the NATS TLS contract arm",
    "config.nats.tls.merge": "the NATS TLS contract arm",
    "configMap.merge": "the NATS TLS contract arm",
    "container.merge": "the broker merge-key arm",
    "podTemplate.merge": "the broker merge-key arm",
    "statefulSet.merge": "the broker merge-key arm",
    "reloader.merge": "the patch arm's reloader arm",
}
# THE OPEN RESIDUAL. These merges write a `nats.conf` block rather than an
# object; each block is off by default, and no arm judges them yet.
NATS_CONF_BLOCKS = ["cluster", "jetstream", "leafnodes", "websocket", "mqtt", "gateway", "resolver"]
NOT_JUDGED = {f"config.{b}.merge" for b in NATS_CONF_BLOCKS} | {
    f"config.{b}.tls.merge" for b in ("cluster", "leafnodes", "websocket", "mqtt", "gateway")
}


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


def merge_at(path: str, merge, **siblings) -> str:
    """`nats.<path>.merge: <merge>`, with `siblings` beside it (an `enabled`)."""
    tree: dict = {"merge": merge, **siblings}
    for key in reversed(path.split(".")):
        tree = {key: tree}
    return yaml.safe_dump({"nats": tree})


# ── REFUSED: EACH SHAPE NAMES ITSELF ────────────────────────────────────────

REFUSED: dict[str, tuple[str, str]] = {
    # The headline measurement: the exporter, on, running a command over the password mount.
    "prom-exporter-command-and-mount": (
        merge_at("promExporter", {
            "command": ["/bin/sh", "-c", "cat /var/run/secrets/nats-auth/iam/password"],
            "volumeMounts": [{"name": "nats-auth-iam", "mountPath": "/var/run/secrets/nats-auth/iam"}],
        }, enabled=True),
        '`nats.promExporter.merge` sets the key "command"',
    ),
    "prom-exporter-mount": (
        merge_at("promExporter", {"volumeMounts": [{"name": "nats-auth-iam", "mountPath": "/x"}]}, enabled=True),
        '`nats.promExporter.merge` sets the key "volumeMounts"',
    ),
    "prom-exporter-disabled-still-judged": (
        merge_at("promExporter", {"args": ["-x"]}),
        '`nats.promExporter.merge` sets the key "args"',
    ),
    # With the exporter off the subchart renders no container to fail on, so the
    # arm is the one that refuses a merge of the wrong kind.
    "prom-exporter-disabled-not-a-map": (merge_at("promExporter", ["x"]), "`nats.promExporter.merge` is not a map (it is slice)"),
    "nats-box-container-env": (
        merge_at("natsBox.container", {"env": [{"name": "X", "value": "y"}]}),
        '`nats.natsBox.container.merge` sets the key "env"',
    ),
    "service-type": (merge_at("service", {"spec": {"type": "NodePort"}}), '`nats.service.merge` sets the key "spec"'),
    "service-metadata-name": (
        merge_at("service", {"metadata": {"name": "other"}}),
        '`nats.service.merge.metadata` sets the key "name"',
    ),
    "service-metadata-not-a-map": (merge_at("service", {"metadata": "x"}), "`nats.service.merge.metadata` is not a map"),
    "pvc-data-source": (
        merge_at("config.jetstream.fileStore.pvc", {"spec": {"dataSource": {"kind": "PersistentVolumeClaim", "name": "x"}}}),
        '`nats.config.jetstream.fileStore.pvc.merge` sets the key "spec"',
    ),
    "secret-data": (
        merge_at("natsBox.contextsSecret", {"stringData": {"x": "y"}}),
        '`nats.natsBox.contextsSecret.merge` sets the key "stringData"',
    ),
    "context-default-merge": (merge_at("natsBox.contexts.default", {"url": "nats://evil:4222"}), "`nats.natsBox.contexts.default.merge` is set"),
    "context-other-merge": (merge_at("natsBox.contexts.other", {"url": "nats://evil:4222"}), "`nats.natsBox.contexts.other.merge` is set"),
}
for _path in OBJECT_MERGES:
    REFUSED[f"object-spec-{_path}"] = (merge_at(_path, {"spec": {}}), f'`nats.{_path}.merge` sets the key "spec"')
for _path in CONTAINER_MERGES:
    REFUSED[f"container-image-{_path}"] = (merge_at(_path, {"image": "busybox"}), f'`nats.{_path}.merge` sets the key "image"')

# MEASURED: the upstream chart's own `merge` fails on a value of the wrong kind
# before the parent's arm runs. Either refusal is a refusal; a pass is not.
SUBCHART_REFUSES_FIRST = {"service-metadata-not-a-map": "wrong type for value"}


@POSTURES
@pytest.mark.parametrize("case", sorted(REFUSED))
def test_a_merge_outside_its_allowlist_is_refused(tmp_path, posture, case):
    body, named = REFUSED[case]
    result = render(tmp_path, posture, body)
    assert result.returncode != 0, f"the render passed for:\n{body}"
    if SUBCHART_REFUSES_FIRST.get(case, "\0") in result.stderr:
        return
    assert REFUSAL in result.stderr, result.stderr
    assert named in result.stderr, result.stderr


# ── ALLOWED: EACH SHAPE RENDERS, AND REACHES ITS OBJECT ──────────────────────

ALLOWED = {
    "shipped": ("{}\n", None),
    "prom-exporter-resources": (
        merge_at("promExporter", {"resources": {"limits": {"memory": "55Mi"}}}, enabled=True),
        "55Mi",
    ),
    "prom-exporter-security-context": (
        merge_at("promExporter", {"securityContext": {"readOnlyRootFilesystem": True}}, enabled=True),
        "readOnlyRootFilesystem: true",
    ),
    "service-label": (merge_at("service", {"metadata": {"labels": {"w553": "label"}}}), "w553: label"),
    "headless-annotation": (merge_at("headlessService", {"metadata": {"annotations": {"w553": "note"}}}), "w553: note"),
    "empty-merges": (merge_at("service", {}), None),
    # helm deletes a `null` merge (v4) or keeps the upstream `{}` (v3.18.4, with a
    # warning); either way nothing is merged, so nothing refuses.
    "null-merge": (merge_at("service", None), None),
}


@POSTURES
@pytest.mark.parametrize("case", sorted(ALLOWED))
def test_a_merge_the_chart_allows_renders(tmp_path, posture, case):
    body, marker = ALLOWED[case]
    result = render(tmp_path, posture, body)
    assert result.returncode == 0, result.stderr
    if marker is not None:
        assert marker in result.stdout, f"{marker!r} did not reach the rendered objects"


def test_the_arm_runs_only_while_the_broker_is_created(tmp_path):
    (tmp_path / "case.yaml").write_text(merge_at("service", {"spec": {"type": "NodePort"}}))
    result = helm("template", "platform", str(CHART), "-f", str(tmp_path / "case.yaml"))
    assert result.returncode == 0, result.stderr


# ── THE LIST IN THE ARM IS THE UPSTREAM CHART'S LIST ────────────────────────


def upstream_merge_paths() -> set[str]:
    lock = yaml.safe_load((CHART / "Chart.lock").read_text())
    version = next(d["version"] for d in lock["dependencies"] if d["name"] == "nats")
    archive = CHART / "charts" / f"nats-{version}.tgz"
    assert archive.is_file(), f"{archive} is absent: run `helm dependency build chart` first."
    with tarfile.open(archive) as tar:
        values = yaml.safe_load(tar.extractfile("nats/values.yaml").read())
    found = set()

    def walk(node, path):
        if isinstance(node, dict):
            for key, value in node.items():
                if key == "merge":
                    found.add(".".join([*path, key]))
                walk(value, [*path, key])

    walk(values, [])
    return found


def arm_text() -> str:
    text = RENDER_CHECKS.read_text()
    return text[text.index("THE BROKER'S REMAINING MERGE ROUTES (yaadgaar 553)"):text.index("end of the object merge arm")]


def test_the_arm_judges_every_object_merge():
    judged = dict(re.findall(r'\(list "([A-Za-z.]+\.merge)" "(container|object)"\)', arm_text()))
    assert judged == {f"{p}.merge": "container" for p in CONTAINER_MERGES} | {f"{p}.merge": "object" for p in OBJECT_MERGES}
    assert "natsBox.contexts" in arm_text()


def test_every_upstream_merge_is_judged_or_listed():
    """A chart bump that adds a merge reddens here until an arm judges it or it is listed."""
    upstream = upstream_merge_paths()
    upstream.discard("natsBox.contexts.default.merge")
    named = {f"{p}.merge" for p in CONTAINER_MERGES + OBJECT_MERGES} | set(JUDGED_ELSEWHERE) | NOT_JUDGED
    assert upstream - named == set(), "the upstream chart has a merge nothing judges or lists"
    assert named - upstream == set(), "a merge is named that the upstream chart no longer has"
