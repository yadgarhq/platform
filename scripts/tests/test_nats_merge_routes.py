"""THE BROKER'S UNJUDGED OBJECT MERGE ROUTES ARE ALLOWLISTS (yaadgaar 553).

THE GAP. The upstream nats chart (2.14.6) runs `nats.loadMergePatch` for every
object it renders: it mergeOverwrites the object's `merge`, then applies its
`patch`. The patch arm refuses every adopter patch, and other arms judge seven
merges (`ARM_ALLOWLISTS` and `PARTLY_JUDGED` below), but every other object merge
reached its object unread. MEASURED rc=0 on main abdbcbb at both TLS
postures: `nats.promExporter.enabled: true` with `merge.command` and a
`volumeMounts` entry for `nats-auth-iam`, which mounts the broker password into a
container that runs any command, in a pod with `shareProcessNamespace: true`.

THE RULE, in `templates/render-checks.yaml`'s object merge arm, while
helm installs the broker (`nats.create` is not the bool `false`): a container merge (`promExporter`, `natsBox.container`)
holds the `nats.container.merge` allowlist; every other object merge holds
`metadata.labels` and `metadata.annotations` only; a nats-box context merge must
be empty. Five merges are allowlists in other arms (`ARM_ALLOWLISTS`, yaadgaar
597). The `nats.conf` block merges are not judged at all, and the two
`PARTLY_JUDGED` merges stay open beyond what their arms read;
`test_every_upstream_merge_is_judged_or_listed` names both, and
`test_a_partly_judged_route_still_renders` pins one open shape of each partly
judged merge, so closing one reddens it and the lists here get updated.

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
# Merges another arm holds to an ALLOWLIST of its own (yaadgaar 597), at every
# TLS posture; `test_a_key_off_an_arm_allowlist_is_refused_at_every_posture` below
# covers each.
ARM_ALLOWLISTS = {
    "config.merge": "the NATS TLS contract arm: `authorization` and `allow_non_tls`",
    "config.nats.tls.merge": "the NATS TLS contract arm: `verify` and `ca_file`",
    "configMap.merge": "the NATS TLS contract arm: `metadata.labels` and `metadata.annotations`",
    "podTemplate.merge": "the broker merge-key arm: `metadata.labels`, `metadata.annotations` and an empty `spec`",
    "statefulSet.merge": "the broker merge-key arm: `metadata.labels`, `metadata.annotations` and an empty `spec`",
}
# Merges another arm judges IN PART, each with the arm and what it leaves open.
# NOT FULLY JUDGED: each stays an open route beyond what its arm reads.
PARTLY_JUDGED = {
    "container.merge": "the broker merge-key arm's allowlist; the securityContext it allows is not narrowed (yaadgaar 554)",
    "reloader.merge": "the patch arm's reloader allowlist; the securityContext it allows is not narrowed (yaadgaar 554)",
}
# ONE OPEN SHAPE PER PARTLY JUDGED MERGE, with the posture it is open at. Each
# renders today; an arm that closes one reddens `test_a_partly_judged_route_still_renders`.
PARTLY_JUDGED_OPEN = {
    "container.merge": ("required", "nats:\n  container:\n    merge:\n      securityContext: {privileged: true}\n", "privileged: true"),
    "reloader.merge": ("required", "nats:\n  reloader:\n    merge:\n      securityContext: {privileged: true}\n", "privileged: true"),
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
    return text[text.index("THE BROKER'S UNJUDGED OBJECT MERGE ROUTES (yaadgaar 553)"):text.index("end of the object merge arm")]


def test_the_arm_judges_every_object_merge():
    judged = dict(re.findall(r'\(list "([A-Za-z.]+\.merge)" "(container|object)"\)', arm_text()))
    assert judged == {f"{p}.merge": "container" for p in CONTAINER_MERGES} | {f"{p}.merge": "object" for p in OBJECT_MERGES}
    assert "natsBox.contexts" in arm_text()


def test_every_upstream_merge_is_judged_or_listed():
    """A chart bump that adds a merge reddens here until an arm judges it or it is listed."""
    upstream = upstream_merge_paths()
    upstream.discard("natsBox.contexts.default.merge")
    named = {f"{p}.merge" for p in CONTAINER_MERGES + OBJECT_MERGES} | set(ARM_ALLOWLISTS) | set(PARTLY_JUDGED) | NOT_JUDGED
    assert upstream - named == set(), "the upstream chart has a merge nothing judges or lists"
    assert named - upstream == set(), "a merge is named that the upstream chart no longer has"


@pytest.mark.parametrize("route", sorted(PARTLY_JUDGED_OPEN))
def test_a_partly_judged_route_still_renders(tmp_path, route):
    """The residual, pinned: each partly judged merge still has an open shape.

    This asserts the gap the docstring and `render-checks.yaml` admit, not a
    feature. When an arm closes one, this goes red: move the route out of
    `PARTLY_JUDGED` and update the coverage prose in the same change.
    """
    assert set(PARTLY_JUDGED_OPEN) == set(PARTLY_JUDGED)
    posture, body, marker = PARTLY_JUDGED_OPEN[route]
    result = render(tmp_path, posture, body)
    assert result.returncode == 0, f"`nats.{route}` is now refused for this shape; update PARTLY_JUDGED: {result.stderr}"
    assert marker in result.stdout, f"{marker!r} did not reach the rendered objects"


# ── THE FIVE ARMS THAT WERE PARTLY JUDGED ARE ALLOWLISTS (yaadgaar 597) ──────
#
# RULED by Max 2026-11-05: "Allowlist every arm. No merge route is an adopter
# power." Each case below rendered rc=0 on main 1cca4ee. Every list holds only
# the keys `values.yaml`, `example/values.yaml` and the documented transport
# step use, matched by exact key, and each arm runs at EVERY TLS posture:
#   - `nats.configMap.merge`: `metadata.labels` and `metadata.annotations`;
#   - `nats.config.merge`: `authorization` and `allow_non_tls`;
#   - `nats.config.nats.tls.merge`: `verify` and `ca_file`;
#   - `nats.podTemplate.merge` and `nats.statefulSet.merge`: `metadata.labels`,
#     `metadata.annotations` and `spec`, and NO key of `spec`.
ARM_REFUSAL = {
    "configMap": "platform: the NATS TLS keys disagree",
    "config": "platform: the NATS TLS keys disagree",
    "tls": "platform: the NATS TLS keys disagree",
    "pod": "platform: the broker's merge keys override what the chart owns",
}
ALLOWLIST_REFUSED: dict[str, tuple[str, str, str]] = {
    # The headline: with TLS off, `data` replaced nats.conf with no `authorization`.
    "config-map-data": ("configMap", merge_at("configMap", {"data": {"nats.conf": "port: 4222\n"}}), "`nats.configMap.merge.data`"),
    "config-map-kind": ("configMap", merge_at("configMap", {"kind": "Secret"}), "`nats.configMap.merge.kind`"),
    "config-map-metadata-name": ("configMap", merge_at("configMap", {"metadata": {"name": "decoy"}}), "`nats.configMap.merge.metadata.name`"),
    "config-no-auth-user": ("config", merge_at("config", {"no_auth_user": "iam"}), '`nats.config.merge` sets the key "no_auth_user"'),
    "config-debug": ("config", merge_at("config", {"debug": True}), '`nats.config.merge` sets the key "debug"'),
    "config-authorization-case": ("config", merge_at("config", {"Authorization": {"token": "x"}}), '`nats.config.merge` sets the key "Authorization"'),
    "tls-verify-and-map": ("tls", merge_at("config.nats.tls", {"verify_and_map": True}), '`nats.config.nats.tls.merge` sets the key "verify_and_map"'),
    "tls-timeout": ("tls", merge_at("config.nats.tls", {"timeout": 7}), '`nats.config.nats.tls.merge` sets the key "timeout"'),
    "pod-host-network": ("pod", merge_at("podTemplate", {"spec": {"hostNetwork": True}}), "`nats.podTemplate.merge.spec.hostNetwork`"),
    "pod-service-account": ("pod", merge_at("podTemplate", {"spec": {"serviceAccountName": "evil"}}), "`nats.podTemplate.merge.spec.serviceAccountName`"),
    "pod-node-selector": ("pod", merge_at("podTemplate", {"spec": {"nodeSelector": {"disk": "ssd"}}}), "`nats.podTemplate.merge.spec.nodeSelector`"),
    "pod-top-level": ("pod", merge_at("podTemplate", {"kind": "Pod"}), '`nats.podTemplate.merge` sets the key "kind"'),
    "pod-metadata-name": ("pod", merge_at("podTemplate", {"metadata": {"name": "x"}}), '`nats.podTemplate.merge.metadata` sets the key "name"'),
    "statefulset-replicas": ("pod", merge_at("statefulSet", {"spec": {"replicas": 3}}), "`nats.statefulSet.merge.spec.replicas`"),
    "statefulset-service-name": ("pod", merge_at("statefulSet", {"spec": {"serviceName": "evil"}}), "`nats.statefulSet.merge.spec.serviceName`"),
    "statefulset-min-ready": ("pod", merge_at("statefulSet", {"spec": {"minReadySeconds": 7}}), "`nats.statefulSet.merge.spec.minReadySeconds`"),
    "statefulset-top-level": ("pod", merge_at("statefulSet", {"apiVersion": "apps/v2"}), '`nats.statefulSet.merge` sets the key "apiVersion"'),
    "statefulset-metadata-namespace": ("pod", merge_at("statefulSet", {"metadata": {"namespace": "x"}}), '`nats.statefulSet.merge.metadata` sets the key "namespace"'),
    "statefulset-metadata-not-a-map": ("pod", merge_at("statefulSet", {"metadata": "x"}), "`nats.statefulSet.merge.metadata` is not a map"),
}
# MEASURED: the upstream chart's own `merge` fails on a value of the wrong kind
# before the parent's arm runs. Either refusal is a refusal; a pass is not.
ALLOWLIST_SUBCHART_REFUSES_FIRST = {"statefulset-metadata-not-a-map": "wrong type for value"}


@POSTURES
@pytest.mark.parametrize("case", sorted(ALLOWLIST_REFUSED))
def test_a_key_off_an_arm_allowlist_is_refused_at_every_posture(tmp_path, posture, case):
    arm, body, named = ALLOWLIST_REFUSED[case]
    result = render(tmp_path, posture, body)
    assert result.returncode != 0, f"the render passed for:\n{body}"
    if ALLOWLIST_SUBCHART_REFUSES_FIRST.get(case, "\0") in result.stderr:
        return
    assert ARM_REFUSAL[arm] in result.stderr, result.stderr
    assert named in result.stderr, result.stderr


ALLOWLIST_ALLOWED = {
    "config-map-labels": (merge_at("configMap", {"metadata": {"labels": {"w597": "label"}}}), "w597: label"),
    "pod-labels": (merge_at("podTemplate", {"metadata": {"labels": {"w597": "pod"}}}), "w597: pod"),
    "statefulset-annotations": (merge_at("statefulSet", {"metadata": {"annotations": {"w597": "sts"}}}), "w597: sts"),
    "pod-empty-spec": (merge_at("podTemplate", {"spec": {}}), None),
}


@POSTURES
@pytest.mark.parametrize("case", sorted(ALLOWLIST_ALLOWED))
def test_a_key_on_an_arm_allowlist_renders(tmp_path, posture, case):
    body, marker = ALLOWLIST_ALLOWED[case]
    result = render(tmp_path, posture, body)
    assert result.returncode == 0, result.stderr
    if marker is not None:
        assert marker in result.stdout, f"{marker!r} did not reach the rendered objects"


def test_the_transport_step_key_stays_on_the_config_merge_allowlist(tmp_path):
    """`allow_non_tls` is the documented transport step (B-N2): TLS on, `clientAuth: "off"`.
    yadgarhq/chart's `test_nats_enabled_with_allow_non_tls_true_does_not_refuse` renders it too."""
    body = (
        "nats:\n  tls: {enabled: true, clientAuth: \"off\"}\n  config:\n    merge:\n      allow_non_tls: true\n"
        "    nats:\n      tls: {enabled: true, secretName: nats-tls}\n"
    )
    result = render(tmp_path, "off", body)
    assert result.returncode == 0, result.stderr
    assert '"allow_non_tls": true' in result.stdout, result.stdout


def nats_config(stdout: str) -> str:
    for doc in yaml.safe_load_all(stdout):
        if isinstance(doc, dict) and doc.get("kind") == "ConfigMap" and doc["metadata"]["name"] == "nats-config":
            return doc["data"]["nats.conf"]
    raise AssertionError("no ConfigMap/nats-config in the render")


@POSTURES
def test_the_shipped_nats_conf_carries_authorization(tmp_path, posture):
    """The baseline the configMap row is measured against: `authorization` is in nats.conf."""
    result = render(tmp_path, posture, "{}\n")
    assert result.returncode == 0, result.stderr
    assert "authorization" in nats_config(result.stdout)


def test_the_config_map_arm_runs_under_a_bare_parent_with_a_non_bool_create(tmp_path):
    """`create: 0` installs the broker under a bare parent (helm reads no bool as enabled),
    so the configMap arm must run there too, with TLS off."""
    from test_force_namespace import bare_parent

    parent = bare_parent(tmp_path)
    (tmp_path / "case.yaml").write_text(
        "platform:\n  nats:\n    create: 0\n    tls: {enabled: false, clientAuth: \"off\"}\n"
        "    configMap:\n      merge:\n        data:\n          nats.conf: \"port: 4222\\n\"\n"
    )
    result = helm("template", "yadgar", str(parent), "--namespace", "yadgar", "-f", str(tmp_path / "case.yaml"))
    assert result.returncode != 0, nats_config(result.stdout)
    assert "`nats.configMap.merge.data`" in result.stderr, result.stderr


# ── `authorization` IS THE CHART'S OWN BLOCK, EXACTLY (yaadgaar 597, review F1) ──
#
# The `config.merge` allowlist refused extra keys but never required
# `authorization` nor read what it held. Measured rc=0 on 624f4a8 against
# nats-server 2.14.6 at TLS off, available and required: `merge: null` and
# `users: []` left an open broker (`auth_required:false`, `CONNECT {}` accepted),
# `users: [{user: anon}]` accepted an empty password, and `token`, `user`/`password`,
# `nkey`, `default_permissions` and `auth_callout` all rendered. The bootstrap Job
# mints the passwords, so a values writer never held password power (ADR-1160):
# the block must equal `values.yaml`'s, compared as JSON.
TLS_AVAILABLE = (
    "nats:\n"
    "  tls: {enabled: true, clientAuth: \"off\"}\n"
    "  config:\n"
    "    nats:\n"
    "      tls:\n"
    "        enabled: true\n"
    "        secretName: nats-tls\n"
)
THREE_POSTURES = pytest.mark.parametrize("posture", ["off", "available", "required"])
OWN_AUTHORIZATION = yaml.safe_load((CHART / "values.yaml").read_text())["nats"]["config"]["merge"]["authorization"]
AUTHORIZATION_REFUSAL = "`nats.config.merge.authorization` is not the chart's own block"


def render3(tmp_path: Path, posture: str, body: str) -> subprocess.CompletedProcess[str]:
    if posture != "available":
        return render(tmp_path, posture, body)
    (tmp_path / "tls.yaml").write_text(TLS_AVAILABLE)
    (tmp_path / "case.yaml").write_text(body)
    return helm(
        "template", "platform", str(CHART), "--namespace", "yadgar", *API_VERSIONS,
        "-f", str(ADOPTER_VALUES), "-f", str(tmp_path / "tls.yaml"), "-f", str(tmp_path / "case.yaml"),
    )


def _changed_permission() -> str:
    users = yaml.safe_load(yaml.safe_dump(OWN_AUTHORIZATION["users"]))
    users[0]["permissions"]["publish"]["allow"] = [">"]
    return yaml.safe_dump({"nats": {"config": {"merge": {"authorization": {"users": users}}}}})


AUTHORIZATION_REFUSED = {
    "merge-null": "nats:\n  config:\n    merge: null\n",
    "authorization-null": "nats:\n  config:\n    merge:\n      authorization: null\n",
    "users-empty": "nats:\n  config:\n    merge:\n      authorization:\n        users: []\n",
    "users-anon": "nats:\n  config:\n    merge:\n      authorization:\n        users: [{user: anon}]\n",
    "added-token": "nats:\n  config:\n    merge:\n      authorization:\n        token: s3cret\n",
    "added-user-password": "nats:\n  config:\n    merge:\n      authorization:\n        user: a\n        password: b\n",
    "changed-permission": _changed_permission(),
}


@THREE_POSTURES
@pytest.mark.parametrize("case", sorted(AUTHORIZATION_REFUSED))
def test_an_authorization_block_that_is_not_the_charts_own_is_refused(tmp_path, posture, case):
    body = AUTHORIZATION_REFUSED[case]
    result = render3(tmp_path, posture, body)
    assert result.returncode != 0, f"the render passed for:\n{body}\n{nats_config(result.stdout)}"
    assert "platform: the NATS TLS keys disagree" in result.stderr, result.stderr
    assert AUTHORIZATION_REFUSAL in result.stderr, result.stderr


@THREE_POSTURES
def test_the_charts_own_authorization_block_renders(tmp_path, posture):
    body = yaml.safe_dump({"nats": {"config": {"merge": {"authorization": OWN_AUTHORIZATION}}}})
    result = render3(tmp_path, posture, body)
    assert result.returncode == 0, result.stderr
    assert "authorization" in nats_config(result.stdout)


def test_the_authorization_literal_matches_values_yaml():
    """`$natsAuthorization` is `values.yaml`'s block as `toRawJson` writes it: keys sorted, compact."""
    import json

    text = RENDER_CHECKS.read_text()
    (line,) = [l for l in text.splitlines() if l.startswith("{{- $natsAuthorization := ")]
    literal = line.removeprefix("{{- $natsAuthorization := `").removesuffix("` }}")
    assert literal == json.dumps(OWN_AUTHORIZATION, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
