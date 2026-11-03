"""THE BROKER'S JSON PATCHES, ITS `$tplYaml` AND ITS RELOADER (yaadgaar 544, 545).

THE GAP. The upstream nats chart (2.14.6) runs `nats.loadMergePatch` for every
object it renders and for every block of `nats.conf`
(`files/config/config.yaml` lines 17, 28, 38, 48, 58, 68, 100 and 110): it
mergeOverwrites the block's `merge` and then applies its `patch`, a JSON patch.
A patch PATH is a key that no key-based check can read, because it is a string
value. Before this file, each of these rendered rc=0 with TLS required (the
estate posture):

  * `nats.config.jetstream.patch: [{op: add, path: "/x$include", value:
    "/dev/null; allow_non_tls: true"}]` put `include /dev/null; allow_non_tls:
    true;` into nats.conf, past the `$include` key arm;
  * the same block adding `/cert_file` with a newline in its value put
    `- /etc/evil.conf` into the reloader's arguments
    (`nats.reloaderConfig`, `_helpers.tpl:263`), past the `cert_file` arm;
  * `nats.container.patch` with `{op: replace, path: /args/0}` after the
    chart's own entries replaced the credential-rotation wrapper (ADR-0924);
  * `nats.container.patch`, `nats.podTemplate.patch` and `nats.statefulSet.patch`
    added volumes and mounts beside the chart's own;
  * `nats.reloader.merge`, `nats.reloader.patch`,
    `nats.reloader.natsVolumeMountPrefixes` and `nats.reloader.image.*` were
    judged by nothing;
  * an adopter `$tplYaml` or `$tplYamlSpread` outside `nats.config` was resolved
    by the upstream chart after every check had read the values (yaadgaar 545).
With TLS off, `nats.config.patch` and `nats.config.nats.tls.patch` passed too.

THE RULE, in `templates/render-checks.yaml`'s patch arm, at both TLS postures
while `nats.create` is true: every `patch` list the upstream chart applies
equals the chart's own list (`values.yaml`'s, matched as JSON) or is empty. NO
ALLOWLIST OF ADOPTER OPS IS OFFERED: a patch is a route past the key-based arms
that exist, and no adopter op has been shown to need one. The refusal has a
cost: a JSON patch can remove a field or edit one list element in place, which
a merge cannot, and most merge sites have no arm of their own, so their merge
route stays open.
`nats.reloader.merge` is held to the allowlist `nats.container.merge` uses,
`natsVolumeMountPrefixes` to the upstream default, and the reloader image to
the unquoted-values arm's kinds. Every `$tplYaml` / `$tplYamlSpread` key under
`nats` or `global` refuses unless it is one of the chart's own entries.

NO SKIPS (ADR-0650): helm absent is a failure.

Run: python3 -m pytest scripts/tests/test_nats_patch_paths.py -q
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
REFUSAL = "platform: the broker's JSON patches, `$tplYaml` or reloader keys are not the chart's own"
# The NATS TLS contract arm runs first and already refuses these two lists while
# TLS is on, in its own words. Either refusal is a refusal; a pass is not.
TLS_ARM = "platform: the NATS TLS keys disagree"
TLS_ARM_OWNS = {
    "config-patch-cert-file": {"required"},
    "config-patch-include": {"required"},
    "config-patch-empty": {"required"},
    "nats-tls-patch": {"required"},
    "config-map-patch": {"required"},
    "tpl-in-config": {"off", "required"},
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


def chart_nats() -> dict:
    return yaml.safe_load((CHART / "values.yaml").read_text())["nats"]


def with_chart_list(key: str, *extra: dict) -> str:
    """The chart's own `nats.<key>.patch` with `extra` appended: the only way an
    adopter can add an entry, because helm replaces a list whole."""
    return yaml.safe_dump({"nats": {key: {"patch": [*chart_nats()[key]["patch"], *extra]}}})


def block_patch(path: str, op: dict, enabled: bool = False) -> str:
    """`nats.<path>.patch: [op]`, with `<path>`'s block enabled when asked."""
    keys = path.split(".")
    tree: dict = {"patch": [op]}
    if enabled:
        tree["enabled"] = True
    for key in reversed(keys):
        tree = {key: tree}
    return yaml.safe_dump({"nats": tree})


INCLUDE = {"op": "add", "path": "/x$include", "value": "/dev/null; allow_non_tls: true"}
CERT_FILE = {"op": "add", "path": "/cert_file", "value": "/x\n- -config\n- /etc/evil.conf"}
HARMLESS = {"op": "add", "path": "/max_payload", "value": 1048576}

# Every config block `files/config/config.yaml` runs through `loadMergePatch`,
# and every non-`nats` TLS block under them.
CONFIG_BLOCKS = ["jetstream", "cluster", "leafnodes", "websocket", "mqtt", "gateway", "resolver"]
TLS_BLOCKS = ["leafnodes", "websocket", "mqtt", "cluster", "gateway"]

# Every other `patch` the upstream chart applies (`templates/*.yaml`,
# `files/stateful-set/*.yaml`, `files/nats-box/**`).
OBJECT_PATCHES = [
    "statefulSet", "reloader", "promExporter", "promExporter.podMonitor", "service",
    "headlessService", "serviceAccount", "podDisruptionBudget", "config.websocket.ingress",
    "config.jetstream.fileStore.pvc", "config.resolver.pvc", "natsBox.container",
    "natsBox.deployment", "natsBox.podTemplate", "natsBox.contextsSecret",
    "natsBox.contentsSecret", "natsBox.serviceAccount",
]

REFUSED: dict[str, tuple[str, str]] = {}
for _block in CONFIG_BLOCKS:
    REFUSED[f"{_block}-patch-include"] = (block_patch(f"config.{_block}", INCLUDE), f"`nats.config.{_block}.patch` is set")
    REFUSED[f"{_block}-patch-cert-file"] = (block_patch(f"config.{_block}", CERT_FILE), f"`nats.config.{_block}.patch` is set")
    REFUSED[f"{_block}-patch-harmless"] = (block_patch(f"config.{_block}", HARMLESS), f"`nats.config.{_block}.patch` is set")
for _block in TLS_BLOCKS:
    REFUSED[f"{_block}-tls-patch"] = (block_patch(f"config.{_block}.tls", CERT_FILE), f"`nats.config.{_block}.tls.patch` is set")
for _path in OBJECT_PATCHES:
    # A container has no `metadata`; the reloader's patch reaches its `args`.
    _op = {"op": "add", "path": "/args/-", "value": "/etc/evil.conf"} if _path == "reloader" else {"op": "add", "path": "/metadata/labels/x", "value": "w544"}
    REFUSED[f"object-patch-{_path}"] = (block_patch(_path, _op), f"`nats.{_path}.patch` is set")
REFUSED.update({
    # The headline measurements, with the block on so the effect is real.
    "jetstream-include-enabled": (block_patch("config.jetstream", INCLUDE, enabled=True), "`nats.config.jetstream.patch` is set"),
    "jetstream-cert-file-enabled": (block_patch("config.jetstream", CERT_FILE, enabled=True), "`nats.config.jetstream.patch` is set"),
    "config-patch-cert-file": (block_patch("config", CERT_FILE), "`nats.config.patch` is not the chart's own list"),
    "config-patch-include": (block_patch("config", INCLUDE), "`nats.config.patch` is not the chart's own list"),
    "config-patch-empty": ("nats:\n  config:\n    patch: []\n", "`nats.config.patch` is not the chart's own list"),
    "nats-tls-patch": (block_patch("config.nats.tls", CERT_FILE), "`nats.config.nats.tls.patch` is set"),
    "config-map-patch": (block_patch("configMap", {"op": "replace", "path": "/data/nats.conf", "value": "port: 4222\n"}), "`nats.configMap.patch` is set"),
    "context-default-patch": (block_patch("natsBox.contexts.default", HARMLESS), "`nats.natsBox.contexts.default.patch` is set"),
    "context-other-patch": (block_patch("natsBox.contexts.other", HARMLESS), "`nats.natsBox.contexts.other.patch` is set"),
    "patch-not-a-list": ("nats:\n  statefulSet:\n    patch: {op: remove}\n", "`nats.statefulSet.patch` is set"),
    # The chart's own lists, with one adopter entry appended.
    "container-args-replaced": (
        with_chart_list("container", {"op": "replace", "path": "/args/0", "value": "exec nats-server --config /etc/nats-config/nats.conf"}),
        "`nats.container.patch` is not the chart's own list",
    ),
    "container-command-replaced": (
        with_chart_list("container", {"op": "replace", "path": "/command", "value": ["nats-server"]}),
        "`nats.container.patch` is not the chart's own list",
    ),
    "container-mount-added": (
        with_chart_list("container", {"op": "add", "path": "/volumeMounts/-", "value": {"name": "x", "mountPath": "/x"}}),
        "`nats.container.patch` is not the chart's own list",
    ),
    "container-mount-removed": (
        with_chart_list("container", {"op": "remove", "path": "/volumeMounts/0"}),
        "`nats.container.patch` is not the chart's own list",
    ),
    "pod-volume-added": (
        with_chart_list("podTemplate", {"op": "add", "path": "/spec/volumes/-", "value": {"name": "x", "emptyDir": {}}}),
        "`nats.podTemplate.patch` is not the chart's own list",
    ),
    "pod-container-added": (
        with_chart_list("podTemplate", {"op": "add", "path": "/spec/containers/-", "value": {"name": "x", "image": "busybox"}}),
        "`nats.podTemplate.patch` is not the chart's own list",
    ),
    "statefulset-volume-added": (
        block_patch("statefulSet", {"op": "add", "path": "/spec/template/spec/volumes/-", "value": {"name": "x", "emptyDir": {}}}),
        "`nats.statefulSet.patch` is set",
    ),
    # The reloader.
    "reloader-merge-args": ("nats:\n  reloader:\n    merge:\n      args: [-config, /etc/evil.conf]\n", '`nats.reloader.merge` sets the key "args"'),
    "reloader-merge-command": ("nats:\n  reloader:\n    merge:\n      command: [/bin/sh]\n", '`nats.reloader.merge` sets the key "command"'),
    "reloader-merge-mounts": ("nats:\n  reloader:\n    merge:\n      volumeMounts: []\n", '`nats.reloader.merge` sets the key "volumeMounts"'),
    "reloader-merge-image": ("nats:\n  reloader:\n    merge:\n      image: busybox\n", '`nats.reloader.merge` sets the key "image"'),
    "reloader-merge-not-a-map": ("nats:\n  reloader:\n    merge: [x]\n", "`nats.reloader.merge` is not a map"),
    "reloader-prefixes-widened": (
        "nats:\n  reloader:\n    natsVolumeMountPrefixes: [/etc/, /var/run/secrets/]\n",
        "`nats.reloader.natsVolumeMountPrefixes` is",
    ),
    "reloader-prefixes-root": ("nats:\n  reloader:\n    natsVolumeMountPrefixes: [/]\n", "`nats.reloader.natsVolumeMountPrefixes` is"),
    # `$tplYaml` outside `nats.config` (yaadgaar 545).
    "tpl-in-container-patch": (
        with_chart_list("container", {"$tplYaml": "{op: replace, path: /args/0, value: x}"}),
        "`$tplYaml` or `$tplYamlSpread` key(s) that are not the chart's own",
    ),
    "tpl-in-pod-patch": (
        with_chart_list("podTemplate", {"$tplYaml": "{op: add, path: /spec/volumes/-, value: {name: x, emptyDir: {}}}"}),
        "`$tplYaml` or `$tplYamlSpread` key(s) that are not the chart's own",
    ),
    "tpl-in-statefulset-merge": (
        "nats:\n  statefulSet:\n    merge:\n      metadata:\n        labels:\n          x: {$tplYaml: w545}\n",
        "1 `$tplYaml` or `$tplYamlSpread` key(s) that are not the chart's own",
    ),
    "tpl-spread-in-pod-merge": (
        "nats:\n  podTemplate:\n    merge:\n      spec:\n        tolerations:\n          - $tplYamlSpread: '[{key: x}]'\n",
        "1 `$tplYaml` or `$tplYamlSpread` key(s) that are not the chart's own",
    ),
    "tpl-in-reloader-merge": (
        "nats:\n  reloader:\n    merge:\n      resources: {$tplYaml: '{}'}\n",
        "1 `$tplYaml` or `$tplYamlSpread` key(s) that are not the chart's own",
    ),
    "tpl-in-reloader-image": (
        "nats:\n  reloader:\n    image:\n      repository: null\n      tag: null\n      $tplYaml: '{repository: x}'\n",
        "1 `$tplYaml` or `$tplYamlSpread` key(s) that are not the chart's own",
    ),
    "tpl-in-reloader-env": (
        "nats:\n  reloader:\n    env:\n      W545: {$tplYaml: '{value: x}'}\n",
        "1 `$tplYaml` or `$tplYamlSpread` key(s) that are not the chart's own",
    ),
    "tpl-in-nats-global": (
        "nats:\n  global:\n    w545: {$tplYaml: x}\n",
        "1 `$tplYaml` or `$tplYamlSpread` key(s) that are not the chart's own",
    ),
    "tpl-in-prom-exporter-image": (
        "nats:\n  promExporter:\n    image:\n      repository: null\n      tag: null\n      $tplYaml: '{repository: x}'\n",
        "1 `$tplYaml` or `$tplYamlSpread` key(s) that are not the chart's own",
    ),
    "tpl-in-global": (
        "global:\n  w545: {$tplYaml: x}\n",
        "1 `$tplYaml` or `$tplYamlSpread` key(s) that are not the chart's own",
    ),
    "tpl-in-config": ("nats:\n  config:\n    merge:\n      debug: {$tplYaml: 'false'}\n", "`$tplYaml` or `$tplYamlSpread` key(s)"),
    # A second copy of a chart entry is not the chart's: only one of each is.
    "tpl-own-entry-twice": (
        with_chart_list("container", chart_nats()["container"]["patch"][-1]),
        "`nats.container.patch` is not the chart's own list",
    ),
})

# Rejected by the unquoted-values arm (yaadgaar 546) that this change widens to
# `nats.reloader.image.*`, which prints through the same `nats.image` helper.
UNQUOTED = "platform: a value the upstream nats chart prints unquoted is not of its kind"
REFUSED_IMAGE = {
    "reloader-tag-newline": ("nats:\n  reloader:\n    image:\n      tag: \"0.23.0\\nsecurityContext: {privileged: true}\"\n", "`nats.reloader.image.tag`"),
    "reloader-repository-newline": ("nats:\n  reloader:\n    image:\n      repository: \"x\\nsecurityContext: {privileged: true}\"\n", "`nats.reloader.image.repository`"),
    "reloader-registry-flow": ("nats:\n  reloader:\n    image:\n      registry: \"{a: b}\"\n", "`nats.reloader.image.registry`"),
    "reloader-full-name-newline": ("nats:\n  reloader:\n    image:\n      fullImageName: \"x\\nargs: [x]\"\n", "`nats.reloader.image.fullImageName`"),
    "reloader-digest-bad": ("nats:\n  reloader:\n    image:\n      digest: \"sha256:zz\"\n", "`nats.reloader.image.digest`"),
    "reloader-pull-policy-bad": ("nats:\n  reloader:\n    image:\n      pullPolicy: \"Always\\nx: y\"\n", "`nats.reloader.image.pullPolicy`"),
}


# MEASURED on helm 4.3.0: helm renders the subchart first, and the upstream
# chart's own `jsonpatch` / `merge` fails on a list or map of the wrong kind
# before the parent's arm runs. Either refusal is a refusal; a pass is not.
SUBCHART_REFUSES_FIRST = {"patch-not-a-list": "wrong type for value", "reloader-merge-not-a-map": "wrong type for value"}


@POSTURES
@pytest.mark.parametrize("case", sorted(REFUSED))
def test_a_patch_tplyaml_or_reloader_key_that_is_not_the_charts_is_refused(tmp_path, posture, case):
    body, named = REFUSED[case]
    result = render(tmp_path, posture, body)
    assert result.returncode != 0, f"the render passed for:\n{body}"
    if posture in TLS_ARM_OWNS.get(case, ()):
        assert TLS_ARM in result.stderr, result.stderr
        return
    if SUBCHART_REFUSES_FIRST.get(case, "\0") in result.stderr:
        return
    assert REFUSAL in result.stderr, result.stderr
    assert named in result.stderr, result.stderr


@POSTURES
@pytest.mark.parametrize("case", sorted(REFUSED_IMAGE))
def test_a_reloader_image_value_not_of_its_kind_is_refused(tmp_path, posture, case):
    body, named = REFUSED_IMAGE[case]
    result = render(tmp_path, posture, body)
    assert result.returncode != 0, f"the render passed for:\n{body}"
    assert UNQUOTED in result.stderr, result.stderr
    assert named in result.stderr, result.stderr


# ── ALLOWED: EACH SHAPE RENDERS ──────────────────────────────────────────────

ALLOWED = {
    "shipped": ("{}\n", None),
    "chart-lists-copied": (
        yaml.safe_dump({"nats": {k: {"patch": chart_nats()[k]["patch"]} for k in ("config", "container", "podTemplate")}}),
        None,
    ),
    "empty-lists": (
        yaml.safe_dump({"nats": {
            "statefulSet": {"patch": []}, "reloader": {"patch": []}, "service": {"patch": []},
            "config": {"jetstream": {"patch": []}, "cluster": {"tls": {"patch": []}}},
        }}),
        None,
    ),
    "reloader-resources": ("nats:\n  reloader:\n    merge:\n      resources: {limits: {memory: 77Mi}}\n", "77Mi"),
    "reloader-security-context": (
        "nats:\n  reloader:\n    merge:\n      securityContext: {readOnlyRootFilesystem: true}\n",
        "readOnlyRootFilesystem: true",
    ),
    "reloader-prefixes-default": ("nats:\n  reloader:\n    natsVolumeMountPrefixes: [/etc/]\n", None),
    "reloader-tag": ("nats:\n  reloader:\n    image:\n      tag: 0.23.1\n", "nats-server-config-reloader:0.23.1"),
    "reloader-full-name": (
        "nats:\n  reloader:\n    image:\n      fullImageName: registry.example/reloader:0.23.0\n",
        "registry.example/reloader:0.23.0",
    ),
    "reloader-digest": (
        "nats:\n  reloader:\n    image:\n      digest: sha256:" + "a" * 64 + "\n",
        "@sha256:" + "a" * 64,
    ),
    # A string VALUE that reads `$tplYaml` is not a key, and the upstream chart
    # resolves only keys.
    "tpl-text-as-a-value": (
        "nats:\n  podTemplate:\n    merge:\n      metadata:\n        annotations:\n          w545: $tplYaml\n",
        "w545: $tplYaml",
    ),
    "global-plain": ("global:\n  w545: plain\n", None),
}


@POSTURES
@pytest.mark.parametrize("case", sorted(ALLOWED))
def test_a_shape_the_chart_allows_renders(tmp_path, posture, case):
    body, marker = ALLOWED[case]
    result = render(tmp_path, posture, body)
    assert result.returncode == 0, result.stderr
    if marker is not None:
        assert marker in result.stdout, f"{marker!r} did not reach the rendered objects"


# ── THE LIST IN THE ARM IS THE UPSTREAM CHART'S LIST ────────────────────────


def vendored_nats_values() -> dict:
    lock = yaml.safe_load((CHART / "Chart.lock").read_text())
    version = next(d["version"] for d in lock["dependencies"] if d["name"] == "nats")
    archive = CHART / "charts" / f"nats-{version}.tgz"
    assert archive.is_file(), f"{archive} is absent: run `helm dependency build chart` first."
    with tarfile.open(archive) as tar:
        return yaml.safe_load(tar.extractfile("nats/values.yaml").read())


def upstream_patch_paths() -> set[str]:
    found = set()

    def walk(node, path):
        if isinstance(node, dict):
            for key, value in node.items():
                if key == "patch":
                    found.add(".".join([*path, key]))
                walk(value, [*path, key])

    walk(vendored_nats_values(), [])
    return found


def arm_text() -> str:
    text = RENDER_CHECKS.read_text()
    return text[text.index("THE BROKER'S JSON PATCHES (yaadgaar 544)"):text.index("end of the patch arm")]


def test_the_arm_judges_every_patch_the_upstream_chart_applies():
    judged = set(re.findall(r'\(list "([A-Za-z.]+\.patch)"', arm_text()))
    upstream = upstream_patch_paths()
    # The nats-box contexts are a map of adopter-named entries; the arm ranges
    # over all of them rather than naming the upstream default one.
    upstream.discard("natsBox.contexts.default.patch")
    assert upstream - judged == set(), "the upstream chart applies a patch the arm does not judge"
    assert judged - upstream == set(), "the arm judges a patch the upstream chart no longer has"
    assert "natsBox.contexts" in arm_text()


def test_the_test_lists_cover_every_upstream_patch():
    named = {f"config.{b}.patch" for b in CONFIG_BLOCKS} | {f"config.{b}.tls.patch" for b in TLS_BLOCKS}
    named |= {f"{p}.patch" for p in OBJECT_PATCHES}
    named |= {"config.patch", "config.nats.tls.patch", "configMap.patch", "container.patch", "podTemplate.patch", "natsBox.contexts.default.patch"}
    assert upstream_patch_paths() == named
