"""EVERY VENDORED CHART SHIPS WITH ITS LICENCE TEXT (yaadgaar 377, ruled by Max 2026-11-02).

THE GAP. `helm package -u` vendors every `Chart.yaml` dependency into the
published `platform-<version>.tgz`, and no packaged upstream chart carries its
own LICENSE file (measured 2026-11-03 over the seven `.tgz` files in
`chart/charts/`). So the package redistributed Apache-2.0 and MIT work with no
licence text beside it.

THE FIX. `chart/LICENSES/<name>-LICENSE` holds each upstream text, copied from
the upstream repository at the tag that matches the pinned version, and
`chart/NOTICE` lists name, version, licence, source, file and SHA-256 for each.
`argo-cd` vendors `redis-ha` from a different upstream repository, so it has
an entry of its own (`inside: argo-cd`). The other nested charts come from
their parent's repository and are listed under the parent's `includes`.

THE GATE IS ONE PURE FUNCTION, `licence_failures`, fed the real inputs by
`test_every_vendored_chart_has_its_licence` and fed one mutation each by
`test_each_mutation_reddens_the_licence_gate`. It fails when a declared
dependency has no licence file, when NOTICE is out of step with `Chart.yaml`
or with the vendored charts, when a file's bytes no longer match the recorded
digest, and when a licence file is referenced by no entry.

THE PACKAGE CARRIES THEM. `.helmignore` ignores neither `LICENSES/` nor
`NOTICE`, so both ship, which is the point: the obligation attaches to the
published artifact. `test_the_package_carries_the_licences_and_the_notice`
packages the chart and reads the tarball.

NO SKIPS (ADR-0650): a missing `chart/charts/` or `helm` is a failure.

Run: python3 -m pytest scripts/tests/test_licenses.py -q
"""

from __future__ import annotations

import copy
import hashlib
import shutil
import subprocess
import tarfile
from pathlib import Path

import pytest
import yaml

REPO = Path(__file__).resolve().parents[2]
CHART = REPO / "chart"
LICENSES = CHART / "LICENSES"
NOTICE = CHART / "NOTICE"
VENDORED = CHART / "charts"

FIELDS = ("name", "version", "license", "source", "file", "sha256")
OPTIONAL_FIELDS = ("includes", "inside", "note")


def parse_notice(text: str) -> list[dict[str, str]]:
    """Every block that starts with `name:`. The prose header is not a block."""
    entries = []
    for block in text.split("\n\n"):
        lines = [line for line in block.strip().splitlines() if line.strip()]
        if not lines or not lines[0].startswith("name: "):
            continue
        entry: dict[str, str] = {}
        for line in lines:
            key, _, value = line.partition(": ")
            entry[key] = value
        entries.append(entry)
    return entries


def declared_dependencies() -> dict[str, str]:
    chart = yaml.safe_load((CHART / "Chart.yaml").read_text())
    return {str(d["name"]): str(d["version"]) for d in chart.get("dependencies") or []}


def vendored_charts() -> dict[str, tuple[str, dict[str, str]]]:
    """name -> (version, {nested name: nested version}), read from `chart/charts/*.tgz`."""
    archives = sorted(VENDORED.glob("*.tgz"))
    assert archives, (
        f"{VENDORED} holds no vendored chart. Run `helm dependency build chart` first; "
        "this gate reads the vendored charts and does not skip without them (ADR-0650)."
    )
    found = {}
    for archive in archives:
        with tarfile.open(archive) as tar:
            charts = {}
            for member in tar.getmembers():
                parts = member.name.split("/")
                if parts[-1] != "Chart.yaml" or len(parts) not in (2, 4):
                    continue
                if len(parts) == 4 and parts[1] != "charts":
                    continue
                handle = tar.extractfile(member)
                assert handle is not None, member.name
                meta = yaml.safe_load(handle.read())
                charts[tuple(parts[:-1])] = (str(meta["name"]), str(meta["version"]))
        tops = [key for key in charts if len(key) == 1]
        assert len(tops) == 1, f"{archive.name}: expected one top-level Chart.yaml, found {tops}"
        name, version = charts[tops[0]]
        nested = {n: v for key, (n, v) in charts.items() if len(key) == 3}
        found[name] = (version, nested)
    return found


def licence_files() -> dict[str, bytes]:
    return {path.name: path.read_bytes() for path in sorted(LICENSES.iterdir()) if path.is_file()}


def split_list(value: str) -> list[str]:
    return [item.strip() for item in value.split(",") if item.strip()]


def licence_failures(
    declared: dict[str, str],
    vendored: dict[str, tuple[str, dict[str, str]]],
    entries: list[dict[str, str]],
    files: dict[str, bytes],
) -> list[str]:
    """PURE. Every way `Chart.yaml`, the vendored charts, NOTICE and LICENSES/ can disagree."""
    failures = []
    by_name: dict[str, dict[str, str]] = {}
    for entry in entries:
        name = entry.get("name", "")
        if name in by_name:
            failures.append(f"NOTICE lists {name!r} twice")
        by_name[name] = entry
        for field in FIELDS:
            if not entry.get(field):
                failures.append(f"NOTICE entry {name!r} has no `{field}`")
        for field in entry:
            if field not in FIELDS + OPTIONAL_FIELDS:
                failures.append(f"NOTICE entry {name!r} has an unknown field `{field}`")

    # Every declared dependency: an entry, a file, the pinned version.
    for name, version in declared.items():
        entry = by_name.get(name)
        if entry is None:
            failures.append(f"`Chart.yaml` declares {name!r} {version} and NOTICE has no entry for it")
        elif entry.get("inside"):
            failures.append(f"{name!r} is a declared dependency, so its NOTICE entry must not say `inside`")
        if f"{name}-LICENSE" not in files:
            failures.append(f"`Chart.yaml` declares {name!r} and `chart/LICENSES/{name}-LICENSE` does not exist")
        if name not in vendored:
            failures.append(f"`Chart.yaml` declares {name!r} and `chart/charts/` does not vendor it")
        elif vendored[name][0] != version:
            failures.append(f"`chart/charts/` vendors {name!r} {vendored[name][0]}, `Chart.yaml` pins {version}")

    # Every entry: the right version, the right file, the right bytes.
    for name, entry in by_name.items():
        expected = declared.get(name)
        parent = entry.get("inside", "")
        if expected is None and parent:
            expected = (vendored.get(parent, ("", {}))[1]).get(name)
            if expected is None:
                failures.append(f"NOTICE says {name!r} is inside {parent!r}, and {parent!r} vendors no such chart")
        elif expected is None:
            failures.append(f"NOTICE lists {name!r}, which `Chart.yaml` does not declare and no entry says it is inside")
        if expected is not None and entry.get("version") != expected:
            failures.append(f"NOTICE gives {name!r} version {entry.get('version')!r}, the pinned version is {expected!r}")
        version = entry.get("version", "")
        source = entry.get("source", "")
        if version and version.lstrip("v") not in source:
            failures.append(f"NOTICE's source for {name!r} ({source}) does not name version {version}")
        if not source.endswith("/LICENSE"):
            failures.append(f"NOTICE's source for {name!r} ({source}) is not a LICENSE file")
        filename = f"{name}-LICENSE"
        if entry.get("file") != f"LICENSES/{filename}":
            failures.append(f"NOTICE gives {name!r} the file {entry.get('file')!r}, expected 'LICENSES/{filename}'")
        body = files.get(filename)
        if body is None:
            failures.append(f"NOTICE lists {name!r} and `chart/LICENSES/{filename}` does not exist")
        elif not body.strip():
            failures.append(f"`chart/LICENSES/{filename}` is empty")
        elif hashlib.sha256(body).hexdigest() != entry.get("sha256"):
            failures.append(
                f"`chart/LICENSES/{filename}` has SHA-256 {hashlib.sha256(body).hexdigest()}, "
                f"NOTICE records {entry.get('sha256')}"
            )

    # Every nested chart: covered by the parent's `includes`, or its own `inside` entry.
    for parent, (_, nested) in vendored.items():
        includes = split_list((by_name.get(parent) or {}).get("includes", ""))
        for name in nested:
            own = by_name.get(name)
            if name in includes or (own is not None and own.get("inside") == parent):
                continue
            failures.append(f"{parent!r} vendors {name!r} and NOTICE neither includes it under {parent!r} nor gives it an entry")
        for name in includes:
            if name not in nested:
                failures.append(f"NOTICE says {parent!r} includes {name!r}, and {parent!r} vendors no such chart")

    # Every licence file is some entry's.
    referenced = {f"{name}-LICENSE" for name in by_name}
    for filename in files:
        if filename not in referenced:
            failures.append(f"`chart/LICENSES/{filename}` is referenced by no NOTICE entry")
    return failures


def real_inputs():
    return declared_dependencies(), vendored_charts(), parse_notice(NOTICE.read_text()), licence_files()


def test_every_vendored_chart_has_its_licence():
    failures = licence_failures(*real_inputs())
    assert failures == [], "\n".join(failures)


def test_the_notice_covers_every_declared_dependency_by_name():
    """THE TRIPWIRE: the gate above passes vacuously on an empty NOTICE and an
    empty Chart.yaml. Pin the real set so neither can shrink to nothing."""
    declared = declared_dependencies()
    names = {entry["name"] for entry in parse_notice(NOTICE.read_text())}
    assert set(declared) == {
        "nats", "cert-manager", "keda", "mariadb-operator", "gateway-helm", "argo-cd", "prometheus",
    }, declared
    assert names == set(declared) | {"redis-ha"}, names


def drop_file(inputs, name):
    del inputs[3][f"{name}-LICENSE"]


def bump_declared(inputs, name):
    inputs[0][name] = "9.9.9"


def drop_entry(inputs, name):
    inputs[2][:] = [entry for entry in inputs[2] if entry["name"] != name]


def add_dependency(inputs, _):
    inputs[0]["new-chart"] = "1.0.0"
    inputs[1]["new-chart"] = ("1.0.0", {})


def alter_bytes(inputs, name):
    inputs[3][f"{name}-LICENSE"] += b"x"


def orphan_file(inputs, _):
    inputs[3]["stray-LICENSE"] = b"text"


def unlisted_nested(inputs, name):
    inputs[1][name][1]["extra-subchart"] = "1.0.0"


def stale_include(inputs, name):
    for entry in inputs[2]:
        if entry["name"] == name:
            entry["includes"] = entry.get("includes", "") + ", gone-subchart"


def unpinned_source(inputs, name):
    for entry in inputs[2]:
        if entry["name"] == name:
            entry["source"] = entry["source"].replace("2.14.6", "main")


def nested_version_drift(inputs, _):
    inputs[1]["argo-cd"][1]["redis-ha"] = "9.9.9"


MUTATIONS = [
    (drop_file, "nats", "chart/LICENSES/nats-LICENSE` does not exist"),
    (bump_declared, "keda", "the pinned version is '9.9.9'"),
    (drop_entry, "prometheus", "NOTICE has no entry for it"),
    (add_dependency, None, "'new-chart'"),
    (alter_bytes, "cert-manager", "NOTICE records"),
    (orphan_file, None, "stray-LICENSE` is referenced by no NOTICE entry"),
    (unlisted_nested, "gateway-helm", "'extra-subchart'"),
    (stale_include, "prometheus", "'gone-subchart'"),
    (unpinned_source, "nats", "does not name version 2.14.6"),
    (drop_entry, "redis-ha", "'redis-ha' and NOTICE neither includes it"),
    (nested_version_drift, None, "the pinned version is '9.9.9'"),
]


@pytest.mark.parametrize(
    ("mutate", "target", "named"),
    MUTATIONS,
    ids=[f"{m.__name__}-{t}" for m, t, _ in MUTATIONS],
)
def test_each_mutation_reddens_the_licence_gate(mutate, target, named):
    inputs = copy.deepcopy(list(real_inputs()))
    mutate(inputs, target)
    failures = licence_failures(*inputs)
    assert any(named in failure for failure in failures), failures


def helm(*arguments: str) -> subprocess.CompletedProcess[str]:
    binary = shutil.which("helm")
    assert binary, "helm is not on PATH; this gate packages the chart and does not skip (ADR-0650)."
    return subprocess.run([binary, *arguments], capture_output=True, text=True)


def test_the_package_carries_the_licences_and_the_notice(tmp_path):
    """`.helmignore` must not drop them: the obligation is the published artifact's.
    Packaged from the already-built `chart/charts/`, so this needs no network."""
    staged = tmp_path / "chart"
    shutil.copytree(CHART, staged)
    packaged = helm("package", str(staged), "--destination", str(tmp_path))
    assert packaged.returncode == 0, packaged.stderr
    (archive,) = sorted(tmp_path.glob("platform-*.tgz"))
    with tarfile.open(archive) as tar:
        members = set(tar.getnames())
        notice = tar.extractfile("platform/NOTICE")
        assert notice is not None
        assert notice.read() == NOTICE.read_bytes()
    expected = {f"platform/LICENSES/{name}" for name in licence_files()}
    assert expected and expected <= members, sorted(expected - members)
