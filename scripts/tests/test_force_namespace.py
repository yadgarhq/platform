"""`prometheus.forceNamespace`, THE ONE ESTATE KEY INSIDE AN OPEN UPSTREAM SECTION.

Run: python3 -m pytest scripts/tests/ -q

WHY A RENDER CHECK AND NOT THE SCHEMA (plan K-3, ledger 1340). `prometheus` is an
upstream section this chart adopts rather than re-types, so `values.schema.json`
leaves it open: closing it would refuse every key the upstream chart accepts. Yet
`forceNamespace` inside it is an estate key. It puts every namespaced Prometheus
object in `observability`, where all seven module charts' default
`autoscaling.prometheusAddress` points, and `templates/prometheus-namespace.yaml`
renders that Namespace off it.

THE DEFECT, MEASURED on helm v4.3.0 and v3.18.4 at 8227302, 2026-10-08, with the
prometheus operator on: `forceNamespace: ""` and `forceNamespace: null` both render
EXIT 0, as the root and under a bare parent alike, with every Prometheus object in
the RELEASE's namespace and no `observability` Namespace. The module ScaledObjects
then query a server that is not there, and nothing says so until KEDA reports
`TriggerError` on a live cluster.

A NON-STRING NEVER REACHES THIS CHECK, and that pre-emption is accepted (K-3). The
upstream chart's own schema types the key: `5`, `[a]` and `{}` are refused before
any template runs, naming `forceNamespace` — `at '/forceNamespace': got number, want
string` on helm v4.3.0, `forceNamespace: Invalid type. Expected: string` on v3.18.4.
The check still carries a kind arm, so the refusal holds if that schema ever drops
the type.

IT RUNS WHEREVER THIS CHART RUNS FOR A MAPPING `operators`; a non-map block is arm
two's diagnosis at the root and the parent's under one. No parent refuses
`platform.prometheus.forceNamespace`, so the arm is not root-only. It sits AFTER
the mixed-release guard, so a release that asks for the operators and the estate
together hears that first.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parents[2]
CHART = REPO / "chart"
RENDER_CHECKS = CHART / "templates" / "render-checks.yaml"

# Literals (ADR-0599): the namespace the module charts query, and the sentence the
# check writes. The sentence is asserted WHOLE per row, not by a substring, so a
# reworded refusal that drops the key or the fix goes red.
PROMETHEUS_NAMESPACE = "observability"
RELEASE_NAMESPACE = "yadgar"

THE_REFUSAL = (
    "platform: prometheus.forceNamespace {problem}, and {key} turns the bundled "
    "Prometheus on. Every namespaced Prometheus object would land in the release's "
    "own namespace rather than the one the module charts' "
    "autoscaling.prometheusAddress queries, and no later step refuses that. "
    "Write prometheus.forceNamespace: observability, the namespace every module "
    "chart queries by default, or set operators.prometheus.create: false and point "
    "each module's autoscaling.prometheusAddress at a Prometheus of your own."
)
EMPTY = "is an empty string"
NULL = "is null or has been deleted, so it names no namespace"

# Each red row: (label, the `prometheus:`/`operators:` overlay, the problem, the key).
ON = "operators:\n  create: true\n"
ON_BY_SUB_KEY = "operators:\n  create: false\n  prometheus:\n    create: true\n"
THE_RED_ROWS = (
    ("empty-string", ON + 'prometheus:\n  forceNamespace: ""\n', EMPTY, "operators.create"),
    ("null", ON + "prometheus:\n  forceNamespace: null\n", NULL, "operators.create"),
    ("bare-key", ON + "prometheus:\n  forceNamespace:\n", NULL, "operators.create"),
    (
        "empty-string-on-by-sub-key",
        ON_BY_SUB_KEY + 'prometheus:\n  forceNamespace: ""\n',
        EMPTY,
        "operators.prometheus.create",
    ),
)

# Shapes the upstream schema refuses before this chart's templates run.
THE_PRE_EMPTED_ROWS = (
    ("a-number", "5"),
    ("a-list", "[a]"),
    ("a-map", "{}"),
)


def helm(*arguments: str) -> subprocess.CompletedProcess[str]:
    binary = shutil.which("helm")
    # NOT A SKIP (ADR-0650), as in every suite beside this one.
    assert binary, "helm is not on PATH. This suite renders the chart."
    return subprocess.run([binary, *arguments], capture_output=True, text=True)


def overlay(tmp_path: Path, name: str, body: str) -> Path:
    path = tmp_path / f"{name}.yaml"
    path.write_text(body)
    # The overlay must parse to the shape the row names, or the row measures
    # nothing and looks green.
    assert isinstance(yaml.safe_load(body), dict), body
    return path


def render_root(tmp_path: Path, name: str, body: str, chart: Path = CHART):
    return helm(
        "template", "platform", str(chart), "--namespace", RELEASE_NAMESPACE,
        "-f", str(overlay(tmp_path, f"root-{name}", body)),
    )


def bare_parent(tmp_path: Path, chart: Path = CHART) -> Path:
    """A parent that pins this chart and refuses nothing of its own.

    The dependency is DECLARED in the parent's `Chart.yaml`: helm resolves a
    subchart's own `condition:` paths only for a declared dependency, so an
    undeclared one would render the prometheus subchart regardless.
    """
    parent = tmp_path / "parent-bare"
    (parent / "templates").mkdir(parents=True)
    manifest = yaml.safe_load((chart / "Chart.yaml").read_text())
    (parent / "Chart.yaml").write_text(
        "apiVersion: v2\nname: parent\nversion: 0.1.0\ndependencies:\n"
        f"  - name: {manifest['name']}\n    version: {manifest['version']}\n"
        '    repository: ""\n'
    )
    (parent / "values.yaml").write_text(f"{manifest['name']}: {{}}\n")
    shutil.copytree(chart, parent / "charts" / manifest["name"])
    return parent


def render_under_parent(tmp_path: Path, parent: Path, name: str, body: str):
    indented = "".join(f"  {line}\n" for line in body.splitlines())
    return helm(
        "template", "yadgar", str(parent), "--namespace", RELEASE_NAMESPACE,
        "-f", str(overlay(tmp_path, f"parent-{name}", f"platform:\n{indented}")),
    )


def documents(stdout: str) -> list[dict]:
    return [d for d in yaml.safe_load_all(stdout) if isinstance(d, dict)]


def namespaces(stdout: str) -> list[str]:
    return sorted(
        d["metadata"]["name"] for d in documents(stdout) if d.get("kind") == "Namespace"
    )


def prometheus_server_namespaces(stdout: str) -> list[str]:
    """Where the `prometheus-server` Deployment lands."""
    return [
        (d["metadata"].get("namespace") or "")
        for d in documents(stdout)
        if d.get("kind") == "Deployment" and d["metadata"].get("name") == "prometheus-server"
    ]


def test_an_empty_or_null_force_namespace_is_refused_by_name_at_the_root(tmp_path):
    for name, body, problem, key in THE_RED_ROWS:
        result = render_root(tmp_path, name, body)
        assert result.returncode != 0, (
            f"`{name}` rendered exit 0 with the Prometheus server in "
            f"{prometheus_server_namespaces(result.stdout)}"
        )
        expected = THE_REFUSAL.format(problem=problem, key=key)
        assert expected in result.stderr, (
            f"`{name}` was refused without the designed sentence.\n"
            f"expected: {expected}\ngot: {result.stderr}"
        )


def test_an_empty_or_null_force_namespace_is_refused_under_a_bare_parent(tmp_path):
    parent = bare_parent(tmp_path)
    for name, body, problem, key in THE_RED_ROWS:
        result = render_under_parent(tmp_path, parent, name, body)
        assert result.returncode != 0, (
            f"`{name}` rendered exit 0 under a bare parent with the Prometheus server "
            f"in {prometheus_server_namespaces(result.stdout)}"
        )
        expected = THE_REFUSAL.format(problem=problem, key=key)
        assert expected in result.stderr, (
            f"`{name}` under a parent: expected {expected}\ngot: {result.stderr}"
        )


def test_the_refusal_gives_no_default_advice():
    """The fix is a value to write, never "omit it and the default applies".

    A deleted key is the very case being refused, so advice to delete it would
    send the adopter back into the refusal.
    """
    for word in ("omit", "default applies", "defaults apply", "accept the chart"):
        assert word not in THE_REFUSAL, word


def test_a_non_string_force_namespace_is_refused_by_the_upstream_schema_first(tmp_path):
    for name, scalar in THE_PRE_EMPTED_ROWS:
        result = render_root(
            tmp_path, f"pre-empted-{name}", ON + f"prometheus:\n  forceNamespace: {scalar}\n"
        )
        assert result.returncode != 0, f"`{name}` rendered exit 0"
        assert "forceNamespace" in result.stderr, (
            f"`{name}` was refused without naming the key: {result.stderr}"
        )


def test_the_check_stays_quiet_when_prometheus_is_off_or_the_namespace_is_usable(tmp_path):
    rows = (
        (
            "off-with-an-empty-namespace",
            'operators:\n  create: false\nprometheus:\n  forceNamespace: ""\n',
            [],
            [],
        ),
        (
            "off-by-sub-key-with-an-empty-namespace",
            "operators:\n  create: true\n  prometheus:\n    create: false\n"
            'prometheus:\n  forceNamespace: ""\n',
            [],
            [],
        ),
        ("on-at-the-default", ON, [PROMETHEUS_NAMESPACE], [PROMETHEUS_NAMESPACE]),
        (
            "on-in-the-release-namespace",
            ON + f"prometheus:\n  forceNamespace: {RELEASE_NAMESPACE}\n",
            [],
            [RELEASE_NAMESPACE],
        ),
    )
    for name, body, expected_namespaces, expected_server in rows:
        result = render_root(tmp_path, name, body)
        assert result.returncode == 0, f"`{name}`: {result.stderr}"
        assert namespaces(result.stdout) == expected_namespaces, (
            f"`{name}` rendered Namespaces {namespaces(result.stdout)}"
        )
        assert prometheus_server_namespaces(result.stdout) == expected_server, (
            f"`{name}` put the Prometheus server in "
            f"{prometheus_server_namespaces(result.stdout)}"
        )


def test_the_mixed_release_refusal_wins_over_an_empty_force_namespace(tmp_path):
    """The mixed release is the deeper diagnosis, so its sentence arrives first.

    With the operators and an estate toggle on together, the release cannot work
    whatever `forceNamespace` says. The arm sits after the mixed-release guard so
    the adopter is told that first.
    """
    result = render_root(
        tmp_path,
        "mixed-beside-an-empty-namespace",
        ON + "bootstrap:\n  create: true\n" + 'prometheus:\n  forceNamespace: ""\n',
    )
    assert result.returncode != 0, result.stdout[:2000]
    assert "this release installs operators AND renders the estate's own objects" in (
        result.stderr
    ), f"the mixed-release refusal did not arrive first: {result.stderr}"
    assert "bootstrap.create asked for the objects" in result.stderr, result.stderr
    assert "prometheus.forceNamespace" not in result.stderr, result.stderr


THE_ARM_OPENS = "{{- /* the prometheus.forceNamespace arm (ledger 1340) */}}"
THE_ARM_CLOSES = "{{- end }}{{/* end of the prometheus.forceNamespace arm */}}\n"


def test_deleting_the_arm_lets_the_misplaced_server_through(tmp_path):
    """The mutation: without the arm, the red rows render exit 0 and misplace the server.

    It proves the rows above measure THIS arm rather than some other refusal.
    """
    copy = tmp_path / "chart"
    shutil.copytree(CHART, copy)
    template = copy / "templates" / "render-checks.yaml"
    text = template.read_text()
    assert text.count(THE_ARM_OPENS) == 1 and text.count(THE_ARM_CLOSES) == 1, (
        "the arm's markers moved; this mutation is testing nothing"
    )
    start = text.index(THE_ARM_OPENS)
    end = text.index(THE_ARM_CLOSES) + len(THE_ARM_CLOSES)
    template.write_text(text[:start] + text[end:])
    for name, body, _problem, _key in THE_RED_ROWS:
        result = render_root(tmp_path, f"mutated-{name}", body, chart=copy)
        assert result.returncode == 0, f"`{name}` with the arm deleted: {result.stderr}"
        assert prometheus_server_namespaces(result.stdout) == [RELEASE_NAMESPACE], (
            f"`{name}` with the arm deleted put the server in "
            f"{prometheus_server_namespaces(result.stdout)}, so the row does not "
            f"measure the misplacement the arm refuses"
        )
        assert PROMETHEUS_NAMESPACE not in namespaces(result.stdout)
