"""THE RENDER-CHECK HARNESS: one constructed red/green pair per check the chart declares.

WHAT A RENDER CHECK IS FOR. A toggle GATES a resource — it says "render a
Certificate". It does not DIAGNOSE a missing prerequisite: a toggle set true on a
cluster with no cert-manager renders cleanly and then fails at apply with
`no matches for kind Certificate`, half-way through an install, naming a kind
rather than an operator somebody has to install. `templates/render-checks.yaml`
turns that into a render-time refusal that names the operator, the API group and
the toggle that asked for it.

THE TRAP, MEASURED ON helm 3.18.4 AND NOT NEGOTIABLE, AND IT DECIDES HOW BOTH
CASES BELOW ARE CONSTRUCTED. A plain `helm template` with NO `--api-versions` does
not populate `.Capabilities.APIVersions` with CRD-backed groups at all — it
carries helm's built-in Kubernetes groups and nothing else — so
`.Capabilities.APIVersions.Has "cert-manager.io/v1"` answers FALSE whatever the
cluster holds, and the check refuses for the RENDERER'S reason rather than for the
target's. A red case built that way cannot tell "the check works" apart from "the
renderer always answers false", which makes it no evidence at all.

SO BOTH CASES PASS `--api-versions`, AND THEY DIFFER ONLY IN WHAT IS IN IT.
Measured at the same time: `--api-versions` ADDS to helm's built-in set rather
than replacing it.

  RED    --api-versions batch/v1               a non-empty set that does NOT name
                                               the group. The refusal is then
                                               attributable to the group being
                                               absent from the target, which is
                                               the thing the check is for.
  GREEN  --api-versions cert-manager.io/v1     the same render, with the group
                                               present, must produce objects.

`test_a_bare_render_refuses_too_and_that_is_the_renderers_reason` below records
the measurement that forces this, so nobody later "simplifies" the red case back
to a bare render.

IT ASSERTS HOW MANY PAIRS IT EXERCISED, against a number written here. The rule
the number is computed from is ONE PAIR PER RENDER CHECK THE CHART DECLARES — not
per CRD-backed kind, because one check can guard several kinds rendered by one
toggle, which is exactly this chart's case: every object it renders comes from
`cert-manager.io/v1`. Printing a count is not asserting one, and the difference is
the whole point: a harness that quietly exercises one fewer check after somebody
deletes one is the "passes having examined nothing" failure wearing a green tick.

Run: python3 -m pytest scripts/tests/ -q
"""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parents[2]
CHART = REPO / "chart"
ADOPTER_VALUES = REPO / "example" / "values.yaml"

# ── WHAT THE CHART DECLARES, WRITTEN DOWN ────────────────────────────────────
# A LITERAL, for the reason every expected count in this estate is a literal: a
# number derived from the thing under test agrees with whatever that thing happens
# to be and detects nothing.
EXPECTED_RENDER_CHECKS = 1
EXPECTED_CHECKS = {"cert-manager.io/v1": "cert-manager"}

# A group that is NOT what any check asks for, and is not built in either, so the
# red render below carries a real `--api-versions` set that simply lacks the one
# the check wants.
A_GROUP_NO_CHECK_ASKS_FOR = "batch/v1"

INVOCATION = re.compile(
    r'include\s+"platform\.require-api"\s+\(dict(?P<body>.*?)\)\s*\}\}', re.DOTALL
)
ARGUMENT = re.compile(r'"(?P<key>apiVersion|operator|toggle)"\s+"(?P<value>[^"]+)"')


def helm(*arguments: str) -> subprocess.CompletedProcess[str]:
    binary = shutil.which("helm")
    # NOT A SKIP, and ADR-0650 is why.
    assert binary, (
        "helm is not on PATH. This suite renders the chart, and so does the "
        "`helm lint and render` pre-commit hook — install helm rather than "
        "letting either report a pass it did not earn."
    )
    return subprocess.run([binary, *arguments], capture_output=True, text=True)


def declared_checks(chart: Path) -> dict[str, str]:
    """API group -> operator, for every check the chart's RENDERED templates call. PURE.

    READ OFF THE TEMPLATES THAT RENDER, and `templates/_*` is skipped deliberately:
    helm never renders a partial, so a `fail` reachable only from one would never
    fire. Reading the definition instead of the call would count a check that
    cannot happen.
    """
    found: dict[str, str] = {}
    for template in sorted((chart / "templates").glob("*.yaml")):
        for invocation in INVOCATION.finditer(template.read_text()):
            arguments = {
                match.group("key"): match.group("value")
                for match in ARGUMENT.finditer(invocation.group("body"))
            }
            assert "apiVersion" in arguments and "operator" in arguments, (
                f"{template.name} calls the render check without naming both the API "
                f"group and the operator, so its refusal cannot name the prerequisite"
            )
            found[arguments["apiVersion"]] = arguments["operator"]
    return found


def declaration_failures(chart: Path, expected: dict[str, str]) -> list[str]:
    """How the declared checks disagree with what this harness expects. PURE."""
    found = declared_checks(chart)
    failures = []
    if len(found) != len(expected):
        failures.append(
            f"expected {len(expected)} render checks declared in the chart, "
            f"found {len(found)}: expected {sorted(expected)}, found {sorted(found)}"
        )
    if found != expected:
        failures.append(f"expected the checks {expected}, found {found}")
    return failures


def render(*arguments: str) -> subprocess.CompletedProcess[str]:
    return helm("template", "platform", str(CHART), "-f", str(ADOPTER_VALUES), *arguments)


def objects(stdout: str) -> list[dict]:
    return [
        document
        for document in yaml.safe_load_all(stdout)
        if isinstance(document, dict) and document.get("apiVersion")
    ]


def test_the_chart_declares_the_checks_this_harness_exercises():
    """The denominator, asserted against the chart rather than assumed."""
    assert declaration_failures(CHART, EXPECTED_CHECKS) == [], declaration_failures(
        CHART, EXPECTED_CHECKS
    )
    assert len(declared_checks(CHART)) == EXPECTED_RENDER_CHECKS


def test_deleting_a_check_from_the_chart_reddens_the_count(tmp_path):
    """The harness's own red case: it goes red on the COUNT, not one check quieter.

    Without this, a check deleted from the chart leaves a harness that exercises
    one fewer pair and reports a pass — a gate that cannot fail because it examined
    nothing.
    """
    copy = tmp_path / "chart"
    shutil.copytree(CHART, copy)
    (copy / "templates" / "render-checks.yaml").unlink()

    failures = declaration_failures(copy, EXPECTED_CHECKS)
    message = "\n".join(failures)
    assert failures, "a check was deleted from the chart and the harness said nothing"
    assert "expected 1 render checks declared in the chart, found 0" in message


def test_the_harness_exercises_one_red_green_pair_per_declared_check():
    """Every declared check refuses without its group and renders with it.

    BOTH RENDERS PASS `--api-versions`, and the module docstring is where the
    measurement that forces that lives: with no `--api-versions` at all helm leaves
    every CRD-backed group out of `.Capabilities.APIVersions`, so a bare render
    refuses whatever the target holds and proves nothing about the check.
    """
    exercised = 0
    for group, operator in sorted(declared_checks(CHART).items()):
        red = render("--api-versions", A_GROUP_NO_CHECK_ASKS_FOR)
        assert red.returncode != 0, (
            f"the render for {operator} succeeded with {group} absent from "
            f"--api-versions, so the check did not refuse"
        )
        assert operator in red.stderr, red.stderr
        assert group in red.stderr, red.stderr
        assert "--api-versions" in red.stderr, red.stderr

        green = render("--api-versions", group)
        assert green.returncode == 0, green.stderr
        rendered = objects(green.stdout)
        assert rendered, (
            f"the render for {operator} succeeded with {group} present and produced "
            f"nothing, so the green half proves nothing"
        )

        exercised += 1

    assert exercised == EXPECTED_RENDER_CHECKS, (
        f"expected {EXPECTED_RENDER_CHECKS} red/green pairs, exercised {exercised}"
    )


def test_a_bare_render_refuses_too_and_that_is_the_renderers_reason():
    """THE MEASUREMENT THAT DECIDES HOW THE RED CASE IS BUILT. Do not simplify it away.

    A render with no `--api-versions` refuses as well — but for the renderer's
    reason, not the target's, because helm populates no CRD-backed group without
    one. Asserting that refusal AS the red case would pass on a chart whose check
    named a group the target does have, which is the case the check exists to let
    through.
    """
    bare = render()
    assert bare.returncode != 0
    assert "cert-manager" in bare.stderr, bare.stderr
    # And the refusal says what to do about it, because this is the render an
    # offline reader meets first.
    assert "--api-versions cert-manager.io/v1" in bare.stderr, bare.stderr


def test_the_checks_are_unreachable_at_the_chart_defaults():
    """A render check may only ever sit behind a default-false toggle.

    `.Capabilities.APIVersions.Has` is false for every group outside helm's
    built-in list whenever there is no cluster, so a check reachable at the
    defaults would refuse every offline render in the estate — `helm lint
    --strict`, the shared `helm lint and render` hook, and every bare `helm
    template` in every suite. This asserts the defaults render bare, with no
    `--api-versions` and no values file at all.
    """
    defaults = helm("template", "platform", str(CHART))
    assert defaults.returncode == 0, defaults.stderr
    assert objects(defaults.stdout) == []
