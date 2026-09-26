"""THE RENDER-CHECK HARNESS: one constructed red/green pair per check the chart declares.

WHAT A RENDER CHECK IS FOR. A toggle GATES a resource — it says "render a
Certificate". It does not DIAGNOSE a missing prerequisite: a toggle set true on a
cluster with no cert-manager renders cleanly and then fails at apply with
`no matches for kind Certificate`, half-way through an install, naming a kind
rather than an operator somebody has to install. `templates/render-checks.yaml`
turns that into a render-time refusal that names the operator, the API group and
the toggle that asked for it.

THE TRAP, MEASURED ON helm 3.18.4 AND 4.3.0 AND NOT NEGOTIABLE, AND IT DECIDES HOW
BOTH CASES BELOW ARE CONSTRUCTED. A plain `helm template` with NO `--api-versions`
does not populate `.Capabilities.APIVersions` with CRD-backed groups at all — it
carries helm's built-in Kubernetes groups and nothing else — so
`.Capabilities.APIVersions.Has "cert-manager.io/v1"` answers FALSE whatever the
cluster holds, and the check refuses for the RENDERER'S reason rather than for the
target's. A red case built that way cannot tell "the check works" apart from "the
renderer always answers false", which makes it no evidence at all.

SO BOTH CASES PASS `--api-versions`, AND THEY DIFFER ONLY IN WHAT IS IN IT.
Measured at the same time: `--api-versions` ADDS to helm's built-in set rather
than replacing it. THAT IS WHY THE FILLER MUST NOT BE BUILT IN: a built-in group
passed through `--api-versions` leaves `.Has` unchanged for every group, so the
render would be indistinguishable from a bare one and the red case would prove
nothing. Say `.Has` and not "changes nothing observable", because the LENGTH does
move — measured, a built-in group passed through `--api-versions` is APPENDED as a
duplicate, so `len .Capabilities.APIVersions` grows by one while `.Has` answers the
same for every group. A tripwire written on the length therefore reports a built-in
group as not built in, inverting the check it exists to protect.
`assert_the_red_group_is_not_built_in` below reads `.Has` and never the length.

THE CONSTRUCTION IS STATED OVER ALL THE CHECKS THE RENDER EXERCISES, NEVER OVER ONE
ALONE, because `fail` aborts the WHOLE chart render at the FIRST failing check and
the refusal names only that check. A red case that leaves a SECOND check unsatisfied
refuses for THAT check's reason rather than for the reason of the check under test —
the same defect one level up from the bare render refusing for the renderer's reason.
So, for a render exercising a set of checks:

  GREEN          `--api-versions` for EVERY group the render's checks ask for. It
                 must succeed and render objects.
  RED, check i   every one of those groups EXCEPT i's, PLUS the filler. It must
                 refuse, and the refusal must name check i's operator. That last
                 clause is what makes the refusal ATTRIBUTABLE to the check under
                 test, and it is the assertion a builder who meets a red suite while
                 adding a check is most tempted to delete. Deleting it is the
                 disarmament this harness exists to prevent.

THE FILLER STAYS IN THE RED CASE AT EVERY COUNT, THE ONE-CHECK CHART INCLUDED. With
one check "every group except i's" is empty, so dropping the filler collapses the red
case back into the bare render this docstring forbids. At one check the construction
reduces to the filler alone; at two or more it does not.

THE FILLER CARRIES A TRIPWIRE ASSERTING TWO THINGS, and both run BEFORE any red case.
First, that the filler is absent from a BARE render's `.Capabilities.APIVersions`
(`assert_the_red_group_is_not_built_in`). Second, that the filler is not one of the
groups the chart's own checks ask for (`assert_the_filler_is_not_a_declared_group`) —
an obligation the generalised red case creates. A colliding filler does not pass
silently: measured, the red case for the group it collides with SUCCEEDS and renders
every object. But what goes red is that check's own red case, reported as "this red
case did not refuse", which names a symptom rather than the cause. The second
assertion names the cause, which is why it runs first.

THE CHART DECLARES TWO KINDS OF CHECK, AND ONLY ONE OF THEM IS CONSTRUCTED THE WAY
EVERYTHING ABOVE DESCRIBES. A CAPABILITY check calls `platform.require-api` and reads
`.Capabilities.APIVersions.Has`, so every paragraph above applies to it: the trap, the
filler, and the `--api-versions` construction on both halves. A VALUES check reads the
release's own values and nothing else — this chart carries five, the mixed-release
refusal, the two arms of the `operators` shape refusal and the two register-key arms,
whose behaviour `scripts/tests/test_operators_shape.py` owns — and for it NONE of that
applies. It
touches no `.Capabilities`, so a bare
render answers it exactly as a cluster would, and ITS RED AND GREEN CASES ARE TWO BARE
RENDERS. THE FILLER TRIPWIRE DOES NOT APPLY TO IT AND MUST NOT BE ADDED TO IT: there is
no group whose absence it refuses over, so `--api-versions` on either half would add a
capability set to a check that reads none and would suggest, to the next reader, that the
bare pair was the defect rather than the design. This paragraph exists because that next
reader's instinct will be to "fix" the bare pair into the construction above.

`EXPECTED_RENDER_CHECKS` counts BOTH kinds, because the count exists so that a check
DELETED from `templates/render-checks.yaml` reddens the suite, and a deletion of either
kind is the thing it guards against. `EXPECTED_CAPABILITY_CHECKS` is the denominator of
the red/green construction above, and it is the smaller of the two.

IT ASSERTS HOW MANY PAIRS IT EXERCISED, against a number written here. The rule the
number is computed from is ONE PAIR PER RENDER CHECK THE CHART DECLARES — not per
CRD-backed kind, and not per API GROUP either, because one toggle can render several
kinds, from more than one group, behind ONE check. `templates/render-checks.yaml` is
where each check states what it guards, and the count of checks is never to be read
off the count of kinds rendered. `EXPECTED_RENDER_CHECKS` below is the one place the
number lives. Printing a count is not asserting one, and the difference is the whole
point: a harness that quietly exercises one fewer check after somebody deletes one is
the "passes having examined nothing" failure wearing a green tick.

AND THE CONSTRUCTION IS PROVED AT A COUNT THIS CHART DOES NOT CONTROL.
`test_the_construction_is_correct_at_two_checks` builds a throwaway TWO-check chart
around THIS chart's own `_require_api.tpl` and runs the SAME construction over it.
The fixture's count is `FIXTURE_RENDER_CHECKS`, which is two whatever
`EXPECTED_RENDER_CHECKS` happens to say — so the generalisation stays proved at two
on a chart declaring one, and stays proved on the next chart this file is copied into
whatever that one declares. THIS PARAGRAPH IS DELIBERATELY WRITTEN OVER NO PARTICULAR
COUNT: this file is copied into every chart that carries a render check, so a reason
stated in terms of one chart's count arrives false in the next.

Run: python3 -m pytest scripts/tests/ -q
"""

from __future__ import annotations

import re
import shutil
import subprocess
from collections.abc import Iterable
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parents[2]
CHART = REPO / "chart"
CHART_MANIFEST = CHART / "Chart.yaml"
CHART_VALUES = CHART / "values.yaml"
RENDER_CHECKS = CHART / "templates" / "render-checks.yaml"
ADOPTER_VALUES = REPO / "example" / "values.yaml"

# ── WHAT THE CHART DECLARES, WRITTEN DOWN ────────────────────────────────────
# A LITERAL, for the reason every expected count in this estate is a literal: a
# number derived from the thing under test agrees with whatever that thing happens
# to be and detects nothing.
#
# THE TOTAL OVER BOTH KINDS OF CHECK — two capability checks and five values
# checks, and the module docstring is where the difference between them lives. It
# is the number a DELETION reddens, whichever kind was deleted.
EXPECTED_RENDER_CHECKS = 7
# The denominator of the `--api-versions` construction, which exercises the
# capability checks and only those. `EXPECTED_CHECKS` below names them.
EXPECTED_CAPABILITY_CHECKS = 2
# FIVE: the mixed-release refusal, the TWO ARMS of the `operators` shape refusal
# — a deleted key, refused wherever this chart runs, and a present non-map,
# refused only when it is the root — and the TWO REGISTER-KEY arms, one per
# dependency `condition:` this chart declares, which refuse an `operators.create`
# or a `nats.create` helm cannot resolve a condition from. They are counted
# separately because each is its own `fail` with its own message and its own red
# case; `scripts/tests/test_operators_shape.py` owns what the five of them DO,
# and this number is only the count, which is what a deletion moves. Each has a
# pair of BARE renders.
EXPECTED_VALUES_CHECKS = 5
EXPECTED_CHECKS = {
    "cert-manager.io/v1": "cert-manager",
    # ENVOY GATEWAY'S OWN GROUP, AND NOT THE GATEWAY API'S. The same cluster serves
    # `gateway.networking.k8s.io/v1` — the UPSTREAM specification, a different
    # project that Istio and every other implementation also registers — and
    # `gateway.networking.x-k8s.io/v1alpha1` beside it. A check written against
    # either is green on a cluster with the Gateway API CRDs and no Envoy Gateway
    # anywhere, which is exactly the adopter state this check exists to refuse.
    # `test_shared_infrastructure.py` asserts the two decoys are absent.
    "gateway.envoyproxy.io/v1alpha1": "Envoy Gateway",
}

# The number of checks the throwaway fixture declares, and it is a LITERAL for the
# same reason — `len(declared_checks(fixture))` would agree with a fixture whose
# second invocation the regex missed, and the two-check case would then be a
# one-check case reporting a pass.
FIXTURE_RENDER_CHECKS = 2

# A group that is NOT what any check asks for, and is NOT in helm's built-in set.
# It must not be built in: `--api-versions` ADDS to the built-in set rather than
# replacing it (see the module docstring), so a built-in group passed through it
# leaves `.Has` unchanged and the red render below would be indistinguishable from
# a bare one. It must not be a group a check asks for either: a colliding filler
# satisfies the very check whose red case it is part of, and that red case then
# renders objects instead of refusing. `assert_the_red_group_is_not_built_in` and
# `assert_the_filler_is_not_a_declared_group` are the two tripwires.
A_GROUP_NO_CHECK_ASKS_FOR = "monitoring.coreos.com/v1"

# The filler's own `--api-versions` pair, funneled through one name so the tripwire
# probe and the tail of every red case can never drift apart from each other.
FILLER_API_VERSIONS = ("--api-versions", A_GROUP_NO_CHECK_ASKS_FOR)

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
            # "CAPABILITY checks" and not "render checks", because `check_count_failures`
            # reports a DIFFERENT and larger number under a name that would otherwise be
            # the same one: the chart declares three render checks, two of which are the
            # capability checks this function counts. Two gates printing one phrase with
            # two numbers is a reader believing whichever they meet first.
            f"expected {len(expected)} capability checks declared in the chart, "
            f"found {len(found)}: expected {sorted(expected)}, found {sorted(found)}"
        )
    if found != expected:
        failures.append(f"expected the checks {expected}, found {found}")
    return failures


# ── THE VALUES CHECK, READ OFF THE SAME FILE ─────────────────────────────────
# A `fail` CALLED DIRECTLY FROM `templates/render-checks.yaml`, which is what a
# values check is: it reads the release's values and refuses on them, with no
# partial and no `.Capabilities` anywhere in it.
DIRECT_FAIL = re.compile(r"\{\{-?\s+fail\s")
# The two lists the mixed-release guard ranges over, read off the template so the
# gates below compare the GUARD with `Chart.yaml` and `values.yaml` rather than
# with a copy of itself.
GUARD_OPERATORS = re.compile(r"range \$operator := \(list (?P<names>[^)]*)\)")
GUARD_TOGGLES = re.compile(r"range \$toggle := \(list (?P<names>[^)]*)\)")
QUOTED = re.compile(r'"([^"]+)"')
# The one line the sub-key mutation below rewrites, and the plausible-but-wrong
# guard it rewrites it into — the guard whose first conjunct is `operators.create`
# alone, which is the form the estate's own plan names as the one to get wrong.
RESOLVED_OPERATOR_LINE = (
    '{{- $key := (include "platform.operator-create" '
    '(dict "context" $ "operator" $operator)) }}'
)
UNRESOLVED_OPERATOR_LINE = (
    '{{- $key := (ternary "operators.create" "" $.Values.operators.create) }}'
)
# The first capability check's guard, and the boundary the deletion red case cuts at.
CERT_MANAGER_GUARD = "{{- if or .Values.internalCA.create"


def declared_values_checks(chart: Path) -> int:
    """How many `fail`s `templates/render-checks.yaml` calls DIRECTLY. PURE.

    SCOPED TO THAT ONE FILE ON PURPOSE, and this is the difference between a count
    that means something and a count that drifts. Other rendered templates call
    `fail` too — `valkey.yaml` twice and `envoy-gateway-probe.yaml` once, measured
    2026-09-25 — and those are VALUES-AGREEMENT refusals about one object's own
    fields, not render checks about a missing prerequisite. Counting every `fail`
    in `templates/` would start this number above the count of checks and move
    whenever an unrelated template gained a guard.

    The capability checks are NOT counted here: they call `platform.require-api`
    and the `fail` lives in the partial, so `declared_checks` is what finds them.
    """
    template = chart / "templates" / "render-checks.yaml"
    return len(DIRECT_FAIL.findall(template.read_text()))


def declared_check_count(chart: Path) -> int:
    """Every check `templates/render-checks.yaml` declares, of both kinds. PURE."""
    return len(declared_checks(chart)) + declared_values_checks(chart)


def check_count_failures(chart: Path) -> list[str]:
    """How the checks the chart declares disagree with the count written here. PURE.

    A FUNCTION RATHER THAN AN INLINE ASSERT, for the reason `declaration_failures` is
    one: the red cases below have to WATCH this go red on a mutated chart, and an
    assertion that only ever runs against the real chart is a gate nobody has seen
    fail. Both addends are reported, so a total that is right because one kind gained
    a check while the other lost one is still named.
    """
    failures = []
    total = declared_check_count(chart)
    if total != EXPECTED_RENDER_CHECKS:
        failures.append(
            f"expected {EXPECTED_RENDER_CHECKS} render checks declared in "
            f"templates/render-checks.yaml, found {total}"
        )
    capability = len(declared_checks(chart))
    if capability != EXPECTED_CAPABILITY_CHECKS:
        failures.append(
            f"expected {EXPECTED_CAPABILITY_CHECKS} capability checks, found {capability}"
        )
    values_checks = declared_values_checks(chart)
    if values_checks != EXPECTED_VALUES_CHECKS:
        failures.append(
            f"expected {EXPECTED_VALUES_CHECKS} values checks, found {values_checks}"
        )
    return failures


def guard_list(pattern: re.Pattern[str], chart: Path) -> list[str]:
    """The quoted names of one `range` list in the mixed-release guard. PURE."""
    text = (chart / "templates" / "render-checks.yaml").read_text()
    match = pattern.search(text)
    assert match, (
        f"the mixed-release guard no longer carries a list matching {pattern.pattern}, "
        f"so the gates that compare it with Chart.yaml and values.yaml read nothing"
    )
    return QUOTED.findall(match.group("names"))


def operator_names_from_chart_manifest(manifest: Path) -> list[str]:
    """The five operator sub-key names, read off each dependency's `condition:`. PURE.

    `operators.<op>.create,operators.create` is the two-path form; its FIRST path's
    middle segment is the sub-key name. `nats.create` has two segments and is not an
    operator, which is what the length test below excludes rather than a name list.
    """
    declared = yaml.safe_load(manifest.read_text()).get("dependencies", [])
    names = []
    for dependency in declared:
        first = dependency.get("condition", "").split(",")[0].split(".")
        if len(first) == 3 and first[0] == "operators":
            names.append(first[1])
    return names


def create_toggles_from_values(values: Path) -> list[str]:
    """Every top-level `<key>.create` the chart's own values file carries. PURE."""
    loaded = yaml.safe_load(values.read_text())
    return [
        key
        for key, value in loaded.items()
        if isinstance(value, dict) and "create" in value
    ]


def api_versions(groups: Iterable[str]) -> tuple[str, ...]:
    """`--api-versions <group>` for each group, in the order given. PURE."""
    return tuple(part for group in groups for part in ("--api-versions", group))


def green_api_versions(declared: Iterable[str]) -> tuple[str, ...]:
    """EVERY group the render's checks ask for. PURE.

    Naming one group of several is NOT a green case: the checks whose groups are
    missing refuse, and `fail` aborts the whole render at the first of them.
    """
    return api_versions(sorted(declared))


def red_api_versions(declared: Iterable[str], under_test: str) -> tuple[str, ...]:
    """Every declared group EXCEPT `under_test`'s, plus the filler. PURE.

    The other groups are what keeps the refusal ATTRIBUTABLE: without them the
    render aborts at whichever other check `fail` reaches first, and names that
    check's operator rather than this one's. The filler is what keeps the render
    distinguishable from a bare one when `under_test` is the only check there is.
    """
    return api_versions(
        sorted(group for group in declared if group != under_test)
    ) + FILLER_API_VERSIONS


def render(chart: Path, *arguments: str) -> subprocess.CompletedProcess[str]:
    return helm("template", "platform", str(chart), *arguments)


def objects(stdout: str) -> list[dict]:
    return [
        document
        for document in yaml.safe_load_all(stdout)
        if isinstance(document, dict) and document.get("apiVersion")
    ]


def probe_capability(group: str, destination: Path, *api_version_arguments: str) -> bool:
    """Whether a throwaway chart's OWN render sees `group` in `.Capabilities.APIVersions`.

    A SEPARATE, ONE-TEMPLATE CHART rather than a re-read of the platform chart's
    render, because the thing under test here is helm's capability mechanism
    itself — what `--api-versions` does and does not add — not anything this
    chart declares. `destination` must be a fresh directory per call: two probes
    sharing one chart directory would collide on `templates/probe.yaml`.
    """
    chart = destination / "capability-probe-m-agahi"
    (chart / "templates").mkdir(parents=True)
    (chart / "Chart.yaml").write_text(
        "apiVersion: v2\nname: capability-probe-m-agahi\nversion: 0.1.0\n"
    )
    (chart / "templates" / "probe.yaml").write_text(
        "apiVersion: v1\n"
        "kind: ConfigMap\n"
        "metadata:\n"
        "  name: probe\n"
        "data:\n"
        '  has: {{ .Capabilities.APIVersions.Has "%s" | quote }}\n' % group
    )
    result = helm("template", "probe", str(chart), *api_version_arguments)
    assert result.returncode == 0, result.stderr
    (configmap,) = objects(result.stdout)
    return configmap["data"]["has"] == "true"


def assert_the_red_group_is_not_built_in(tmp_path: Path) -> None:
    """The filler's first tripwire, following `test_ladder.py`'s collision twin.

    PROVES BOTH HALVES OF WHAT MAKES `A_GROUP_NO_CHECK_ASKS_FOR` USABLE AS THE
    FILLER. First, that it is absent from a BARE render's `.Capabilities.APIVersions`
    — i.e. it is not one of helm's built-in groups, because a built-in group passed
    through `--api-versions` leaves `.Has` unchanged (module docstring) and the red
    render below would then be indistinguishable from a bare one. Second, that it IS
    present once passed through `FILLER_API_VERSIONS` — i.e. the tail every red case
    carries actually reaches `.Capabilities.APIVersions`, so a red case rewired to
    carry no `--api-versions` at all is caught here too.

    READ WITH `.Has`, NEVER BY COMPARING `len .Capabilities.APIVersions`. A built-in
    group passed through `--api-versions` is APPENDED as a duplicate, so the length
    moves while `.Has` does not — a length-based tripwire reports a built-in group as
    not built in and inverts the check it protects.
    """
    bare = probe_capability(A_GROUP_NO_CHECK_ASKS_FOR, tmp_path / "bare")
    assert not bare, (
        f"{A_GROUP_NO_CHECK_ASKS_FOR} is present in a bare render's "
        f".Capabilities.APIVersions, so it is one of helm's built-in groups and "
        f"the red case below can no longer be told apart from a bare render"
    )
    red = probe_capability(
        A_GROUP_NO_CHECK_ASKS_FOR, tmp_path / "red", *FILLER_API_VERSIONS
    )
    assert red, (
        f"{A_GROUP_NO_CHECK_ASKS_FOR} did not reach .Capabilities.APIVersions "
        f"through {FILLER_API_VERSIONS}, so the red render below no longer carries a "
        f"capability set that differs from a bare render"
    )


def assert_the_filler_is_not_a_declared_group(declared: dict[str, str]) -> None:
    """The filler's second tripwire, and the generalised red case is what creates it.

    The red case for check i carries every OTHER declared group plus the filler. If
    the filler IS one of the declared groups then check i's red case hands that other
    check its own group back and takes nothing away from check i, the render SUCCEEDS
    and produces objects — measured — and what goes red is the red case for the group
    collided with, reported as "this red case did not refuse". That names a symptom.
    This names the cause, which is why it runs BEFORE any red case rather than after.
    """
    assert A_GROUP_NO_CHECK_ASKS_FOR not in declared, (
        f"the filler {A_GROUP_NO_CHECK_ASKS_FOR} is one of the groups the chart's own "
        f"checks ask for ({declared[A_GROUP_NO_CHECK_ASKS_FOR]}), so it satisfies a "
        f"check whose red case it is part of and that red case renders objects "
        f"instead of refusing — choose a filler outside {sorted(declared)}"
    )


def exercise_one_pair_per_declared_check(
    chart: Path, values_arguments: tuple[str, ...], expected_pairs: int, tmp_path: Path
) -> list[dict]:
    """The construction itself, over whatever set of checks `chart` declares.

    ONE FUNCTION, CALLED FOR THE PLATFORM CHART AND FOR THE TWO-CHECK FIXTURE, because
    a construction proved only at the count the chart happens to declare today is not
    a generalisation. Returns the GREEN render's objects so each caller can assert its
    own literal count.

    THE GREEN HALF IS ONE RENDER SHARED BY EVERY PAIR, and that follows from the
    construction rather than from thrift: GREEN is stated over the whole set of checks,
    so there is exactly one green argv however many checks there are.
    """
    assert_the_red_group_is_not_built_in(tmp_path)
    declared = declared_checks(chart)
    assert_the_filler_is_not_a_declared_group(declared)

    green = render(chart, *values_arguments, *green_api_versions(declared))
    assert green.returncode == 0, (
        f"the render naming every declared group {sorted(declared)} refused, so the "
        f"green half proves nothing: {green.stderr}"
    )
    rendered = objects(green.stdout)
    assert rendered, (
        f"the render naming every declared group {sorted(declared)} succeeded and "
        f"produced nothing, so the green half proves nothing"
    )

    exercised = 0
    for group, operator in sorted(declared.items()):
        red = render(chart, *values_arguments, *red_api_versions(declared, group))

        # THE RED CASE'S THIRD TRIPWIRE, ORTHOGONAL TO THE TWO ABOVE. Those guard the
        # filler CONSTANT; this one guards the CALL SITE — it reads
        # `subprocess.CompletedProcess.args`, the literal argv `helm()` ran, so a red
        # case rewritten straight to a bare `render(chart)` is caught here instead of
        # silently reverting to the bare render
        # `test_a_bare_render_refuses_too_and_that_is_the_renderers_reason` exists to
        # keep out. At ONE check that is the ONLY assertion that catches it: a bare
        # render still exits non-zero and still names the one operator there is.
        #
        # EVERY CLAUSE IS PHRASED OVER SOMETHING `red_api_versions` DID NOT PRODUCE —
        # the module-level filler literal, the group under test, and the groups read
        # off the chart. Asserting `set(red_api_versions(...)) <= set(red.args)`
        # instead would compare the builder with itself and could not fail.
        assert A_GROUP_NO_CHECK_ASKS_FOR in red.args, (
            f"the red render for {operator} no longer carries the filler "
            f"{A_GROUP_NO_CHECK_ASKS_FOR}, so at one check it is a bare render: {red.args}"
        )
        assert group not in red.args, (
            f"the red render for {operator} carries {group}, the very group whose "
            f"absence it exists to refuse over: {red.args}"
        )
        for other in declared:
            if other != group:
                assert other in red.args, (
                    f"the red render for {operator} does not carry {other}, so it "
                    f"aborts at that check and names {declared[other]} rather than "
                    f"{operator}: {red.args}"
                )
        assert red.args.count("--api-versions") == len(declared), (
            f"the red render for {operator} passed --api-versions "
            f"{red.args.count('--api-versions')} times; {len(declared)} is the whole "
            f"construction — every declared group but {group}, plus the filler: {red.args}"
        )

        assert red.returncode != 0, (
            f"the render for {operator} succeeded with {group} absent from "
            f"--api-versions, so the check did not refuse"
        )
        # ATTRIBUTABILITY, AND THIS IS THE ASSERTION THE WHOLE CONSTRUCTION SERVES.
        # `fail` aborts the render at the first failing check and names only that one,
        # so a refusal naming some OTHER operator is a refusal for another check's
        # reason and says nothing about this one. Do not delete it to quiet a red
        # suite met while adding a check — fix the construction, which is what the
        # other declared groups in the argv above are for.
        assert operator in red.stderr, red.stderr
        assert group in red.stderr, red.stderr
        assert "--api-versions" in red.stderr, red.stderr

        exercised += 1

    assert exercised == expected_pairs, (
        f"expected {expected_pairs} red/green pairs, exercised {exercised}"
    )
    return rendered


def two_check_fixture(destination: Path) -> Path:
    """A throwaway chart declaring TWO render checks, built around THIS chart's partial.

    `_require_api.tpl` is COPIED rather than reimplemented, so the fixture exercises
    the refusal this chart actually ships. Both toggles default false, per the rule
    that a render check only ever sits behind a default-false toggle, and the cases
    below turn them on with `--set`.
    """
    chart = destination / "two-check-fixture-m-agahi"
    (chart / "templates").mkdir(parents=True)
    (chart / "Chart.yaml").write_text(
        "apiVersion: v2\nname: two-check-fixture-m-agahi\nversion: 0.1.0\n"
    )
    (chart / "values.yaml").write_text(
        "certificates:\n  create: false\nautoscaling:\n  enabled: false\n"
    )
    shutil.copy(
        CHART / "templates" / "_require_api.tpl", chart / "templates" / "_require_api.tpl"
    )
    (chart / "templates" / "render-checks.yaml").write_text(
        "{{- if .Values.certificates.create }}\n"
        '{{- include "platform.require-api" (dict\n'
        '      "context" $\n'
        '      "apiVersion" "cert-manager.io/v1"\n'
        '      "operator" "cert-manager"\n'
        '      "toggle" "certificates.create") }}\n'
        "{{- end }}\n"
        "{{- if .Values.autoscaling.enabled }}\n"
        '{{- include "platform.require-api" (dict\n'
        '      "context" $\n'
        '      "apiVersion" "keda.sh/v1alpha1"\n'
        '      "operator" "KEDA"\n'
        '      "toggle" "autoscaling.enabled") }}\n'
        "{{- end }}\n"
    )
    (chart / "templates" / "objects.yaml").write_text(
        "{{- if .Values.certificates.create }}\n"
        "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: from-cert-manager\n---\n"
        "{{- end }}\n"
        "{{- if .Values.autoscaling.enabled }}\n"
        "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: from-keda\n"
        "{{- end }}\n"
    )
    return chart


BOTH_FIXTURE_TOGGLES_ON = (
    "--set",
    "certificates.create=true",
    "--set",
    "autoscaling.enabled=true",
)


def test_the_chart_declares_the_checks_this_harness_exercises():
    """The denominator, asserted against the chart rather than assumed.

    BOTH KINDS OF CHECK ARE COUNTED, and the two addends are asserted separately
    as well as summed: a total that is right because one kind gained a check while
    the other lost one is the arithmetic a bare sum cannot see.
    """
    assert len(EXPECTED_CHECKS) == EXPECTED_CAPABILITY_CHECKS, (
        f"EXPECTED_CHECKS names {len(EXPECTED_CHECKS)} checks and "
        f"EXPECTED_CAPABILITY_CHECKS says {EXPECTED_CAPABILITY_CHECKS}"
    )
    assert EXPECTED_CAPABILITY_CHECKS + EXPECTED_VALUES_CHECKS == EXPECTED_RENDER_CHECKS, (
        f"{EXPECTED_CAPABILITY_CHECKS} capability checks and {EXPECTED_VALUES_CHECKS} "
        f"values checks do not add up to the {EXPECTED_RENDER_CHECKS} this file expects"
    )
    assert declaration_failures(CHART, EXPECTED_CHECKS) == [], declaration_failures(
        CHART, EXPECTED_CHECKS
    )
    assert check_count_failures(CHART) == [], check_count_failures(CHART)


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
    assert (
        f"expected {EXPECTED_CAPABILITY_CHECKS} capability checks declared in the chart, "
        f"found 0" in message
    )


def test_the_harness_exercises_one_red_green_pair_per_declared_check(tmp_path):
    """Every declared check refuses without its group and renders with it.

    BOTH RENDERS PASS `--api-versions`, and the module docstring is where the
    measurement that forces that lives: with no `--api-versions` at all helm leaves
    every CRD-backed group out of `.Capabilities.APIVersions`, so a bare render
    refuses whatever the target holds and proves nothing about the check.
    """
    exercise_one_pair_per_declared_check(
        CHART, ("-f", str(ADOPTER_VALUES)), EXPECTED_CAPABILITY_CHECKS, tmp_path
    )


def test_the_construction_is_correct_at_two_checks(tmp_path):
    """THE GENERALISATION, PROVED AT A COUNT THIS CHART DOES NOT CONTROL.

    AT ONE CHECK the construction above is indistinguishable from the narrower one it
    replaced — green naming "the group under test" and red naming "the filler alone".
    Measured on helm 3.18.4 and 4.3.0 against a two-check chart, that narrower one is
    FALSE, and `test_the_narrower_construction_is_false_at_two_checks` below is where
    that measurement is asserted rather than described.

    SO THE COUNT EXERCISED HERE IS THE FIXTURE'S, NEVER THE CHART'S, AND THAT IS WHAT
    THIS CASE BUYS. `FIXTURE_RENDER_CHECKS` is two however many checks
    `EXPECTED_RENDER_CHECKS` says the chart declares, so the generalisation is proved
    at two on a chart declaring one and stays proved the day a chart drops back to
    one. This file is copied into every chart that carries a render check, and those
    charts declare different counts; a case whose reason for existing is read off one
    chart's count arrives stale in the next.

    IT ALSO ASSERTS SOMETHING NO RENDER OF A REAL CHART CAN GIVE. The fixture renders
    exactly one object per check, so the green half is asserted to produce one object
    PER CHECK rather than merely to produce something — the difference between a green
    half that exercised every check it counted and one that rendered anything at all.
    """
    fixture = two_check_fixture(tmp_path / "fixture")

    rendered = exercise_one_pair_per_declared_check(
        fixture, BOTH_FIXTURE_TOGGLES_ON, FIXTURE_RENDER_CHECKS, tmp_path / "probes"
    )
    assert len(rendered) == FIXTURE_RENDER_CHECKS, (
        f"the fixture's green render produced {len(rendered)} objects, expected "
        f"{FIXTURE_RENDER_CHECKS} — one per check, and a green half that renders "
        f"fewer is not exercising every check it counts"
    )


def test_the_narrower_construction_is_false_at_two_checks(tmp_path):
    """THE MEASUREMENT THAT FORCES THE CONSTRUCTION ABOVE. Do not simplify it away.

    Records both halves of what breaks at two checks, so a later reader who wonders
    why green does not simply name "the group under test" meets the answer as an
    assertion rather than as prose. Green built the narrower way REFUSES, naming the
    other check; and the filler alone refuses naming cert-manager and never KEDA, so
    it is not KEDA's red case at all.

    Its own red case is helm rendering every check before aborting instead of
    stopping at the first `fail`: both renders below would then behave differently
    and these assertions would go red, which is the correct outcome — the
    construction above rests on the same behaviour and would need revisiting too.
    """
    fixture = two_check_fixture(tmp_path / "fixture")

    green_the_narrower_way = render(
        fixture, *BOTH_FIXTURE_TOGGLES_ON, "--api-versions", "cert-manager.io/v1"
    )
    assert green_the_narrower_way.returncode != 0, (
        "naming only the group under test rendered a two-check chart, so the narrower "
        "construction's green case is no longer the thing this case records"
    )
    assert "KEDA" in green_the_narrower_way.stderr, green_the_narrower_way.stderr

    red_the_narrower_way = render(fixture, *BOTH_FIXTURE_TOGGLES_ON, *FILLER_API_VERSIONS)
    assert red_the_narrower_way.returncode != 0
    assert "cert-manager" in red_the_narrower_way.stderr, red_the_narrower_way.stderr
    assert "KEDA" not in red_the_narrower_way.stderr, (
        "the filler alone named KEDA, so it would be a usable red case for KEDA after "
        f"all: {red_the_narrower_way.stderr}"
    )


def test_a_bare_render_refuses_too_and_that_is_the_renderers_reason():
    """THE MEASUREMENT THAT DECIDES HOW THE RED CASE IS BUILT. Do not simplify it away.

    A render with no `--api-versions` refuses as well — but for the renderer's
    reason, not the target's, because helm populates no CRD-backed group without
    one. Asserting that refusal AS the red case would pass on a chart whose check
    named a group the target does have, which is the case the check exists to let
    through.

    EXACTLY ONE DECLARED OPERATOR, NOT A NAMED ONE. `fail` aborts at the first failing
    check, so which operator a bare render names depends on the order of the
    invocations in `templates/render-checks.yaml` and changes the day a check is
    inserted above another. This asserts exactly one declared operator is named — the
    only correct answer at every count — and that the refusal says what to do about
    THAT one, which is the clause an `any(...)` rewrite would drop.
    """
    declared = declared_checks(CHART)
    bare = render(CHART, "-f", str(ADOPTER_VALUES))
    assert bare.returncode != 0

    named = sorted(group for group, operator in declared.items() if operator in bare.stderr)
    assert len(named) == 1, (
        f"a bare render named the operators of {named} out of {sorted(declared)}; "
        f"`fail` aborts at the first failing check, so exactly one is the only "
        f"correct answer: {bare.stderr}"
    )
    (group,) = named
    # And the refusal says what to do about it, because this is the render an
    # offline reader meets first.
    assert f"--api-versions {group}" in bare.stderr, bare.stderr


def test_the_checks_are_unreachable_at_the_chart_defaults():
    """A render check may only ever sit behind a default-false toggle.

    `.Capabilities.APIVersions.Has` is false for every group outside helm's
    built-in list whenever there is no cluster, so a check reachable at the
    defaults would refuse every offline render in the estate — `helm lint
    --strict`, the shared `helm lint and render` hook, and every bare `helm
    template` in every suite. This asserts the defaults render bare, with no
    `--api-versions` and no values file at all.
    """
    defaults = render(CHART)
    assert defaults.returncode == 0, defaults.stderr
    assert objects(defaults.stdout) == []


# ── THE MIXED-RELEASE REFUSAL: A VALUES CHECK, AND ITS PAIR IS TWO BARE RENDERS ──
# `plans/the-operators-toggle.md` step 3. `operators.create: true` names a release
# that installs the five operators and NOTHING ELSE, because a release that installs
# an operator and also renders an object of a kind that operator provides cannot
# work: the CRD does not exist at discovery time, so this chart's own capability
# check refuses first on a bare cluster, and helm is in any case understood to
# resolve every kind in a release before it applies anything. That second mechanism
# is READ rather than measured and nothing here rests on it.
#
# EVERY CASE BELOW IS A BARE RENDER, and that is the design rather than an
# oversight — see the module docstring. Do not add `--api-versions` to any of them.

ONLY_OPERATORS = ("--set", "operators.create=true")
OPERATORS_AND_CERTIFICATES = (
    "--set",
    "operators.create=true",
    "--set",
    "certificates.create=true",
)
# THE SUB-KEY SHAPE, AND IT IS A PROOF OF THIS CHECK RATHER THAN A FOOTNOTE. The
# register key is FALSE here and cert-manager installs anyway, because the
# dependency's `condition:` reads `operators.certManager.create` first. Measured on
# 2026-09-25 at the step-1 head: this shape WITHOUT `certificates.create` renders 50
# objects, which is cert-manager installing with the register key off.
SUB_KEY_AND_CERTIFICATES = (
    "--set",
    "operators.create=false",
    "--set",
    "operators.certManager.create=true",
    "--set",
    "certificates.create=true",
)


def assert_it_is_the_mixed_release_refusal(
    result: subprocess.CompletedProcess[str], *keys: str
) -> None:
    """The refusal is THIS check's, it names every key given, and it is a bare render.

    `--api-versions` ABSENT FROM stderr IS THE LOAD-BEARING CLAUSE, and it is what
    makes the refusal attributable to this check. Every shape below also trips the
    cert-manager CAPABILITY check — `certificates.create` is true in all of them and
    a bare render has no `cert-manager.io/v1` — so both checks would refuse and both
    exits are non-zero. The capability refusal ends by telling the reader to pass
    `--api-versions cert-manager.io/v1`; this one never mentions the flag. That
    clause is therefore the only thing distinguishing "the mixed-release check fired"
    from "the check declared after it fired instead", which is exactly what a later
    reader who moves this check down the file would cause.
    """
    assert result.returncode != 0, (
        f"the mixed release rendered instead of being refused: {result.stdout[:400]}"
    )
    for key in keys:
        assert key in result.stderr, (
            f"the refusal does not name {key}, so it tells an adopter to turn off "
            f"something other than what they set: {result.stderr}"
        )
    assert "--api-versions" not in result.stderr, (
        "the refusal came from a capability check rather than from the mixed-release "
        f"check — it is declared after another check that this shape also trips: "
        f"{result.stderr}"
    )
    assert "--api-versions" not in result.args, (
        f"this case is not a bare render any more: {result.args}"
    )


def test_operators_alone_render_and_that_is_the_green_half():
    """`operators.create: true` with every other toggle false is release 1, and it renders.

    THE GREEN HALF OF THE PAIR, and it is a BARE render: this check reads no
    `.Capabilities`, so nothing here needs `--api-versions`. It asserts CRDs are among
    the objects rather than merely that something rendered — the operators' own
    CustomResourceDefinitions are what tells this render apart from a render of this
    chart's ordinary objects, and a green half that cannot tell those apart would pass
    on a chart where the dependencies never resolved.
    """
    green = render(CHART, *ONLY_OPERATORS)
    assert green.returncode == 0, (
        f"the operators-only release was refused, and it is the shape the refusal "
        f"below tells adopters to use: {green.stderr}"
    )
    rendered = objects(green.stdout)
    assert rendered, "the operators-only release rendered nothing"
    crds = [
        document
        for document in rendered
        if document.get("kind") == "CustomResourceDefinition"
    ]
    assert crds, (
        "the operators-only release rendered no CustomResourceDefinition, so the "
        "operator subcharts did not render — run `helm dependency build chart/`"
    )
    assert "--api-versions" not in green.args, green.args


def test_the_mixed_release_is_refused_and_the_refusal_names_both_keys():
    """THE RED HALF: operators beside an object of a kind those operators provide."""
    assert_it_is_the_mixed_release_refusal(
        render(CHART, *OPERATORS_AND_CERTIFICATES),
        "operators.create",
        "certificates.create",
    )


def test_the_mixed_release_is_refused_through_a_per_operator_sub_key_too():
    """THE SHAPE THE OBVIOUS GUARD MISSES, and it is a proof of this check.

    `operators.create` is FALSE here. cert-manager installs anyway, because the
    dependency's `condition:` reads `operators.certManager.create` first and helm
    stops at the first valid path. A guard whose first conjunct is `operators.create`
    alone is false in this shape and never fires — and
    `test_a_guard_reading_only_the_register_key_misses_the_sub_key_case` below
    constructs exactly that guard and watches this case stop being refused.
    """
    assert_it_is_the_mixed_release_refusal(
        render(CHART, *SUB_KEY_AND_CERTIFICATES),
        "operators.certManager.create",
        "certificates.create",
    )


def test_a_guard_reading_only_the_register_key_misses_the_sub_key_case(tmp_path):
    """THE CONSTRUCTED RED CASE FOR THE GUARD'S SHAPE (ADR-0793).

    The mutation is one line: the guard resolves each operator the way helm resolves
    the dependency's own two-path `condition:` — `dig`, with the register key as the
    FALLBACK — and this rewrites it to read the register key ALONE. That is the
    plausible-but-wrong guard, and under it the sub-key shape is no longer refused by
    this check: the render falls through to the cert-manager capability check, which
    refuses for a different reason and says to pass `--api-versions`.

    IT ASSERTS THE MUTATION LANDED BEFORE IT ASSERTS ANYTHING ABOUT THE RENDER. A
    rewrite whose pattern no longer matches leaves the correct guard in place, and
    this case would then "pass" having changed nothing at all.
    """
    copy = tmp_path / "chart"
    shutil.copytree(CHART, copy)
    template = copy / "templates" / "render-checks.yaml"
    original = template.read_text()
    assert RESOLVED_OPERATOR_LINE in original, (
        f"the guard no longer contains the line this mutation rewrites, so the "
        f"mutation would change nothing: {RESOLVED_OPERATOR_LINE}"
    )
    template.write_text(original.replace(RESOLVED_OPERATOR_LINE, UNRESOLVED_OPERATOR_LINE))
    assert template.read_text() != original

    weakened = render(copy, *SUB_KEY_AND_CERTIFICATES)
    assert "operators.certManager.create" not in weakened.stderr, (
        "the guard reading the register key alone still refused the sub-key shape, so "
        f"the mutation did not weaken what this case claims it weakens: {weakened.stderr}"
    )
    # What it does instead: falls through to the capability check declared after it,
    # which refuses for the renderer's reason and names the flag. Asserted so the case
    # records the ACTUAL behaviour of the wrong guard rather than only an absence.
    assert "--api-versions" in weakened.stderr, weakened.stderr

    # AND THE HARM ITSELF, MEASURED. Give the capability check the group it wants and
    # the wrong guard lets the mixed release through outright: cert-manager installing
    # beside Certificates of the kind it has not registered yet. The correct chart
    # refuses the same argv, which is the whole difference between the two guards and
    # the only assertion here phrased on an exit code rather than on a message.
    # THIS PAIR IS THE ONE PLACE `--api-versions` APPEARS IN A MIXED-RELEASE CASE, and
    # it is here to quiet the OTHER check rather than to feed this one — the module
    # docstring's rule that this check's own pair is two bare renders is unaffected.
    quieted = ("--api-versions", "cert-manager.io/v1")
    permitted = render(copy, *SUB_KEY_AND_CERTIFICATES, *quieted)
    assert permitted.returncode == 0, (
        f"the weakened guard refused anyway, so this case no longer measures what the "
        f"wrong guard permits: {permitted.stderr}"
    )
    assert objects(permitted.stdout), "the weakened guard rendered nothing"
    refused = render(CHART, *SUB_KEY_AND_CERTIFICATES, *quieted)
    assert refused.returncode != 0, (
        "the chart's own guard permitted the mixed release once the capability check "
        "was satisfied, which is the shape it exists to refuse"
    )


def test_the_values_check_is_declared_BEFORE_the_capability_checks():
    """ORDER IS LOAD-BEARING, and this names the cause the red cases name a symptom of.

    `fail` aborts the whole render at the FIRST failing check. Every mixed shape also
    trips the cert-manager capability check, so with this check declared after it the
    bare renders above would refuse with the capability message and the mixed-release
    check would be unproved. Declaring it first is also what makes the plan's "two
    bare renders" literally true — the alternative is passing `--api-versions` to
    quiet the other check, which drags a capability set into a check that reads none.
    """
    text = RENDER_CHECKS.read_text()
    fail_at = DIRECT_FAIL.search(text)
    include_at = INVOCATION.search(text)
    assert fail_at and include_at, text[:400]
    assert fail_at.start() < include_at.start(), (
        "the mixed-release check is declared after a capability check, so every shape "
        "that trips both is refused with the capability check's message and the "
        "mixed-release check is no longer attributable"
    )


def test_deleting_the_values_check_reddens_the_count(tmp_path):
    """RED AT 2: the `fail` half of the count, watched going red.

    Deletes the mixed-release check and leaves the two capability checks standing, so
    the total falls to two — the number this file carried before step 3 of
    `plans/the-operators-toggle.md`. Without this, a deleted values check leaves a
    harness that counts what it happens to find and reports a pass.
    """
    copy = tmp_path / "chart"
    shutil.copytree(CHART, copy)
    template = copy / "templates" / "render-checks.yaml"
    original = template.read_text()
    # Everything above the first capability check goes, which is the values check and
    # the header comment; the two capability checks below it stay standing.
    first_capability_check = original.index(CERT_MANAGER_GUARD)
    assert DIRECT_FAIL.search(original).start() < first_capability_check, original[:400]
    template.write_text(original[first_capability_check:])
    assert declared_values_checks(copy) == 0, "the values check survived the deletion"

    failures = check_count_failures(copy)
    message = "\n".join(failures)
    assert failures, "the values check was deleted and the count said nothing"
    assert (
        f"expected {EXPECTED_RENDER_CHECKS} render checks declared in "
        f"templates/render-checks.yaml, found 2" in message
    ), message
    assert f"expected {EXPECTED_VALUES_CHECKS} values checks, found 0" in message, message


def test_an_eighth_check_reddens_the_count(tmp_path):
    """RED AT 8: the `include` half of the count, watched going red.

    THE OTHER ADDEND ON PURPOSE. The case above deletes a values check and this one
    adds a capability check, so each half of the sum has been seen moving the total.
    Two mutations of the same addend would leave the other half unproved.
    """
    copy = tmp_path / "chart"
    shutil.copytree(CHART, copy)
    template = copy / "templates" / "render-checks.yaml"
    template.write_text(
        template.read_text()
        + "\n{{- if .Values.valkey.create }}\n"
        '{{- include "platform.require-api" (dict\n'
        '      "context" $\n'
        '      "apiVersion" "example.invalid/v1"\n'
        '      "operator" "an eighth check"\n'
        '      "toggle" "valkey.create") }}\n'
        "{{- end }}\n"
    )
    assert declared_check_count(copy) == 8, "the eighth check was not counted at all"

    failures = check_count_failures(copy)
    message = "\n".join(failures)
    assert failures, "an eighth check was added and the count said nothing"
    assert (
        f"expected {EXPECTED_RENDER_CHECKS} render checks declared in "
        f"templates/render-checks.yaml, found 8" in message
    ), message


def test_the_guard_names_every_operator_THE_CHART_DECLARES():
    """The guard's operator list against `Chart.yaml`, and neither is a copy of the other.

    THE DRIFT THIS CLOSES, AND THE SHARED HELPER DOES NOT CLOSE IT.
    `templates/_operators.tpl` now states the RESOLUTION once, for this guard and
    for the eighteen vendored-CRD guards of step 2 — the helper
    `plans/the-operators-toggle.md` asked for. It says nothing about WHICH
    operators exist: the list below is still a list, and a sixth operator declared
    as a dependency and not added to it is a hole in the refusal. That is what
    reddens here.
    """
    declared = operator_names_from_chart_manifest(CHART_MANIFEST)
    assert len(declared) == 5, (
        f"expected five operator dependencies with a two-path condition, found "
        f"{declared} — the guard's list below is checked against this one"
    )
    assert sorted(guard_list(GUARD_OPERATORS, CHART)) == sorted(declared), (
        f"the mixed-release guard ranges over {guard_list(GUARD_OPERATORS, CHART)} and "
        f"Chart.yaml declares {declared}: an operator missing from the guard installs "
        f"beside the estate's own objects and is never refused"
    )


def test_the_guard_names_every_OTHER_create_toggle_the_values_file_carries():
    """The guard's other half against `values.yaml`, for the same reason.

    The plan states the second conjunct as the OR of every OTHER `create` toggle the
    chart carries, so a toggle added to `values.yaml` and not to the guard leaves a
    mixed release that renders. `operators` is the one exclusion and it is the subject
    of the first conjunct.

    `bootstrap.iamKeys.create` IS NOT IN EITHER LIST AND THAT IS CORRECT. It is
    nested, and `templates/bootstrap-secrets.yaml` renders its block only inside the
    `{{- if .Values.bootstrap.create }}` that opens the file, so it reaches nothing
    the OR over `bootstrap.create` does not already cover. This comparison is over
    TOP-LEVEL keys for that reason.
    """
    carried = sorted(
        key for key in create_toggles_from_values(CHART_VALUES) if key != "operators"
    )
    assert carried, "values.yaml carries no create toggles at all, which cannot be right"
    assert sorted(guard_list(GUARD_TOGGLES, CHART)) == carried, (
        f"the mixed-release guard ranges over {sorted(guard_list(GUARD_TOGGLES, CHART))} "
        f"and values.yaml carries {carried}: a toggle missing from the guard renders "
        f"its objects beside the operators and is never refused"
    )
