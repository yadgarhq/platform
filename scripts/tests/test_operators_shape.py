"""THE TYPE GUARD OVER `operators`, AND THE TWO CHARTS IT HAS TO BE RIGHT IN.

Run: python3 -m pytest scripts/tests/ -q

WHAT THIS FILE IS ABOUT. `operators` is read by NINETEEN template sites in this
chart — the eighteen vendored CRDs and the mixed-release guard in
`templates/render-checks.yaml` — and until this gate existed not one of them
tested its SHAPE. An adopter who wrote `operators: true`, which is what somebody
writes who thinks the toggle IS the block rather than a key inside it, got a Go
stack trace out of whichever of the nineteen helm reached first.

AND UNDER THE PARENT CHART IT WAS WORSE THAN A STACK TRACE. `yadgarhq/chart`
carries a deliberate refusal for exactly that typo — ADR-0794's clause in its
`chart/templates/_validate.tpl`, which names the key and the type the adopter
wrote. Measured on helm v4.3.0 and v3.20.2 alike (`scripts/tests/` of this
repository, 2026-09-26): WHEN A SUBCHART AND ITS PARENT BOTH ABORT, THE
SUBCHART'S MESSAGE IS THE ONE THE ADOPTER SEES. helm executes the deepest
template path first, so a parent `fail` can never pre-empt a child's. The
subchart's raise therefore SHADOWED the parent's named refusal, and no change to
`yadgarhq/chart` could have reached it.

THE SHAPE THIS CHART SETTLED ON, AND IT IS NOT THE OBVIOUS ONE. Two obvious
answers were measured and both are wrong:

  (a) stay silent on a bad value and let the parent refuse — REJECTED, and the
      reason is helm's own resolution rather than taste. Each operator is
      declared `condition: operators.<op>.create,operators.create`, and HELM
      LEAVES A DEPENDENCY ENABLED WHEN NO PATH OF A MULTI-PATH `condition:`
      RESOLVES (ADR-0794). So `operators: true` standing alone installs all five
      operators — while a silent guard skips every vendored CRD, and
      `keda.crds.install` is false. That is KEDA installed with no CRDs at all,
      at exit 0. Silence converts a loud failure into the quiet one, which is
      the exact inversion ADR-0794 exists to forbid.

  (b) raise this chart's own named refusal unconditionally — REJECTED, measured:
      it shadows the parent's refusal, so `yadgarhq/chart`'s clause becomes dead
      code AND its own test starts passing against THIS chart's message. A gate
      that would stay green with the thing it tests deleted is worse than no
      gate.

  (c) WHAT IS BUILT: refuse by name WHEN THIS CHART IS THE ROOT, and defer
      SILENTLY when it is a subchart, so the parent's refusal — which names the
      path the adopter actually typed, `platform.operators` — is the one that
      fires. ADR-0794's own rejected-alternatives say the child's guard "puts the
      diagnosis in the wrong chart"; deferring is that sentence implemented. A
      standalone `helm install platform` still gets a refusal naming the key
      instead of a stack trace.

THE DISCRIMINATOR IS `.Template.BasePath`, MEASURED ON BOTH PINS. As the root
chart it is `platform/templates`; under a parent it is
`<parent>/charts/platform/templates`. `contains "/charts/"` therefore separates
the two, and it is the same answer on helm v3.20.2 and v4.3.0.

THE RESIDUAL, STATED RATHER THAN HIDDEN. A parent that pins this chart and
carries NO refusal of its own gets the silent fail-open described under (a).
`yadgarhq/chart` is the only parent this estate ships and it carries one; a
third-party parent would not. `test_the_parent_is_the_one_that_names_the_key`
below is written against a throwaway parent that DOES carry one, because that is
the contract this chart defers to.

`null` IS NOT A PRESENT KEY INSIDE THIS CHART, AND THAT IS MEASURED. Helm's
coalescing DELETES a key whose value is null, including one this chart's own
`values.yaml` supplies a default for. So `--set operators=null` and
`operators: null` in a values file both leave `hasKey .Values "operators"` FALSE
here — the distinction ADR-0794 buys with `hasKey` exists one layer up, in the
parent, and does not exist here. This chart therefore refuses an ABSENT
`operators` too, and reports it as `null`: absent can only happen when somebody
removed the default, and helm's fail-open then installs five operators out of a
key nobody can read.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parents[2]
CHART = REPO / "chart"
VENDORED = CHART / "templates" / "vendored-crds"
RENDER_CHECKS = CHART / "templates" / "render-checks.yaml"
OPERATORS_PARTIAL = CHART / "templates" / "_operators.tpl"

# ── WHAT THE GUARD LOOKS LIKE, AS ONE STRING EACH ────────────────────────────
# The helper every one of the nineteen sites goes through. It is a LITERAL here
# because the point of the gate is that nobody writes the nineteenth site by
# hand: a new vendored CRD that inlines `dig` instead is the defect this file
# exists to catch, and a regex loose enough to match both would catch neither.
HELPER = "platform.operator-create"
HELPER_CALL = re.compile(r'include\s+"platform\.operator-create"\s+\(dict')

# Every site that reads the key, counted. Eighteen vendored CRDs and the one
# `range` in `render-checks.yaml`. A LITERAL, for the reason every expected count
# in this estate is a literal.
EXPECTED_GUARD_SITES = 19
EXPECTED_VENDORED_FILES = 18

# The raw read no template may perform any more. `.Values.operators.create` is
# the dereference that raised: it is a field access on a value of unknown type.
THE_RAW_READ = ".Values.operators.create"

# ── THE EIGHT SHAPES, SPLIT BY WHO CAN SEE THEM ──────────────────────────────
# THE SAME EIGHT `yadgarhq/chart` ASSERTS, so the two charts answer for the same
# input class (ADR-0794: "the two implementations must adopt the SAME idiom for
# the same input class"). Each kind below is MEASURED against this chart on helm
# v4.3.0 and v3.20.2, 2026-09-26, not copied from the parent's table.
#
# SEVEN OF THE EIGHT SURVIVE COALESCING AS A PRESENT NON-MAP, so the parent can
# see them and the parent is the one that names the key.
#
# `yes` IS A BOOL AND NOT A STRING — YAML 1.1, which is what helm parses.
THE_SEVEN_PRESENT_NON_MAPS = (
    ("operators-is-a-bool", "true", "bool"),
    ("operators-is-the-yaml-yes", "yes", "bool"),
    ("operators-is-false", "false", "bool"),
    ("operators-is-zero", "0", "float64"),
    ("operators-is-an-empty-string", '""', "string"),
    ("operators-is-an-empty-list", "[]", "slice"),
    ("operators-is-a-list", "[a]", "slice"),
)

# THE EIGHTH IS NOT LIKE THE OTHER SEVEN, AND THE DIFFERENCE IS THE WHOLE REASON
# THIS CHART CARRIES TWO ARMS. `operators: null` — and a bare `operators:` with
# nothing under it, which is the same YAML — makes helm DELETE the key, without
# putting this chart's own default back. So no template anywhere, in this chart
# or in the parent, can tell it from an adopter who never wrote the key, and
# `kindOf` answers `invalid` for both.
#
# EXCEPT HERE, AND ONLY HERE: `chart/values.yaml` ships `operators.create:
# false`, so an ABSENT key in this chart's merged values can only mean somebody
# deleted it. That is information no other chart holds, which is why this arm
# refuses whether this chart is the root or a subchart.
THE_DELETED_KEY = ("operators-is-null", "null")

# The phrase arm two alone writes, and the phrase arm one alone writes. They are
# DIFFERENT STRINGS on purpose: several tests below assert that exactly one of
# the two fired, and two messages sharing a phrase could not discriminate.
THE_SHAPE_REFUSAL = "rather than a mapping"
THE_DELETED_KEY_REFUSAL = "the operators key has been deleted"

# THE THREE TEXTS A RAISE LEAVES IN STDERR (ADR-0794). A refusal and a raise both
# exit 1, so the exit code alone cannot tell a named key from a stack trace — and
# the refusal's own wording may not contain any of them, or the assertion below
# is satisfied by the very thing it is looking for.
THE_TEXTS_A_RAISE_LEAVES = ("nil pointer", "can't evaluate field", "error calling")

# The throwaway parent's refusal, which stands in for `yadgarhq/chart`'s clause.
# A DIFFERENT STRING FROM THIS CHART'S ON PURPOSE: the assertion that the parent
# won is `THE_PARENT_REFUSAL in stderr and THE_SHAPE_REFUSAL not in stderr`, and
# two messages sharing a phrase could not discriminate.
THE_PARENT_REFUSAL = "THE-PARENT-NAMED-THE-KEY"

# THE THROWAWAY PARENT'S CLAUSE, WRITTEN IN `yadgarhq/chart`'s OWN IDIOM: `hasKey`
# for presence, `kindIs "map"` on the RAW value for shape, `invalid` renamed to
# `null`. It is a STAND-IN and not a copy — what it has to reproduce is that a
# parent refuses these shapes by name, not the parent's exact wording, which
# lives in that repository's own suite.
#
# IT HAS NO ARM FOR AN ABSENT KEY, AND NEITHER DOES `yadgarhq/chart`. That is the
# point rather than an omission: a parent CANNOT refuse an absent
# `platform.operators`, because that is what every adopter who never wrote the
# key has. `test_a_deleted_operators_key_is_refused_wherever_this_chart_runs`
# asserts this double stays shut on that shape, which is what makes this chart's
# unconditional arm one necessary rather than merely defensible.
THE_PARENT_CLAUSE = """{{- $platform := .Values.platform | default dict }}
{{- $shape := "" }}
{{- if hasKey $platform "operators" }}
{{- if not (kindIs "map" $platform.operators) }}
{{- $shape = kindOf $platform.operators }}
{{- if eq $shape "invalid" }}{{ $shape = "null" }}{{ end }}
{{- end }}
{{- end }}
{{- if $shape }}
{{- fail (printf "REFUSAL_MARKER: platform.operators is a %s rather than a mapping" $shape) }}
{{- end }}
"""


def helm(*arguments: str) -> subprocess.CompletedProcess[str]:
    binary = shutil.which("helm")
    # NOT A SKIP, and ADR-0650 is why.
    assert binary, (
        "helm is not on PATH. This suite renders the chart, and so does the "
        "`helm lint and render` pre-commit hook — install helm rather than "
        "letting either report a pass it did not earn."
    )
    return subprocess.run([binary, *arguments], capture_output=True, text=True)


def values_file(destination: Path, body: str) -> Path:
    """One overlay, written as a WHOLE FILE.

    NEVER APPENDED TO ANOTHER FILE, and the reason is a measured incident rather
    than tidiness: an agent building this estate's operator overlays appended
    `operators:` to an existing file and landed it under the preceding block's
    indentation, so every shape read as permitted — including the ones that must
    refuse — and the harness looked green while measuring nothing.
    """
    destination.write_text(body)
    return destination


def render_root(tmp_path: Path, name: str, body: str) -> subprocess.CompletedProcess[str]:
    """Render THIS chart as the root chart, with one whole-file overlay."""
    return helm(
        "template",
        "platform",
        str(CHART),
        "-f",
        str(values_file(tmp_path / f"root-{name}.yaml", body)),
    )


def chart_copy(tmp_path: Path, name: str = "chart") -> Path:
    copy = tmp_path / name
    shutil.copytree(CHART, copy)
    return copy


def build_parent(parent: Path, child: Path) -> Path:
    """A minimal parent chart with `child` unpacked into its `charts/`.

    IT DECLARES THE DEPENDENCY, AND THAT LINE IS LOAD-BEARING RATHER THAN
    CEREMONIAL. Measured 2026-09-26 on helm v4.3.0: a chart sitting in `charts/`
    that the parent's `Chart.yaml` does NOT declare is rendered with EVERY
    `condition:` in its own `Chart.yaml` ignored — helm walks the declared
    dependency tree to resolve conditions, and an undeclared subchart is never
    reached. A parent built without this line rendered NATS with `nats.create`
    false, so it measured nothing about what a toggle does. The first version of
    this harness had that defect.
    """
    (parent / "templates").mkdir(parents=True)
    manifest = yaml.safe_load((child / "Chart.yaml").read_text())
    name, version = manifest["name"], manifest["version"]
    (parent / "Chart.yaml").write_text(
        "apiVersion: v2\n"
        "name: parent\n"
        "version: 0.1.0\n"
        "dependencies:\n"
        f"  - name: {name}\n"
        f"    version: {version}\n"
        '    repository: ""\n'
    )
    (parent / "values.yaml").write_text(f"{name}: {{}}\n")
    shutil.copytree(child, parent / "charts" / name)
    return parent


def parent_around(tmp_path: Path, *, with_refusal: bool) -> Path:
    """A throwaway parent that pins THIS chart as a subchart.

    IT IS BUILT HERE RATHER THAN POINTED AT `yadgarhq/chart`, because a gate in
    this repository may not depend on another repository being checked out beside
    it. What it reproduces is the only property this chart defers to: a parent
    that refuses a non-mapping `platform.operators` by name.

    `with_refusal` FALSE IS THE THIRD-PARTY PARENT — the residual this chart
    documents rather than closes. Both arms are exercised, because "the parent
    wins" is only meaningful beside a measurement of what happens when there is
    no parent refusal to win.
    """
    parent = tmp_path / ("parent-guarded" if with_refusal else "parent-bare")
    build_parent(parent, CHART)
    if with_refusal:
        # The shape of `yadgarhq/chart`'s own clause: `hasKey` for presence,
        # `kindIs "map"` on the RAW value for shape, `invalid` mapped to `null`.
        (parent / "templates" / "validate.yaml").write_text(
            THE_PARENT_CLAUSE.replace("REFUSAL_MARKER", THE_PARENT_REFUSAL)
        )
    return parent


def render_under_parent(
    tmp_path: Path, parent: Path, name: str, scalar: str
) -> subprocess.CompletedProcess[str]:
    return helm(
        "template",
        "yadgar",
        str(parent),
        "-f",
        str(
            values_file(
                tmp_path / f"{parent.name}-{name}.yaml",
                f"platform:\n  operators: {scalar}\n",
            )
        ),
    )


def documents(stdout: str) -> list[dict]:
    return [d for d in yaml.safe_load_all(stdout) if d]


# The three API groups the eighteen vendored CRDs belong to, and they are the
# filter rather than the `# Source:` comment. Splitting the stream on `---` to
# reach that comment is not safe: the upstream schemas carry `---` inside quoted
# descriptions and the split cuts a document in half. The groups discriminate
# cleanly — `operators.create=true` renders 27 CRDs, and the other nine belong to
# cert-manager, Argo CD and Envoy Gateway.
VENDORED_GROUPS = frozenset({"keda.sh", "eventing.keda.sh", "k8s.mariadb.com"})


def vendored_crd_names(stdout: str) -> list[str]:
    """The `metadata.name` of every CRD this chart's OWN vendored templates emit."""
    return sorted(
        document["metadata"]["name"]
        for document in documents(stdout)
        if document.get("kind") == "CustomResourceDefinition"
        and (document.get("spec") or {}).get("group") in VENDORED_GROUPS
    )


# ═══ THE GUARD IS FACTORED ONCE, AND EVERY SITE GOES THROUGH IT ══════════════


def test_every_site_that_reads_operators_goes_through_the_one_helper():
    """Nineteen sites, one expression. READ OFF THE FILES, not off a render.

    A render proves what the guards DO at the values it was given. This proves
    every site carries one AT ALL, so a twentieth site added with an inlined
    `dig` — the shape all nineteen had before this change — is caught the moment
    it is written rather than the first time an adopter mistypes the key.
    """
    assert OPERATORS_PARTIAL.exists(), (
        f"{OPERATORS_PARTIAL} is missing: the guard has nowhere to be factored to"
    )
    assert f'define "{HELPER}"' in OPERATORS_PARTIAL.read_text(), (
        f"{OPERATORS_PARTIAL} does not define `{HELPER}`"
    )

    templates = sorted(p for p in (CHART / "templates").rglob("*.yaml"))
    sites = {
        path: len(HELPER_CALL.findall(path.read_text()))
        for path in templates
        if HELPER_CALL.search(path.read_text())
    }
    total = sum(sites.values())
    assert total == EXPECTED_GUARD_SITES, (
        f"expected {EXPECTED_GUARD_SITES} guard sites through `{HELPER}`, found "
        f"{total} across {sorted(p.name for p in sites)}"
    )

    raw = sorted(
        path.relative_to(CHART).as_posix()
        for path in templates
        # The prose headers of these files quote the read they replaced, so only
        # a line helm EXECUTES counts — a comment naming the old expression is
        # documentation, not a read.
        if any(
            THE_RAW_READ in line and not line.lstrip().startswith(("#",))
            and "{{" in line
            for line in path.read_text().splitlines()
        )
    )
    assert raw == [], (
        f"{raw} still dereference `{THE_RAW_READ}` in an executed line. That is a "
        f"field access on a value of unknown type, which is what raised."
    )
    print(
        f"operators-shape: {total} guard sites through `{HELPER}` across "
        f"{len(sites)} templates"
    )


def test_all_eighteen_vendored_files_name_their_own_operator():
    """Each vendored CRD guards on ITS dependency's key, not on the directory's.

    The per-file guard is ADR-0787's, and this gate is the shape half of
    `test_every_vendored_file_is_guarded_by_its_own_dependency_condition` in
    `test_vendored_crds.py`: that one asserts the guard exists, this one asserts
    it reaches the type-safe helper with the right operator name.
    """
    expected = {"keda-": "keda", "mariadb-": "mariadbOperator"}
    files = sorted(VENDORED.glob("*.yaml"))
    assert len(files) == EXPECTED_VENDORED_FILES, (
        f"{len(files)} vendored files, expected {EXPECTED_VENDORED_FILES}"
    )
    wrong = []
    for path in files:
        prefix = next(p for p in expected if path.name.startswith(p))
        needle = f'include "{HELPER}" (dict "context" $ "operator" "{expected[prefix]}")'
        if needle not in path.read_text():
            wrong.append(path.name)
    assert wrong == [], (
        f"{wrong} do not guard through `{HELPER}` naming their own operator"
    )
    print(f"operators-shape: {len(files)} vendored files read their own operator key")


# ═══ THE ROOT CHART REFUSES ALL EIGHT SHAPES BY NAME ═════════════════════════


def test_the_root_chart_refuses_every_non_mapping_shape_by_name(tmp_path):
    """Eight shapes, eight refusals, each naming the type the adopter wrote.

    ASSERTED ON THE ABSENCE OF A RAISE, not on the exit code. A refusal and a
    raise both exit 1, so an implementation that went back to raising satisfies
    `returncode != 0` while handing the adopter a stack trace.

    THE TYPE NAME IS ASSERTED PER ROW. `"rather than a mapping" in stderr` is
    satisfied by an implementation that calls every shape a bool, and the whole
    point of `kindOf` here is that the adopter is told what they wrote.
    """
    for name, scalar, kind in THE_SEVEN_PRESENT_NON_MAPS:
        result = render_root(tmp_path, name, f"operators: {scalar}\n")
        assert result.returncode != 0, (
            f"`{name}` rendered exit 0. helm leaves every operator dependency "
            f"ENABLED when no path of its `condition:` resolves, so this is five "
            f"operators installed out of a key nothing can read.\n{result.stdout[:2000]}"
        )
        assert f"operators is a {kind} rather than a mapping" in result.stderr, (
            f"`{name}` refused without naming the type the adopter wrote: "
            f"{result.stderr}"
        )
        assert THE_DELETED_KEY_REFUSAL not in result.stderr, (
            f"`{name}` tripped the DELETED-KEY arm, which is the wrong diagnosis "
            f"for a key that is present: {result.stderr}"
        )
        for raise_text in THE_TEXTS_A_RAISE_LEAVES:
            assert raise_text not in result.stderr, (
                f"`{name}` RAISED instead of refusing: {result.stderr}"
            )
    print(
        f"operators-shape: {len(THE_SEVEN_PRESENT_NON_MAPS)} present non-map shapes "
        f"refused at the root"
    )


def test_the_root_refusal_is_reachable_at_the_chart_defaults(tmp_path):
    """And is SILENT there — the half a refusal this loud has to prove.

    `operators` is a mapping in `chart/values.yaml`, so the defaults render. A
    refusal that fired at the defaults would refuse every offline render in the
    estate, `helm lint` included.
    """
    result = helm("template", "platform", str(CHART))
    assert result.returncode == 0, result.stderr
    assert THE_SHAPE_REFUSAL not in result.stderr


# ═══ UNDER A PARENT, THE PARENT NAMES THE KEY ════════════════════════════════


def test_the_parent_is_the_one_that_names_the_key(tmp_path):
    """The property `yadgarhq/chart`'s own suite depends on, measured HERE.

    helm executes the deepest template path first, so if this chart refused as a
    subchart its message would be the one the adopter saw and the parent's clause
    would be unreachable. Both halves are asserted: the parent's phrase is
    present AND this chart's is absent. Asserting only the first would pass
    against a chart that refused too, since a refusal aborts before the parent
    runs and the parent's phrase would then be missing — which is why the
    positive assertion comes first and would fail loudly.
    """
    parent = parent_around(tmp_path, with_refusal=True)
    for name, scalar, kind in THE_SEVEN_PRESENT_NON_MAPS:
        result = render_under_parent(tmp_path, parent, name, scalar)
        assert result.returncode != 0, f"`{name}` was not refused: {result.stdout[:2000]}"
        assert THE_PARENT_REFUSAL in result.stderr, (
            f"`{name}`: the parent's refusal did not reach the adopter. This "
            f"chart shadowed it.\n{result.stderr}"
        )
        assert f"platform.operators is a {kind} rather than a mapping" in result.stderr
        assert THE_SHAPE_REFUSAL not in result.stderr.replace(
            f"platform.operators is a {kind} rather than a mapping", ""
        ), f"`{name}`: this chart refused as well as the parent: {result.stderr}"
        for raise_text in THE_TEXTS_A_RAISE_LEAVES:
            assert raise_text not in result.stderr, (
                f"`{name}` RAISED inside the subchart: {result.stderr}"
            )
    print(
        f"operators-shape: {len(THE_SEVEN_PRESENT_NON_MAPS)} present non-map shapes "
        f"deferred to the parent's refusal"
    )


def test_a_deleted_operators_key_is_refused_wherever_this_chart_runs(tmp_path):
    """ARM ONE, AND THE ONE SHAPE THE PARENT STRUCTURALLY CANNOT SEE.

    `operators: null` makes helm delete the key WITHOUT restoring this chart's
    default, so every template everywhere measures `hasKey` FALSE — the parent
    included, where it is then indistinguishable from the adopter who never wrote
    the key, which is every other adopter. Measured 2026-09-26 on helm v4.3.0
    against `yadgarhq/chart` with `platform.enabled: true`:

        platform.operators omitted          ->  32 objects,   0 from the operator subcharts
        platform.operators {create: false}  ->  32 objects,   0 from the operator subcharts
        platform.operators null             -> 197 objects, 165 from the operator
                                               subcharts, 0 vendored CRDs, EXIT 0
        platform.operators {create: true}   -> exit 1, the parent refuses the path

    The third row is the hazard: helm resolves each dependency's `condition:`
    against the RAW user values, where the key is null, so all five operators go
    in — and the CRDs this chart vendored for them do not. That row is why this
    arm refuses as a subchart too, which is the one place this chart does not
    defer to the parent.
    """
    name, scalar = THE_DELETED_KEY
    parent = parent_around(tmp_path, with_refusal=True)
    cases = (
        ("as the root chart", render_root(tmp_path, name, f"operators: {scalar}\n")),
        (
            "as a subchart",
            render_under_parent(tmp_path, parent, name, scalar),
        ),
    )
    for label, result in cases:
        assert result.returncode != 0, (
            f"{label}: `operators: {scalar}` rendered exit 0, which is the "
            f"165-object fail-open.\n{result.stdout[:2000]}"
        )
        assert THE_DELETED_KEY_REFUSAL in result.stderr, (
            f"{label}: refused without naming the deleted key: {result.stderr}"
        )
        assert THE_SHAPE_REFUSAL not in result.stderr, (
            f"{label}: the PRESENT-non-map arm fired for an absent key, which is "
            f"the wrong diagnosis: {result.stderr}"
        )
        for raise_text in THE_TEXTS_A_RAISE_LEAVES:
            assert raise_text not in result.stderr, (
                f"{label} RAISED instead of refusing: {result.stderr}"
            )
    # AND THE PARENT DOES NOT GET A LOOK IN, because it cannot: its own clause
    # measures `hasKey` false and stays shut. Asserted so nobody "simplifies"
    # this arm into arm two's root-only branch.
    assert THE_PARENT_REFUSAL not in cases[1][1].stderr, (
        "the throwaway parent refused a deleted key, so this arm is not the only "
        "thing that can see it and its unconditional reach needs re-arguing: "
        f"{cases[1][1].stderr}"
    )
    print("operators-shape: the deleted key is refused as root AND as a subchart")


def test_a_parent_with_no_refusal_is_the_residual_this_chart_documents(tmp_path):
    """THE HOLE, MEASURED RATHER THAN ASSERTED AWAY.

    A third-party parent carrying no refusal of its own gets the silent
    fail-open: helm leaves every operator dependency enabled, this chart's own
    vendored CRDs skip, and nothing says so. This is not a gate on desired
    behaviour — it is the measurement that keeps the residual honest, and it
    reddens if a future change closes it, at which point delete this test and
    the paragraph in the module docstring together.
    """
    parent = parent_around(tmp_path, with_refusal=False)
    result = render_under_parent(tmp_path, parent, "bool-true", "true")
    assert result.returncode == 0, result.stderr
    for raise_text in THE_TEXTS_A_RAISE_LEAVES:
        assert raise_text not in result.stderr, result.stderr
    assert vendored_crd_names(result.stdout) == [], (
        "the vendored CRDs rendered under an unusable `operators`, so the helper "
        "is not skipping"
    )
    rendered = len(documents(result.stdout))
    assert rendered > 0, (
        "nothing rendered at all, so this case no longer measures the fail-open "
        "it exists to record"
    )
    print(
        f"operators-shape: a bare parent renders {rendered} objects and 0 vendored "
        f"CRDs — the documented residual"
    )


# ═══ THE GREEN SIDE: THE GUARD CHANGED NO USABLE VALUE ═══════════════════════


def test_the_helper_resolves_exactly_what_the_dependency_condition_resolves(tmp_path):
    """The register key, the sub-key, and the sub-key beating a false register.

    This is helm's own `condition: operators.<op>.create,operators.create`
    semantics, and the guard may not have moved it. Read off the RENDER, since
    what is being asserted is behaviour rather than the presence of a line.
    """
    rows = (
        ("operators:\n  create: true\n", 18, "the register key alone"),
        ("operators:\n  create: false\n", 0, "the register key false"),
        (
            "operators:\n  create: false\n  keda:\n    create: true\n",
            6,
            "a sub-key beating a false register key",
        ),
        (
            "operators:\n  create: true\n  keda:\n    create: false\n",
            12,
            "a sub-key beating a true register key",
        ),
    )
    for body, expected, label in rows:
        result = render_root(tmp_path, label.replace(" ", "-"), body)
        assert result.returncode == 0, f"{label}: {result.stderr}"
        names = vendored_crd_names(result.stdout)
        assert len(names) == expected, (
            f"{label} rendered {len(names)} vendored CRDs, expected {expected}: {names}"
        )
    print("operators-shape: 4 usable shapes resolve exactly as helm's condition does")


# ═══ THE CONSTRUCTED RED CASES ═══════════════════════════════════════════════


def test_unguarding_the_helper_brings_the_raise_back(tmp_path):
    """RED CASE 1 — the type arm inside the helper is what stops the stack trace.

    Rewrite the helper into the expression all nineteen sites carried before,
    and the render must RAISE again. Without this, `test_the_root_chart_refuses_
    every_non_mapping_shape_by_name` could be passing on the refusal alone while
    the helper guarded nothing, and the eighteen vendored files under a PARENT —
    where no refusal fires — would still raise.
    """
    copy = chart_copy(tmp_path, "unguarded")
    partial = copy / "templates" / "_operators.tpl"
    original = partial.read_text()
    start = original.index('{{- define "platform.operator-create" -}}')
    unguarded = (
        original[:start]
        + '{{- define "platform.operator-create" -}}\n'
        + '{{- $operators := .context.Values.operators -}}\n'
        + '{{- if (dig .operator "create" $operators.create $operators) -}}on{{- end -}}\n'
        + "{{- end -}}\n"
    )
    partial.write_text(unguarded)
    assert partial.read_text() != original

    # A PARENT, not the root: the root's own refusal would abort first and this
    # case would be green for the refusal's reason rather than the helper's.
    parent = build_parent(tmp_path / "parent-unguarded", copy)

    result = render_under_parent(tmp_path, parent, "unguarded", "true")
    assert result.returncode != 0, (
        "the unguarded helper rendered exit 0, so this case proves nothing"
    )
    assert any(text in result.stderr for text in THE_TEXTS_A_RAISE_LEAVES), (
        f"the unguarded helper did not RAISE, so the type arm is not what stops "
        f"the stack trace: {result.stderr}"
    )
    print("operators-shape: red case 1 — unguarding the helper restores the raise")


def test_deleting_the_root_refusal_lets_the_fail_open_through(tmp_path):
    """RED CASE 2 — the refusal is what stops five operators installing silently.

    With the helper still guarding and the refusal removed, `operators: true`
    renders at exit 0: helm leaves every dependency enabled because no path of
    its `condition:` resolves, and the vendored CRDs skip. That is the state the
    refusal exists to prevent, and this is the measurement of it.
    """
    copy = chart_copy(tmp_path, "no-refusal")
    template = copy / "templates" / "render-checks.yaml"
    original = template.read_text()
    # ARM TWO ONLY. Arm one stays, so this case measures what the PRESENT
    # non-map refusal buys and nothing else.
    pivot = '{{- else if not (contains "/charts/" .Template.BasePath) }}'
    closing = "{{- end }}{{/* end of the two operators-shape arms */}}\n"
    assert pivot in original, (
        f"arm two no longer opens with {pivot!r}, so this mutation would cut at "
        f"the wrong place"
    )
    assert closing in original, f"the arms no longer close with {closing!r}"
    head, rest = original.split(pivot, 1)
    _, tail = rest.split(closing, 1)
    template.write_text(head + "{{- end }}\n" + tail)
    assert template.read_text() != original

    result = helm(
        "template",
        "platform",
        str(copy),
        "-f",
        str(values_file(tmp_path / "no-refusal.yaml", "operators: true\n")),
    )
    assert result.returncode == 0, (
        f"the chart without its refusal still refused, so this case does not "
        f"measure what the refusal buys: {result.stderr}"
    )
    assert vendored_crd_names(result.stdout) == [], result.stdout[:500]
    # AND THE HARM ITSELF: the operators went in anyway. `Deployment/keda-operator`
    # is the discriminator — it comes from the dependency chart helm left enabled.
    deployments = [
        (d.get("metadata") or {}).get("name")
        for d in documents(result.stdout)
        if d.get("kind") == "Deployment"
    ]
    assert any(name and "keda" in name for name in deployments), (
        f"no KEDA deployment rendered, so the fail-open this case records did not "
        f"happen: {sorted(n for n in deployments if n)}"
    )
    print(
        "operators-shape: red case 2 — without the refusal, `operators: true` "
        "installs KEDA with 0 of its CRDs at exit 0"
    )


def test_deleting_arm_one_lets_the_165_object_fail_open_through(tmp_path):
    """RED CASE 4 — the measurement that makes arm one's reach necessary.

    Cut arm one out and render `operators: null` under a parent that carries the
    `yadgarhq/chart` clause. Nothing refuses: helm resolved every dependency's
    `condition:` against the raw user values before the key was deleted, so the
    five operator subcharts render, and the CRDs this chart vendored for them do
    not. A KEDA install with none of its own CustomResourceDefinitions, exit 0.
    """
    copy = chart_copy(tmp_path, "no-arm-one")
    template = copy / "templates" / "render-checks.yaml"
    original = template.read_text()
    opening = '{{- if not (hasKey .Values "operators") }}'
    pivot = '{{- else if not (contains "/charts/" .Template.BasePath) }}'
    assert opening in original and pivot in original, (
        "arm one no longer opens and pivots where this mutation cuts"
    )
    head, rest = original.split(opening, 1)
    _, tail = rest.split(pivot, 1)
    # Re-open arm two on its own, so ONLY arm one is removed.
    template.write_text(
        head + '{{- if not (contains "/charts/" .Template.BasePath) }}' + tail
    )
    assert template.read_text() != original

    parent = build_parent(tmp_path / "parent-no-arm-one", copy)
    (parent / "templates" / "validate.yaml").write_text(
        THE_PARENT_CLAUSE.replace("REFUSAL_MARKER", THE_PARENT_REFUSAL)
    )
    result = render_under_parent(tmp_path, parent, "no-arm-one", "null")

    assert result.returncode == 0, (
        f"something still refused, so this case does not measure the fail-open "
        f"arm one prevents: {result.stderr}"
    )
    assert THE_PARENT_REFUSAL not in result.stderr
    assert vendored_crd_names(result.stdout) == [], (
        "the vendored CRDs rendered, so the harm this case records is not the "
        "one described"
    )
    operators_in = [
        (document.get("metadata") or {}).get("name")
        for document in documents(result.stdout)
        if document.get("kind") == "Deployment"
    ]
    assert any(name and "keda" in name for name in operators_in), (
        f"KEDA did not render, so the fail-open did not happen and arm one is "
        f"guarding nothing: {sorted(n for n in operators_in if n)}"
    )
    print(
        f"operators-shape: red case 4 — without arm one, a deleted key renders "
        f"{len(documents(result.stdout))} objects and 0 vendored CRDs at exit 0"
    )


def test_refusing_from_the_subchart_would_shadow_the_parent(tmp_path):
    """RED CASE 3 — the root-only arm is load-bearing, not decoration.

    Drop the `.Template.BasePath` test and this chart refuses everywhere. The
    parent's named refusal then never reaches the adopter, which is the defect
    this whole change exists to remove — arriving from the other direction.
    """
    copy = chart_copy(tmp_path, "always-refuses")
    template = copy / "templates" / "render-checks.yaml"
    original = template.read_text()
    pivot = '{{- else if not (contains "/charts/" .Template.BasePath) }}'
    assert pivot in original, f"arm two no longer opens with {pivot!r}"
    template.write_text(original.replace(pivot, "{{- else if true }}"))
    assert template.read_text() != original

    parent = build_parent(tmp_path / "parent-shadowed", copy)
    (parent / "templates" / "validate.yaml").write_text(
        THE_PARENT_CLAUSE.replace("REFUSAL_MARKER", THE_PARENT_REFUSAL)
    )

    result = render_under_parent(tmp_path, parent, "shadowed", "true")
    assert result.returncode != 0
    assert THE_SHAPE_REFUSAL in result.stderr, result.stderr
    assert THE_PARENT_REFUSAL not in result.stderr, (
        "the parent's refusal reached the adopter even with the subchart refusing, "
        "so the root-only arm guards nothing and this case proves nothing"
    )
    print(
        "operators-shape: red case 3 — a subchart that refuses shadows the parent's "
        "message"
    )
