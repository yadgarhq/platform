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
CHART_MANIFEST = CHART / "Chart.yaml"
CHART_VALUES = CHART / "values.yaml"
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

# Every site that reads the key, counted. Eighteen vendored CRDs, the one `range`
# in `render-checks.yaml`, and the bundled Prometheus's Namespace (ADR-0820). A
# LITERAL, for the reason every expected count in this estate is a literal.
EXPECTED_GUARD_SITES = 20
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

# ── THE REGISTER KEYS, ONE LEVEL DOWN, AND THE HOLE THE EIGHT SHAPES LEFT ────
# THE EIGHT SHAPES ABOVE ARE ALL SHAPES OF THE BLOCK. Not one of them is a shape
# of the key helm's `condition:` actually reads, and the two arms that refuse
# them stopped exactly one level too high. `operators` written as a MAPPING whose
# `create` is unusable walked straight through both.
#
# THE RULE THIS FILE NOW ENFORCES, AND IT IS WIDER THAN THE ONE THE TWO ARMS
# WERE WRITTEN FOR. A key that ANY dependency `condition:` reads, and that some
# chart in the tree DECLARES, must arrive at template time as a BOOL. Neither
# half of that is optional and neither half is the other:
#
#   - `hasKey` alone is not enough. `operators: {create: {}}` is a PRESENT key
#     and installs all five operators at exit 0 with no warning at all.
#   - `kindIs "bool"` alone cannot word the message. A deleted key and a `null`
#     both answer `invalid`, and the adopter needs different advice.
#
# PATH COUNT IS IRRELEVANT, which is where the rule ADR-0794 was written under
# is too narrow. That ADR reasons about the MULTI-path `condition:` the five
# operators carry. `nats` carries a SINGLE-path `condition: nats.create` and
# fails open in the same direction for the same reason: helm leaves a dependency
# ENABLED when the path its condition names does not resolve, and it does not
# care how many paths were on offer.
#
# MEASURED 2026-09-26 against `chart/` as the ROOT chart, on helm v3.20.2 and
# v4.3.0 alike, both lines identical. Objects from the five operator subcharts,
# against a baseline of 0:
#
#   operators.create: false   ->     0 subchart objects, 0 vendored CRDs   (the default)
#   operators.create: true    ->   165 subchart objects, 18 vendored CRDs  (asked for)
#   operators.create: <null>  ->   165 subchart objects,  0 vendored CRDs  no warning
#   operators.create: {}      ->   165 subchart objects,  0 vendored CRDs  no warning
#   operators.create: 0       ->   165 subchart objects,  0 vendored CRDs  warns
#   operators.create: ""      ->   165 subchart objects,  0 vendored CRDs  warns
#   operators.create: []      ->   165 subchart objects,  0 vendored CRDs  warns
#   operators.create: "yes"   ->   165 subchart objects, 18 vendored CRDs  warns
#   operators.create: "no"    ->   165 subchart objects, 18 vendored CRDs  warns
#   operators.create: 1       ->   165 subchart objects, 18 vendored CRDs  warns
#
# `"no"` INSTALLS ALL FIVE, and that row alone settles the argument. Every shape
# but the two bools installs cert-manager, KEDA, argo-cd, Envoy Gateway and
# mariadb-operator CLUSTER-WIDE; the truthy ones at least bring the vendored
# CRDs, and the falsy ones leave KEDA and mariadb without theirs. ADR-0787
# defaults the toggle false because a second cert-manager "can break the existing
# tenant's certificate issuance".
#
# TWO OF THE TEN ARE NOT EVEN WARNED ABOUT. helm emits `Condition path
# 'operators.create' ... returned non-bool value` for a scalar it cannot read,
# and NOTHING for a deleted key or for `{}`. So the loudest signal available to
# an adopter is absent in exactly the two rows they are most likely to write.
#
# EACH ROW: (name, what is written under `operators:`, the kind reported).
THE_REGISTER_KEY_IS_NOT_A_BOOL = (
    ("operators-create-is-the-yaml-yes-string", '"yes"', "string"),
    ("operators-create-is-the-yaml-no-string", '"no"', "string"),
    ("operators-create-is-zero", "0", "float64"),
    ("operators-create-is-one", "1", "float64"),
    ("operators-create-is-an-empty-string", '""', "string"),
    ("operators-create-is-an-empty-list", "[]", "slice"),
    ("operators-create-is-an-empty-map", "{}", "map"),
)

# THE ELEVENTH SHAPE, AND IT IS THE ONE THAT NEEDS ITS OWN WORDING. `create:`
# with nothing after it deletes the key — `hasKey` FALSE — where every row above
# leaves it present and unusable.
THE_DELETED_REGISTER_KEY = ("operators-create-is-null", "")

# ── THE SAME CLASS ON THE BROKER, WHICH CARRIES A SINGLE-PATH CONDITION ──────
# `nats` IS THE FOURTH MEMBER, and finding it is what widened the rule above.
# Measured the same day, the same two helm lines, against `chart/` as the root.
# Documents from the `nats` subchart, against a baseline of 0:
#
#   nats.create: false   -> 0 subchart docs                       (the default)
#   nats.create: true    -> 5 subchart docs + the NetworkPolicy   (asked for)
#   nats.create: <null>  -> 5 subchart docs, NO NetworkPolicy     warns
#   nats.create: "yes"   -> 5 subchart docs, NO NetworkPolicy     warns
#   nats.create: 0       -> 5 subchart docs, NO NetworkPolicy     warns
#   nats.create: {}      -> 5 subchart docs, NO NetworkPolicy     no warning
#   nats: <null>         -> 8 subchart docs, NO NetworkPolICY     no warning
#
# THE LAST ROW IS THE WORST OF THEM AND IT IS THE QUIETEST. `nats:` with nothing
# under it deletes the WHOLE block, so the broker renders on the UPSTREAM chart's
# own defaults — eight documents rather than five, because none of this chart's
# settings survived: no authorization users, `natsBox` back on. A broker with no
# accounts, no NetworkPolicy, and no warning.
#
# A PRESENT NON-MAP `nats` NEEDS NO ARM HERE, AND THAT IS MEASURED RATHER THAN
# ASSUMED: `nats: true` and `nats: []` are refused by HELM ITSELF, `type mismatch
# on nats`, before any template runs. The `operators` block has no subchart of
# its own to be coalesced against, which is why it gets no such protection and
# needs arms one and two.
THE_BROKER_REGISTER_IS_NOT_A_BOOL = (
    ("nats-create-is-null", "nats:\n  create:\n", "invalid"),
    ("nats-create-is-the-yaml-yes-string", 'nats:\n  create: "yes"\n', "string"),
    ("nats-create-is-zero", "nats:\n  create: 0\n", "float64"),
    ("nats-create-is-an-empty-map", "nats:\n  create: {}\n", "map"),
)
THE_DELETED_BROKER_BLOCK = ("nats-is-null", "nats:\n")

# The phrases the two register-key refusals write. DIFFERENT FROM EACH OTHER AND
# FROM BOTH ARMS ABOVE, for the reason `THE_SHAPE_REFUSAL` and
# `THE_DELETED_KEY_REFUSAL` are different from each other: the assertions below
# say which one of the four fired, and a shared phrase could not discriminate.
# `THE_DELETED_KEY_REFUSAL` is `the operators key has been deleted`, which is NOT
# a substring of `operators.create has been deleted` — checked rather than
# assumed, by `test_no_two_refusal_phrases_are_substrings_of_one_another`.
THE_REGISTER_KEY_REFUSAL = "rather than true or false"
THE_DELETED_OPERATORS_REGISTER_REFUSAL = "operators.create has been deleted"
THE_DELETED_BROKER_REGISTER_REFUSAL = "nats.create has been deleted"

# WHERE THE TWO REGISTER ARMS OPEN AND CLOSE, so the red cases below can cut
# exactly one of them out. LITERALS, asserted present before each mutation runs:
# a mutation that silently matched nothing would leave the chart intact and the
# red case would pass for the guard's reason rather than its own.
#
# THEY ARE THEIR OWN BLOCKS RATHER THAN A THIRD BRANCH OF THE `if/else if` ABOVE,
# and that is placement rather than taste. `test_deleting_arm_one_...` cuts
# between arm one's opening and arm two's pivot; a register arm wedged between
# them would be removed by that mutation too, and its stated reason — "cut arm
# one out" — would stop being true.
REGISTER_ARM_OPENS = '{{- if kindIs "map" .Values.operators }}'
REGISTER_ARM_CLOSES = "{{- end }}{{/* end of the operators register-key arm */}}\n"
BROKER_ARM_OPENS = '{{- if kindIs "map" .Values.nats }}'
BROKER_ARM_CLOSES = "{{- end }}{{/* end of the nats register-key arm */}}\n"
# The root-only pivot each register arm carries, which RED CASE 7 switches off.
# THE SAME LINE ARM TWO USES, deliberately: one idiom for one question, so a
# reader does not have to check whether two spellings mean the same thing.
THE_ROOT_ONLY_PIVOT = '{{- else if not (contains "/charts/" .Template.BasePath) }}'

# ── THE PER-OPERATOR SUB-KEY, RESOLVED THE WAY HELM RESOLVES IT (ledger 1252) ──
# Each operator is declared `condition: operators.<op>.create,operators.create`.
# helm reads each path in turn and USES THE FIRST ONE THAT HOLDS A BOOL: a path
# that is absent, null, or any other kind is skipped with at most a warning, and
# the register key decides. The helper used to read the sub-key by truthiness
# through `dig`, so it disagreed with helm in both directions. MEASURED on helm
# v4.3.0, 2026-10-03, with this chart as the root, before the fix:
#
#   create: false, keda: {create: "false"}  -> EXIT 0, 6 vendored KEDA CRDs,
#                                              0 documents from KEDA's chart
#   create: true,  keda: {create: "false"}  -> EXIT 0, KEDA installed, and the
#                                              mixed refusal named the sub-key
#   create: false, keda:                    -> RAISE inside the helper
#   create: false, keda: true               -> RAISE inside the helper
#
# The first row is CRDs for an operator that is not there; ADR-0794's class one
# level down. So a present non-bool sub-key is REFUSED BY NAME at the root, and
# under a parent the helper resolves it exactly as helm does and stays quiet.
THE_SUB_KEY_REFUSAL = "so helm skips it and operators.create decides"
# EACH ROW: (name, the `operators:` block, the operator, the kind reported).
# `create: null` IS PRESENT HERE, unlike the register key's: `values.yaml`
# declares no per-operator sub-key, so helm does not delete a null written there,
# and `kindOf` answers `invalid`, which the refusal prints as `null`.
THE_SUB_KEY_IS_NOT_A_BOOL = (
    (
        "keda-create-is-the-string-false",
        'operators:\n  create: false\n  keda:\n    create: "false"\n',
        "keda",
        "string",
    ),
    (
        "keda-create-is-the-string-false-under-a-true-register",
        'operators:\n  create: true\n  keda:\n    create: "false"\n',
        "keda",
        "string",
    ),
    ("keda-create-is-zero", "operators:\n  create: false\n  keda:\n    create: 0\n", "keda", "float64"),
    ("keda-create-is-an-empty-map", "operators:\n  create: false\n  keda:\n    create: {}\n", "keda", "map"),
    ("keda-create-is-null", "operators:\n  create: false\n  keda:\n    create:\n", "keda", "null"),
    (
        "cert-manager-create-is-the-string-yes",
        'operators:\n  create: false\n  certManager:\n    create: "yes"\n',
        "certManager",
        "string",
    ),
)
# Sub-blocks helm's condition CANNOT read a `create` out of, and so skips: the
# register key decides. Each is rendered with the register key false and true.
#
# `keda-is-a-map-with-no-create` ("  keda:\n    foo: x\n") MOVED OUT (ledger
# 990): `chart/values.schema.json` now closes `operators.keda` to exactly
# `{create}`, so a map under it carrying any other key — "foo" included — is
# a SCHEMA refusal naming that key, before this helper's own fallback logic
# ever runs. `test_a_map_with_an_unknown_sub_key_is_a_schema_refusal` below
# is that row's new home.
THE_SUB_BLOCKS_THE_CONDITION_SKIPS = (
    ("keda-is-null", "  keda:\n"),
    ("keda-is-a-bool", "  keda: true\n"),
    ("keda-is-a-string", '  keda: "on"\n'),
)
# WHERE THE SUB-KEY ARM OPENS AND CLOSES, for its red case. The opener is NOT
# `REGISTER_ARM_OPENS`, and it carries no `else if` pivot, so the cuts the red
# cases above make cannot reach it by accident.
SUB_KEY_ARM_OPENS = (
    '{{- if and (kindIs "map" .Values.operators) '
    '(not (contains "/charts/" .Template.BasePath)) }}'
)
SUB_KEY_ARM_CLOSES = "{{- end }}{{/* end of the per-operator create arm */}}\n"
# The helper as it stood before ledger 1252, for the red case that reverts it.
THE_DIG_HELPER = """{{- define "platform.operator-create" -}}
{{- $operators := .context.Values.operators -}}
{{- if kindIs "map" $operators -}}
{{- if (dig .operator "create" $operators.create $operators) -}}
{{- if hasKey $operators .operator -}}
operators.{{ .operator }}.create
{{- else -}}
operators.create
{{- end -}}
{{- end -}}
{{- end -}}
{{- end -}}"""

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
#
# IT DOES CARRY A `create`-SHAPE ARM, BECAUSE `yadgarhq/chart` CARRIES ONE.
# Measured against that parent at 5d23f59 with `platform` 0.1.11 — the parent
# standing alone, before the register arms existed — every PRESENT non-bool
# `platform.operators.create` and `platform.nats.create` is refused there, by a
# message naming the key and `rather than a boolean`. That is the contract the
# register arms' present-non-bool branch defers to, so the stand-in has to
# reproduce it or the deferral would be tested against a parent that refuses
# nothing. IT STILL HAS NO ARM FOR A DELETED `create`, and neither does
# `yadgarhq/chart`: that parent ranges over the `create` toggles it can FIND, and
# a deleted key is not one. The three EXIT 0 rows in `render-checks.yaml`'s prose
# are that hole measured.
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
{{- range $block := (list "operators" "nats") }}
{{- $values := index $platform $block }}
{{- if kindIs "map" $values }}
{{- if hasKey $values "create" }}
{{- if not (kindIs "bool" $values.create) }}
{{- fail (printf "REFUSAL_MARKER: platform.%s.create is a %s rather than a boolean" $block (kindOf $values.create)) }}
{{- end }}
{{- end }}
{{- end }}
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


def render_under_parent_body(
    tmp_path: Path, parent: Path, name: str, body: str
) -> subprocess.CompletedProcess[str]:
    """`render_under_parent` for a body deeper than one scalar.

    The register-key shapes are two levels down — `platform.operators.create` —
    so they cannot be written as the `operators: <scalar>` that function builds.
    The body is INDENTED WHOLE rather than interpolated line by line, because an
    overlay that lands under the wrong parent key measures nothing and looks
    green, which is the incident `values_file` above records.
    """
    indented = "".join(f"  {line}\n" for line in body.splitlines())
    return helm(
        "template",
        "yadgar",
        str(parent),
        "-f",
        str(values_file(tmp_path / f"{parent.name}-{name}.yaml", f"platform:\n{indented}")),
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


def keda_crds(stdout: str) -> int:
    """How many of the six vendored KEDA CRDs rendered."""
    return sum(1 for name in vendored_crd_names(stdout) if "keda.sh" in name)


def keda_documents(stdout: str) -> int:
    """How many documents came from KEDA's own subchart, by `# Source:`.

    The vendored CRDs live under `platform/templates/vendored-crds/`, so they are
    NOT counted here. The two numbers must agree on zero-or-not: CRDs without the
    operator, or the operator without its CRDs, is the defect ledger 1252 names.
    """
    return sum(
        1
        for line in stdout.splitlines()
        if line.startswith("# Source: ") and "platform/charts/keda/" in line
    )


def assert_crds_follow_the_operator(label: str, stdout: str, installed: bool) -> None:
    crds, operator = keda_crds(stdout), keda_documents(stdout)
    if installed:
        assert crds == 6 and operator > 0, (
            f"{label}: helm installs KEDA here, so its 6 vendored CRDs must render "
            f"beside it; got {crds} CRDs and {operator} KEDA documents"
        )
    else:
        assert crds == 0 and operator == 0, (
            f"{label}: helm leaves KEDA out here, so none of its vendored CRDs may "
            f"render; got {crds} CRDs and {operator} KEDA documents"
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


# THE TWO RANGES A THIRD-PARTY PARENT IS STILL EXPOSED TO, one row each. BOTH are
# needed: arm two and the register arms stand down as a subchart for the same
# reason and the residual is now the union of the two, so a test carrying only the
# older row would go on reporting a pass while the newer half widened underneath
# it. `create: "yes"` is the register row rather than `create: {}` because it is
# the truthy one — the vendored CRDs DO render for it, which is a different
# rendered state from arm two's and worth measuring as such.
THE_RESIDUAL_ROWS = (
    ("arm two — a present non-map block", "operators: true\n", 0),
    ("the register arm — a present non-bool create", 'operators:\n  create: "yes"\n', 18),
)


def test_a_parent_with_no_refusal_is_the_residual_this_chart_documents(tmp_path):
    """THE HOLE, MEASURED RATHER THAN ASSERTED AWAY.

    A third-party parent carrying no refusal of its own gets the silent
    fail-open: helm leaves every operator dependency enabled and nothing says so.
    This is not a gate on desired behaviour — it is the measurement that keeps the
    residual honest, and it reddens if a future change closes it, at which point
    delete this test and the paragraphs in `render-checks.yaml` together.

    ONE ROW PER RANGE THAT STANDS DOWN AS A SUBCHART, and the vendored-CRD count
    differs between them, which is the point of carrying both. Arm two's shapes
    make the whole block unreadable, so the helper skips and NO vendored CRD
    renders. The register arm's non-bool shapes, falsy ones included since
    ledger 1291, leave the block readable, so all eighteen render — beside
    five operators the adopter did not ask for.
    """
    parent = parent_around(tmp_path, with_refusal=False)
    for label, body, expected_crds in THE_RESIDUAL_ROWS:
        result = render_under_parent_body(
            tmp_path, parent, label.replace(" ", "-").replace("—", "-"), body
        )
        assert result.returncode == 0, f"{label}: {result.stderr}"
        for raise_text in THE_TEXTS_A_RAISE_LEAVES:
            assert raise_text not in result.stderr, f"{label}: {result.stderr}"
        names = vendored_crd_names(result.stdout)
        assert len(names) == expected_crds, (
            f"{label} rendered {len(names)} vendored CRDs, expected {expected_crds}: "
            f"{names}"
        )
        rendered = len(documents(result.stdout))
        assert rendered > 0, (
            f"{label} rendered nothing at all, so this case no longer measures the "
            f"fail-open it exists to record"
        )
        arrived = subchart_documents(result.stdout)
        assert arrived > 100, (
            f"{label} rendered {arrived} documents from the operator subcharts, so "
            f"the fail-open this case records did not happen"
        )
        print(
            f"operators-shape: a bare parent renders {rendered} objects, "
            f"{len(names)} vendored CRDs and {arrived} subchart documents for "
            f"{label} — the documented residual"
        )

    # THE TOGGLE RANGE DOES NOT STAND DOWN, and this row is what holds it (ledger
    # 1121 review). A truthy non-bool `create` on an estate toggle is refused by
    # name only at the root; under a parent it is still COUNTED as on, the way the
    # object templates read it, so the mixed release stays refused. Measured
    # before this row existed: `certificates.create: "false"` beside
    # `operators.create: true` under this bare parent, with the cert-manager group
    # passed, rendered at exit 0 with the Certificates and the operators' CRDs in
    # one release. The group is passed so the capability check cannot be the
    # refusal that arrives.
    for toggle in ("certificates", "valkey"):
        overlay = values_file(
            tmp_path / f"toggle-{toggle}.yaml",
            f'platform:\n  operators:\n    create: true\n  {toggle}:\n    create: "false"\n',
        )
        result = helm(
            "template", "yadgar", str(parent), "-f", str(overlay),
            "--api-versions", "cert-manager.io/v1",
        )
        assert result.returncode != 0, (
            f'{toggle}.create: "false" beside the operators rendered under a bare parent '
            f"— the mixed release this chart refuses at the root went through"
        )
        assert f"{toggle}.create asked for the objects" in result.stderr, result.stderr


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


# ═══ THE PER-OPERATOR SUB-KEY, ONE LEVEL BELOW THE REGISTER KEY (ledger 1252) ═


def test_a_non_bool_sub_key_is_refused_at_the_root_by_name(tmp_path):
    """A present `operators.<op>.create` that is not a bool is refused, named.

    helm skips it and lets `operators.create` decide, which is never what the
    adopter who wrote `keda: {create: "false"}` meant. Before ledger 1252 the
    first row rendered KEDA's six CRDs at exit 0 with KEDA itself left out.

    ROOT ONLY, for the register arms' reason: helm runs the subchart's templates
    first, so a refusal here would shadow any parent that names the key itself.
    `test_under_a_parent_the_helper_resolves_a_sub_key_exactly_as_helm_does`
    holds the other half.
    """
    for name, body, operator, kind in THE_SUB_KEY_IS_NOT_A_BOOL:
        result = render_root(tmp_path, name, body)
        assert result.returncode != 0, (
            f"`{name}` rendered exit 0, so a sub-key helm cannot read went "
            f"unrefused.\n{result.stdout[:2000]}"
        )
        assert f"operators.{operator}.create is a {kind} rather than true or false" in (
            result.stderr
        ), f"`{name}` refused without naming what the adopter wrote: {result.stderr}"
        assert THE_SUB_KEY_REFUSAL in result.stderr, (
            f"`{name}` was refused by some other arm: {result.stderr}"
        )
        assert THE_DELETED_OPERATORS_REGISTER_REFUSAL not in result.stderr, result.stderr
        for raise_text in THE_TEXTS_A_RAISE_LEAVES:
            assert raise_text not in result.stderr, (
                f"`{name}` RAISED instead of refusing: {result.stderr}"
            )
    print(
        f"operators-shape: {len(THE_SUB_KEY_IS_NOT_A_BOOL)} non-bool per-operator "
        f"create values refused by name"
    )


def test_the_sub_key_arm_ranges_over_every_two_path_operator():
    """The arm's operator list against `Chart.yaml`. READ OFF THE FILES.

    `.Chart.Dependencies` cannot replace the literal: helm drops a disabled
    dependency from it before templates run. So the literal is compared with the
    first path of every `condition:` that falls back to `operators.create`, and a
    seventh operator reddens this gate until the arm covers it.
    """
    manifest = yaml.safe_load(CHART_MANIFEST.read_text())
    declared = sorted(
        paths[0].strip().split(".")[1]
        for dependency in manifest.get("dependencies", [])
        if len(paths := (dependency.get("condition") or "").split(",")) == 2
        and paths[1].strip() == "operators.create"
    )
    assert declared, "no dependency in Chart.yaml falls back to operators.create"
    text = RENDER_CHECKS.read_text()
    arm = text[text.index(SUB_KEY_ARM_OPENS) : text.index(SUB_KEY_ARM_CLOSES)]
    listed = re.search(r"range \$subKeyOperator := \(list (?P<names>[^)]*)\)", arm)
    assert listed, "the sub-key arm no longer ranges over a literal list"
    names = sorted(re.findall(r'"([^"]+)"', listed.group("names")))
    assert names == declared, (
        f"the sub-key arm ranges over {names} and Chart.yaml declares {declared}: "
        f"a mistyped sub-key for a missing operator goes unrefused"
    )
    print(f"operators-shape: the sub-key arm covers all {len(declared)} operators")


def test_a_sub_block_the_condition_skips_falls_back_to_the_register_key(tmp_path):
    """`keda:` null, a scalar, or a map with no `create`: the register key decides.

    helm's condition finds no bool at `operators.keda.create` in any of these and
    falls through to `operators.create`. The helper must do the same, with NO
    RAISE: `null` and `true` used to raise inside `dig`.
    """
    for name, sub_block in THE_SUB_BLOCKS_THE_CONDITION_SKIPS:
        for register in (False, True):
            label = f"{name}-register-{str(register).lower()}"
            body = f"operators:\n  create: {str(register).lower()}\n{sub_block}"
            result = render_root(tmp_path, label, body)
            for raise_text in THE_TEXTS_A_RAISE_LEAVES:
                assert raise_text not in result.stderr, (
                    f"{label} RAISED: {result.stderr}"
                )
            assert result.returncode == 0, f"{label}: {result.stderr}"
            assert_crds_follow_the_operator(label, result.stdout, installed=register)
            expected = 18 if register else 0
            assert len(vendored_crd_names(result.stdout)) == expected, (
                f"{label}: {vendored_crd_names(result.stdout)}"
            )
    print(
        f"operators-shape: {2 * len(THE_SUB_BLOCKS_THE_CONDITION_SKIPS)} unreadable "
        f"sub-blocks fall back to the register key with no raise"
    )


def test_the_mixed_refusal_names_the_key_that_turned_the_operator_on(tmp_path):
    """`keda: true` under a true register key is `operators.create`'s doing.

    The helper named `operators.keda.create` whenever a `keda` block EXISTED,
    whether or not it carried a usable `create`, so the mixed-release refusal
    told the adopter to change a key that decided nothing.

    `keda: true` REPLACES `keda: {foo: x}` here (ledger 990): the latter is
    now a SCHEMA refusal (`test_a_map_with_an_unknown_sub_key_is_a_schema_
    refusal` below), refused before this helper's fallback ever runs, so it
    can no longer reach the render-level assertion this test makes. `keda:
    true` is a non-map `operators.keda`, which the schema does not
    constrain at all (§3.2: `properties`/`additionalProperties` do not apply
    to a non-object instance) — it reaches the SAME fallback-to-register
    branch `keda: {foo: x}` used to.
    """
    result = render_root(
        tmp_path,
        "mixed-with-an-inert-sub-block",
        "operators:\n  create: true\n  keda: true\ncertificates:\n  create: true\n",
    )
    assert result.returncode != 0, result.stdout[:2000]
    assert "operators.create asked for the operators" in result.stderr, result.stderr
    assert "operators.keda.create" not in result.stderr, (
        f"the refusal named a sub-key that holds no bool: {result.stderr}"
    )
    # The usable sub-key is still named when it is the one that decided.
    result = render_root(
        tmp_path,
        "mixed-with-a-deciding-sub-key",
        "operators:\n  create: false\n  keda:\n    create: true\ncertificates:\n  create: true\n",
    )
    assert result.returncode != 0, result.stdout[:2000]
    assert "operators.keda.create asked for the operators" in result.stderr, result.stderr
    print("operators-shape: the mixed refusal names the key helm's condition used")


def test_a_map_with_an_unknown_sub_key_is_a_schema_refusal(tmp_path):
    """`keda: {foo: x}` MOVED HERE from `THE_SUB_BLOCKS_THE_CONDITION_SKIPS`
    (ledger 990). `chart/values.schema.json` closes `operators.keda` to
    exactly `{create}`, so a map carrying any other key is refused by name
    at render, before this file's own fallback-to-register logic ever runs
    — this is now the point at which `operators.<op>`'s key set is
    enforced, replacing the SILENT fall-through this file's helper used to
    give it.
    """
    for register in (False, True):
        label = f"keda-is-a-map-with-no-create-register-{str(register).lower()}"
        body = f"operators:\n  create: {str(register).lower()}\n  keda:\n    foo: x\n"
        result = render_root(tmp_path, label, body)
        assert result.returncode != 0, f"{label}: rendered clean, {result.stdout[:500]}"
        assert "foo" in result.stderr, f"{label}: {result.stderr}"
        # The path fragment, NEVER helm's sentence: helm 3.18.4 prints
        # "operators.keda: Additional property foo is not allowed"; 3.20.2
        # and 4.3.0 print "at '/operators/keda': additional properties
        # 'foo' not allowed". Both name `operators.keda`; neither shares a
        # word with the other beyond that.
        assert "operators.keda" in result.stderr or "/operators/keda" in result.stderr, (
            f"{label}: {result.stderr}"
        )
    print("operators-shape: a map with an unknown sub-key is now a schema refusal, not a silent fall-through")


def test_under_a_parent_the_helper_resolves_a_sub_key_exactly_as_helm_does(tmp_path):
    """No refusal as a subchart, and the CRDs follow the operator.

    This is the only place the helper's handling of a non-bool sub-key is
    observable, because at the root the refusal fires first. Both parents are
    used: neither refuses a sub-key, so neither may be shadowed.
    """
    rows = (
        ('operators:\n  create: false\n  keda:\n    create: "false"\n', False),
        ('operators:\n  create: true\n  keda:\n    create: "false"\n', True),
        ("operators:\n  create: false\n  keda:\n    create: 0\n", False),
        ("operators:\n  create: false\n  keda:\n", False),
        ("operators:\n  create: true\n  keda: true\n", True),
        ("operators:\n  create: true\n  keda:\n    create: false\n", False),
        ("operators:\n  create: false\n  keda:\n    create: true\n", True),
    )
    for with_refusal in (False, True):
        parent = parent_around(tmp_path, with_refusal=with_refusal)
        for index, (body, installed) in enumerate(rows):
            label = f"{parent.name}-row-{index}"
            result = render_under_parent_body(tmp_path, parent, label, body)
            assert result.returncode == 0, f"{label}: {body!r}: {result.stderr}"
            assert THE_SUB_KEY_REFUSAL not in result.stderr, result.stderr
            assert_crds_follow_the_operator(f"{label}: {body!r}", result.stdout, installed)
    print(
        f"operators-shape: {2 * len(rows)} sub-key rows under a parent, CRDs "
        f"follow the operator in every one"
    )


# ═══ THE REGISTER KEY ITSELF, ONE LEVEL DOWN FROM THE EIGHT SHAPES ═══════════


def test_no_two_refusal_phrases_are_substrings_of_one_another():
    """The discriminators discriminate. PURE, and it reads no chart.

    Every assertion in this file of the form "arm X fired and arm Y did not" is
    only as good as the four phrases being genuinely distinct. `the operators key
    has been deleted` and `operators.create has been deleted` are close enough to
    each other that the next person to reword one could make the pair overlap
    without noticing, at which point several tests below would stop measuring
    what they say.
    """
    phrases = (
        THE_SHAPE_REFUSAL,
        THE_DELETED_KEY_REFUSAL,
        THE_REGISTER_KEY_REFUSAL,
        THE_DELETED_OPERATORS_REGISTER_REFUSAL,
        THE_DELETED_BROKER_REGISTER_REFUSAL,
        THE_SUB_KEY_REFUSAL,
    )
    overlapping = [
        (one, other)
        for one in phrases
        for other in phrases
        if one != other and one in other
    ]
    assert overlapping == [], (
        f"these refusal phrases contain one another, so the assertions that say "
        f"which arm fired cannot tell them apart: {overlapping}"
    )
    print(f"operators-shape: {len(phrases)} refusal phrases, none a substring of another")


def test_a_register_key_that_is_not_a_bool_is_refused_at_the_root_by_name(tmp_path):
    """Seven present-but-unusable `operators.create` values, seven refusals.

    EVERY ONE OF THEM INSTALLS ALL FIVE OPERATORS TODAY, at exit 0 — the table
    beside `THE_REGISTER_KEY_IS_NOT_A_BOOL` is the measurement. Two of the seven
    do not even draw helm's `non-bool value` warning.

    AT THE ROOT, WHICH IS ARM TWO'S DIVISION OF LABOUR AND NOT A NARROWING.
    `yadgarhq/chart` already refuses every one of these shapes by a message that
    names `platform.operators.create`, measured at `platform` 0.1.11 before this
    arm existed. A subchart `fail` would SHADOW it, so this branch stands down as
    a subchart and `test_the_parent_is_the_one_that_names_a_non_bool_register_key`
    is what holds the other half.

    ASSERTED ON THE ABSENCE OF A RAISE, not on the exit code, for the reason
    every case in this file is: a refusal and a raise both exit 1.
    """
    for name, scalar, kind in THE_REGISTER_KEY_IS_NOT_A_BOOL:
        result = render_root(tmp_path, name, f"operators:\n  create: {scalar}\n")
        assert result.returncode != 0, (
            f"`operators.create: {scalar}` rendered exit 0. helm leaves every "
            f"operator dependency ENABLED when no path of its `condition:` "
            f"resolves, so this installs five operators cluster-wide out of a "
            f"value helm could not read.\n{result.stdout[:2000]}"
        )
        assert f"operators.create is a {kind} rather than true or false" in result.stderr, (
            f"`{name}` refused without naming what the adopter wrote: {result.stderr}"
        )
        assert THE_DELETED_OPERATORS_REGISTER_REFUSAL not in result.stderr, (
            f"`{name}` tripped the DELETED-key arm, which is the wrong diagnosis "
            f"for a key that is present: {result.stderr}"
        )
        for raise_text in THE_TEXTS_A_RAISE_LEAVES:
            assert raise_text not in result.stderr, (
                f"`{name}` RAISED instead of refusing: {result.stderr}"
            )
    print(
        f"operators-shape: {len(THE_REGISTER_KEY_IS_NOT_A_BOOL)} non-bool register "
        f"values refused by name"
    )


def test_under_a_bare_parent_the_register_key_resolves_exactly_as_helm_does(tmp_path):
    """RED (ledger 1291): the register-key branch read `operators.create` by
    truthiness, so a FALSY non-bool value disagreed with helm's own resolution.

    `yadgarhq/chart`, and the throwaway stand-in built with `with_refusal=True`,
    both refuse every one of these seven shapes at the parent — which is why
    `test_a_register_key_that_is_not_a_bool_is_refused_at_the_root_by_name` and
    `test_the_parent_is_the_one_that_names_a_non_bool_register_key` only ever
    measure a REFUSAL for them. Under a BARE parent that carries none, nothing
    refuses, and helm's own `condition: operators.<op>.create,operators.create`
    resolution is the only thing deciding whether KEDA installs: no path of it
    holds a bool, so helm leaves the dependency ENABLED regardless of which of
    the seven shapes was written — a present `0` and a present `"yes"` install
    KEDA exactly alike.

    THE OLD HELPER DISAGREED FOR THE FOUR FALSY ONES. `else if $operators.create`
    read `0`, `""`, `{}` and `[]` as OFF by Go's own truthiness, so KEDA installed
    with none of its six vendored CRDs — the ledger-1252 defect reopened one
    level down, in the one key that defect's own fix still read by truthiness.
    `"yes"` and `"no"` were already right, by the same accident ledger 1252's
    sub-key table records: a non-empty string is truthy either way.
    """
    parent = parent_around(tmp_path, with_refusal=False)
    for name, scalar, _kind in THE_REGISTER_KEY_IS_NOT_A_BOOL:
        body = f"operators:\n  create: {scalar}\n"
        result = render_under_parent_body(tmp_path, parent, name, body)
        assert result.returncode == 0, f"`{name}`: {result.stderr}"
        for raise_text in THE_TEXTS_A_RAISE_LEAVES:
            assert raise_text not in result.stderr, f"`{name}`: {result.stderr}"
        assert_crds_follow_the_operator(name, result.stdout, installed=True)
    print(
        f"operators-shape: {len(THE_REGISTER_KEY_IS_NOT_A_BOOL)} non-bool register "
        f"keys leave KEDA's CRDs following the operator under a bare parent"
    )


def test_a_deleted_register_key_is_refused_wherever_this_chart_runs(tmp_path):
    """THE DEFECT THIS ARM WAS BUILT FOR, and it refuses as a subchart too.

    `operators:` followed by `create:` with nothing after it is the shape an
    adopter writes who started to state the toggle and stopped. helm DELETES the
    key and does not put this chart's own `operators.create: false` back, so the
    five dependencies' `condition:` finds no path it can resolve and leaves every
    one of them ENABLED. Measured against `yadgarhq/chart` at 5d23f59 with
    `platform` 0.1.11, on helm v3.20.2 and v4.3.0 alike:

        platform.operators.create omitted  ->  32 objects,   0 from the operator subcharts
        platform.operators.create: false   ->  32 objects,   0 from the operator subcharts
        platform.operators.create: <null>  -> 197 objects, 165 from the operator
                                              subcharts, 0 vendored CRDs, EXIT 0

    WHY IT REFUSES AS A SUBCHART, WHICH IS NOT ARM ONE'S REASON. Arm one is
    unconditional because NOTHING else in the estate can see a deleted `operators`
    block — the parent measures `hasKey` false and cannot tell it from the adopter
    who never wrote the key. THAT ARGUMENT IS FALSE HERE and it was measured
    rather than assumed: a parent probe reads `hasKey $platform.operators
    "create"` FALSE for this shape and TRUE for `operators: {}`, for the key
    omitted, and for `operators: {keda: {create: true}}`. The parent CAN see it.

    IT IS UNCONDITIONAL BECAUSE THE PARENT'S GUARD CANNOT REACH IT, which is a
    different blindness from arm one's and was measured rather than argued.
    `yadgarhq/chart` refuses every PRESENT non-bool `platform.operators.create` —
    `"true"`, `"yes"`, `"no"`, `0`, `1`, `[]`, `""` and `{}` all exit 1 there at
    `platform` 0.1.11, naming the key — because its guard ranges over the `create`
    toggles it can FIND. A DELETED key is not one of them, so that range passes
    over it in silence and the row above renders 197 objects at exit 0. The
    present-non-bool branch of this same arm therefore stands down as a subchart
    and this one does not.

    `yadgarhq/chart`'s own row for this shape asserts that THIS message is the one
    that arrives, so the two repositories cannot drift into both refusing without
    a test going red.
    """
    name, scalar = THE_DELETED_REGISTER_KEY
    body = f"operators:\n  create: {scalar}\n"
    parent = parent_around(tmp_path, with_refusal=True)
    cases = (
        ("as the root chart", render_root(tmp_path, name, body)),
        ("as a subchart", render_under_parent_body(tmp_path, parent, name, body)),
    )
    for label, result in cases:
        assert result.returncode != 0, (
            f"{label}: a deleted `operators.create` rendered exit 0, which is the "
            f"165-object fail-open.\n{result.stdout[:2000]}"
        )
        assert THE_DELETED_OPERATORS_REGISTER_REFUSAL in result.stderr, (
            f"{label}: refused without naming the deleted register key: {result.stderr}"
        )
        assert THE_REGISTER_KEY_REFUSAL not in result.stderr, (
            f"{label}: the PRESENT-non-bool arm fired for an absent key, which is "
            f"the wrong diagnosis: {result.stderr}"
        )
        assert THE_DELETED_KEY_REFUSAL not in result.stderr, (
            f"{label}: arm one fired, and the `operators` block is present here: "
            f"{result.stderr}"
        )
        for raise_text in THE_TEXTS_A_RAISE_LEAVES:
            assert raise_text not in result.stderr, (
                f"{label} RAISED instead of refusing: {result.stderr}"
            )
    assert THE_PARENT_REFUSAL not in cases[1][1].stderr, (
        "the throwaway parent refused a deleted register key as well, so this arm "
        "shadows a live parent refusal and the division of labour needs re-arguing: "
        f"{cases[1][1].stderr}"
    )
    print("operators-shape: a deleted operators.create is refused as root AND as a subchart")


def test_the_brokers_register_key_must_be_a_bool_too(tmp_path):
    """THE FOURTH CLASS MEMBER, and its `condition:` names ONE path.

    `nats` is declared `condition: nats.create`, a single path, and it fails open
    exactly as the five operators do — which is what widened the rule from
    ADR-0794's multi-path wording. Every row installs the broker at exit 0 while
    this chart's own `nats-ingress` NetworkPolicy skips, because that template
    reads the same unusable value and reads it as false.

    AT THE ROOT, for the same reason the operators' present-non-bool branch is:
    `yadgarhq/chart` refuses `platform.nats.create: "yes"`, `0` and `{}` itself,
    measured at `platform` 0.1.11, and a subchart `fail` would shadow it.
    """
    for name, body, kind in THE_BROKER_REGISTER_IS_NOT_A_BOOL:
        result = render_root(tmp_path, name, body)
        assert result.returncode != 0, (
            f"`{name}` rendered exit 0, which is a NATS broker installed out of a "
            f"value helm could not read, with no NetworkPolicy in front of it."
            f"\n{result.stdout[:2000]}"
        )
        assert f"nats.create is a {kind} rather than true or false" in result.stderr, (
            f"`{name}` refused without naming what the adopter wrote: {result.stderr}"
        )
        for raise_text in THE_TEXTS_A_RAISE_LEAVES:
            assert raise_text not in result.stderr, (
                f"`{name}` RAISED instead of refusing: {result.stderr}"
            )
    print(
        f"operators-shape: {len(THE_BROKER_REGISTER_IS_NOT_A_BOOL)} non-bool "
        f"nats.create values refused by name"
    )


def test_a_deleted_nats_block_is_refused_and_is_the_quietest_row(tmp_path):
    """`nats:` with nothing under it — the row that renders MORE than `true` does.

    Deleting the block takes this chart's authorization users and its `natsBox:
    {enabled: false}` with it, so the broker renders on the upstream chart's own
    defaults: EIGHT documents where `nats.create: true` renders five, no accounts,
    and no warning from helm at all.
    """
    name, body = THE_DELETED_BROKER_BLOCK
    result = render_root(tmp_path, name, body)
    assert result.returncode != 0, (
        f"a deleted `nats` block rendered exit 0, which is an unconfigured broker "
        f"on upstream defaults.\n{result.stdout[:2000]}"
    )
    assert THE_DELETED_BROKER_REGISTER_REFUSAL in result.stderr, (
        f"refused without naming the deleted register key: {result.stderr}"
    )
    assert THE_REGISTER_KEY_REFUSAL not in result.stderr, (
        f"the PRESENT-non-bool arm fired for an absent key: {result.stderr}"
    )
    for raise_text in THE_TEXTS_A_RAISE_LEAVES:
        assert raise_text not in result.stderr, (
            f"RAISED instead of refusing: {result.stderr}"
        )
    print("operators-shape: a deleted nats block is refused by name")


def test_the_parent_is_the_one_that_names_a_non_bool_register_key(tmp_path):
    """The other half of the root-only branch, and the half that is easy to lose.

    `yadgarhq/chart` refuses every present non-bool `platform.operators.create`
    and `platform.nats.create` by a message that names the path the adopter
    actually typed. helm executes the deepest template path first, so if this
    chart refused as a subchart its message would be the one the adopter saw and
    that parent's clause would be unreachable — the same defect arms one and two
    were built around, one level down.

    BOTH HALVES ARE ASSERTED: the parent's phrase is present AND this chart's is
    absent. The positive assertion comes first and would fail loudly, because
    asserting only the negative would pass against a chart that refused too.
    """
    parent = parent_around(tmp_path, with_refusal=True)
    rows = [
        (f"operators-{name}", f"operators:\n  create: {scalar}\n", "operators", kind)
        for name, scalar, kind in THE_REGISTER_KEY_IS_NOT_A_BOOL
    ] + [
        (name, body, "nats", kind)
        for name, body, kind in THE_BROKER_REGISTER_IS_NOT_A_BOOL
    ]
    for name, body, block, kind in rows:
        result = render_under_parent_body(tmp_path, parent, f"deferred-{name}", body)
        assert result.returncode != 0, f"`{name}` was not refused: {result.stdout[:2000]}"
        assert THE_PARENT_REFUSAL in result.stderr, (
            f"`{name}`: the parent's refusal did not reach the adopter. This chart "
            f"shadowed it.\n{result.stderr}"
        )
        assert f"platform.{block}.create is a {kind} rather than a boolean" in result.stderr, (
            f"`{name}`: the parent refused without naming what the adopter wrote: "
            f"{result.stderr}"
        )
        assert THE_REGISTER_KEY_REFUSAL not in result.stderr, (
            f"`{name}`: this chart refused as well as the parent: {result.stderr}"
        )
        for raise_text in THE_TEXTS_A_RAISE_LEAVES:
            assert raise_text not in result.stderr, (
                f"`{name}` RAISED inside the subchart: {result.stderr}"
            )
    print(
        f"operators-shape: {len(rows)} non-bool register values deferred to the "
        f"parent's refusal"
    )


def test_every_condition_path_in_chart_yaml_has_a_guarded_register_key():
    """THE LIST IS GATED AGAINST ITS SOURCE, never kept in step by attention.

    A SEVENTH dependency added to `Chart.yaml` tomorrow brings a `condition:` of
    its own, and its register key is in this class the moment `values.yaml`
    declares it. Nothing about the arms below notices. This reads the conditions
    OFF the manifest and asserts each register key is named in the guard, so the
    gate goes red in the pull request that adds the dependency rather than the
    first time an adopter mistypes the new key.

    THE REGISTER KEY IS THE LAST PATH of a `condition:`, which is helm's own
    fallback: `operators.<op>.create,operators.create` falls back to
    `operators.create`, and a single-path `nats.create` is its own fallback. The
    per-operator paths are NOT in this gate's class — `values.yaml` declares none
    of them, so a null there is not deleted. They have an arm of their own, which
    ranges over a literal list that
    `test_the_sub_key_arm_ranges_over_every_two_path_operator` keeps in step with
    `Chart.yaml`;
    `test_a_non_bool_sub_key_is_refused_at_the_root_by_name` holds it (ledger 1252).
    """
    manifest = yaml.safe_load(CHART_MANIFEST.read_text())
    registers = sorted(
        {
            dependency["condition"].split(",")[-1].strip()
            for dependency in manifest.get("dependencies", [])
            if dependency.get("condition")
        }
    )
    assert registers, "no dependency in Chart.yaml declares a condition"
    values = yaml.safe_load(CHART_VALUES.read_text())
    guard = RENDER_CHECKS.read_text()
    unguarded = []
    for register in registers:
        block, _, leaf = register.partition(".")
        # Only a key this chart DECLARES is in the class: helm deletes a null on
        # a declared key, and leaves an undeclared one present and unreadable.
        if leaf not in (values.get(block) or {}):
            continue
        # THE TWO EXPRESSIONS THE ARM IS MADE OF, read off the template source.
        # Not the refusal's wording: that is assembled by `printf` at render time
        # and no literal of it exists in the file, so a test looking for one would
        # be asserting against a string that is never there.
        presence = f'hasKey .Values.{block} "create"'
        shape = f'kindIs "bool" (index .Values.{block} "create")'
        if presence not in guard or shape not in guard:
            unguarded.append(register)
    assert unguarded == [], (
        f"{unguarded} are register keys a Chart.yaml `condition:` reads and "
        f"values.yaml declares, with no arm in {RENDER_CHECKS.name} refusing an "
        f"unusable value for them. helm leaves the dependency ENABLED when the "
        f"condition cannot be resolved."
    )
    print(f"operators-shape: {len(registers)} condition register keys, all guarded")


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


def subchart_documents(stdout: str) -> int:
    """How many documents came from a subchart of this chart, by `# Source:`.

    READ OFF THE COMMENT AND NOT OFF THE PARSED STREAM, because what is being
    counted is provenance rather than kind. The `---` split that
    `vendored_crd_names` avoids is avoided here too: this counts the `# Source:`
    lines themselves, which no quoted description contains at column zero.
    """
    return sum(
        1
        for line in stdout.splitlines()
        # MATCHED ON THE SEGMENT AND NOT ON THE WHOLE PREFIX, because this chart
        # is `platform/charts/...` as the root and `<parent>/charts/platform/
        # charts/...` under a parent, and both are counted here.
        if line.startswith("# Source: ") and "platform/charts/" in line
    )


def test_deleting_the_register_arm_lets_the_operators_fail_open_through(tmp_path):
    """RED CASE 5 — the measurement that makes the register-key arm necessary.

    Cut the `operators` register arm out and render `operators: {create: }`. The
    five dependencies go in, silently, at exit 0 — nothing names the deleted key.

    RE-BASELINED FOR LEDGER 1291. Before that fix, the vendored CRDs did NOT
    follow: the helper's register-key branch read `$operators.create` by
    truthiness, and a deleted key resolves to Go's zero value for an
    `interface{}` — `nil`, which is falsy — so all eighteen vendored CRDs stayed
    off while the five operators installed. That was asserted here as
    `vendored_crd_names(result.stdout) == []`.

    Ledger 1291 made the register-key branch agree with helm for every non-bool
    shape, `nil` included: `or (not (kindIs "bool" $operators.create))
    $operators.create` now reads an absent key as "on", the same as `0`, `""`,
    `{}` and `[]`. So this same render now ALSO renders all eighteen vendored
    CRDs beside the five operators — the CRD/operator mismatch ledger 1252 and
    1291 both exist to prevent no longer happens here. What is left for this red
    case to measure is narrower than its name now says: not a MISMATCH, but the
    missing NAMED REFUSAL — the adopter still gets five operators installed out
    of a key they do not know they deleted, with no message saying so, which is
    the one thing only this arm (removed here) can see (`render-checks.yaml`'s
    own prose above this arm). `test_under_a_bare_parent_the_register_key_
    resolves_exactly_as_helm_does` and RED CASE 10 below already assert the
    CRD/operator agreement itself, across every non-bool register-key shape;
    this case keeps only the print's informational count.

    THE SUBCHART COUNT IS STILL ASSERTED AS AN INEQUALITY. 171 is what the six
    operator subcharts (the five operators and prometheus) render, not counting
    the eighteen vendored CRDs, at the versions `Chart.yaml` pins today; a
    version bump moves it for a reason that has nothing to do with this guard,
    and a row that reddens for the wrong reason is worse than one that does not
    redden at all. What must stay true is that a LOT of subchart objects arrive
    where the baseline renders NONE.
    """
    copy = chart_copy(tmp_path, "no-register-arm")
    template = copy / "templates" / "render-checks.yaml"
    original = template.read_text()
    opening = REGISTER_ARM_OPENS
    closing = REGISTER_ARM_CLOSES
    assert opening in original, f"the register arm no longer opens with {opening!r}"
    assert closing in original, f"the register arm no longer closes with {closing!r}"
    head, rest = original.split(opening, 1)
    _, tail = rest.split(closing, 1)
    template.write_text(head + tail)
    assert template.read_text() != original

    result = helm(
        "template",
        "platform",
        str(copy),
        "-f",
        str(values_file(tmp_path / "no-register-arm.yaml", "operators:\n  create:\n")),
    )
    assert result.returncode == 0, (
        f"the chart without the register arm still refused, so this case does not "
        f"measure what that arm buys: {result.stderr}"
    )
    # `len(names) == EXPECTED_VENDORED_FILES` and `assert_crds_follow_the_operator`
    # are NOT asserted here: `test_under_a_bare_parent_the_register_key_resolves_
    # exactly_as_helm_does` and RED CASE 10 below already own that property, for
    # every non-bool register-key shape including this one's `nil`. `names` is
    # kept for the print only.
    names = vendored_crd_names(result.stdout)
    arrived = subchart_documents(result.stdout)
    assert arrived > 100, (
        f"only {arrived} documents arrived from the operator subcharts, so the "
        f"fail-open this case records did not happen"
    )
    deployments = [
        (d.get("metadata") or {}).get("name")
        for d in documents(result.stdout)
        if d.get("kind") == "Deployment"
    ]
    assert any(name and "keda" in name for name in deployments), (
        f"no KEDA deployment rendered: {sorted(n for n in deployments if n)}"
    )
    print(
        f"operators-shape: red case 5 — without the register arm, a deleted "
        f"`operators.create` renders {arrived} subchart documents and "
        f"{len(names)} vendored CRDs at exit 0, with no named refusal"
    )


def test_deleting_the_broker_arm_lets_an_unconfigured_broker_through(tmp_path):
    """RED CASE 6 — the same measurement on the single-path `condition:`.

    `nats:` with nothing under it, with the broker arm cut out: the NATS subchart
    renders on ITS OWN defaults, because this chart's whole `nats` block went with
    the deleted key. More documents than `nats.create: true` produces, and no
    `nats-ingress` NetworkPolicy in front of any of them.
    """
    copy = chart_copy(tmp_path, "no-broker-arm")
    template = copy / "templates" / "render-checks.yaml"
    original = template.read_text()
    assert BROKER_ARM_OPENS in original, (
        f"the broker arm no longer opens with {BROKER_ARM_OPENS!r}"
    )
    assert BROKER_ARM_CLOSES in original, (
        f"the broker arm no longer closes with {BROKER_ARM_CLOSES!r}"
    )
    head, rest = original.split(BROKER_ARM_OPENS, 1)
    _, tail = rest.split(BROKER_ARM_CLOSES, 1)
    template.write_text(head + tail)
    assert template.read_text() != original

    asked = helm(
        "template",
        "platform",
        str(copy),
        "-f",
        str(values_file(tmp_path / "broker-asked.yaml", "nats:\n  create: true\n")),
    )
    assert asked.returncode == 0, asked.stderr
    deleted = helm(
        "template",
        "platform",
        str(copy),
        "-f",
        str(values_file(tmp_path / "broker-deleted.yaml", "nats:\n")),
    )
    assert deleted.returncode == 0, (
        f"the chart without the broker arm still refused, so this case does not "
        f"measure what that arm buys: {deleted.stderr}"
    )
    assert subchart_documents(deleted.stdout) > subchart_documents(asked.stdout), (
        f"a deleted `nats` block rendered {subchart_documents(deleted.stdout)} "
        f"subchart documents and an explicit `nats.create: true` rendered "
        f"{subchart_documents(asked.stdout)}. The harm this case records is that "
        f"the deleted key renders MORE, on upstream defaults."
    )
    policies = [
        (d.get("metadata") or {}).get("name")
        for d in documents(deleted.stdout)
        if d.get("kind") == "NetworkPolicy"
    ]
    assert not any(name and "nats" in name for name in policies), (
        f"a nats NetworkPolicy rendered, so the harm is not the one described: "
        f"{sorted(n for n in policies if n)}"
    )
    print(
        f"operators-shape: red case 6 — without the broker arm, a deleted `nats` "
        f"block renders {subchart_documents(deleted.stdout)} subchart documents "
        f"against {subchart_documents(asked.stdout)} for an explicit true, and no "
        f"NetworkPolicy"
    )


def test_refusing_a_non_bool_register_key_from_the_subchart_would_shadow_the_parent(
    tmp_path,
):
    """RED CASE 7 — the register arm's root-only branch is load-bearing too.

    Drop the `.Template.BasePath` test from the `operators` register arm and this
    chart refuses a present non-bool `create` everywhere. The parent's named
    refusal then never reaches the adopter, which is the same defect RED CASE 3
    records one level up.
    """
    copy = chart_copy(tmp_path, "register-always-refuses")
    template = copy / "templates" / "render-checks.yaml"
    original = template.read_text()
    start = original.index(REGISTER_ARM_OPENS)
    end = original.index(REGISTER_ARM_CLOSES, start)
    arm = original[start:end]
    assert arm.count(THE_ROOT_ONLY_PIVOT) == 1, (
        f"the operators register arm no longer carries exactly one "
        f"{THE_ROOT_ONLY_PIVOT!r}, so this mutation would cut at the wrong place"
    )
    template.write_text(
        original[:start] + arm.replace(THE_ROOT_ONLY_PIVOT, "{{- else if true }}") + original[end:]
    )
    assert template.read_text() != original

    parent = build_parent(tmp_path / "parent-register-shadowed", copy)
    (parent / "templates" / "validate.yaml").write_text(
        THE_PARENT_CLAUSE.replace("REFUSAL_MARKER", THE_PARENT_REFUSAL)
    )
    result = render_under_parent_body(
        tmp_path, parent, "register-shadowed", 'operators:\n  create: "yes"\n'
    )
    assert result.returncode != 0
    assert THE_REGISTER_KEY_REFUSAL in result.stderr, result.stderr
    assert THE_PARENT_REFUSAL not in result.stderr, (
        "the parent's refusal reached the adopter even with the subchart refusing, "
        "so the root-only branch guards nothing and this case proves nothing"
    )
    print(
        "operators-shape: red case 7 — a subchart that refuses a non-bool register "
        "key shadows the parent's message"
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


def test_the_dig_helper_puts_crds_beside_an_operator_helm_left_out(tmp_path):
    """RED CASE 8 — revert the helper to `dig`, and the CRDs stop following KEDA.

    Under a parent no refusal fires, so the helper alone decides. The `dig`
    helper reads `keda.create: "false"` as TRUE, while helm skips it and reads
    `operators.create: false`: KEDA's six CRDs on a cluster with no KEDA.
    """
    copy = chart_copy(tmp_path, "dig-helper")
    partial = copy / "templates" / "_operators.tpl"
    original = partial.read_text()
    start = original.index('{{- define "platform.operator-create" -}}')
    partial.write_text(original[:start] + THE_DIG_HELPER + "\n")
    assert partial.read_text() != original
    parent = build_parent(tmp_path / "parent-dig-helper", copy)
    result = render_under_parent_body(
        tmp_path,
        parent,
        "dig-helper",
        'operators:\n  create: false\n  keda:\n    create: "false"\n',
    )
    assert result.returncode == 0, result.stderr
    assert keda_crds(result.stdout) == 6 and keda_documents(result.stdout) == 0, (
        "the dig helper no longer renders KEDA's CRDs without KEDA, so this case "
        "does not record what the fix buys"
    )
    print("operators-shape: red case 8 — the dig helper renders 6 KEDA CRDs with no KEDA")


def test_deleting_the_sub_key_arm_lets_a_non_bool_sub_key_through(tmp_path):
    """RED CASE 9 — cut the per-operator arm, and the typo renders at exit 0."""
    copy = chart_copy(tmp_path, "no-sub-key-arm")
    template = copy / "templates" / "render-checks.yaml"
    original = template.read_text()
    assert original.count(SUB_KEY_ARM_OPENS) == 1, (
        f"the sub-key arm no longer opens with {SUB_KEY_ARM_OPENS!r}"
    )
    assert original.count(SUB_KEY_ARM_CLOSES) == 1, (
        f"the sub-key arm no longer closes with {SUB_KEY_ARM_CLOSES!r}"
    )
    head, rest = original.split(SUB_KEY_ARM_OPENS, 1)
    _, tail = rest.split(SUB_KEY_ARM_CLOSES, 1)
    template.write_text(head + tail)
    assert template.read_text() != original
    result = helm(
        "template",
        "platform",
        str(copy),
        "-f",
        str(
            values_file(
                tmp_path / "no-sub-key-arm.yaml",
                'operators:\n  create: false\n  keda:\n    create: "false"\n',
            )
        ),
    )
    assert result.returncode == 0, (
        f"the chart without the sub-key arm still refused, so this case does not "
        f"measure what that arm buys: {result.stderr}"
    )
    print("operators-shape: red case 9 — without the sub-key arm, the typo renders at exit 0")


def test_reverting_the_register_branch_to_truthiness_puts_crds_beside_an_operator_helm_left_out(
    tmp_path,
):
    """RED CASE 10 — revert ONLY the register-key branch, and the mismatch returns.

    `{{- else if $operators.create -}}` is the pre-ledger-1291 line: it read the
    register key by truthiness rather than `kindIs "bool"`, the same shape of
    defect RED CASE 8 reverts for the sub-key, one branch narrower. Under a bare
    parent with `operators.create: 0` and no per-operator override, helm leaves
    KEDA enabled because no path of its condition resolves to a bool — and the
    reverted branch reads `0` as falsy, so none of KEDA's six vendored CRDs
    follow it.
    """
    copy = chart_copy(tmp_path, "truthy-register-branch")
    partial = copy / "templates" / "_operators.tpl"
    original = partial.read_text()
    fixed = '{{- else if or (not (kindIs "bool" $operators.create)) $operators.create -}}'
    assert fixed in original, f"the register branch no longer reads {fixed!r}"
    partial.write_text(original.replace(fixed, "{{- else if $operators.create -}}"))
    assert partial.read_text() != original

    parent = build_parent(tmp_path / "parent-truthy-register-branch", copy)
    result = render_under_parent_body(
        tmp_path, parent, "truthy-register-branch", "operators:\n  create: 0\n"
    )
    assert result.returncode == 0, result.stderr
    assert keda_crds(result.stdout) == 0 and keda_documents(result.stdout) > 0, (
        "reverting the register branch to truthiness no longer installs KEDA "
        "with none of its CRDs, so this case does not record what the fix buys"
    )
    print(
        "operators-shape: red case 10 — a truthy-only register branch installs "
        "KEDA with 0 of its CRDs when `operators.create` is a falsy non-bool"
    )
