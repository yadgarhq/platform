"""THE LADDER GATE: the renewal ladder is one invariant, and this is where it is read.

WHAT THE INVARIANT IS. The `renewBefore` values across every leaf certificate in
this estate are DISTINCT and six hours apart, so at most one service restarts per
renewal instant. That is a property of the SET, not of any one certificate, and an
invariant is checkable only where every one of its terms is visible at once — which
is why the leaves live in this chart at all (ADR-0752 as amended by ADR-0754) even
though each has exactly one consuming module.

IT ASSERTS THE COUNT IT EXAMINED. A gate that renders a set, finds no violation
among zero members and reports a pass has proved nothing: rename the values key the
range walks and "every `renewBefore` is distinct" is VACUOUSLY TRUE over what is
left, with the suite green and the ladder gone. So every case below states the
number of Certificate OBJECTS it expects and the SET of ladder values it expects,
and fails with both numbers in the message.

THE NUMBER IS PER RENDER, NOT ONE NUMBER FOR ALL OF THEM. Three renders, three
pairs of numbers:

  R1  the chart's own defaults          0 Certificates
  R2  `example/values.yaml`            14 Certificates, 13 ladder values
  R3  R2 with `edgeTLS.create` false   13 Certificates, 12 ladder values

A single expected number across all three would be vacuous at the defaults, where
every `create` toggle is false and nothing renders. R1's zero is asserted as an
EQUALITY against zero and carries its own red case, because a pass that expects
zero and would also report a pass on one is not a gate.

THE LADDER SET IS SCOPED TO THE CERTIFICATES THAT ARE NOT `isCA`, and that is the
difference between 14 objects and 13 values rather than an omission. The CA root
carries a `renewBefore` of its own — one year against a ten-year duration — and it
is not a rung: nothing mounts it as a serving or client credential, and its renewal
re-signs with the same key rather than restarting a service. Fourteen objects
contributing thirteen rungs is exactly one object contributing none, and that object
is the CA root.

EVERY RENDER HERE PASSES `--api-versions cert-manager.io/v1`. `helm template` does
not populate `.Capabilities.APIVersions` with CRD-backed groups from anywhere but a
live cluster, so a bare render of any of these values files is refused by this
chart's own render check before a single Certificate exists to count.
`test_render_checks.py` is where that refusal is the subject; here it is only the
reason for the flag.

NO SKIPS (ADR-0650). `helm` absent is a failure, not a skip: this suite and the
shared `helm lint and render` hook both need it, and a suite that skips when its
subject is absent reports a pass nobody earned.

Run: python3 -m pytest scripts/tests/ -q
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parents[2]
CHART = REPO / "chart"
ADOPTER_VALUES = REPO / "example" / "values.yaml"

# ── EVERY GROUP THE CHART'S RENDER CHECKS ASK FOR ────────────────────────────
# ONE ENTRY PER CHECK THE CHART DECLARES, AND A LITERAL RATHER THAN A LIST READ
# OFF THE CHART. `fail` aborts the WHOLE render at the FIRST failing check and
# names only that one, so a render here that omits a group is refused for THAT
# check's reason before the objects this suite counts exist at all — which is how
# every case in this file went red the day the second check landed. Deriving the
# tuple from `test_render_checks.py`'s `declared_checks` would follow a check
# DELETED from the chart, so these renders would keep passing over one fewer group
# and stop discriminating at the moment the checks stopped existing.
#
# `test_render_checks.py` owns the count of what the chart declares; this is the
# independent restatement that disagrees with it when somebody moves one and not
# the other.
DECLARED_API_VERSIONS = ("cert-manager.io/v1", "gateway.envoyproxy.io/v1alpha1")

# `--api-versions <group>` for each of them, spliced into every render below.
API_VERSIONS = tuple(
    part for group in DECLARED_API_VERSIONS for part in ("--api-versions", group)
)

# ── THE EXPECTED NUMBERS, ONE PAIR PER RENDER ────────────────────────────────
# THEY ARE LITERALS AND THEY MUST STAY LITERALS. A count derived from the render
# agrees with whatever the render happens to be and therefore detects nothing. The
# whole value of these is that somebody looked at the number and wrote it down.

# R1 — the chart's own `values.yaml`, every `create` toggle false.
CERTIFICATES_AT_THE_DEFAULTS = 0

# R2 — `example/values.yaml`: the twelve internal leaves, the CA root, the edge leaf.
CERTIFICATES_WITH_THE_EDGE_LEAF = 14

# R3 — R2 with `edgeTLS.create` false: the same, less the edge leaf.
CERTIFICATES_WITHOUT_THE_EDGE_LEAF = 13

# THE LADDER ITSELF, as the set of values and not as a count of leaves. Stated this
# way on purpose: "thirteen leaf values, pairwise distinct" leaves the literal thirteen
# unmoved when two leaves share one value, and a number a red case cannot move is
# not an assertion. 720h is the EDGE leaf's rung, held out of the internal map and
# part of the same ladder — a step is free only if neither uses it.
LADDER = {
    "720h",
    "726h",
    "732h",
    "738h",
    "744h",
    "750h",
    "756h",
    "762h",
    "768h",
    "774h",
    "780h",
    # nats-tls and valkey-tls, the two serving leaves B-L1 adds (ADR-0588: the next
    # two free steps after 780h).
    "786h",
    "792h",
}
LADDER_WITHOUT_THE_EDGE_LEAF = LADDER - {"720h"}


def helm(*arguments: str) -> subprocess.CompletedProcess[str]:
    binary = shutil.which("helm")
    # NOT A SKIP, and ADR-0650 is why. Same wording as `yadgarhq/config`'s and
    # `yadgarhq/chart`'s suites, which made the same decision for the same reason.
    assert binary, (
        "helm is not on PATH. This suite renders the chart, and so does the "
        "`helm lint and render` pre-commit hook — install helm rather than "
        "letting either report a pass it did not earn."
    )
    return subprocess.run([binary, *arguments], capture_output=True, text=True)


def render(chart: Path, *arguments: str) -> list[dict]:
    result = helm(
        "template", "platform", str(chart), *API_VERSIONS, *arguments
    )
    assert result.returncode == 0, result.stderr
    return [
        document
        for document in yaml.safe_load_all(result.stdout)
        if isinstance(document, dict) and document.get("apiVersion")
    ]


def certificates(documents: list[dict]) -> list[dict]:
    return [document for document in documents if document.get("kind") == "Certificate"]


def rungs(documents: list[dict]) -> dict[str, list[str]]:
    """Ladder value -> every certificate holding it. PURE.

    SCOPED TO THE CERTIFICATES THAT ARE NOT `isCA`. The CA root's `renewBefore` is
    its own renewal window and not a rung — see the module docstring.
    """
    index: dict[str, list[str]] = {}
    for document in certificates(documents):
        specification = document.get("spec") or {}
        if specification.get("isCA"):
            continue
        name = str((document.get("metadata") or {}).get("name"))
        index.setdefault(str(specification.get("renewBefore")), []).append(name)
    return index


def ladder_failures(
    documents: list[dict], expected_objects: int, expected_values: set[str]
) -> list[str]:
    """Every way this render disagrees with the ladder, each naming both numbers. PURE.

    PURE AND DOCUMENT-TAKING SO THE RED CASES NEVER TOUCH THE REAL TREE, following
    `yadgarhq/chart`'s suite: a gate that has only ever been fed the real render has
    never been shown to refuse anything.
    """
    failures = []

    found = certificates(documents)
    if len(found) != expected_objects:
        names = sorted(str((document.get("metadata") or {}).get("name")) for document in found)
        failures.append(
            f"expected {expected_objects} Certificate objects, found {len(found)}: {names}"
        )

    held = rungs(documents)
    if set(held) != expected_values:
        failures.append(
            f"expected {len(expected_values)} distinct renewBefore values, "
            f"found {len(held)}: expected {sorted(expected_values)}, "
            f"found {sorted(held)}"
        )
    for value, holders in sorted(held.items()):
        if len(holders) > 1:
            failures.append(
                f"renewBefore {value} is held by {len(holders)} certificates, "
                f"{', '.join(sorted(holders))} — the ladder needs one service per "
                f"renewal instant, so every value is distinct"
            )

    return failures


def chart_with_the_leaves_key_renamed(destination: Path) -> Path:
    """A copy of the chart whose values file no longer holds `certificates.leaves`.

    THE RED CASE THE WHOLE GATE EXISTS FOR. The range in
    `templates/certificates.yaml` then walks nothing, the twelve leaves vanish, and
    "every `renewBefore` is distinct" becomes vacuously true over what is left. The
    CA root and the edge leaf still render, because each sits behind its own toggle
    and neither is reached by that range — which is what puts a number other than
    zero in the failure message.

    THE SCHEMA IS RENAMED TOO (ledger 990), and this is load-bearing since
    `values.schema.json` closed `certificates` to exactly its five known
    keys: without this second rename, the copy's schema still declares
    `leaves` and refuses the renamed `leafs` as an unknown key BEFORE the
    range in `templates/certificates.yaml` ever runs, which would make this
    a schema-refusal case rather than the silent-range-walks-nothing case
    this fixture exists to produce.
    """
    copy = destination / "chart"
    shutil.copytree(CHART, copy)
    values = copy / "values.yaml"
    text = values.read_text()
    assert "\n  leaves:\n" in text, "the leaves key moved; this red case is now testing nothing"
    values.write_text(text.replace("\n  leaves:\n", "\n  leafs:\n"))

    schema_path = copy / "values.schema.json"
    schema = json.loads(schema_path.read_text())
    certificates_properties = schema["properties"]["certificates"]["properties"]
    assert "leaves" in certificates_properties, "the schema's `leaves` key moved too"
    certificates_properties["leafs"] = certificates_properties.pop("leaves")
    schema_path.write_text(json.dumps(schema))
    return copy


def values_file(destination: Path, name: str, body: str) -> Path:
    path = destination / name
    path.write_text(body)
    return path


# THE COLLISION THE DUPLICATE RED CASES CONSTRUCT: `task-tls` is moved onto
# `iam-tls`'s rung through an override values file.
COLLIDING = ("iam-tls", "task-tls")
COLLISION = "certificates:\n  leaves:\n    task-tls:\n      renewBefore: 726h\n"


def assert_the_collision_has_something_to_collide_with(documents: list[dict]) -> None:
    """The duplicate red case's own tripwire, and the rename case's has a twin.

    An override naming a leaf the chart no longer carries ADDS a thirteenth leaf
    rather than moving an existing one onto an occupied rung. The set would then
    grow instead of shrinking, the red case would still fail the equality, and it
    would be failing for a reason that has nothing to do with a duplicate — the
    "passes for the wrong reason" form, one layer in.
    """
    holders = {name for names in rungs(documents).values() for name in names}
    assert set(COLLIDING) <= holders, (
        f"the leaves this red case collides, {COLLIDING}, are not both in the "
        f"render: found {sorted(holders)}. The override would add a leaf rather "
        f"than move one, so this case is no longer testing a duplicate"
    )


# ── R1: the chart's own defaults ─────────────────────────────────────────────


def test_the_defaults_render_no_certificate_at_all():
    """Every `create` toggle is false, so the count is zero and it is an EQUALITY."""
    assert ladder_failures(render(CHART), CERTIFICATES_AT_THE_DEFAULTS, set()) == []


def test_turning_the_leaves_on_reddens_the_defaults_zero(tmp_path):
    """R1's red case: the zero must be falsifiable, or it is not an assertion."""
    overridden = values_file(tmp_path, "on.yaml", "certificates:\n  create: true\n")
    failures = ladder_failures(
        render(CHART, "-f", str(overridden)), CERTIFICATES_AT_THE_DEFAULTS, set()
    )
    assert failures, "the defaults-zero passed over a render that produced certificates"
    assert "expected 0 Certificate objects" in failures[0]
    assert "found 0" not in failures[0]


# ── R2: example/values.yaml, the whole layer on ──────────────────────────────


def test_the_adopter_render_carries_the_whole_ladder():
    """Fourteen Certificate objects; thirteen of them on distinct rungs."""
    documents = render(CHART, "-f", str(ADOPTER_VALUES))
    assert (
        ladder_failures(documents, CERTIFICATES_WITH_THE_EDGE_LEAF, LADDER) == []
    ), ladder_failures(documents, CERTIFICATES_WITH_THE_EDGE_LEAF, LADDER)


def test_two_leaves_on_one_rung_are_refused(tmp_path):
    """R2's first red case, and the failure has to name both leaves.

    A duplicate moves the SIZE of the set — thirteen values become twelve — which is why
    the expectation is stated as a set rather than as a count of leaves.
    """
    assert_the_collision_has_something_to_collide_with(render(CHART, "-f", str(ADOPTER_VALUES)))
    collision = values_file(tmp_path, "collision.yaml", COLLISION)
    failures = ladder_failures(
        render(CHART, "-f", str(ADOPTER_VALUES), "-f", str(collision)),
        CERTIFICATES_WITH_THE_EDGE_LEAF,
        LADDER,
    )
    message = "\n".join(failures)
    assert failures, "two leaves shared one rung and the ladder gate passed"
    assert "expected 13 distinct renewBefore values, found 12" in message
    assert "iam-tls" in message and "task-tls" in message


def test_renaming_the_leaves_key_is_refused(tmp_path):
    """R2's second red case: the range walks nothing and the count catches it."""
    failures = ladder_failures(
        render(chart_with_the_leaves_key_renamed(tmp_path), "-f", str(ADOPTER_VALUES)),
        CERTIFICATES_WITH_THE_EDGE_LEAF,
        LADDER,
    )
    message = "\n".join(failures)
    assert failures, "the twelve leaves vanished and the ladder gate passed"
    assert "expected 14 Certificate objects, found 2" in message


# ── R3: R2 with the edge leaf off ────────────────────────────────────────────
#
# A DIFFERENT PAIR OF NUMBERS, because the edge leaf sits behind its OWN toggle. A
# gate asserting distinctness has to say which render it is asserting over, and
# this is the render that makes the difference visible.


def without_the_edge_leaf(destination: Path) -> Path:
    return values_file(destination, "no-edge.yaml", "edgeTLS:\n  create: false\n")


def test_the_render_without_the_edge_leaf_carries_the_rest_of_the_ladder(tmp_path):
    documents = render(
        CHART, "-f", str(ADOPTER_VALUES), "-f", str(without_the_edge_leaf(tmp_path))
    )
    failures = ladder_failures(
        documents, CERTIFICATES_WITHOUT_THE_EDGE_LEAF, LADDER_WITHOUT_THE_EDGE_LEAF
    )
    assert failures == [], failures


def test_two_leaves_on_one_rung_are_refused_without_the_edge_leaf(tmp_path):
    """The duplicate case carries over unchanged, against the smaller set."""
    assert_the_collision_has_something_to_collide_with(
        render(CHART, "-f", str(ADOPTER_VALUES), "-f", str(without_the_edge_leaf(tmp_path)))
    )
    collision = values_file(tmp_path, "collision.yaml", COLLISION)
    failures = ladder_failures(
        render(
            CHART,
            "-f",
            str(ADOPTER_VALUES),
            "-f",
            str(without_the_edge_leaf(tmp_path)),
            "-f",
            str(collision),
        ),
        CERTIFICATES_WITHOUT_THE_EDGE_LEAF,
        LADDER_WITHOUT_THE_EDGE_LEAF,
    )
    message = "\n".join(failures)
    assert failures, "two leaves shared one rung and the ladder gate passed"
    assert "expected 12 distinct renewBefore values, found 11" in message
    assert "iam-tls" in message and "task-tls" in message


def test_renaming_the_leaves_key_without_the_edge_leaf_leaves_the_ca_root_alone(tmp_path):
    """The same rename, with ONE arithmetic difference the register names.

    `edgeTLS.create` is already false here, so the rename leaves the CA root
    standing alone and the failure names thirteen and the one it found.
    """
    chart = chart_with_the_leaves_key_renamed(tmp_path)
    failures = ladder_failures(
        render(chart, "-f", str(ADOPTER_VALUES), "-f", str(without_the_edge_leaf(tmp_path))),
        CERTIFICATES_WITHOUT_THE_EDGE_LEAF,
        LADDER_WITHOUT_THE_EDGE_LEAF,
    )
    message = "\n".join(failures)
    assert failures, "the twelve leaves vanished and the ladder gate passed"
    assert "expected 13 Certificate objects, found 1" in message


# ── THE EDGE LEAF'S ISSUER FALLS BACK TO THE INTERNAL CA ─────────────────────
#
# B3 of plans/the-one-application-install.md (ADR-0803): `edgeTLS.issuerRef`
# keeps its `{}` default in `chart/values.yaml` — no populated default was added
# there — and `chart/templates/edge-certificate.yaml` fills it with
# `{name: internalCA.name, kind: Issuer}` ONLY when the map is left completely
# empty AND `internalCA.create` is true, so the parent chart's whole-estate
# defaults render a working edge Certificate with no issuer override. A map an
# adopter has stated EVEN PARTIALLY — one key, not both — never receives the
# fallback and still hits the `required` guards, which is what tells this design
# apart from putting the default directly on the values key: MEASURED (a first
# revision of this step got this wrong), a non-empty `values.yaml` default merges
# with a partial override key-by-key, so `issuerRef: {name: my-cluster-ca}` alone
# would have silently inherited `kind: Issuer` from that default instead of
# refusing.


def test_the_edge_certificate_defaults_to_the_internal_ca_issuer(tmp_path):
    """B3's GREEN CASE: with no issuer override, the fallback names a REAL Issuer.

    `edgeTLS.create` and `internalCA.create` on, and nothing else — the edge
    Certificate's `issuerRef` must name the SAME Issuer object this render itself
    emits, not a literal this test carries independently of `values.yaml`. A
    rename of `internalCA.name` has to move both sides together or this reddens.
    """
    values = values_file(
        tmp_path,
        "edge-and-internal-ca.yaml",
        "edgeTLS:\n  create: true\ninternalCA:\n  create: true\n",
    )
    documents = render(CHART, "-f", str(values))

    edge_leaves = [
        document for document in certificates(documents) if not document["spec"].get("isCA")
    ]
    assert len(edge_leaves) == 1, (
        f"expected exactly one non-CA Certificate, found {len(edge_leaves)}: "
        f"{[document['metadata']['name'] for document in edge_leaves]}"
    )
    (edge,) = edge_leaves

    issuer_names = {
        document["metadata"]["name"] for document in documents if document.get("kind") == "Issuer"
    }
    issuer_ref = edge["spec"]["issuerRef"]
    assert issuer_ref["kind"] == "Issuer", issuer_ref
    assert issuer_ref["name"] in issuer_names, (
        f"the edge Certificate's issuerRef names {issuer_ref['name']!r}, which is "
        f"not among the Issuers this render emits: {sorted(issuer_names)}"
    )


def test_the_edge_leaf_refuses_a_partial_issuer_even_when_internal_ca_is_on(tmp_path):
    """RED CASE (a): a PARTIAL map never gets the fallback, even with it eligible.

    `internalCA.create` true and `edgeTLS.issuerRef.name` alone — an adopter
    naming their own issuer but forgetting `kind`. A values-key default would
    have inherited `kind: Issuer` from it here and rendered silently; the
    fallback living in the template, gated on the map being COMPLETELY empty,
    refuses instead. This is the exact shape a first revision of this step got
    wrong, re-measured here as its own case rather than left to the docstring.
    """
    values = values_file(
        tmp_path,
        "partial-issuer.yaml",
        "edgeTLS:\n  create: true\n  issuerRef:\n    name: my-cluster-ca\ninternalCA:\n  create: true\n",
    )
    result = helm("template", "platform", str(CHART), *API_VERSIONS, "-f", str(values))
    assert result.returncode != 0, "a name-only issuerRef did not refuse"
    assert "edgeTLS.issuerRef.kind" in result.stderr, result.stderr


def test_the_edge_leaf_refuses_an_empty_issuer_when_internal_ca_is_off(tmp_path):
    """RED CASE (b): the fallback is CONDITIONAL on `internalCA.create`, not automatic.

    `edgeTLS.create` alone, `internalCA.create` at its own default (false) —
    there is no Issuer this chart renders for the fallback to name, so it must
    not apply. A first revision of this step got this wrong the other way: a
    populated `values.yaml` default rendered `issuerRef.name: yadgar-internal-ca`
    here with NO Issuer object anywhere in the render, which is silently worse
    than the refusal this case now asserts — a Certificate that can never go
    Ready, with no message pointing at why.
    """
    values = values_file(tmp_path, "edge-only.yaml", "edgeTLS:\n  create: true\n")
    result = helm("template", "platform", str(CHART), *API_VERSIONS, "-f", str(values))
    assert result.returncode != 0, "an empty issuerRef with internalCA off did not refuse"
    assert "edgeTLS.issuerRef.name" in result.stderr, result.stderr


def test_the_edge_leaf_refuses_when_the_issuer_is_cleared_with_null(tmp_path):
    """RED CASE (c): explicit `null` behaves like the key was never stated at all.

    Both here have `internalCA.create` at its own default (false), so neither
    reaches the fallback regardless of how the map was cleared — the whole map
    with a bare `null`, and one field with the other stated, because helm
    deletes a destination key only when the override names it `null` and leaves
    every other key of a partly-cleared map alone (which is what lets the second
    case clear `kind` without also reintroducing the first case's `name`
    refusal). NOT asserted with `internalCA.create` true: helm cannot tell an
    explicit `issuerRef: null` apart from the key never having been stated once
    both merge to the same empty map, so with the fallback eligible a bare
    `null` renders the internal CA rather than refusing — the same reason the
    fallback could not live as a `values.yaml` default in the first place.
    """
    for body, key in (
        ("edgeTLS:\n  create: true\n  issuerRef: null\n", "edgeTLS.issuerRef.name"),
        (
            "edgeTLS:\n  create: true\n  issuerRef:\n    name: some-ca\n    kind: null\n",
            "edgeTLS.issuerRef.kind",
        ),
    ):
        overridden = values_file(tmp_path, f"{key}.yaml", body)
        result = helm(
            "template",
            "platform",
            str(CHART),
            *API_VERSIONS,
            "-f",
            str(overridden),
        )
        assert result.returncode != 0, f"{key} was cleared and the render did not refuse"
        assert key in result.stderr, result.stderr


def test_the_groups_this_file_names_are_the_groups_the_chart_declares():
    """`DECLARED_API_VERSIONS` RESTATED AGAINST THE CHART. An assertion, NOT a derivation.

    THE LITERAL ABOVE STAYS A LITERAL, and that is deliberate rather than an omission
    this case tidies up. A tuple computed from `declared_checks(CHART)` would FOLLOW a
    check deleted from the chart: every render in this file would keep passing over
    one fewer group and this file would stop discriminating at exactly the moment the
    render checks stopped existing. `test_render_checks.py` catches that deletion on
    its own count. So the independent restatement has to survive, and what was missing
    beside it was the comparison.

    WHAT THE COMPARISON BUYS IS A NAMED CAUSE. This constant is spliced into every
    enabled render in this file, and `fail` aborts a whole chart render at the first
    check whose group is absent. So ONE stale entry here does not fail as "this tuple
    is stale" — it fails as dozens of cases across this file, each printing the
    CHART's refusal and naming the chart's operator. The reader meets a symptom that
    names the chart and is caused by a constant in a test file. This case fails first
    and says so.

    It is imported inside the function, following this file's existing precedent, so
    the constant stays readable without a module-level dependency between suites.
    """
    from test_render_checks import declared_checks

    declared = tuple(sorted(declared_checks(CHART)))
    assert DECLARED_API_VERSIONS == declared, (
        f"this file's DECLARED_API_VERSIONS names {DECLARED_API_VERSIONS} and the "
        f"chart declares {declared}. Every enabled render in this file passes the "
        f"first, and `fail` aborts each of them at the first check whose group is "
        f"missing — so a stale entry HERE reddens this whole file with the CHART's "
        f"refusal, naming the chart rather than this constant. Move this tuple to "
        f"match the chart, or restore the check the chart lost"
    )
