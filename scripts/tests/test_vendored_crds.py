"""THE DRIFT GATE for the eighteen vendored CRDs, and the guard that carries them.

WHY THIS FILE IS THE CONDITION OF THE COMMIT RATHER THAN A COMPANION TO IT.
ADR-0792 permits a chart repository to commit a DOCUMENT EXTRACTED from a
dependency — rather than the dependency itself — when and only when four things
hold. Its third is that a drift gate ships in the SAME change, comparing the
committed copy against a fresh render of the pinned upstream, printing the count
of documents it examined, and carrying a constructed red case that actually
reddens. So a pull request that adds `chart/templates/vendored-crds/` without this
file has not merely shipped a defect: it has landed a change the decision that
permits the copies does not authorise.

WHAT IS COMPARED, AND WHY BOTH SIDES ARE RENDERS. `keda/templates/crds/crd-*.yaml`
carry seven Go-template directives each — `crds.additionalAnnotations` is templated
into them — so a byte comparison against a plain-YAML vendored copy can never
match. `mariadb-operator-crds/templates/crds.yaml` carries none, but it goes
through the same path so one code path serves both sets. Each side is therefore a
`helm template` render, and the comparison is over the parsed documents.

THE VENDORED SIDE IS FILTERED BY THE `# Source:` COMMENT, NOT BY `kind`. That
distinction is the difference between a gate that is green on a correct tree and
one that is red on its first run with nothing broken.
`helm template platform chart/ --set operators.create=true` emits 27 CRDs, not 18:
cert-manager contributes 6 and Argo CD 3 as ordinary subchart templates. Every
vendored document carries `# Source: platform/templates/vendored-crds/` and none
of the other nine does. The API group is asserted too, but as a CROSS-CHECK rather
than as the filter — a vendored file that landed in the wrong directory would pass
the group check and fail the path filter, and one that acquired an unexpected group
would do the reverse.

THE RENDER IS PINNED WITH NO PER-OPERATOR SUB-KEY SET, and that is load-bearing
rather than tidy. Under `--set operators.keda.create=false` the same filter yields
12, so `compared == 18` would be red on a tree nobody touched.
`test_each_vendored_set_travels_with_its_own_operator` is where that 12 is measured
rather than asserted here.

WHAT IT COMPARES THEM BY. A SHA-256 digest over each document's canonical JSON,
keys sorted, after deleting the fields that legitimately differ between a vendored
copy and an upstream render. THE STRIP LIST IS RE-DERIVED FROM THE RENDER rather
than written from convention, and an earlier draft's was wrong in four ways:

  - `helm.sh/resource-policy` — deleted on both sides. `platform` adds it on
    purpose and upstream does not carry it. This is the only deletion that is
    load-bearing TODAY, which is why the green case passing at all proves it works.
  - KEDA labels `helm.sh/chart`, `app.kubernetes.io/version`,
    `app.kubernetes.io/managed-by`, and — the two the earlier list MISSED —
    `app.kubernetes.io/name` and `app.kubernetes.io/part-of`, which both render
    `{{ .Values.operator.name }}`, measured by `--set operator.name=zzz` moving
    both on all six. Without those two an ordinary values change to
    `keda.operator.name` reddens this gate naming a CRD whose schema has not moved.
  - NOT `app.kubernetes.io/component`, which is the literal `operator` on all six,
    and NOT `controller-gen.kubebuilder.io/version`, which is the generator version
    and is real upstream content that SHOULD move the digest when upstream moves.
  - `app.kubernetes.io/instance` is NOT stripped because it is ABSENT from all six
    KEDA CRDs: the CRD files include `keda.crd-labels`, and it is `keda.labels`
    that appends the instance label. Stripping it would be a no-op that reads as
    coverage. The same goes for any annotation `crds.additionalAnnotations` would
    contribute: at the pinned defaults it contributes none.

  MARIADB NEEDS NO LABEL STRIPS AT ALL, and that asymmetry is stated rather than
  smoothed over: `metadata.labels` is absent from every one of the twelve. The
  KEDA branch has six deletions and the mariadb branch has one.

  NOT `spec.versions` either, and the reason is the failure mode: a list of served
  version names is unchanged by a schema edit WITHIN a version, and a newer
  controller writing a field a stale CRD's schema rejects is exactly the drift this
  gate exists to catch. The digest covers the whole document, schemas included.

THE THREE ASSERTIONS, AND THE THREE RED CASES THAT EACH REDDEN A DIFFERENT ONE.
The count as an EQUALITY at a literal 18; SET equality on the names; and
PER-DOCUMENT DIGEST equality. They are three rather than one because each is blind
to what the others catch — a schema edit leaves the count at 18 and the names
unmoved, and an upstream that ADDS a CRD leaves the vendored count at 18 while the
upstream side is 19. Each red case below asserts WHICH assertion it reddened, not
merely that the gate failed: three red cases that all trip the same assertion prove
one gate rather than three.

`compared == 18` IS AN EQUALITY AND NEVER `> 0`. A gate that compared zero
documents and passed is the failure the count exists to catch, and `> 0` only
catches the zero — an equality catches 17 as well, which is the shape an
accidentally-deleted vendored file takes. The 18 is a LITERAL here, in this
repository's convention, because a number derived from the render agrees with
whatever the render happens to be.

WHAT THIS GATE DOES NOT PROVE. It proves the vendored bytes match the PINNED
chart. It says nothing about whether the pin is CURRENT — an operator three
versions behind is perfectly self-consistent and this gate is green. That half is
step 5 of `plans/the-operators-toggle.md`, and it is a different mechanism.

Run: python3 -m pytest scripts/tests/ -q
"""

from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import tarfile
from dataclasses import dataclass
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parents[2]
CHART = REPO / "chart"
VENDORED = CHART / "templates" / "vendored-crds"

# ── WHAT THE GATE READS, AND FROM WHERE ──────────────────────────────────────
# The `# Source:` prefix helm prints for this chart's own vendored templates. It
# is the PRIMARY filter, for the reason the module docstring measures: filtering
# on `kind` alone keeps 27 documents and asserts 18.
SOURCE_PREFIX = "platform/templates/vendored-crds/"

# The one render the vendored side is taken from. NO per-operator sub-key, because
# `compared == 18` is an equality over a FIXED render and a sub-key moves it.
VENDORED_RENDER = ("--set", "operators.create=true")

# ── WHAT IS EXPECTED, ALL LITERALS ───────────────────────────────────────────
# ADR-0792's condition 2 is that the extracted set is ENUMERATED and bounded. This
# is that enumeration, and it is what makes the set assertion an assertion rather
# than a tautology over whatever the render produced.
EXPECTED_COMPARED = 18

EXPECTED_KEDA_NAMES = frozenset(
    {
        "cloudeventsources.eventing.keda.sh",
        "clustercloudeventsources.eventing.keda.sh",
        "clustertriggerauthentications.keda.sh",
        "scaledjobs.keda.sh",
        "scaledobjects.keda.sh",
        "triggerauthentications.keda.sh",
    }
)

EXPECTED_MARIADB_NAMES = frozenset(
    {
        f"{plural}.k8s.mariadb.com"
        for plural in (
            "backups",
            "connections",
            "databases",
            "externalmariadbs",
            "grants",
            "mariadbs",
            "maxscales",
            "physicalbackups",
            "pointintimerecoveries",
            "restores",
            "sqljobs",
            "users",
        )
    }
)

# The CROSS-CHECK, not the filter. Three groups, because KEDA splits its six over
# two of them.
EXPECTED_GROUPS = frozenset({"keda.sh", "eventing.keda.sh", "k8s.mariadb.com"})

# The line ADR-0792's condition 3 asks this gate to print. A LITERAL on this side;
# every number and version in the line the gate builds is read off the render and
# off `chart/Chart.yaml`. Asserted rather than only printed, because
# `pytest -q` — which is what the pre-commit hook runs — swallows a passing test's
# stdout, and a line nobody reads is the weak form of the condition.
EXPECTED_LINE = (
    "vendored-crds: compared 18 CRDs — 6 against keda 2.20.2, "
    "12 against mariadb-operator-crds 26.6.0"
)

# The annotation the whole extraction exists to add. Stripped before the digest, so
# NOTHING ELSE IN THIS FILE WOULD NOTICE ITS ABSENCE — hence its own test.
KEEP_ANNOTATION = "helm.sh/resource-policy"
KEEP_VALUE = "keep"

# ── RED CASE 3'S UPSTREAM VERSION, MEASURED RATHER THAN CHOSEN ───────────────
# `plans/the-operators-toggle.md` deliberately names no version here and says the
# build must render candidates and take the nearest one whose CRD SET differs from
# the pin. Measured 2026-09-25 on helm v4.3.0, rendering each candidate with
# `--set crds.install=true` and taking the `metadata.name` set:
#
#   2.21.0  6 names, identical to the pin      (upward, nothing differs)
#   2.20.1  6 names, identical to the pin
#   2.19.0  6 names, identical
#   2.18.0  6 names, identical
#   2.17.0  6 names, identical
#   2.16.1  6 names, identical
#   2.16.0  6 names, identical      <- the boundary is here
#   2.15.2  5 names, MISSING `clustercloudeventsources.eventing.keda.sh`
#
# So 2.15.2 is the nearest version below the pin whose set differs, and the one
# missing name is what red case 3 asserts the gate reports.
RED_KEDA_VERSION = "2.15.2"
RED_KEDA_MISSING = "clustercloudeventsources.eventing.keda.sh"

# The render-count proofs of this step, from the plan's step 2. LITERALS.
EXPECTED_OPERATORS_OBJECTS = 183
EXPECTED_OPERATORS_CRDS = 27
EXPECTED_MARIADB_ONLY_OBJECTS = 154
EXPECTED_MARIADB_ONLY_CRDS = 21
EXPECTED_KEDA_ONLY_OBJECTS = 29
EXPECTED_KEDA_ONLY_CRDS = 6


@dataclass(frozen=True, kw_only=True)
class UpstreamSet:
    """One vendored set, and everything needed to render the chart it came from."""

    key: str
    dependency: str
    release: str
    settings: tuple[str, ...]
    # The subchart that actually holds the CRDs, when it is not the dependency
    # itself. mariadb's twelve live in `mariadb-operator-crds`, which
    # `mariadb-operator` pulls in behind its own `crds.enabled`.
    crd_subchart: str | None
    strip_labels: tuple[str, ...]
    expected_names: frozenset[str]


KEDA = UpstreamSet(
    key="keda",
    dependency="keda",
    release="keda",
    settings=("--set", "crds.install=true"),
    crd_subchart=None,
    strip_labels=(
        "helm.sh/chart",
        "app.kubernetes.io/version",
        "app.kubernetes.io/managed-by",
        "app.kubernetes.io/name",
        "app.kubernetes.io/part-of",
    ),
    expected_names=EXPECTED_KEDA_NAMES,
)

MARIADB = UpstreamSet(
    key="mariadb",
    dependency="mariadb-operator",
    release="mariadb-operator",
    settings=("--set", "crds.enabled=true"),
    crd_subchart="mariadb-operator-crds",
    strip_labels=(),
    expected_names=EXPECTED_MARIADB_NAMES,
)

SETS: tuple[UpstreamSet, ...] = (KEDA, MARIADB)

# Which set a document belongs to, by its API group. The groups come off the
# rendered documents; the mapping is written here so a document in an unexpected
# group is unattributable rather than silently filed under one of the two.
GROUP_OWNER = {
    "keda.sh": KEDA,
    "eventing.keda.sh": KEDA,
    "k8s.mariadb.com": MARIADB,
}


@dataclass(frozen=True, kw_only=True)
class Comparison:
    """What one run of the gate examined, and everything it found wrong."""

    compared: int
    vendored_names: dict[str, frozenset[str]]
    upstream_names: dict[str, frozenset[str]]
    versions: dict[str, str]
    digest_failures: tuple[str, ...]
    set_failures: tuple[str, ...]
    group_failures: tuple[str, ...]
    line: str

    @property
    def failures(self) -> tuple[str, ...]:
        return self.digest_failures + self.set_failures + self.group_failures


def helm(*arguments: str) -> subprocess.CompletedProcess[str]:
    binary = shutil.which("helm")
    # NOT A SKIP, and ADR-0650 is why. Same wording as this repository's four
    # sibling suites, which made the same decision for the same reason.
    assert binary, (
        "helm is not on PATH. This suite renders the chart, and so does the "
        "`helm lint and render` pre-commit hook — install helm rather than "
        "letting either report a pass it did not earn."
    )
    return subprocess.run([binary, *arguments], capture_output=True, text=True)


def render(chart: Path, release: str, *arguments: str) -> str:
    result = helm("template", release, str(chart), *arguments)
    assert result.returncode == 0, result.stderr
    return result.stdout


def documents(stdout: str) -> list[tuple[str | None, dict]]:
    """(the `# Source:` path, the document) for every manifest in a render. PURE.

    The source path is read out of the comment helm prints above each manifest,
    which is the only place the render says WHICH template produced a document.
    """
    found: list[tuple[str | None, dict]] = []
    for chunk in stdout.split("\n---\n"):
        source: str | None = None
        for line in chunk.splitlines():
            if line.startswith("# Source: "):
                source = line[len("# Source: ") :].strip()
                break
        document = yaml.safe_load(chunk)
        if isinstance(document, dict) and document.get("apiVersion"):
            found.append((source, document))
    return found


def crds(stdout: str) -> list[dict]:
    return [
        document
        for _, document in documents(stdout)
        if document.get("kind") == "CustomResourceDefinition"
    ]


def vendored_documents(chart: Path) -> list[dict]:
    """Every CRD the chart renders FROM `templates/vendored-crds/`, and no other."""
    return [
        document
        for source, document in documents(render(chart, "platform", *VENDORED_RENDER))
        if source is not None
        and source.startswith(SOURCE_PREFIX)
        and document.get("kind") == "CustomResourceDefinition"
    ]


def declared_dependencies(chart: Path) -> dict[str, dict]:
    """The `dependencies:` block of a chart's `Chart.yaml`, by name. PURE."""
    declared = yaml.safe_load((chart / "Chart.yaml").read_text())
    return {entry["name"]: entry for entry in declared.get("dependencies", [])}


def upstream_tarball(chart: Path, name: str, version: str) -> Path:
    """The resolved subchart `helm dependency build` left in `charts/`.

    NOT A NETWORK FETCH, and that is deliberate: the pinned tarball is already on
    disk because every render in this repository needs it. A missing one is a
    setup fault with a named fix, never a skip.
    """
    tarball = chart / "charts" / f"{name}-{version}.tgz"
    assert tarball.is_file(), (
        f"{tarball} is missing. `chart/charts/` is ignored by git and resolved at "
        f"render time — run `helm dependency build {chart}` rather than letting "
        f"this gate report a pass over a chart it could not read."
    )
    return tarball


def crd_chart_version(tarball: Path, upstream: UpstreamSet, pinned: str) -> str:
    """The version of the chart the CRDs actually come from. READ, not assumed.

    For KEDA that is the pinned dependency itself. For mariadb the twelve live in
    `mariadb-operator-crds`, a subchart `mariadb-operator` pins in its own
    `Chart.yaml`, and printing the parent's digit would be a guess that happens to
    be right today.
    """
    if upstream.crd_subchart is None:
        return pinned
    with tarfile.open(tarball) as archive:
        member = archive.extractfile(f"{upstream.dependency}/Chart.yaml")
        assert member is not None, f"{tarball} carries no {upstream.dependency}/Chart.yaml"
        declared = yaml.safe_load(member.read().decode())
    for entry in declared.get("dependencies", []):
        if entry["name"] == upstream.crd_subchart:
            return str(entry["version"])
    raise AssertionError(
        f"{upstream.dependency} {pinned} declares no {upstream.crd_subchart} "
        f"dependency, so the version of the vendored CRDs cannot be read"
    )


def stripped(document: dict, strip_labels: tuple[str, ...]) -> dict:
    """The document with the fields that legitimately differ deleted. PURE."""
    copy = json.loads(json.dumps(document))
    metadata = copy.get("metadata", {})
    annotations = metadata.get("annotations")
    if isinstance(annotations, dict):
        annotations.pop(KEEP_ANNOTATION, None)
        if not annotations:
            metadata.pop("annotations", None)
    labels = metadata.get("labels")
    if isinstance(labels, dict):
        for label in strip_labels:
            labels.pop(label, None)
        if not labels:
            metadata.pop("labels", None)
    return copy


def digest(document: dict, strip_labels: tuple[str, ...]) -> str:
    canonical = json.dumps(
        stripped(document, strip_labels), sort_keys=True, separators=(",", ":")
    )
    return hashlib.sha256(canonical.encode()).hexdigest()


def by_name(rendered: list[dict]) -> dict[str, dict]:
    return {document["metadata"]["name"]: document for document in rendered}


def owner(document: dict) -> UpstreamSet | None:
    return GROUP_OWNER.get(document.get("spec", {}).get("group", ""))


def compare(chart: Path) -> Comparison:
    """Run the gate over one chart directory and report everything it found.

    Returns rather than asserts, so each red case below can say WHICH of the three
    assertions it reddened instead of only that the gate failed.
    """
    vendored = vendored_documents(chart)
    pins = declared_dependencies(chart)

    vendored_by_set: dict[str, dict[str, dict]] = {upstream.key: {} for upstream in SETS}
    group_failures: list[str] = []
    for document in vendored:
        name = document["metadata"]["name"]
        group = document.get("spec", {}).get("group", "")
        holder = owner(document)
        if holder is None:
            group_failures.append(
                f"vendored-crds: {name} belongs to API group {group!r}, which is "
                f"none of {sorted(EXPECTED_GROUPS)} — a vendored document in an "
                f"unexpected group is drift the name set cannot see"
            )
            continue
        vendored_by_set[holder.key][name] = document

    versions: dict[str, str] = {}
    upstream_names: dict[str, frozenset[str]] = {}
    vendored_names: dict[str, frozenset[str]] = {}
    digest_failures: list[str] = []
    set_failures: list[str] = []

    for upstream in SETS:
        entry = pins.get(upstream.dependency)
        assert entry is not None, (
            f"chart/Chart.yaml declares no {upstream.dependency} dependency, so "
            f"this gate has no pin to render — the pins are read from there and "
            f"nowhere else, so a second copy cannot drift from them"
        )
        pinned = str(entry["version"])
        tarball = upstream_tarball(chart, upstream.dependency, pinned)
        reported_version = crd_chart_version(tarball, upstream, pinned)
        reported_name = upstream.crd_subchart or upstream.dependency
        versions[upstream.key] = f"{reported_name} {reported_version}"

        upstream_by_name = by_name(
            crds(render(tarball, upstream.release, *upstream.settings))
        )
        mine = vendored_by_set[upstream.key]
        upstream_names[upstream.key] = frozenset(upstream_by_name)
        vendored_names[upstream.key] = frozenset(mine)

        for name in sorted(set(mine) - set(upstream_by_name)):
            set_failures.append(
                f"vendored-crds: {name} is vendored but ABSENT from the "
                f"{reported_name} {reported_version} render — re-vendor or delete it"
            )
        for name in sorted(set(upstream_by_name) - set(mine)):
            set_failures.append(
                f"vendored-crds: {name} is in the {reported_name} "
                f"{reported_version} render but is NOT vendored — the upstream set "
                f"moved and `chart/templates/vendored-crds/` did not"
            )
        for name in sorted(set(mine) & set(upstream_by_name)):
            ours = digest(mine[name], upstream.strip_labels)
            theirs = digest(upstream_by_name[name], upstream.strip_labels)
            if ours != theirs:
                digest_failures.append(
                    f"vendored-crds: {name} DIFFERS from the {reported_name} "
                    f"{reported_version} render (vendored {ours[:12]}, upstream "
                    f"{theirs[:12]}) — re-vendor it"
                )

    compared = sum(len(names) for names in vendored_names.values())
    line = (
        f"vendored-crds: compared {compared} CRDs — "
        f"{len(vendored_names[KEDA.key])} against {versions[KEDA.key]}, "
        f"{len(vendored_names[MARIADB.key])} against {versions[MARIADB.key]}"
    )
    return Comparison(
        compared=compared,
        vendored_names=vendored_names,
        upstream_names=upstream_names,
        versions=versions,
        digest_failures=tuple(digest_failures),
        set_failures=tuple(set_failures),
        group_failures=tuple(group_failures),
        line=line,
    )


def chart_copy(destination: Path) -> Path:
    """A whole copy of the chart, `charts/` included, for a red case to mutate."""
    copy = destination / "chart"
    shutil.copytree(CHART, copy)
    return copy


def objects(stdout: str) -> int:
    return sum(1 for line in stdout.splitlines() if line.startswith("kind:"))


def crd_objects(stdout: str) -> int:
    return sum(
        1
        for line in stdout.splitlines()
        if line == "kind: CustomResourceDefinition"
    )


# ═══ THE GREEN CASE, AND WHAT IT PRINTS ══════════════════════════════════════


def test_the_vendored_crds_match_the_pinned_upstream_renders(capsys):
    """THE GATE. All three assertions, on the tree as it stands.

    The count is asserted as an EQUALITY against a literal, never as `> 0`: a gate
    that compared zero documents and passed is the failure the count exists to
    catch, and `> 0` catches only the zero.
    """
    comparison = compare(CHART)

    assert comparison.failures == (), "\n".join(comparison.failures)
    assert comparison.compared == EXPECTED_COMPARED, (
        f"expected {EXPECTED_COMPARED} vendored CRDs in the render, compared "
        f"{comparison.compared}: {sorted(comparison.vendored_names[KEDA.key] | comparison.vendored_names[MARIADB.key])}"
    )
    assert comparison.line == EXPECTED_LINE, (
        f"the gate printed {comparison.line!r}, expected {EXPECTED_LINE!r}"
    )

    with capsys.disabled():
        print(comparison.line)


def test_the_vendored_set_is_the_eighteen_adr_0792_enumerates():
    """ADR-0792's condition 2: the extracted set is ENUMERATED and bounded.

    Against the literals above rather than against the render, which is what makes
    this an assertion and not a tautology over whatever the chart happens to hold.
    """
    comparison = compare(CHART)

    assert comparison.vendored_names[KEDA.key] == EXPECTED_KEDA_NAMES
    assert comparison.vendored_names[MARIADB.key] == EXPECTED_MARIADB_NAMES
    assert (
        len(EXPECTED_KEDA_NAMES) + len(EXPECTED_MARIADB_NAMES) == EXPECTED_COMPARED
    ), "the enumeration and the count disagree, so one of them was edited alone"


def test_every_vendored_document_carries_the_keep_annotation():
    """The annotation the whole extraction exists to add.

    THE DIGEST STRIPS IT ON BOTH SIDES, so nothing else in this file would notice
    it missing — a vendored copy with no `helm.sh/resource-policy: keep` compares
    equal to upstream, passes the count, passes the set, and buys nothing at all.
    This is the only gate that reads it.
    """
    rendered = vendored_documents(CHART)
    assert len(rendered) == EXPECTED_COMPARED

    unprotected = sorted(
        document["metadata"]["name"]
        for document in rendered
        if document["metadata"].get("annotations", {}).get(KEEP_ANNOTATION)
        != KEEP_VALUE
    )
    assert unprotected == [], (
        f"{len(unprotected)} vendored CRDs carry no "
        f"{KEEP_ANNOTATION}: {KEEP_VALUE}: {unprotected}"
    )


def test_the_upstream_documents_carry_no_such_annotation():
    """ADR-0792's condition 1, asserted rather than quoted.

    The property cannot exist at release time BECAUSE upstream does not ship it and
    resolution copies upstream bytes faithfully. The day either chart starts
    shipping it, this test goes red — and that red is the revisit trigger firing,
    not a defect: condition 4 says the copies should then be DELETED rather than
    maintained.
    """
    pins = declared_dependencies(CHART)
    protected: list[str] = []
    for upstream in SETS:
        pinned = str(pins[upstream.dependency]["version"])
        tarball = upstream_tarball(CHART, upstream.dependency, pinned)
        for document in crds(render(tarball, upstream.release, *upstream.settings)):
            if document["metadata"].get("annotations", {}).get(KEEP_ANNOTATION):
                protected.append(document["metadata"]["name"])

    assert protected == [], (
        f"{sorted(protected)} now ship {KEEP_ANNOTATION} upstream. ADR-0792's "
        f"revisit trigger has fired: delete the vendored copies rather than "
        f"renewing them."
    )


# ═══ THE THREE RED CASES, EACH REDDENING A DIFFERENT ASSERTION ═══════════════


def test_editing_a_vendored_schema_reddens_the_digest_and_nothing_else(tmp_path):
    """RED CASE 1 — drift WITHIN a schema, which the count and the set cannot see.

    Deleting a `properties` entry from one vendored CRD leaves 18 documents with
    18 unchanged names, so a gate without the per-document digest is green on a
    CRD whose schema now rejects a field the pinned controller writes.

    The mutation has to unwrap the guard first: these files are helm templates —
    which is why `check-yaml` excludes `chart/templates/` — so the body is sliced
    out from between the `{{- if (dig ...) }}` line and the `{{- end }}`, parsed,
    edited and re-wrapped.
    """
    copy = chart_copy(tmp_path)
    target = copy / "templates" / "vendored-crds" / "keda-scaledobjects.yaml"
    removed = delete_one_schema_property(target)

    comparison = compare(copy)

    assert removed, "the mutation deleted nothing, so this red case proves nothing"
    assert comparison.compared == EXPECTED_COMPARED, (
        "the count must be UNMOVED here — if it moved, this case is red for red "
        "case 2's reason and the digest assertion is still unexercised"
    )
    assert comparison.set_failures == (), (
        f"the names must be unmoved here: {comparison.set_failures}"
    )
    assert comparison.group_failures == ()
    assert len(comparison.digest_failures) == 1, comparison.digest_failures
    message = comparison.digest_failures[0]
    assert "scaledobjects.keda.sh" in message, message
    assert "DIFFERS" in message, message


def test_deleting_a_vendored_file_reddens_the_count(tmp_path):
    """RED CASE 2 — the count equality, and the name it reports.

    This is the shape an accidentally-deleted vendored file takes, and it is why
    the count is an equality: `compared > 0` is green at 17.
    """
    copy = chart_copy(tmp_path)
    (copy / "templates" / "vendored-crds" / "mariadb-users.yaml").unlink()

    comparison = compare(copy)

    assert comparison.compared == EXPECTED_COMPARED - 1, comparison.line
    assert comparison.compared != EXPECTED_COMPARED
    assert comparison.digest_failures == (), (
        f"the surviving 17 must still match: {comparison.digest_failures}"
    )
    assert len(comparison.set_failures) == 1, comparison.set_failures
    message = comparison.set_failures[0]
    assert "users.k8s.mariadb.com" in message, message
    assert "is NOT vendored" in message, message
    assert "compared 17 CRDs" in comparison.line


def test_moving_the_upstream_pin_reddens_the_name_set(tmp_path):
    """RED CASE 3 — the UPSTREAM side moves, which is the real version bump.

    Genuinely different from red case 2: that one moves the vendored side and
    this one moves upstream, which is the direction an operator release actually
    travels. `keda` 2.15.2 is the nearest version below the 2.20.2 pin whose CRD
    SET differs — the measurement is recorded beside `RED_KEDA_VERSION` — and it
    is missing exactly one of the six.

    THIS CASE FETCHES FROM THE NETWORK, because the moved pin is by construction
    not the one `helm dependency build` resolved. The fetch is asserted on its own,
    with its own message, so a registry outage reads as a failed fetch rather than
    as drift.

    A FIVE-MINOR MOVE ALSO MOVES FIVE DIGESTS, and that is asserted here rather
    than tolerated: the schemas of the CRDs that survive the move changed too, so a
    run reporting ONLY the missing name would mean the digest assertion had gone
    blind. The assertion this case exists for is the SET one, and it is singled out
    by count and by message.
    """
    copy = chart_copy(tmp_path)
    declared = yaml.safe_load((copy / "Chart.yaml").read_text())
    pinned = ""
    for entry in declared["dependencies"]:
        if entry["name"] == KEDA.dependency:
            pinned = str(entry["version"])
            entry["version"] = RED_KEDA_VERSION
    assert pinned and pinned != RED_KEDA_VERSION, (
        f"chart/Chart.yaml pins keda at {pinned!r} and this red case moves it to "
        f"{RED_KEDA_VERSION!r} — a case that moves the pin to itself proves nothing"
    )
    (copy / "Chart.yaml").write_text(yaml.safe_dump(declared, sort_keys=False))

    # The resolved tarball must move with the pin, or `helm template` refuses the
    # whole chart and nothing is compared.
    (copy / "charts" / f"{KEDA.dependency}-{pinned}.tgz").unlink()
    fetched = helm(
        "pull",
        KEDA.dependency,
        "--repo",
        str(declared_dependencies(copy)[KEDA.dependency]["repository"]),
        "--version",
        RED_KEDA_VERSION,
        "--destination",
        str(copy / "charts"),
    )
    assert fetched.returncode == 0, (
        f"COULD NOT FETCH keda {RED_KEDA_VERSION}, so this red case ran against "
        f"nothing — this is a fetch failure and NOT drift: {fetched.stderr}"
    )

    comparison = compare(copy)

    assert comparison.compared == EXPECTED_COMPARED, (
        "the VENDORED side is untouched here, so it must still be 18 — a moved "
        "count means this case reddened red case 2's assertion instead"
    )
    assert comparison.upstream_names[KEDA.key] == EXPECTED_KEDA_NAMES - {
        RED_KEDA_MISSING
    }, sorted(comparison.upstream_names[KEDA.key])
    assert len(comparison.set_failures) == 1, comparison.set_failures
    message = comparison.set_failures[0]
    assert RED_KEDA_MISSING in message, message
    assert "ABSENT from the" in message, message
    assert f"keda {RED_KEDA_VERSION}" in message, message
    assert comparison.digest_failures != (), (
        "the five surviving KEDA schemas moved across five minor versions, so a "
        "run that reported no digest failure would mean that assertion had gone "
        "blind rather than that nothing changed"
    )


def delete_one_schema_property(path: Path) -> str:
    """Delete one `spec` property from a vendored CRD's schema, in place. Returns it.

    The guard is sliced off and re-attached rather than parsed, because a helm
    template is not YAML.
    """
    text = path.read_text()
    opening = '{{- if (include "platform.operator-create"'
    closing = "{{- end }}\n"
    start = text.index(opening)
    head = text[: text.index("\n", start) + 1]
    assert text.endswith(closing), f"{path} does not end with the guard's {closing!r}"
    body = text[len(head) : -len(closing)]

    document = yaml.safe_load(body)
    schema = document["spec"]["versions"][0]["schema"]["openAPIV3Schema"]
    properties = schema["properties"]["spec"]["properties"]
    removed = sorted(properties)[0]
    del properties[removed]

    path.write_text(
        head
        + yaml.safe_dump(document, sort_keys=False, width=1000, allow_unicode=True)
        + closing
    )
    return removed


# ═══ THE GUARD THE VENDORED FILES CARRY, AND THE PAIR THAT DISCRIMINATES ═════


def test_the_chart_defaults_render_nothing():
    """A REGRESSION assertion, and labelled so nobody promotes it to a proof.

    R1 rendered zero objects BEFORE any of this landed, so this passes identically
    whether the eighteen files exist or not. It carries none of this step's weight;
    what it guarantees is that the defaults are unmoved, which is what the guards
    are there for.
    """
    assert objects(render(CHART, "platform")) == 0


def test_the_operators_render_carries_the_eighteen_vendored_crds():
    """183 objects and 27 CRDs, and BOTH numbers are the point.

    27 rather than 18 because cert-manager contributes 6 and Argo CD 3 as ordinary
    subchart templates — which is why this gate's filter is the `# Source:` path
    and not `kind`. NO `--api-versions`: this render passes none, so a check that
    became reachable here would refuse rather than pass quietly.
    """
    result = helm("template", "platform", str(CHART), *VENDORED_RENDER)
    assert result.returncode == 0, result.stderr
    assert objects(result.stdout) == EXPECTED_OPERATORS_OBJECTS
    assert crd_objects(result.stdout) == EXPECTED_OPERATORS_CRDS
    assert len(vendored_documents(CHART)) == EXPECTED_COMPARED


def test_each_vendored_set_travels_with_its_own_operator():
    """THE PROOF OF THE PER-FILE GUARD, and the one a directory guard fails.

    `{{- if .Values.operators.create }}` over the whole directory passes every
    other assertion in this file and fails only this pair. Measured on the scratch
    chart the plan was written against, the wrong guard gives:

        operators.create=true,  operators.keda.create=false  ->  160 objects, 27 CRDs
        operators.create=false, operators.keda.create=true   ->   23 objects,  0 CRDs

    The second is the worse one: `keda.crds.install` is false because `platform`
    owns those six, so a KEDA release whose vendored six are suppressed has NO CRDs
    from either side and every ScaledObject in the cluster fails on a kind the API
    server has never heard of.

    `or` does not fix it either, because `or .Values.operators.keda.create
    .Values.operators.create` is TRUE in the first row, where helm's own
    `condition:` — which reads the first valid path and ignores the rest — is
    false. `dig` with `operators.create` as the fallback is the expression that
    mirrors helm.
    """
    mariadb_only = render(
        CHART,
        "platform",
        "--set",
        "operators.create=true",
        "--set",
        "operators.keda.create=false",
    )
    keda_only = render(
        CHART,
        "platform",
        "--set",
        "operators.create=false",
        "--set",
        "operators.keda.create=true",
    )

    assert objects(mariadb_only) == EXPECTED_MARIADB_ONLY_OBJECTS
    assert crd_objects(mariadb_only) == EXPECTED_MARIADB_ONLY_CRDS
    assert objects(keda_only) == EXPECTED_KEDA_ONLY_OBJECTS
    assert crd_objects(keda_only) == EXPECTED_KEDA_ONLY_CRDS

    # And the sets travel with the right operator, which the counts alone only
    # imply. The KEDA-only render carries KEDA's six and nothing of mariadb's.
    kept = {
        document["metadata"]["name"]
        for source, document in documents(keda_only)
        if source is not None and source.startswith(SOURCE_PREFIX)
    }
    assert kept == EXPECTED_KEDA_NAMES, sorted(kept)


def test_a_sub_key_moves_the_count_the_gate_pins_itself_to():
    """WHY `VENDORED_RENDER` NAMES NO PER-OPERATOR SUB-KEY.

    `compared == 18` is an equality over a FIXED render. Under
    `operators.keda.create=false` the same `# Source:` filter keeps 12, so a gate
    that let a sub-key reach its render would be red on a tree nobody touched.
    This is the measurement behind that sentence rather than the sentence.
    """
    narrowed = render(
        CHART,
        "platform",
        *VENDORED_RENDER,
        "--set",
        "operators.keda.create=false",
    )
    kept = [
        document
        for source, document in documents(narrowed)
        if source is not None and source.startswith(SOURCE_PREFIX)
    ]
    assert len(kept) == len(EXPECTED_MARIADB_NAMES)
    assert len(kept) != EXPECTED_COMPARED


def test_every_vendored_file_is_guarded_by_its_own_dependency_condition():
    """The guard is read off each file, not inferred from the render.

    A render proves what the guards DO at the values it was given; this proves
    every file carries one at all, so a nineteenth file added without a guard is
    caught before somebody has to notice a count.
    """
    expected = {
        "keda": '{{- if (include "platform.operator-create" (dict "context" $ "operator" "keda")) }}',
        "mariadb": '{{- if (include "platform.operator-create" (dict "context" $ "operator" "mariadbOperator")) }}',
    }
    files = sorted(VENDORED.glob("*.yaml"))
    assert len(files) == EXPECTED_COMPARED, [path.name for path in files]

    unguarded = [
        path.name
        for path in files
        if expected[path.name.split("-", 1)[0]] not in path.read_text()
    ]
    assert unguarded == [], (
        f"{unguarded} carry no per-file guard mirroring their dependency's "
        f"`condition:` — a directory-wide `operators.create` guard applies a CRD "
        f"set to a cluster running neither operator"
    )


def test_every_vendored_file_names_the_adr_and_its_revisit_trigger():
    """ADR-0792's condition 4, in the place whoever re-vendors will actually read.

    The bound and the revisit trigger live in the decision; this asserts each copy
    carries the pointer, so the next builder learns why the file exists before
    renewing it out of habit.
    """
    missing = [
        path.name
        for path in sorted(VENDORED.glob("*.yaml"))
        for text in [path.read_text()]
        if not ("ADR-0792" in text and "revisit trigger" in text and "ADR-0787" in text)
    ]
    assert missing == [], (
        f"{missing} do not name ADR-0787, ADR-0792 and the revisit trigger that "
        f"would DELETE them"
    )


def test_the_upstream_tarball_is_resolved_rather_than_fetched(tmp_path):
    """A missing `charts/` is a named setup fault, never a skip and never a pass.

    ADR-0650: a gate that reports success having examined nothing is the failure
    this estate has already shipped. Deleting the resolved tarball must abort with
    the command that fixes it.
    """
    copy = chart_copy(tmp_path)
    pins = declared_dependencies(copy)
    pinned = str(pins[KEDA.dependency]["version"])
    (copy / "charts" / f"{KEDA.dependency}-{pinned}.tgz").unlink()

    try:
        compare(copy)
    except AssertionError as failure:
        assert "helm dependency build" in str(failure), str(failure)
    else:
        raise AssertionError(
            "the resolved tarball was deleted and the gate compared on regardless"
        )
