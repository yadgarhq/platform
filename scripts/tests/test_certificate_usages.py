"""THE USAGES WALL, PORTED FROM `yadgarhq/actions` AND RUN AT RENDER TIME.

WHAT THIS PORTS AND WHY IT MOVES HERE. `yadgarhq/actions` `hooks/certificate_usages.py`
(pinned at v1.20.1 in this repository's `.pre-commit-config.yaml`, and unchanged at
`origin/main` when this file was written) walks a consumer's committed YAML by hand
and judges every `kind: Certificate` it finds: `judge()` at lines 327-356 is the rule,
restated here verbatim in `usage_failures()` below. THAT HOOK ALSO SKIPS EVERY
TEMPLATED FILE — its own docstring, "WHAT IT DOES NOT CHECK": "A TEMPLATED FILE IS NOT
READ, AND THE COUNT SAYS SO. Any file carrying a `{{` is skipped". Every Certificate
this chart renders is a Helm template, so the hook has never once judged one — it is
not wired into this repository's `.pre-commit-config.yaml` at all, and could not be:
templated files are exactly what it cannot read. `platform`'s leaves render from
`internalCA.create` + `certificates.create` + `edgeTLS.create`
(`chart/templates/internal-ca.yaml`, `chart/templates/certificates.yaml`,
`chart/templates/edge-certificate.yaml`), so the wall has to run AFTER `helm template`
resolves the templates into plain objects, which is what this file does — the same
`render()` shape `test_ladder.py` already uses, over the same `example/values.yaml`.

THE RULE ITSELF, PORTED WITHOUT THE PARSER. The hook hand-parses YAML text because it
reads a Helm template's SOURCE, which no real YAML parser can do (`{{ .Values.x }}`
is not a scalar). This suite reads a RENDER instead — `helm template`'s stdout is
concrete YAML, already `yaml.safe_load_all`-clean — so the hand-written scanner
(`significant()`, `read_usages()`, the regexes) has nothing to do here and is not
ported: PyYAML gives `spec.isCA` and `spec.usages` directly. What is ported is
`judge()`'s VERDICT, unchanged:

  * `isCA: true`   names `server auth` OR `client auth`  -> refused (an authority
                    signs; it neither answers nor dials).
  * otherwise      names BOTH                            -> refused (one authority
                    signs both directions here; a leaf naming both collapses the
                    wall that keeps a caller from replaying a serving credential).
  * otherwise      names NEITHER                         -> refused (cert-manager
                    then issues a leaf with no extended key usage, which webpki
                    accepts in BOTH directions per the hook's own docstring — an
                    omission is WIDER than naming both, not narrower).
  * otherwise (exactly one of the two, on a leaf)         -> passes. The hook's own
                    "WHAT IT DOES NOT CHECK" section is explicit that WHICH single
                    direction a leaf names is not this wall's question — "a hook
                    that pretended to know would be the 'two definitions of clean'
                    failure this estate keeps refusing" — and this port keeps that
                    boundary rather than widening it.

FLOORS, BUT NOT THE HOOK'S FLOORS. The hook's `MINIMUM_CERTIFICATES = 2` and
`MINIMUM_LEAVES = 2` are floors for AN UNKNOWN REPOSITORY it has never rendered —
low enough that any real estate clears them by a wide margin, because the hook's job
is to notice "a glob matched nothing" rather than "this exact chart's count moved".
This suite renders one exact chart with one exact values file, and the numbers below
are MEASURED against it: 12 Certificates (the CA root, ten internal leaves, the edge
leaf) and 11 leaves (every one of the twelve except the CA root). `>=` rather than
`==`, following `MINIMUM_CERTIFICATES`/`MINIMUM_LEAVES`'s own reasoning restated at
this chart's own count: adding a twelfth leaf is a legitimate change and must not
redden this suite, but a render that silently drops one below what is measured today
must.

Tests: `python3 -m pytest scripts/tests/test_certificate_usages.py -q`.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parents[2]
CHART = REPO / "chart"
ADOPTER_VALUES = REPO / "example" / "values.yaml"

# Same set `test_ladder.py` and this chart's own render checks require — a bare
# `helm template` never populates a CRD-backed group in `.Capabilities.APIVersions`,
# so every render below would be refused by `chart/templates/render-checks.yaml`
# before a single Certificate exists to examine.
DECLARED_API_VERSIONS = ("cert-manager.io/v1", "gateway.envoyproxy.io/v1alpha1")
API_VERSIONS = tuple(
    part for group in DECLARED_API_VERSIONS for part in ("--api-versions", group)
)

# `hooks/certificate_usages.py:122-123` (yadgarhq/actions, pinned v1.20.1 here and
# unchanged at origin/main). The two directions the wall judges; every other
# extended key usage (`digital signature`, on every leaf in this chart) is inert to
# it, exactly as it is to the hook.
SERVER = "server auth"
CLIENT = "client auth"

# MEASURED against `helm template chart -f example/values.yaml`: 12 Certificate
# objects (the CA root, the ten internal leaves, the edge leaf) and 11 leaves (every
# one of the twelve except the CA root, which the wall exempts by `isCA` rather than
# judging). Literals, not derived from the render they gate — the whole point of a
# floor is that it does not move with the thing it is measuring.
CERTIFICATE_FLOOR = 12
LEAF_FLOOR = 11


def helm(*arguments: str) -> subprocess.CompletedProcess[str]:
    binary = shutil.which("helm")
    # NOT A SKIP (ADR-0650), matching every other suite in this directory: helm
    # absent is this suite's own failure, not license to report a pass it did not
    # earn.
    assert binary, (
        "helm is not on PATH. This suite renders the chart, and so does the "
        "`helm lint and render` pre-commit hook — install helm rather than "
        "letting either report a pass it did not earn."
    )
    return subprocess.run([binary, *arguments], capture_output=True, text=True)


def render(chart: Path, *arguments: str) -> list[dict]:
    result = helm("template", "platform", str(chart), *API_VERSIONS, *arguments)
    assert result.returncode == 0, result.stderr
    return [
        document
        for document in yaml.safe_load_all(result.stdout)
        if isinstance(document, dict) and document.get("apiVersion")
    ]


def certificates(documents: list[dict]) -> list[dict]:
    return [document for document in documents if document.get("kind") == "Certificate"]


def usage_failures(documents: list[dict]) -> list[str]:
    """`judge()`, `hooks/certificate_usages.py:327-356`, restated over parsed specs.

    Reads `spec.isCA` and `spec.usages` straight off the render — no hand parser,
    because this input is already YAML a real parser produced, not Helm template
    source. The verdict is unchanged from the hook: an `isCA` document must name
    neither direction; any other Certificate must name exactly one.
    """
    failures = []
    for document in certificates(documents):
        specification = document.get("spec") or {}
        name = str((document.get("metadata") or {}).get("name"))
        is_ca = bool(specification.get("isCA"))
        named = set(specification.get("usages") or [])
        serves = SERVER in named
        dials = CLIENT in named

        if is_ca:
            if serves or dials:
                failures.append(
                    f"{name}: `isCA: true` and names "
                    f"{'`' + SERVER + '`' if serves else ''}"
                    f"{' and ' if serves and dials else ''}"
                    f"{'`' + CLIENT + '`' if dials else ''}. An authority signs; it "
                    f"neither answers nor dials."
                )
            continue

        if serves and dials:
            failures.append(
                f"{name}: names both `{SERVER}` and `{CLIENT}`. One authority signs "
                f"both directions here, so this list is the whole of what stops a "
                f"leaf that should only answer being replayed as a caller."
            )
        elif not serves and not dials:
            failures.append(
                f"{name}: names neither `{SERVER}` nor `{CLIENT}` "
                f"(usages: {sorted(named) or 'absent'}). cert-manager then issues a "
                f"leaf with no extended key usage, which webpki accepts in BOTH "
                f"directions."
            )
    return failures


def values_file(destination: Path, name: str, body: str) -> Path:
    path = destination / name
    path.write_text(body)
    return path


# ── GREEN: the real render, every leaf named, the wall silent ───────────────────


def test_the_adopter_render_examines_the_measured_count_and_the_wall_holds():
    """The render this chart ships names one direction per leaf and neither on the CA.

    Prints the count examined, the same shape `certificate_usages.py:394-398`
    prints for its own walk, so a reader of `-s` output sees the same two numbers
    the hook would have reported had it been able to read this chart at all.
    """
    documents = render(CHART, "-f", str(ADOPTER_VALUES))
    found = certificates(documents)
    leaves = [
        document for document in found if not (document.get("spec") or {}).get("isCA")
    ]
    print(
        f"certificate-usages: inspected {len(found)} Certificate(s), "
        f"{len(leaves)} of them leaves subject to the `{SERVER}` / `{CLIENT}` wall"
    )

    assert len(found) >= CERTIFICATE_FLOOR, (
        f"expected at least {CERTIFICATE_FLOOR} Certificate objects (measured "
        f"{CERTIFICATE_FLOOR} today: the CA root, the ten internal leaves and the "
        f"edge leaf), found {len(found)}: {sorted(str((d.get('metadata') or {}).get('name')) for d in found)}. "
        f"A render that silently drops a certificate must redden here rather than "
        f"pass having examined less than it used to."
    )
    assert len(leaves) >= LEAF_FLOOR, (
        f"expected at least {LEAF_FLOOR} leaves subject to the wall, found "
        f"{len(leaves)}. Every Certificate here is exempt as an authority, which is "
        f"the shape an issuer rename could reach — it must fail rather than pass."
    )

    failures = usage_failures(documents)
    assert failures == [], "\n".join(failures)


# ── RED 1: certificates.create false collapses the floor ────────────────────────


def test_disabling_the_internal_leaves_reddens_the_certificate_floor(tmp_path):
    """`certificates.create: false` drops ten of twelve Certificates. The floor catches it.

    THE CONSTRUCTED RED CASE FOR THE FLOOR ITSELF: with the ten internal leaves off,
    only the CA root and the edge leaf remain — 2 Certificates, 1 leaf — both well
    under `CERTIFICATE_FLOOR` and `LEAF_FLOOR`. A suite whose floor never moves is
    not a floor; this is what proves it can.
    """
    disabled = values_file(
        tmp_path, "certificates-off.yaml", "certificates:\n  create: false\n"
    )
    documents = render(CHART, "-f", str(ADOPTER_VALUES), "-f", str(disabled))
    found = certificates(documents)
    leaves = [
        document for document in found if not (document.get("spec") or {}).get("isCA")
    ]

    assert len(found) == 2, (
        "this red case is supposed to leave the CA root and the edge leaf only; "
        f"found {len(found)}: {sorted(str((d.get('metadata') or {}).get('name')) for d in found)} — "
        "construct a different disabling override"
    )

    assert len(found) < CERTIFICATE_FLOOR, (
        f"expected the certificate floor to catch {len(found)} < {CERTIFICATE_FLOOR}, "
        f"and it did not — the floor no longer reddens a render that drops the "
        f"internal leaves"
    )
    assert len(leaves) < LEAF_FLOOR, (
        f"expected the leaf floor to catch {len(leaves)} < {LEAF_FLOOR}, and it did "
        f"not — the floor no longer reddens a render that drops the internal leaves"
    )


# ── RED 2: a leaf naming both directions ─────────────────────────────────────────


def test_a_leaf_naming_both_directions_is_refused_and_named(tmp_path):
    """`iam-tls` (server-only) widened to name `client auth` too. `judge()`'s first arm.

    `iam-tls` answers under this estate's one authority; a leaf naming both
    directions is exactly the leaf `judge()` at
    `hooks/certificate_usages.py:344-349` refuses, because the extended key usage
    is the only thing that would then stop a stolen serving certificate being
    replayed as a caller. The override is a single-key map merge onto the values
    file's own `certificates.leaves.iam-tls`, following `test_ladder.py`'s
    `COLLISION` override — `usages:` is a list, so Helm replaces it wholesale
    rather than merging it, and every other key on the leaf (`commonName`,
    `clusterLocalNames`, `renewBefore`) survives untouched.
    """
    override = values_file(
        tmp_path,
        "both-directions.yaml",
        "certificates:\n  leaves:\n    iam-tls:\n      usages: [server auth, client auth]\n",
    )
    documents = render(CHART, "-f", str(ADOPTER_VALUES), "-f", str(override))
    failures = usage_failures(documents)
    message = "\n".join(failures)

    assert failures, "iam-tls named both server auth and client auth and the wall passed"
    assert "iam-tls" in message and "both" in message, message


# ── RED 3: a leaf naming neither direction ───────────────────────────────────────


def test_a_leaf_naming_neither_direction_is_refused_and_named(tmp_path):
    """`iam-tls` stripped to `digital signature` alone. `judge()`'s second arm.

    Omitting both directions is the shape `hooks/certificate_usages.py`'s module
    docstring calls WORSE than naming both: webpki's `KeyUsage::client_auth()` and
    `KeyUsage::server_auth()` are `required_if_present`, so a leaf with no extended
    key usage at all is accepted in BOTH directions by the library that reads it —
    the exact cert-manager default this wall exists to refuse rather than pass
    silently.
    """
    override = values_file(
        tmp_path,
        "neither-direction.yaml",
        "certificates:\n  leaves:\n    iam-tls:\n      usages: [digital signature]\n",
    )
    documents = render(CHART, "-f", str(ADOPTER_VALUES), "-f", str(override))
    failures = usage_failures(documents)
    message = "\n".join(failures)

    assert failures, "iam-tls named neither direction and the wall passed"
    assert "iam-tls" in message and "neither" in message, message


# ── RED 4: the CA root naming a direction ────────────────────────────────────────


def chart_with_the_ca_root_naming_server_auth(destination: Path) -> Path:
    """A copy of the chart whose CA root's `usages` also names `server auth`.

    `internal-ca.yaml`'s `usages` block is NOT values-driven (`cert sign` /
    `crl sign` are literals in the template), so this red case — unlike the two
    above — mutates a chart copy rather than an override values file, following
    `test_ladder.py`'s `chart_with_the_leaves_key_renamed`.
    """
    copy = destination / "chart"
    shutil.copytree(CHART, copy)
    template = copy / "templates" / "internal-ca.yaml"
    text = template.read_text()
    needle = "  usages:\n    - cert sign\n    - crl sign\n"
    assert needle in text, "internal-ca.yaml's usages block moved; this red case is now testing nothing"
    template.write_text(text.replace(needle, needle.replace("- crl sign\n", "- crl sign\n    - server auth\n")))
    return copy


def test_the_ca_root_naming_a_direction_is_refused_and_named(tmp_path):
    """`judge()`'s third arm, `hooks/certificate_usages.py:333-341`: an authority signs; it does not answer.

    `isCA: true` is exempted from the wall by what the document IS, not by an
    issuer allowlist a rename could escape — so a CA root that also claims
    `server auth` is refused rather than silently passed as "not a leaf".
    """
    chart = chart_with_the_ca_root_naming_server_auth(tmp_path)
    documents = render(chart, "-f", str(ADOPTER_VALUES))
    failures = usage_failures(documents)
    message = "\n".join(failures)

    assert failures, "the CA root named server auth and the wall passed"
    assert "yadgar-internal-ca" in message and "isCA" in message, message


# ── THE GROUPS THIS FILE NAMES ARE THE GROUPS THE CHART DECLARES ────────────────


def test_the_groups_this_file_names_are_the_groups_the_chart_declares():
    """`DECLARED_API_VERSIONS` restated against the chart. See `test_ladder.py`'s
    twin of this case for the full argument: the literal has to stay a literal, and
    this comparison is what catches it going stale rather than the render checks
    failing with a cause that names this file only after a detour through the
    chart's own refusal.
    """
    from test_render_checks import declared_checks

    declared = tuple(sorted(declared_checks(CHART)))
    assert DECLARED_API_VERSIONS == declared, (
        f"this file's DECLARED_API_VERSIONS names {DECLARED_API_VERSIONS} and the "
        f"chart declares {declared}. Every render in this file passes the first, "
        f"and `fail` aborts each of them at the first check whose group is missing "
        f"— so a stale entry HERE reddens this whole file with the CHART's refusal, "
        f"naming the chart rather than this constant. Move this tuple to match the "
        f"chart, or restore the check the chart lost"
    )
