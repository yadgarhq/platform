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
are MEASURED against it: 15 Certificates (the CA root, thirteen internal leaves, the
edge leaf) and 14 leaves (every one of the fifteen except the CA root). `>=` rather than
`==`, following `MINIMUM_CERTIFICATES`/`MINIMUM_LEAVES`'s own reasoning restated at
this chart's own count: adding a fifteenth leaf is a legitimate change and must not
redden this suite, but a render that silently drops one below what is measured today
must.

Tests: `python3 -m pytest scripts/tests/test_certificate_usages.py -q`.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest
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

# MEASURED against `helm template chart -f example/values.yaml`: 15 Certificate
# objects (the CA root, the thirteen internal leaves, the edge leaf) and 14 leaves (every
# one of the fifteen except the CA root, which the wall exempts by `isCA` rather than
# judging). Literals, not derived from the render they gate — the whole point of a
# floor is that it does not move with the thing it is measuring.
CERTIFICATE_FLOOR = 15
LEAF_FLOOR = 14


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
        f"{CERTIFICATE_FLOOR} today: the CA root, the thirteen internal leaves and the "
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
    """`certificates.create: false` drops thirteen of fifteen Certificates. The floor catches it.

    THE CONSTRUCTED RED CASE FOR THE FLOOR ITSELF: with the thirteen internal leaves off,
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


# ── RED 2 AND 3: the wall's two leaf arms, judged over a constructed document ───
#
# THESE USED TO RENDER THE CHART, and they cannot any more: since yaadgaar 279 the
# chart's own render check refuses both overrides before a Certificate exists to
# judge (the render-time cases below). The wall is still this suite's, so its two
# leaf arms are proved over a document built here, the shape `helm template` emits.


def leaf_document(name: str, usages: list[str]) -> dict:
    return {
        "apiVersion": "cert-manager.io/v1",
        "kind": "Certificate",
        "metadata": {"name": name},
        "spec": {"secretName": name, "usages": usages},
    }


def test_a_leaf_naming_both_directions_is_refused_and_named():
    """`judge()`'s first arm: one authority signs both directions here, so a leaf
    naming both collapses the wall that stops a serving leaf being replayed as a
    caller."""
    failures = usage_failures([leaf_document("iam-tls", [SERVER, CLIENT])])
    message = "\n".join(failures)
    assert failures, "iam-tls named both server auth and client auth and the wall passed"
    assert "iam-tls" in message and "both" in message, message


def test_a_leaf_naming_neither_direction_is_refused_and_named():
    """`judge()`'s second arm: webpki accepts a leaf with no extended key usage in
    BOTH directions, so an omission is wider than naming both."""
    failures = usage_failures([leaf_document("iam-tls", ["digital signature"])])
    message = "\n".join(failures)
    assert failures, "iam-tls named neither direction and the wall passed"
    assert "iam-tls" in message and "neither" in message, message


# ── THE SAME RULE AT RENDER TIME, FOR AN ADOPTER'S VALUES (yaadgaar 279) ────────
#
# The wall above judges THIS repository's values. An adopter's override of
# `certificates.leaves.<name>.usages` never reaches it, so `render-checks.yaml`
# carries the rule too and refuses the render, naming the leaf. It runs as the
# root AND as a subchart: no parent carries an equivalent (ADR-0794).
# `any` is refused as well: it is `anyExtendedKeyUsage`, which every verifier
# accepts for either direction, so `[server auth, any]` names one direction and
# grants both.

USAGES_REFUSAL = "platform: a certificates.leaves entry does not name exactly one direction"


def helm_render_result(*arguments: str) -> subprocess.CompletedProcess[str]:
    return helm("template", "platform", str(CHART), *API_VERSIONS, *arguments)


@pytest.mark.parametrize(
    ("usages", "named"),
    [
        ("[digital signature, key encipherment]", "names neither `server auth` nor `client auth`"),
        ("[server auth, client auth]", "names both `server auth` and `client auth`"),
        ("[server auth, digital signature, any]", "names `any`"),
        ("[]", "names neither `server auth` nor `client auth`"),
        ("server auth", "is not a list"),
        ("{server: auth}", "is not a list"),
        ("null", "is not a list"),
        ("[Server Auth, digital signature]", "names neither `server auth` nor `client auth`"),
    ],
    ids=["neither", "both", "any", "empty", "scalar", "map", "null", "wrong-case"],
)
def test_an_adopter_leaf_that_does_not_name_one_direction_is_refused(tmp_path, usages, named):
    override = values_file(
        tmp_path,
        "leaf.yaml",
        f"certificates:\n  leaves:\n    iam-tls:\n      usages: {usages}\n",
    )
    result = helm_render_result("-f", str(ADOPTER_VALUES), "-f", str(override))
    assert result.returncode != 0, f"rendered instead of refusing: {result.stdout[:400]}"
    assert USAGES_REFUSAL in result.stderr, result.stderr
    assert "`certificates.leaves.iam-tls.usages`" in result.stderr, result.stderr
    assert named in result.stderr, result.stderr


# AN ELEMENT OUTSIDE CERT-MANAGER'S ENUM IS REFUSED (the review of 279).
# `certificates.yaml` used to render each element raw, so one string carrying a
# newline became two list items: the injected `client auth` below rendered as
# its own item, a two-way leaf the `has` checks above never saw, at rc=0. Every
# element must be a string that is exactly one of cert-manager v1.21.1's
# `KeyUsage` values.
ESTATE_VALUES = CHART / "ci" / "estate-values.yaml"
INJECTED_USAGES = (
    'certificates: {leaves: {nats-tls: {usages: ["server auth", '
    '"digital signature\\n    - client auth"]}}}\n'
)


def test_a_usages_element_carrying_an_injected_item_is_refused(tmp_path):
    override = values_file(tmp_path, "injected.yaml", INJECTED_USAGES)
    assert yaml.safe_load(override.read_text())["certificates"]["leaves"]["nats-tls"][
        "usages"
    ] == ["server auth", "digital signature\n    - client auth"]
    result = helm_render_result("-f", str(ESTATE_VALUES), "-f", str(override))
    assert result.returncode != 0, f"rendered instead of refusing: {result.stdout[:400]}"
    assert USAGES_REFUSAL in result.stderr, result.stderr
    assert "`certificates.leaves.nats-tls.usages`" in result.stderr, result.stderr
    assert "is not a cert-manager KeyUsage" in result.stderr, result.stderr


@pytest.mark.parametrize(
    ("usages", "named"),
    [
        ('["server auth", "digital signature\\n    - any"]', "is not a cert-manager KeyUsage"),
        ("[server auth, serverAuth]", "is not a cert-manager KeyUsage"),
        ("[server auth, 1]", "is not a string"),
        ("[server auth, [client auth]]", "is not a string"),
        ("[server auth, null]", "is not a string"),
    ],
    ids=["injected-any", "off-enum", "number", "nested-list", "null-element"],
)
def test_a_usages_element_outside_the_enum_is_refused(tmp_path, usages, named):
    override = values_file(
        tmp_path,
        "element.yaml",
        f"certificates:\n  leaves:\n    iam-tls:\n      usages: {usages}\n",
    )
    result = helm_render_result("-f", str(ADOPTER_VALUES), "-f", str(override))
    assert result.returncode != 0, f"rendered instead of refusing: {result.stdout[:400]}"
    assert USAGES_REFUSAL in result.stderr, result.stderr
    assert "`certificates.leaves.iam-tls.usages`" in result.stderr, result.stderr
    assert named in result.stderr, result.stderr


def test_an_adopter_leaf_without_a_usages_key_is_refused(tmp_path):
    """A NEW leaf with no `usages` at all: cert-manager would issue it with no EKU."""
    override = values_file(
        tmp_path,
        "new-leaf.yaml",
        "certificates:\n  leaves:\n    extra-tls:\n      commonName: extra\n      renewBefore: 900h\n",
    )
    result = helm_render_result("-f", str(ADOPTER_VALUES), "-f", str(override))
    assert result.returncode != 0, f"rendered instead of refusing: {result.stdout[:400]}"
    assert "`certificates.leaves.extra-tls.usages`" in result.stderr, result.stderr


def test_every_offending_leaf_is_named_in_one_refusal(tmp_path):
    override = values_file(
        tmp_path,
        "two.yaml",
        "certificates:\n  leaves:\n"
        "    iam-tls:\n      usages: [digital signature]\n"
        "    gateway-client-tls:\n      usages: [client auth, server auth]\n",
    )
    result = helm_render_result("-f", str(ADOPTER_VALUES), "-f", str(override))
    assert result.returncode != 0, result.stdout[:400]
    for leaf in ("iam-tls", "gateway-client-tls"):
        assert f"`certificates.leaves.{leaf}.usages`" in result.stderr, result.stderr


@pytest.mark.parametrize("usages", ["[client auth, digital signature]", "[server auth]"])
def test_an_adopter_leaf_naming_exactly_one_direction_renders(tmp_path, usages):
    override = values_file(
        tmp_path,
        "one.yaml",
        f"certificates:\n  leaves:\n    iam-tls:\n      usages: {usages}\n",
    )
    result = helm_render_result("-f", str(ADOPTER_VALUES), "-f", str(override))
    assert result.returncode == 0, result.stderr


def test_the_usages_check_also_refuses_as_a_subchart(tmp_path):
    """No parent carries this rule, so the arm must not stand down under one
    (ADR-0794). The parent is the throwaway `test_operators_shape.py` builds."""
    from test_operators_shape import build_parent

    parent = build_parent(tmp_path / "parent", CHART)
    override = values_file(
        tmp_path,
        "parent.yaml",
        "platform:\n  certificates:\n    create: true\n"
        "    leaves:\n      iam-tls:\n        usages: [digital signature]\n",
    )
    result = helm("template", "yadgar", str(parent), *API_VERSIONS, "-f", str(override))
    assert result.returncode != 0, result.stdout[:400]
    assert "charts/platform/templates/render-checks.yaml" in result.stderr, result.stderr
    assert "`certificates.leaves.iam-tls.usages`" in result.stderr, result.stderr


def test_the_usages_check_stands_down_while_certificates_create_is_false(tmp_path):
    """No leaf renders, so there is nothing to refuse."""
    override = values_file(
        tmp_path,
        "off.yaml",
        "certificates:\n  create: false\n  leaves:\n    iam-tls:\n      usages: [digital signature]\n",
    )
    result = helm_render_result("-f", str(ADOPTER_VALUES), "-f", str(override))
    assert result.returncode == 0, result.stderr


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

    SINCE YAADGAAR 534 THE CHART REFUSES THIS RENDER ITSELF: the last arm of
    `render-checks.yaml` judges the parsed CA too. So the chart copy is asserted
    refused, and `usage_failures()` is held to the same verdict over the render
    with that one `usages` changed after the fact.
    """
    chart = chart_with_the_ca_root_naming_server_auth(tmp_path)
    result = helm("template", "platform", str(chart), *API_VERSIONS, "-f", str(ADOPTER_VALUES))
    assert result.returncode != 0, result.stdout[:400]
    assert "`yadgar-internal-ca` from `templates/internal-ca.yaml` is the internal CA and names a direction" in (
        result.stderr
    ), result.stderr

    documents = render(CHART, "-f", str(ADOPTER_VALUES))
    for document in certificates(documents):
        if document["metadata"]["name"] == CA_NAME:
            document["spec"]["usages"] = [*document["spec"]["usages"], SERVER]
    failures = usage_failures(documents)
    message = "\n".join(failures)

    assert failures, "the CA root named server auth and the wall passed"
    assert "yadgar-internal-ca" in message and "isCA" in message, message


# ── THE OTHER SECURITY-BEARING FIELDS, ASSERTED AS LITERALS (yaadgaar 378) ────
#
# `usages` had a wall; the key, the issuer, `isCA` and the CA chain had none. A
# `values.yaml` edit to `rotationPolicy: Never` on the leaves, an RSA-1024 key, or a
# leaf `issuerRef` naming another authority rendered clean and nothing read it.
# LITERALS, not read back from `values.yaml`: a value derived from the thing under
# test agrees with whatever it says.
LEAF_KEY = {"algorithm": "ECDSA", "size": 256, "rotationPolicy": "Always"}
CA_KEY = {"algorithm": "ECDSA", "size": 256, "rotationPolicy": "Never"}
INTERNAL_ISSUER = {"name": "yadgar-internal-ca", "kind": "Issuer", "group": "cert-manager.io"}
SELF_SIGN_ISSUER = {"name": "yadgar-internal-selfsign", "kind": "Issuer", "group": "cert-manager.io"}
CA_NAME = "yadgar-internal-ca"
EDGE_NAME = "gateway-tls"
LEAF_DURATION = "2160h"
CA_DURATION = "87600h"
CA_USAGES = ["cert sign", "crl sign"]
EDGE_USAGES = [SERVER]


def security_field_failures(documents: list[dict]) -> list[str]:
    """Every Certificate/Issuer field that carries trust and differs from the literal. PURE."""
    failures = []
    found = {}
    for document in documents:
        if document.get("kind") in ("Certificate", "Issuer", "ClusterIssuer"):
            found[(document["kind"], document["metadata"]["name"])] = document.get("spec") or {}

    def expect(key: tuple[str, str], field: str, want: object) -> None:
        got = found.get(key, {}).get(field)
        if got != want:
            failures.append(f"{key[0]}/{key[1]}: `{field}` is {got!r}, expected {want!r}")

    ca = ("Certificate", CA_NAME)
    if ca not in found:
        failures.append(f"no Certificate/{CA_NAME} rendered")
    expect(ca, "isCA", True)
    expect(ca, "privateKey", CA_KEY)
    expect(ca, "issuerRef", SELF_SIGN_ISSUER)
    expect(ca, "usages", CA_USAGES)
    expect(ca, "duration", CA_DURATION)
    expect(("Issuer", CA_NAME), "ca", {"secretName": CA_NAME})
    expect(("Issuer", SELF_SIGN_ISSUER["name"]), "selfSigned", {})

    edge = ("Certificate", EDGE_NAME)
    expect(edge, "privateKey", LEAF_KEY)
    expect(edge, "usages", EDGE_USAGES)
    if found.get(edge, {}).get("isCA"):
        failures.append(f"Certificate/{EDGE_NAME}: `isCA` is set on the edge leaf")

    for (kind, name), spec in sorted(found.items()):
        if kind != "Certificate" or name in (CA_NAME, EDGE_NAME):
            continue
        if spec.get("isCA"):
            failures.append(f"Certificate/{name}: `isCA` is set on an internal leaf")
        expect((kind, name), "privateKey", LEAF_KEY)
        expect((kind, name), "issuerRef", INTERNAL_ISSUER)
        expect((kind, name), "duration", LEAF_DURATION)
    return failures


def test_every_certificate_carries_the_security_fields_the_estate_relies_on():
    documents = render(CHART, "-f", str(ADOPTER_VALUES))
    leaves = [d for d in certificates(documents) if d["metadata"]["name"] not in (CA_NAME, EDGE_NAME)]
    assert len(leaves) >= LEAF_FLOOR - 1, len(leaves)
    failures = security_field_failures(documents)
    assert failures == [], "\n".join(failures)


@pytest.mark.parametrize(
    ("override", "named"),
    [
        ("certificates:\n  privateKey: {rotationPolicy: Never}\n", "`privateKey`"),
        ("certificates:\n  privateKey: {algorithm: RSA, size: 1024}\n", "`privateKey`"),
        ("certificates:\n  issuerRef: {name: some-other-ca, kind: ClusterIssuer}\n", "`issuerRef`"),
        ("certificates:\n  duration: 87600h\n", "`duration`"),
        ("internalCA:\n  privateKey: {rotationPolicy: Always}\n", "yadgar-internal-ca: `privateKey`"),
        # NOT `[server auth, client auth]` any more: the chart's edge usages arm
        # refuses that render itself (yaadgaar 534), so the gate is fed a list the
        # chart accepts and the literal does not.
        ("edgeTLS:\n  usages: [server auth, digital signature]\n", "gateway-tls: `usages`"),
        ("edgeTLS:\n  privateKey: {algorithm: RSA, size: 2048}\n", "gateway-tls: `privateKey`"),
    ],
    ids=["leaf-no-rotation", "leaf-weak-key", "leaf-other-issuer", "leaf-ten-years", "ca-rotates", "edge-both", "edge-rsa"],
)
def test_a_changed_security_field_reddens_the_gate(tmp_path, override, named):
    path = values_file(tmp_path, "changed.yaml", override)
    documents = render(CHART, "-f", str(ADOPTER_VALUES), "-f", str(path))
    message = "\n".join(security_field_failures(documents))
    assert named in message, message


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


# ── A SCALAR THAT CARRIES A SECOND KEY (yaadgaar 534) ────────────────────────────
#
# `certificates.yaml` and `edge-certificate.yaml` printed `commonName`, every
# `dnsNames` item and the edge `usages` raw. A newline in any of them ended the
# scalar and started a sibling key of `spec`, and helm keeps the LAST of two equal
# keys: `isCA: true` on a leaf the internal CA signs is a sub-CA that can mint any
# leaf in the estate. Three walls now stand: the templates YAML-encode each value,
# `render-checks.yaml` refuses a control character in a name and holds the edge's
# usages to cert-manager's enum and the serving direction, and a last arm parses
# every Certificate the chart renders back and judges `isCA` and `usages` on the
# parsed object, whatever field carried them in.
NAMES_REFUSAL = "platform: a value this chart prints is not one line of text"
EDGE_USAGES_REFUSAL = "platform: `edgeTLS.usages` does not name the one direction an edge leaf serves"
RENDERED_REFUSAL = "platform: a Certificate this chart renders breaks the trust rules once it is parsed back"


def refused(tmp_path: Path, body: str, *needles: str) -> str:
    override = values_file(tmp_path, "override.yaml", body)
    result = helm_render_result("-f", str(ESTATE_VALUES), "-f", str(override))
    assert result.returncode != 0, f"rendered instead of refusing: {result.stdout[:400]}"
    for needle in needles:
        assert needle in result.stderr, result.stderr
    return result.stderr


@pytest.mark.parametrize("cluster_local_names", ["false", "true"], ids=["commonName", "dnsNames"])
def test_a_leaf_common_name_carrying_is_ca_is_refused(tmp_path, cluster_local_names):
    """The leaf's `commonName` is also every one of its `dnsNames`, so one value is both routes."""
    refused(
        tmp_path,
        "certificates:\n  leaves:\n    iam-tls:\n"
        f"      clusterLocalNames: {cluster_local_names}\n"
        '      commonName: "iam\\n  isCA: true"\n',
        NAMES_REFUSAL,
        "`certificates.leaves.iam-tls.commonName`",
    )


@pytest.mark.parametrize(
    ("body", "named"),
    [
        ('edgeTLS:\n  commonName: "yadgar.example.test\\n  isCA: true"\n', "`edgeTLS.commonName`"),
        ('edgeTLS:\n  dnsNames: ["yadgar.example.test\\n  isCA: true"]\n', "`edgeTLS.dnsNames` element 0"),
        (
            'edgeTLS:\n  commonName: ""\n  dnsNames: []\nglobal:\n  hostname: "a.test\\n  isCA: true"\n',
            "`global.hostname`",
        ),
    ],
    ids=["edge-commonName", "edge-dnsNames", "global-hostname"],
)
def test_an_edge_name_carrying_is_ca_is_refused(tmp_path, body, named):
    refused(tmp_path, body, NAMES_REFUSAL, named)


@pytest.mark.parametrize(
    "character",
    ["\\t", "\\r", "\\x00", "\\x7f", "\\x85", "\\u2028", "\\u2029"],
    ids=["tab", "carriage-return", "nul", "delete", "next-line", "line-separator", "paragraph-separator"],
)
def test_a_control_character_in_a_name_is_refused(tmp_path, character):
    """YAML 1.1 breaks a line at NEL, U+2028 and U+2029 too, not only at `\\n`.

    TWO REFUSALS COUNT, AND ONLY THOSE TWO. Helm 3 (3.18.4, the CI pin, and
    3.20.2) refuses DEL while it LOADS the values file — "yaml: control
    characters are not allowed" — so the chart never runs and its message cannot
    appear; helm 4 loads the value and the chart refuses it. Either way the render
    must fail.
    """
    override = values_file(tmp_path, "override.yaml", f'edgeTLS:\n  dnsNames: ["yadgar{character}.example.test"]\n')
    result = helm_render_result("-f", str(ESTATE_VALUES), "-f", str(override))
    assert result.returncode != 0, f"rendered instead of refusing: {result.stdout[:400]}"
    chart_refused = NAMES_REFUSAL in result.stderr and "`edgeTLS.dnsNames` element 0" in result.stderr
    loader_refused = "control characters are not allowed" in result.stderr
    assert chart_refused or loader_refused, result.stderr


@pytest.mark.parametrize(
    ("body", "named"),
    [
        ("certificates:\n  leaves:\n    iam-tls:\n      commonName: 5\n", "`certificates.leaves.iam-tls.commonName` is not a string"),
        ("certificates:\n  leaves:\n    iam-tls:\n      commonName: null\n", "`certificates.leaves.iam-tls.commonName` is not a string"),
        ("edgeTLS:\n  dnsNames: yadgar.example.test\n", "`edgeTLS.dnsNames` is not a list"),
        ("edgeTLS:\n  dnsNames: [5]\n", "`edgeTLS.dnsNames` element 0 is not a string"),
    ],
    ids=["leaf-number", "leaf-null", "edge-scalar", "edge-number"],
)
def test_a_name_that_is_not_a_string_is_refused(tmp_path, body, named):
    refused(tmp_path, body, NAMES_REFUSAL, named)


@pytest.mark.parametrize(
    ("usages", "named"),
    [
        ('["server auth", "digital signature\\n    - client auth"]', "is not a cert-manager KeyUsage"),
        ("[server auth, serverAuth]", "is not a cert-manager KeyUsage"),
        ("[server auth, 1]", "is not a string"),
        ("[server auth, client auth]", "names `client auth`"),
        ("[client auth, digital signature]", "names `client auth`"),
        ("[server auth, any]", "names `any`"),
        ("[digital signature]", "does not name `server auth`"),
        ("server auth", "is not a list"),
    ],
    ids=["injected", "off-enum", "number", "both", "client-only", "any", "neither", "scalar"],
)
def test_an_edge_usages_list_that_does_not_serve_one_way_is_refused(tmp_path, usages, named):
    refused(tmp_path, f"edgeTLS:\n  usages: {usages}\n", EDGE_USAGES_REFUSAL, named)


def test_an_edge_usages_list_that_serves_renders(tmp_path):
    override = values_file(tmp_path, "edge.yaml", "edgeTLS:\n  usages: [server auth, digital signature]\n")
    documents = render(CHART, "-f", str(ESTATE_VALUES), "-f", str(override))
    edge = [d for d in certificates(documents) if d["metadata"]["name"] == EDGE_NAME]
    assert edge and edge[0]["spec"]["usages"] == [SERVER, "digital signature"], edge


# THE TEMPLATES' OWN WALL, WITH NO CONTROL CHARACTER FOR THE REFUSAL TO SEE. A
# value YAML reads as something other than a string — `*` opens an alias, ` #`
# opens a comment — was misread when printed raw. Encoded, it renders as itself.
@pytest.mark.parametrize(
    ("body", "name", "field", "want"),
    [
        ("edgeTLS:\n  dnsNames: ['*.example.test']\n", EDGE_NAME, "dnsNames", ["*.example.test"]),
        ("edgeTLS:\n  commonName: '*.example.test'\n", EDGE_NAME, "commonName", "*.example.test"),
        (
            "certificates:\n  leaves:\n    iam-tls:\n      clusterLocalNames: false\n      commonName: 'iam #x'\n",
            "iam-tls",
            "dnsNames",
            ["iam #x"],
        ),
        (
            "certificates:\n  leaves:\n    iam-tls:\n      commonName: 'iam #x'\n",
            "iam-tls",
            "commonName",
            "iam #x",
        ),
    ],
    ids=["edge-dnsNames", "edge-commonName", "leaf-dnsNames", "leaf-commonName"],
)
def test_a_name_yaml_would_misread_renders_as_itself(tmp_path, body, name, field, want):
    override = values_file(tmp_path, "name.yaml", body)
    documents = render(CHART, "-f", str(ESTATE_VALUES), "-f", str(override))
    found = [d for d in certificates(documents) if d["metadata"]["name"] == name]
    assert found and found[0]["spec"][field] == want, found


def test_the_names_check_also_refuses_as_a_subchart(tmp_path):
    from test_operators_shape import build_parent

    parent = build_parent(tmp_path / "parent", CHART)
    override = values_file(
        tmp_path,
        "parent.yaml",
        "platform:\n  certificates:\n    create: true\n"
        '    leaves:\n      iam-tls:\n        commonName: "iam\\n  isCA: true"\n',
    )
    result = helm("template", "yadgar", str(parent), *API_VERSIONS, "-f", str(override))
    assert result.returncode != 0, result.stdout[:400]
    assert NAMES_REFUSAL in result.stderr, result.stderr


# ── THE RENDERED CERTIFICATES, PARSED BACK ───────────────────────────────────────
#
# BEFORE YAADGAAR 537 these payloads came in through values — `renewBefore`, and
# `certificates.issuerRef.name`, which prints AFTER `usages` so a second `usages`
# there won over the judged one. Every such value is now encoded and refused
# (`test_a_value_carrying_a_document_of_its_own_is_refused`), so no values file
# reaches this arm; each red case below edits a COPY of the chart instead.
EDGE_TAIL = '    group: cert-manager.io\n{{- end }}\n{{- end }}\n{{- include "platform.certificates.edge" . }}\n'
CA_TAIL = "  ca:\n    {{- dict \"secretName\" $ca.name | toYaml | nindent 4 }}\n{{- end }}\n"
EVIL = (
    "apiVersion: cert-manager.io/v1\nkind: {kind}\nmetadata:\n  name: {name}\n"
    "spec:\n  isCA: true\n  secretName: {name}\n  commonName: evil\n  usages: [cert sign, crl sign]\n"
    "  issuerRef:\n    name: yadgar-internal-ca\n    kind: Issuer\n"
)


def edited_chart(destination: Path, template: str, needle: str, replacement: str) -> Path:
    copy = destination / "chart"
    shutil.copytree(CHART, copy)
    path = copy / "templates" / template
    text = path.read_text()
    assert text.count(needle) == 1, f"{template} moved; this red case is now testing nothing"
    path.write_bytes(text.replace(needle, replacement).encode())
    return copy


def refused_render(chart: Path, *needles: str, values: Path = ESTATE_VALUES) -> str:
    result = helm("template", "platform", str(chart), *API_VERSIONS, "-f", str(values))
    assert result.returncode != 0, f"rendered instead of refusing: {result.stdout[:400]}"
    assert RENDERED_REFUSAL in result.stderr, result.stderr
    for needle in needles:
        assert needle in result.stderr, result.stderr
    return result.stderr


LEAF_TAIL = '    group: cert-manager.io\n{{- end }}\n{{- end }}\n{{- end }}\n{{- include "platform.certificates.leaves" . }}\n'


@pytest.mark.parametrize(
    ("template", "tail", "extra", "named"),
    [
        ("certificates.yaml", LEAF_TAIL, "  isCA: true\n", "`iam-tls` from `templates/certificates.yaml` sets `isCA`"),
        (
            "certificates.yaml",
            LEAF_TAIL,
            "  usages: [server auth, client auth]\n",
            "`iam-tls` from `templates/certificates.yaml` names both `server auth` and `client auth`",
        ),
        ("edge-certificate.yaml", EDGE_TAIL, "  isCA: true\n", "`gateway-tls` from `templates/edge-certificate.yaml` sets `isCA`"),
    ],
    ids=["leaf-is-ca", "leaf-usages-after-the-check", "edge-is-ca"],
)
def test_a_rendered_certificate_breaking_the_trust_rules_is_refused(tmp_path, template, tail, extra, named):
    """A key printed after the judged `usages`, last key wins: the arm judges the parsed object."""
    chart = edited_chart(tmp_path, template, tail, tail.replace("    group: cert-manager.io\n", "    group: cert-manager.io\n" + extra, 1))
    refused_render(chart, named)


def test_a_template_that_sets_is_ca_on_a_leaf_is_refused(tmp_path):
    """A template edit, not a value: the arm judges what renders, not what values say."""
    copy = tmp_path / "chart"
    shutil.copytree(CHART, copy)
    template = copy / "templates" / "certificates.yaml"
    text = template.read_text()
    needle = '  {{- dict "secretName" $name | toYaml | nindent 2 }}\n'
    assert needle in text, "certificates.yaml's secretName line moved; this red case is now testing nothing"
    template.write_text(text.replace(needle, needle + "  isCA: true\n"))
    result = helm("template", "platform", str(copy), *API_VERSIONS, "-f", str(ESTATE_VALUES))
    assert result.returncode != 0, result.stdout[:400]
    assert RENDERED_REFUSAL in result.stderr, result.stderr
    assert "`iam-tls` from `templates/certificates.yaml` sets `isCA`" in result.stderr, result.stderr


def test_the_one_ca_the_chart_declares_renders(tmp_path):
    """The allowlist is exact: the internal CA, from `internal-ca.yaml`, by the name `internalCA.name` gives it."""
    override = values_file(tmp_path, "ca.yaml", "internalCA:\n  name: another-ca\n")
    documents = render(CHART, "-f", str(ESTATE_VALUES), "-f", str(override))
    cas = [d["metadata"]["name"] for d in certificates(documents) if d["spec"].get("isCA")]
    assert cas == ["another-ca"], cas


# ── EVERY OTHER VALUE THE CERTIFICATES AND THE GATEWAY PRINT (yaadgaar 537) ──────
#
# Each of these printed raw. A newline in one ended the scalar; a following line
# starting `---` began a whole new document, which the review of platform#75
# measured as a Certificate `evil-subca` with `isCA`, signed by the internal CA,
# at rc=0. Each is now YAML-encoded in its template and refused by the one-line
# values arm. The payload names `isCA` so a regression is the full hole, not a
# cosmetic one.
PAYLOAD = "\\n--- #\\napiVersion: cert-manager.io/v1\\nkind: Certificate\\nmetadata: {name: x}\\nspec: {isCA: true}"
ONE_LINE_FIELDS = [
    ("certificates: {leaves: {\"iam-tls" + PAYLOAD + "\": {commonName: x, usages: [server auth], renewBefore: 999h}}}", "the `certificates.leaves` key"),
    ("certificates: {leaves: {iam-tls: {renewBefore: \"726h" + PAYLOAD + "\"}}}", "`certificates.leaves.iam-tls.renewBefore`"),
    ("certificates: {duration: \"2160h" + PAYLOAD + "\"}", "`certificates.duration`"),
    ("certificates: {privateKey: {algorithm: \"ECDSA" + PAYLOAD + "\"}}", "`certificates.privateKey.algorithm`"),
    ("certificates: {privateKey: {rotationPolicy: \"Always" + PAYLOAD + "\"}}", "`certificates.privateKey.rotationPolicy`"),
    ("certificates: {issuerRef: {name: \"yadgar-internal-ca" + PAYLOAD + "\"}}", "`certificates.issuerRef.name`"),
    ("certificates: {issuerRef: {kind: \"Issuer" + PAYLOAD + "\"}}", "`certificates.issuerRef.kind`"),
    ("edgeTLS: {name: \"gateway-tls" + PAYLOAD + "\"}", "`edgeTLS.name`"),
    ("edgeTLS: {duration: \"2160h" + PAYLOAD + "\"}", "`edgeTLS.duration`"),
    ("edgeTLS: {renewBefore: \"720h" + PAYLOAD + "\"}", "`edgeTLS.renewBefore`"),
    ("edgeTLS: {privateKey: {algorithm: \"ECDSA" + PAYLOAD + "\"}}", "`edgeTLS.privateKey.algorithm`"),
    ("edgeTLS: {privateKey: {rotationPolicy: \"Always" + PAYLOAD + "\"}}", "`edgeTLS.privateKey.rotationPolicy`"),
    ("edgeTLS: {issuerRef: {name: \"yadgar-internal-ca" + PAYLOAD + "\"}}", "`edgeTLS.issuerRef.name`"),
    ("edgeTLS: {issuerRef: {kind: \"Issuer" + PAYLOAD + "\"}}", "`edgeTLS.issuerRef.kind`"),
    ("internalCA: {name: \"yadgar-internal-ca" + PAYLOAD + "\"}", "`internalCA.name`"),
    ("internalCA: {selfSignedIssuerName: \"yadgar-internal-selfsign" + PAYLOAD + "\"}", "`internalCA.selfSignedIssuerName`"),
    ("internalCA: {commonName: \"ca" + PAYLOAD + "\"}", "`internalCA.commonName`"),
    ("internalCA: {duration: \"87600h" + PAYLOAD + "\"}", "`internalCA.duration`"),
    ("internalCA: {renewBefore: \"720h" + PAYLOAD + "\"}", "`internalCA.renewBefore`"),
    ("internalCA: {privateKey: {algorithm: \"ECDSA" + PAYLOAD + "\"}}", "`internalCA.privateKey.algorithm`"),
    ("internalCA: {privateKey: {rotationPolicy: \"Never" + PAYLOAD + "\"}}", "`internalCA.privateKey.rotationPolicy`"),
    ("gatewayListener: {hostname: \"yadgar.example.test" + PAYLOAD + "\"}", "`gatewayListener.hostname`"),
]


@pytest.mark.parametrize(("body", "named"), ONE_LINE_FIELDS, ids=[named.strip("`").split("`")[0] or "leaf-key" for _, named in ONE_LINE_FIELDS])
def test_a_value_carrying_a_document_of_its_own_is_refused(tmp_path, body, named):
    refused(tmp_path, body + "\n", NAMES_REFUSAL, named)


# THE ENCODING ITSELF, WITH NOTHING FOR THE REFUSAL TO SEE. ` #` opens a YAML
# comment, so a raw print drops everything after it; encoded, the value renders
# as itself. One row per encoded string field; `privateKey.size` is a number and
# renders the same either way.
ENCODED_FIELDS = [
    ("certificates: {leaves: {\"iam-tls #x\": {commonName: x, usages: [server auth], renewBefore: 999h}}}", ("Certificate", "iam-tls #x"), ("metadata", "name")),
    ("certificates: {leaves: {\"iam-tls #x\": {commonName: x, usages: [server auth], renewBefore: 999h}}}", ("Certificate", "iam-tls #x"), ("spec", "secretName")),
    ("certificates: {leaves: {iam-tls: {renewBefore: \"726h #x\"}}}", ("Certificate", "iam-tls"), ("spec", "renewBefore")),
    ("certificates: {duration: \"2160h #x\"}", ("Certificate", "iam-tls"), ("spec", "duration")),
    ("certificates: {privateKey: {algorithm: \"ECDSA #x\"}}", ("Certificate", "iam-tls"), ("spec", "privateKey", "algorithm")),
    ("certificates: {privateKey: {rotationPolicy: \"Always #x\"}}", ("Certificate", "iam-tls"), ("spec", "privateKey", "rotationPolicy")),
    ("certificates: {issuerRef: {name: \"yadgar-internal-ca #x\"}}", ("Certificate", "iam-tls"), ("spec", "issuerRef", "name")),
    ("certificates: {issuerRef: {kind: \"Issuer #x\"}}", ("Certificate", "iam-tls"), ("spec", "issuerRef", "kind")),
    ("edgeTLS: {name: \"gateway-tls #x\"}", ("Certificate", "gateway-tls #x"), ("metadata", "name")),
    ("edgeTLS: {name: \"gateway-tls #x\"}", ("Certificate", "gateway-tls #x"), ("spec", "secretName")),
    ("edgeTLS: {duration: \"2160h #x\"}", ("Certificate", EDGE_NAME), ("spec", "duration")),
    ("edgeTLS: {renewBefore: \"720h #x\"}", ("Certificate", EDGE_NAME), ("spec", "renewBefore")),
    ("edgeTLS: {privateKey: {algorithm: \"ECDSA #x\"}}", ("Certificate", EDGE_NAME), ("spec", "privateKey", "algorithm")),
    ("edgeTLS: {privateKey: {rotationPolicy: \"Always #x\"}}", ("Certificate", EDGE_NAME), ("spec", "privateKey", "rotationPolicy")),
    ("edgeTLS: {issuerRef: {name: \"yadgar-internal-ca #x\"}}", ("Certificate", EDGE_NAME), ("spec", "issuerRef", "name")),
    ("edgeTLS: {issuerRef: {kind: \"Issuer #x\"}}", ("Certificate", EDGE_NAME), ("spec", "issuerRef", "kind")),
    ("internalCA: {name: \"yadgar-internal-ca #x\"}", ("Certificate", "yadgar-internal-ca #x"), ("metadata", "name")),
    ("internalCA: {name: \"yadgar-internal-ca #x\"}", ("Certificate", "yadgar-internal-ca #x"), ("spec", "secretName")),
    ("internalCA: {name: \"yadgar-internal-ca #x\"}", ("Issuer", "yadgar-internal-ca #x"), ("metadata", "name")),
    ("internalCA: {name: \"yadgar-internal-ca #x\"}", ("Issuer", "yadgar-internal-ca #x"), ("spec", "ca", "secretName")),
    ("internalCA: {selfSignedIssuerName: \"yadgar-internal-selfsign #x\"}", ("Issuer", "yadgar-internal-selfsign #x"), ("metadata", "name")),
    ("internalCA: {selfSignedIssuerName: \"yadgar-internal-selfsign #x\"}", ("Certificate", CA_NAME), ("spec", "issuerRef", "name")),
    ("internalCA: {duration: \"87600h #x\"}", ("Certificate", CA_NAME), ("spec", "duration")),
    ("internalCA: {renewBefore: \"720h #x\"}", ("Certificate", CA_NAME), ("spec", "renewBefore")),
    ("internalCA: {privateKey: {algorithm: \"ECDSA #x\"}}", ("Certificate", CA_NAME), ("spec", "privateKey", "algorithm")),
    ("internalCA: {privateKey: {rotationPolicy: \"Never #x\"}}", ("Certificate", CA_NAME), ("spec", "privateKey", "rotationPolicy")),
    ("gatewayListener: {hostname: \"yadgar.example.test #x\"}", ("Gateway", None), ("spec", "listeners", 0, "hostname")),
]


@pytest.mark.parametrize(
    ("body", "target", "path"),
    ENCODED_FIELDS,
    ids=[f"{t[0]}-{'.'.join(str(s) for s in p)}-{i}" for i, (_, t, p) in enumerate(ENCODED_FIELDS)],
)
def test_an_encoded_value_renders_as_itself(tmp_path, body, target, path):
    override = values_file(tmp_path, "encoded.yaml", body + "\n")
    documents = render(CHART, "-f", str(ESTATE_VALUES), "-f", str(override))
    kind, name = target
    found = [d for d in documents if d.get("kind") == kind and (name is None or d["metadata"]["name"] == name)]
    assert len(found) == 1, [(d.get("kind"), d["metadata"].get("name")) for d in documents if d.get("kind") == kind]
    value = found[0]
    for step in path:
        value = value[step]
    assert isinstance(value, str) and value.endswith(" #x"), value


# ── THE RENDERED ARM'S OWN GUARDS, REACHED BY TEMPLATE EDITS ─────────────────────
#
# With every value encoded and refused, no values file can reach these guards any
# more, so each red case edits a COPY of the chart, the way
# `test_a_template_that_sets_is_ca_on_a_leaf_is_refused` does. Each asserts the
# guard's OWN message, so a mutant that disables that guard and leaves another to
# catch the render still goes red.
@pytest.mark.parametrize("separator", ["--- #", "--- !!map", "---\r"], ids=["comment", "tag", "carriage-return"])
def test_a_separator_helm_splits_on_is_split_on_here_too(tmp_path, separator):
    chart = edited_chart(
        tmp_path,
        "edge-certificate.yaml",
        EDGE_TAIL,
        EDGE_TAIL.replace("{{- end }}\n{{- end }}", "\n" + separator + "\n" + EVIL.format(kind="Certificate", name="evil-subca") + "{{- end }}\n{{- end }}", 1),
    )
    refused_render(
        chart,
        "`evil-subca` from `templates/edge-certificate.yaml` sets `isCA`",
        "`templates/edge-certificate.yaml` renders 2 documents where 1 are declared",
    )


def test_an_injected_document_of_another_kind_is_refused(tmp_path):
    """A CertificateRequest carries `isCA` too; the arm used to judge only Certificates."""
    chart = edited_chart(
        tmp_path,
        "edge-certificate.yaml",
        EDGE_TAIL,
        EDGE_TAIL.replace("{{- end }}\n{{- end }}", "\n---\n" + EVIL.format(kind="CertificateRequest", name="evil-cr") + "{{- end }}\n{{- end }}", 1),
    )
    refused_render(chart, 'from `templates/edge-certificate.yaml` is a "CertificateRequest"')


def test_an_extra_document_of_an_allowed_kind_is_refused_by_the_count(tmp_path):
    """An Issuer is a kind `internal-ca.yaml` renders, and carries no `isCA`: only the count sees it."""
    chart = edited_chart(
        tmp_path,
        "internal-ca.yaml",
        CA_TAIL,
        CA_TAIL.replace("{{- end }}", "---\napiVersion: cert-manager.io/v1\nkind: Issuer\nmetadata:\n  name: extra\nspec:\n  selfSigned: {}\n{{- end }}"),
    )
    refused_render(chart, "`templates/internal-ca.yaml` renders 4 documents where 3 are declared")


# THE LAST ISSUER IN `internal-ca.yaml`, REPLACED BY AN `isCA` CERTIFICATE, keeps the
# document count at three and every kind allowed, so only the allowlist sees it.
CA_ISSUER = "kind: Issuer\nmetadata:\n  {{- dict \"name\" $ca.name | toYaml | nindent 2 }}\nspec:\n  ca:\n"


def test_a_second_is_ca_document_under_the_ca_name_is_refused(tmp_path):
    chart = edited_chart(
        tmp_path,
        "internal-ca.yaml",
        CA_ISSUER,
        "kind: Certificate\nmetadata:\n  {{- dict \"name\" $ca.name | toYaml | nindent 2 }}\nspec:\n  isCA: true\n  usages: [cert sign]\n  ca:\n",
    )
    refused_render(chart, "`yadgar-internal-ca` from `templates/internal-ca.yaml` sets `isCA`")


# THE FIRST ISSUER, THE SELF-SIGNED ONE, REPLACED BY AN `isCA` CERTIFICATE UNDER
# ANOTHER NAME. It comes BEFORE the real CA, so a name check that let it through
# would spend the one allowed `isCA` on it and refuse the real CA instead.
SELF_SIGN_ISSUER_DOC = "kind: Issuer\nmetadata:\n  {{- dict \"name\" $ca.selfSignedIssuerName | toYaml | nindent 2 }}\nspec:\n  selfSigned: {}\n"


def test_an_is_ca_document_under_another_name_is_refused(tmp_path):
    chart = edited_chart(
        tmp_path,
        "internal-ca.yaml",
        SELF_SIGN_ISSUER_DOC,
        "kind: Certificate\nmetadata:\n  name: other-ca\nspec:\n  isCA: true\n  usages: [cert sign]\n",
    )
    refused_render(chart, "`other-ca` from `templates/internal-ca.yaml` sets `isCA`")


def test_a_leaf_keyed_like_the_ca_is_judged_by_its_source(tmp_path):
    """No internal CA renders, and a leaf takes its name: the allowlist is the source, not the name."""
    chart = edited_chart(
        tmp_path,
        "certificates.yaml",
        '  {{- dict "secretName" $name | toYaml | nindent 2 }}\n',
        '  {{- dict "secretName" $name | toYaml | nindent 2 }}\n  {{- if eq $name "yadgar-internal-ca" }}\n  isCA: true\n  {{- end }}\n',
    )
    values = values_file(
        tmp_path,
        "ca-off.yaml",
        "internalCA:\n  create: false\ncertificates:\n  leaves:\n    yadgar-internal-ca:\n"
        "      commonName: ca\n      usages: [server auth]\n      renewBefore: 999h\n",
    )
    result = helm("template", "platform", str(chart), *API_VERSIONS, "-f", str(ESTATE_VALUES), "-f", str(values))
    assert result.returncode != 0, result.stdout[:400]
    assert "`yadgar-internal-ca` from `templates/certificates.yaml` sets `isCA`" in result.stderr, result.stderr


def test_a_document_that_does_not_parse_is_refused(tmp_path):
    chart = edited_chart(tmp_path, "edge-certificate.yaml", EDGE_TAIL, EDGE_TAIL.replace("{{- end }}\n{{- end }}", "\n---\n- [unclosed\n{{- end }}\n{{- end }}", 1))
    refused_render(chart, "document 1 from `templates/edge-certificate.yaml` does not parse")
