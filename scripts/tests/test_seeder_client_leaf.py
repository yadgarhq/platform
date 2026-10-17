"""THE SEEDER'S CLIENT LEAF: `seeder-client-tls`, D35 seeder plan stage 4.

WHAT THIS LEAF IS FOR. The seeder (`yadgarhq/seeder`) is a new caller of
`project` on its gRPC hop, which already requires a client certificate on all
eight ADR-0852 hops. It does NOT reuse `project-client-tls`: the common name is
the caller's identity, and `project`'s caller check reads it, so a new caller
needs its own leaf (`plans/the-d35-seeder.md`, "mTLS").

WHAT IS ASSERTED, AND AGAINST WHICH RENDER.

  * `example/values.yaml`: the leaf renders with common name `seeder-caller`,
    `dnsNames` exactly `[seeder-caller]` (no namespace forms: nothing dials a
    caller), `usages` exactly `[client auth, digital signature]` (the other four
    client leaves' pair; ledger 1287's rule is that a client leaf names `client
    auth` and never `server auth`), and the next free rung, 798h.
  * the chart's own defaults: `certificates.create` is false, so the leaf is
    absent. The leaf has no gate of its own; the one toggle every internal leaf
    shares is the gate.
  * `certificates.create: false` over `example/values.yaml`: absent again, so
    the gate is shown to reach this leaf and not only the defaults.

The counts the leaf moves (15 Certificate objects, 14 rungs) are asserted where
the ladder and the usages wall already count: `test_ladder.py` and
`test_certificate_usages.py`.

NO SKIPS (ADR-0650): helm absent is a failure.

Run: python3 -m pytest scripts/tests/test_seeder_client_leaf.py -q
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parents[2]
CHART = REPO / "chart"
ADOPTER_VALUES = REPO / "example" / "values.yaml"

DECLARED_API_VERSIONS = ("cert-manager.io/v1", "gateway.envoyproxy.io/v1alpha1")
API_VERSIONS = tuple(
    part for group in DECLARED_API_VERSIONS for part in ("--api-versions", group)
)

LEAF = "seeder-client-tls"
COMMON_NAME = "seeder-caller"
USAGES = ["client auth", "digital signature"]
RUNG = "798h"


def helm(*arguments: str) -> subprocess.CompletedProcess[str]:
    binary = shutil.which("helm")
    assert binary, (
        "helm is not on PATH. This suite renders the chart, and so does the "
        "`helm lint and render` pre-commit hook — install helm rather than "
        "letting either report a pass it did not earn."
    )
    return subprocess.run([binary, *arguments], capture_output=True, text=True)


def render(*arguments: str) -> list[dict]:
    result = helm(
        "template", "platform", str(CHART), *API_VERSIONS, "--namespace", "yadgar", *arguments
    )
    assert result.returncode == 0, result.stderr
    return [
        document
        for document in yaml.safe_load_all(result.stdout)
        if isinstance(document, dict) and document.get("apiVersion")
    ]


def certificate_names(documents: list[dict]) -> list[str]:
    return sorted(
        str(document["metadata"]["name"])
        for document in documents
        if document.get("kind") == "Certificate"
    )


def the_leaf(documents: list[dict]) -> dict:
    found = [
        document
        for document in documents
        if document.get("kind") == "Certificate" and document["metadata"]["name"] == LEAF
    ]
    assert len(found) == 1, (
        f"expected exactly one Certificate named {LEAF}, found {len(found)} among "
        f"{certificate_names(documents)}"
    )
    return found[0]


def test_the_seeder_leaf_renders_as_a_caller_with_its_own_rung():
    """CN `seeder-caller`, the CN as its only SAN, client auth only, rung 798h."""
    specification = the_leaf(render("-f", str(ADOPTER_VALUES)))["spec"]
    assert specification["secretName"] == LEAF, specification
    assert specification["commonName"] == COMMON_NAME, specification
    assert specification["dnsNames"] == [COMMON_NAME], (
        f"a caller's leaf names only its identity; nothing dials a caller, so no "
        f"Service form belongs on it: {specification['dnsNames']}"
    )
    assert specification["usages"] == USAGES, specification["usages"]
    assert "server auth" not in specification["usages"], specification["usages"]
    assert specification["renewBefore"] == RUNG, specification["renewBefore"]
    assert specification.get("isCA") is not True, specification


def test_the_seeder_leaf_is_absent_at_the_defaults():
    """`certificates.create` is false in `values.yaml`: no Certificate at all."""
    documents = render()
    assert LEAF not in certificate_names(documents), certificate_names(documents)


def test_the_seeder_leaf_follows_the_shared_toggle(tmp_path):
    """The red case for the gate: the adopter render with `certificates.create` off."""
    off = tmp_path / "off.yaml"
    off.write_text("certificates:\n  create: false\n")
    documents = render("-f", str(ADOPTER_VALUES), "-f", str(off))
    names = certificate_names(documents)
    assert LEAF not in names, names
    # THE TRIPWIRE: the same override must leave the CA root and the edge leaf,
    # or it disabled more than the leaves and this case proves nothing about them.
    assert len(names) == 2, names
