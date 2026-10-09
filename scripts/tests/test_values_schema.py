"""THE CLOSED KEY SET, `values.schema.json` (ledger 990, ADR-0847, ADR-0850).

WHAT THIS FILE IS NOT. `test_render_checks.py`, `test_operators_shape.py` and
`test_preflight.py` assert what a key is READ AS, once it is read. This file
asserts which KEYS are read AT ALL: every block this chart's own
`chart/values.yaml` declares is now closed, so a typo under any of them is
refused BY NAME at render, rather than merged into the values tree and
silently never read. ADR-0847 draws the line between the two kinds of file:
TYPES, toggle SHAPES and `required` stay in `render-checks.yaml`; this file
closes KEY SETS and nothing else. A value written at the wrong SHAPE — a
string where a block belongs, a non-bool on a toggle — PASSES this schema and
is the other file's refusal to make; the green cases below prove that rather
than assert it from the two files' names alone.

NINE PATHS STAY OPEN (`OPEN` below), asserted bare `{}`, never typed, and ONE
IS PARTLY OPEN (`PARTLY_OPEN`): `nats`, open at its own level with the
platform-owned `nats.tls` closed beneath it (B-L1).
`global` is Helm's own reserved key (ADR-0722). The SEVEN upstream sections
are each a Helm dependency this chart adopts rather than re-types: `nats`,
`cert-manager`, `keda`, `mariadb-operator`, `gateway-helm`, `argo-cd` and
`prometheus` (ADR-0787, ADR-0792, ADR-0820). TWO NESTED PATHS stay open for
the same reason: `gatewayListener.envoyProxy.pod.nodeSelector` (a raw
node-selector map) and `valkey.resources` (a raw `corev1.
ResourceRequirements`). `edgeTLS.issuerRef` is NOT one of these (coordinator
ruling): `templates/edge-certificate.yaml` reads only `.name` and `.kind` off
it and hardcodes `group: cert-manager.io` itself, so an open map there would
silently DROP a key like `group: awspca.cert-manager.io` rather than refuse
it — closed to exactly `{name, kind}` instead, same shape as a keyed block.

THE EXTRAS (`EXTRAS` below) are declared though `chart/values.yaml` never
states them, because a template, or the parent's own condition resolution,
reads every one anyway:

  - `enabled` — read by NO template in this chart. It exists so the PARENT's
    `condition: platform.enabled` (its dependency on this chart) resolves
    against a key the coalesced values tree carries; without it a closed root
    refuses the parent's own default render at `''` (measured, correction 10).
  - `gateway-helm`, `argo-cd` — the two upstream sections `values.yaml` never
    mentions at all (unlike the other five, which at least carry a
    `crds`/`create` line of their own).
  - `operators.certManager.create`, `operators.keda.create`,
    `operators.mariadbOperator.create`, `operators.envoyGateway.create`,
    `operators.argoCd.create`, `operators.prometheus.create` — each read off
    `chart/Chart.yaml`'s own `condition:` for that dependency and resolved by
    `templates/_operators.tpl`. `values.yaml` ships only the register key,
    `operators.create`: no per-operator key, by design, so an unset one
    defers to the register (ledger 1252).
  - `preflight.probes.certManager`, `preflight.probes.keda`,
    `preflight.probes.mariadb`, `preflight.probes.prometheus`,
    `preflight.probes.envoyGateway` — each read by
    `templates/_preflight.tpl`'s `platform.preflight.probe`, which tests
    `hasKey` against `preflight.probes` rather than `default` so that an
    explicit `false` is always honoured. `values.yaml` ships
    `preflight.probes: {}`, stating none of the five itself. The brief this
    PR implements first measured only four of the five (dropping
    `certManager`); `_preflight.tpl` reads `probes.certManager` too, so
    dropping it would refuse a legitimate override
    (`preflight.probes.certManager: false` beside `internalCA.create: true`).
  - `edgeTLS.issuerRef.name`, `edgeTLS.issuerRef.kind` — `values.yaml` ships
    `issuerRef: {}`, empty; `templates/edge-certificate.yaml` `required`s
    both, so both are declared here rather than left for an open map to
    swallow a typo of either silently.
  - `nats.tls` and `valkey.tls` with their keys (`enabled`, `clientAuth`,
    and `plaintext` for valkey) — the platform-owned TLS switches B-L1
    declares and B-N2 / B-V2 render. Absent from `values.yaml` by design:
    the contracts make them required with no default (ADR-0845, ADR-0854).

TWO RESIDUALS ARE NOT, AND CANNOT BE, REFUSABLE HERE: `nats.create` (inside
the open `nats` section; `render-checks.yaml`'s own mixed-release guard only
ever sees the CORRECTLY SPELLED key) and `prometheus.forceNamespace` (inside
the open `prometheus` section, read by `templates/prometheus-namespace.yaml`;
`render-checks.yaml` refuses it empty or null while prometheus is on, ledger
1340, but cannot see a typo'd sibling key). Closing either key means closing its whole upstream
section, which would also refuse every key the upstream chart itself
accepts. The green rows below assert they pass THIS schema at exit 0, each
with a comment naming the render check (or the absence of one) that is the
only place they are refusable.

THE STRUCTURAL TESTS BELOW ARE PURE — no helm, no subprocess — and are the
ones the four required mutations are checked against: delete root
`additionalProperties`, delete `global`, delete one extra, close one open
map. Each mutation is its own test, built on a FRESH read of the real file so
one mutated copy cannot bleed into the next assertion.

THE RENDER TESTS use `helm template`, reusing `CHART`, `helm` and `render`
from `test_render_checks.py` rather than re-deriving the chart path or the
binary lookup a second time. `ADOPTER_VALUES` (`example/values.yaml`) is the
same live file `test_render_checks.py`, `test_ladder.py` and
`test_bootstrap.py` already render.

Run: python3 -m pytest scripts/tests/ -q
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import yaml

from test_render_checks import ADOPTER_VALUES, CHART, helm, render

SCHEMA = CHART / "values.schema.json"
VALUES = CHART / "values.yaml"

# Paths whose schema node MUST be the bare `{}` an open map is. See the
# module docstring and the schema's own `$comment` for why each is open.
OPEN = (
    "global",
    "cert-manager",
    "keda",
    "mariadb-operator",
    "gateway-helm",
    "argo-cd",
    "prometheus",
    "gatewayListener.envoyProxy.pod.nodeSelector",
    "valkey.resources",
)

# PARTLY OPEN: an upstream section that ALSO carries one platform-owned block
# (B-L1, the folded B-N2 expand). `nats` is the nats subchart's own values, so
# it stays open to every key upstream accepts — no `additionalProperties` at
# that level — while `nats.tls` is THIS chart's key (the platform-owned switch
# ADR-0845 needs, because the parent always sees the subchart's own default for
# `nats.config.nats.tls.enabled`) and is closed like any other block. The
# upstream chart reads no top-level `tls`, so declaring it shadows nothing.
PARTLY_OPEN = {"nats": {"tls"}}

# Leaves a template (or the parent's own condition resolution) reads that
# `values.yaml` never states (§2 step 2's "read-but-undeclared keys"),
# declared here as closed-block leaves. Two of these — `gateway-helm` and
# `argo-cd` — are ALSO in OPEN: undeclared-in-`values.yaml` is an accounting
# fact about where a path came from, open-vs-closed is a fact about its
# shape, and the two upstream sections are both at once.
EXTRAS = (
    "enabled",
    "gateway-helm",
    "argo-cd",
    # Each `operators.<op>` CONTAINER is itself undeclared in `values.yaml`
    # (which states only `operators.create`), so the block and its one leaf
    # are BOTH new paths this schema adds.
    "operators.certManager",
    "operators.certManager.create",
    "operators.keda",
    "operators.keda.create",
    "operators.mariadbOperator",
    "operators.mariadbOperator.create",
    "operators.envoyGateway",
    "operators.envoyGateway.create",
    "operators.argoCd",
    "operators.argoCd.create",
    "operators.prometheus",
    "operators.prometheus.create",
    "preflight.probes.certManager",
    "preflight.probes.keda",
    "preflight.probes.mariadb",
    "preflight.probes.prometheus",
    "preflight.probes.envoyGateway",
    # `values.yaml` ships `edgeTLS.issuerRef: {}`, empty — the two keys the
    # template `required`s are declared here rather than left open.
    "edgeTLS.issuerRef.name",
    "edgeTLS.issuerRef.kind",
    # THE NATS AND VALKEY TLS KEYS (B-L1, the folded B-N2 / B-V2 expand). Absent
    # from `values.yaml` BY DESIGN: the contracts make them required with no
    # chart default (ADR-0845, ADR-0854), and an expand that shipped a default
    # would have to delete it again. `render-checks.yaml` validates each one
    # when present and refuses every value the contracts have not rendered yet.
    "nats.tls",
    "nats.tls.enabled",
    "nats.tls.clientAuth",
    "valkey.tls",
    "valkey.tls.enabled",
    "valkey.tls.clientAuth",
    "valkey.tls.plaintext",
)

# `certificates.leaves` is a KEYED MAP (§3.5): any leaf NAME is accepted, so
# the schema declares no per-name path at all, and `values.yaml`'s ten named
# leaves must not be walked into when checking "every values.yaml leaf is
# declared" — they are covered by the wildcard `additionalProperties` schema
# `test_the_certificates_leaves_are_a_keyed_map_with_closed_values` checks
# directly, not by a matching dotted path.
KEYED_MAPS = ("certificates.leaves",)

# This chart retains no typed leaf of its own (unlike gateway's `toolsPoll` or
# the twins' `database.migrationLockTimeoutSeconds`): `gatewayListener.
# envoyProxy.httpsNodePort` ships `null` in this chart's own `values.yaml`,
# and a typed leaf there would refuse this chart's own default render.
RETAINED: tuple[str, ...] = ()

CERT_MANAGER_AND_GATEWAY_API = (
    "--api-versions",
    "cert-manager.io/v1",
    "--api-versions",
    "gateway.envoyproxy.io/v1alpha1",
)


# ── READERS, PURE ─────────────────────────────────────────────────────────


def load_schema() -> dict:
    return json.loads(SCHEMA.read_text())


def load_values() -> dict:
    return yaml.safe_load(VALUES.read_text())


def schema_paths(schema: dict, prefix: str = "") -> set[str]:
    """Every dotted path declared under some `properties` key, anywhere. PURE."""
    paths: set[str] = set()
    for key, node in schema.get("properties", {}).items():
        path = f"{prefix}.{key}" if prefix else key
        paths.add(path)
        if isinstance(node, dict):
            paths |= schema_paths(node, path)
    return paths


def values_paths(
    values: dict, prefix: str = "", open_paths: tuple[str, ...] = OPEN + tuple(PARTLY_OPEN)
) -> set[str]:
    """Every dotted path `values.yaml` itself states, PURE.

    MIRRORS `gen_schema.py`'s OWN RECURSION: an open path's children are never
    visited, because the schema does not declare them either. A PARTLY open path
    is not walked either: `values.yaml` states only upstream keys under it.
    """
    paths: set[str] = set()
    for key, value in values.items():
        path = f"{prefix}.{key}" if prefix else key
        paths.add(path)
        if isinstance(value, dict) and value and path not in open_paths:
            paths |= values_paths(value, path, open_paths)
    return paths


def schema_node(schema: dict, path: str):
    """The node at a dotted path, or `None` if any step is undeclared. PURE."""
    cursor = schema
    for step in path.split("."):
        cursor = cursor.get("properties", {}).get(step)
        if cursor is None:
            return None
    return cursor


def open_paths_failures(schema: dict) -> list[str]:
    """Every `OPEN` path that is not the bare, unconstrained `{}` an open map is."""
    failures = []
    for path in OPEN:
        node = schema_node(schema, path)
        if node != {}:
            failures.append(f"{path} is declared as {node!r}, not the bare {{}} an open map is")
    return failures


def partly_open_failures(schema: dict) -> list[str]:
    """Every `PARTLY_OPEN` path that is not open at its own level with exactly
    the platform-owned blocks declared. PURE.

    TWO WAYS TO GET IT WRONG, both checked: `additionalProperties: false` at the
    section's own level refuses every key the upstream chart accepts, and a
    declared block beyond the platform-owned set is a key this chart claims
    from upstream without reading it.
    """
    failures = []
    for path, owned in PARTLY_OPEN.items():
        node = schema_node(schema, path)
        if node is None:
            failures.append(f"{path} is not declared at all")
            continue
        if "additionalProperties" in node:
            failures.append(
                f"{path} carries `additionalProperties`, so it is no longer open to "
                f"the upstream chart's own keys"
            )
        declared = set(node.get("properties", {}))
        if declared != owned:
            failures.append(f"{path} declares {sorted(declared)}, expected {sorted(owned)}")
    return failures


def nodes_with_properties(schema: dict, prefix: str = ""):
    """Yield (path, node) for every node in the tree carrying `properties`.

    `prefix` is `""` for the root itself, so a root-level offender prints as
    `(root)` rather than an empty string nobody can read as a path.
    """
    if "properties" in schema:
        yield prefix, schema
        for key, node in schema["properties"].items():
            if isinstance(node, dict):
                yield from nodes_with_properties(node, f"{prefix}.{key}" if prefix else key)


def closure_offenders(schema: dict) -> list[str]:
    """`PARTLY_OPEN` paths are the one exemption, and `partly_open_failures`
    is their own check: open at their level, closed below it."""
    return [
        path or "(root)"
        for path, node in nodes_with_properties(schema)
        if node.get("additionalProperties") is not False and path not in PARTLY_OPEN
    ]


FORBIDDEN_KEYWORDS = ("type", "enum", "required", "default")


def all_nodes(schema: dict, prefix: str = ""):
    """Yield (path, node) for EVERY node in the tree, root included — unlike
    `nodes_with_properties`, this also descends into a keyed map's VALUE
    schema (`additionalProperties`, when it is itself a dict), because
    `certificates.leaves`'s value schema is a node this check must reach too.
    """
    yield prefix, schema
    for key, node in schema.get("properties", {}).items():
        if isinstance(node, dict):
            yield from all_nodes(node, f"{prefix}.{key}" if prefix else key)
    additional = schema.get("additionalProperties")
    if isinstance(additional, dict):
        yield from all_nodes(additional, f"{prefix}[*]" if prefix else "[*]")


def forbidden_keyword_offenders(schema: dict) -> list[str]:
    """Every node outside `RETAINED` that carries `type`, `enum`, `required`
    or `default` — ADR-0847's line, that this file closes KEY SETS only and
    leaves TYPES, toggle SHAPES and `required` to `render-checks.yaml`. PURE.
    """
    offenders = []
    for path, node in all_nodes(schema):
        if path in RETAINED:
            continue
        for keyword in FORBIDDEN_KEYWORDS:
            if keyword in node:
                offenders.append(f"{path or '(root)'} carries `{keyword}`")
    return offenders


def extras_found(schema: dict, values: dict) -> set[str]:
    """Schema paths beyond what `values.yaml` itself states. PURE.

    Only `global` needs an explicit exemption beyond "stated in values.yaml":
    every other `OPEN` path (`nats`, `cert-manager`, `keda`, `mariadb-
    operator`, `prometheus`, `gatewayListener.envoyProxy.pod.nodeSelector`,
    `valkey.resources`) IS a key `values.yaml` states, so `values_paths`
    already carries it. `gateway-helm` and `argo-cd` are NOT stated either,
    which is exactly why both are in `EXTRAS` too, open-shaped extras rather
    than closed ones.
    """
    stated = values_paths(values, open_paths=OPEN + tuple(PARTLY_OPEN) + KEYED_MAPS)
    return schema_paths(schema) - stated - {"global"} - set(RETAINED)


def overlay(body, destination: Path) -> Path:
    """One values overlay, WRITTEN AS A WHOLE FILE. See `test_render_checks.py`'s
    construction for why a whole file rather than an appended key: appending
    onto a sibling key can nest a value under the wrong parent and silently
    test a different shape than the one named.
    """
    destination.mkdir(parents=True, exist_ok=True)
    path = destination / "values.yaml"
    path.write_text(body if isinstance(body, str) else yaml.safe_dump(body))
    return path


def render_with_overlay(chart: Path, body, destination: Path, *extra_args: str):
    path = overlay(body, destination)
    return render(chart, "-f", str(path), *extra_args)


def object_count(stdout: str) -> int:
    return stdout.count("\nkind: ")


def assert_schema_refusal(stderr: str, key: str, dotted_path: str = "") -> None:
    """Assert a schema refusal names BOTH the key and the path, tolerant of
    EITHER helm message shape (never asserting the sentence itself).

    helm 3.20.2 and 4.3.0 share one shape: `at '/a/b': additional properties
    'key' not allowed` (root is `at ''`). helm 3.18.4 prints a different one:
    `a.b: Additional property key is not allowed` (root is `(root):`). Both
    name the key unquoted-as-a-substring and the path, in their own notation
    — this checks both notations so the suite is not pinned to one helm.

    `key` MUST NOT be a substring of any real key this schema declares (a
    typo like `creat` is a substring of `create`, and `renewBefor` of
    `renewBefore` — both would still match if the real key appeared anywhere
    else in a longer, unrelated message). Choose a token like `crate` or
    `kedaa` that collides with nothing.
    """
    assert key in stderr, f"{key!r} not named in {stderr!r}"
    if dotted_path == "":
        assert "at ''" in stderr or "(root):" in stderr, (
            f"root path not named (either shape) in {stderr!r}"
        )
    else:
        slash_path = "/" + dotted_path.replace(".", "/")
        assert f"'{slash_path}'" in stderr or f"{dotted_path}:" in stderr, (
            f"{dotted_path!r} not named (either shape) in {stderr!r}"
        )


# ── STRUCTURAL TESTS, PURE ───────────────────────────────────────────────


def test_every_node_with_properties_is_closed():
    """`additionalProperties: false` wherever `properties` appears, root included.

    THE RED CASE for this is `test_mutation_deleting_root_additional_properties_
    reddens_the_closure_check` below — a fresh schema read, not this one mutated
    in place, so the mutation cannot leak into a later assertion. This is also
    the gate that `gen_schema.py`'s own merge-step regression (D-S(gateway),
    #101) would have reddened, had this chart carried an existing schema for it
    to merge over — it does not, so that regression cannot reach this chart.
    """
    offenders = closure_offenders(load_schema())
    assert offenders == [], (
        f"{offenders} carries `properties` with no `additionalProperties: false` "
        f"— an adopter's typo under it is accepted rather than refused"
    )


def test_the_open_paths_are_exactly_bare():
    """The nine `OPEN` paths are `{}` — open, untyped, unchecked.

    NOT merely "has no `additionalProperties`": a node like `{"type": "object"}`
    would pass a laxer check and still be a TYPED open map, which is not what
    this chart ships for any of the nine.
    """
    failures = open_paths_failures(load_schema())
    assert failures == [], "\n".join(failures)


def test_the_partly_open_paths_are_open_above_the_platform_owned_block():
    """`nats` stays open to upstream's keys; `nats.tls` alone is declared."""
    failures = partly_open_failures(load_schema())
    assert failures == [], "\n".join(failures)


def test_the_nats_and_valkey_tls_blocks_are_closed_to_their_keys():
    """B-L1: the platform-owned TLS keys, by name, each block closed.

    NATS has no `plaintext`: the transport step there is the upstream
    `nats.config.merge.allow_non_tls` (B-N2), not a platform key.
    """
    schema = load_schema()
    expected = {
        "nats.tls": {"enabled", "clientAuth"},
        "valkey.tls": {"enabled", "clientAuth", "plaintext"},
    }
    for path, keys in expected.items():
        node = schema_node(schema, path)
        assert node is not None, f"{path} is not declared"
        assert node.get("additionalProperties") is False, f"{path} is not closed"
        assert set(node["properties"]) == keys, (path, sorted(node["properties"]))
        for key in keys:
            assert node["properties"][key] == {}, (path, key)


def test_mutation_closing_nats_at_its_own_level_reddens_the_partly_open_check():
    schema = load_schema()
    schema["properties"]["nats"]["additionalProperties"] = False
    failures = partly_open_failures(schema)
    assert any("carries `additionalProperties`" in failure for failure in failures), failures


def test_mutation_opening_nats_tls_reddens_the_closure_check():
    schema = load_schema()
    del schema["properties"]["nats"]["properties"]["tls"]["additionalProperties"]
    assert closure_offenders(schema) == ["nats.tls"]


def test_mutation_claiming_an_upstream_nats_key_reddens_the_partly_open_check():
    schema = load_schema()
    schema["properties"]["nats"]["properties"]["config"] = {}
    failures = partly_open_failures(schema)
    assert any("expected ['tls']" in failure for failure in failures), failures


def test_every_values_yaml_leaf_is_declared():
    """Every path `values.yaml` itself states is declared somewhere in the schema.

    THE DIRECTION THAT MATTERS MOST: a key `values.yaml` ships with no
    matching schema entry is refused by the chart's OWN defaults the moment
    somebody rewrites it, which is a worse failure than a typo ever is.
    """
    declared = schema_paths(load_schema())
    stated = values_paths(load_values(), open_paths=OPEN + tuple(PARTLY_OPEN) + KEYED_MAPS)
    missing = sorted(stated - declared)
    assert missing == [], (
        f"chart/values.yaml states {missing} and the schema declares none of "
        f"them — an adopter writing the CORRECT key would be refused by it"
    )


def test_every_schema_extra_is_exactly_the_declared_set():
    """Schema paths beyond values.yaml and the open paths == EXTRAS.

    BOTH DIRECTIONS AT ONCE: a path missing from EXTRAS that the schema still
    declares is undocumented (and untested below); a path in EXTRAS the
    schema no longer declares is stale documentation for a key nothing
    refuses.
    """
    found = extras_found(load_schema(), load_values())
    assert found == set(EXTRAS), (
        f"found {sorted(found)}, EXTRAS says {sorted(EXTRAS)} — a path declared "
        f"with no template reading it, or a template read with nothing "
        f"declared, is a typo in one of the two"
    )


def test_enabled_and_the_five_probes_and_six_operator_creates_are_declared():
    """The specific keys ledger 990's K-3 and the design brief's correction 10
    name, asserted by name rather than only by the set-equality check above —
    a reader who only wants to know "is `enabled` really there" should not
    have to read `extras_found`'s formula to answer it.
    """
    schema = load_schema()
    assert schema_node(schema, "enabled") == {}
    for operator in ("certManager", "keda", "mariadbOperator", "envoyGateway", "argoCd", "prometheus"):
        assert schema_node(schema, f"operators.{operator}.create") == {}, operator
    for probe in ("certManager", "keda", "mariadb", "prometheus", "envoyGateway"):
        assert schema_node(schema, f"preflight.probes.{probe}") == {}, probe


def test_the_certificates_leaves_are_a_keyed_map_with_closed_values():
    """§3.5: open KEYS (any leaf name), closed VALUES (the four fields every
    leaf may carry). NOT the per-leaf-name enumeration `gen_schema.py` emits
    unaided — that would refuse a future eleventh leaf by name, which this
    chart's own `certificates.leaves` is a `range $name, $leaf` over, with no
    name list anywhere that would need a schema update to match.
    """
    leaves = load_schema()["properties"]["certificates"]["properties"]["leaves"]
    assert set(leaves.keys()) == {"additionalProperties"}, leaves
    value_schema = leaves["additionalProperties"]
    assert value_schema["additionalProperties"] is False
    assert set(value_schema["properties"].keys()) == {
        "commonName",
        "clusterLocalNames",
        "usages",
        "renewBefore",
    }


def test_no_node_carries_a_type_enum_required_or_default_beyond_retained():
    """ADR-0847's line, checked over the WHOLE tree rather than trusted from
    the module docstring's claim alone: `RETAINED` is empty today (this
    chart keeps no typed leaf of its own), so no node anywhere — root
    included, and the `certificates.leaves` value schema included — may
    carry `type`, `enum`, `required` or `default`. Red case: `test_mutation_
    adding_type_integer_on_valkey_port_reddens_the_keyword_check` and
    `test_mutation_adding_root_type_object_reddens_the_keyword_check` below.
    """
    offenders = forbidden_keyword_offenders(load_schema())
    assert offenders == [], (
        f"{offenders} — types, toggle shapes and `required` belong in "
        f"render-checks.yaml (ADR-0847), not here"
    )


# ── THE FOUR MUTATIONS (preamble: "mutation-check the key assertion") ──────


def test_mutation_deleting_root_additional_properties_reddens_the_closure_check():
    schema = load_schema()
    del schema["additionalProperties"]
    assert closure_offenders(schema) == ["(root)"]


def test_mutation_deleting_global_reddens_the_open_path_check():
    schema = load_schema()
    del schema["properties"]["global"]
    assert open_paths_failures(schema) != []


def test_mutation_deleting_an_extra_reddens_the_extras_check():
    schema = load_schema()
    del schema["properties"]["enabled"]
    found = extras_found(schema, load_values())
    assert found != set(EXTRAS)
    assert "enabled" not in found


def test_mutation_closing_an_open_map_reddens_the_open_path_check():
    schema = load_schema()
    schema["properties"]["valkey"]["properties"]["resources"] = {
        "properties": {},
        "additionalProperties": False,
    }
    assert open_paths_failures(schema) != []


def test_mutation_reopening_internal_ca_lets_the_root_level_typo_through(tmp_path):
    """THE RENDER-LEVEL MUTATION CHECK for the red cases below.

    The four Python mutations above prove the STRUCTURAL tests are
    falsifiable. This one proves the RENDER-based red case
    (`test_a_typo_under_internal_ca_is_refused_by_name`) actually depends on
    THIS schema's closure and not on some other guard reaching the key first:
    with `internalCA` reopened, the exact same typo renders clean.
    """
    copy = tmp_path / "chart"
    shutil.copytree(CHART, copy)
    schema = json.loads((copy / "values.schema.json").read_text())
    schema["properties"]["internalCA"]["additionalProperties"] = True
    (copy / "values.schema.json").write_text(json.dumps(schema))

    result = render_with_overlay(copy, {"internalCA": {"crate": True}}, tmp_path / "reopened")
    assert result.returncode == 0, (
        f"reopening `internalCA` and the red case below STILL refused, so "
        f"that case is not exercising this schema's closure: {result.stderr}"
    )


def test_mutation_adding_type_integer_on_valkey_port_reddens_the_keyword_check():
    schema = load_schema()
    schema["properties"]["valkey"]["properties"]["port"] = {"type": "integer"}
    offenders = forbidden_keyword_offenders(schema)
    assert offenders != []
    assert any("valkey.port" in offender for offender in offenders), offenders


def test_mutation_adding_root_type_object_reddens_the_keyword_check():
    schema = load_schema()
    schema["type"] = "object"
    offenders = forbidden_keyword_offenders(schema)
    assert offenders != []
    assert any("(root)" in offender for offender in offenders), offenders


# ── RED: A TYPO UNDER A CLOSED BLOCK IS REFUSED BY NAME ────────────────────


def test_a_root_typo_is_refused_by_name(tmp_path):
    result = render_with_overlay(CHART, {"interncalCA": {"create": True}}, tmp_path)
    assert result.returncode != 0, result.stdout
    assert_schema_refusal(result.stderr, "interncalCA")


def test_a_typo_under_internal_ca_is_refused_by_name(tmp_path):
    result = render_with_overlay(CHART, {"internalCA": {"crate": True}}, tmp_path)
    assert result.returncode != 0, result.stdout
    assert_schema_refusal(result.stderr, "crate", "internalCA")


def test_a_typo_two_levels_down_under_operators_is_refused_by_name(tmp_path):
    result = render_with_overlay(CHART, {"operators": {"certManager": {"crate": True}}}, tmp_path)
    assert result.returncode != 0, result.stdout
    assert_schema_refusal(result.stderr, "crate", "operators.certManager")


def test_a_typo_under_preflight_probes_is_refused_by_name(tmp_path):
    result = render_with_overlay(CHART, {"preflight": {"probes": {"kedaa": True}}}, tmp_path)
    assert result.returncode != 0, result.stdout
    assert_schema_refusal(result.stderr, "kedaa", "preflight.probes")


def test_a_typo_under_gateway_listener_envoy_proxy_is_refused_by_name(tmp_path):
    result = render_with_overlay(
        CHART, {"gatewayListener": {"envoyProxy": {"httpsNodePrt": 1}}}, tmp_path
    )
    assert result.returncode != 0, result.stdout
    assert_schema_refusal(result.stderr, "httpsNodePrt", "gatewayListener.envoyProxy")


def test_a_typo_in_a_certificates_leaf_is_refused_by_name(tmp_path):
    result = render_with_overlay(
        CHART,
        {"certificates": {"leaves": {"new-tls": {"renewBeforX": "1h"}}}},
        tmp_path,
    )
    assert result.returncode != 0, result.stdout
    assert_schema_refusal(result.stderr, "renewBeforX", "certificates.leaves.new-tls")


def test_an_edge_tls_issuer_ref_group_is_refused_by_name(tmp_path):
    """COORDINATOR RULING on `edgeTLS.issuerRef`: `templates/edge-certificate.
    yaml` reads only `.name` and `.kind` off it and hardcodes `group: cert-
    manager.io` itself — an open map there would silently DROP a stated
    `group` (e.g. `awspca.cert-manager.io`, a real cert-manager external
    issuer) rather than refuse it. Closed to exactly `{name, kind}`, `group`
    is now refused by name instead.
    """
    result = render_with_overlay(
        CHART,
        {
            "edgeTLS": {
                "issuerRef": {
                    "name": "x",
                    "kind": "ClusterIssuer",
                    "group": "awspca.cert-manager.io",
                }
            }
        },
        tmp_path,
    )
    assert result.returncode != 0, result.stdout
    assert_schema_refusal(result.stderr, "group", "edgeTLS.issuerRef")


def test_helm_lint_strict_also_refuses_the_root_typo(tmp_path):
    """The same schema applies in `helm lint --strict`, which the `helm-lint`
    pre-commit hook runs — a schema that only `helm template` enforced would
    leave that hook blind to the very typo this file exists to catch.
    """
    path = overlay({"interncalCA": {"create": True}}, tmp_path)
    result = helm("lint", "--strict", str(CHART), "-f", str(path))
    assert result.returncode != 0, result.stdout
    assert "interncalCA" in (result.stdout + result.stderr)


# ── GREEN: THE WRONG SHAPE PASSES THIS SCHEMA (ADR-0847 draws the line) ────


def test_operators_as_a_string_passes_this_schema_and_is_refused_downstream(tmp_path):
    """`operators: "x"` is a BLOCK written as a scalar — not this schema's job
    (§3.2: a block is `{"properties": ..., "additionalProperties": false}`
    with NO `type`, so JSON Schema's `properties` keyword does not even apply
    to a non-object instance). `templates/_operators.tpl` / `render-checks.
    yaml`'s own shape refusal is what catches it.
    """
    result = render_with_overlay(CHART, 'operators: "x"\n', tmp_path)
    assert result.returncode != 0, result.stdout
    assert "operators is a string rather than a mapping" in result.stderr, result.stderr
    assert "additional propert" not in result.stderr.lower(), result.stderr


# ── GREEN: AN OPEN MAP TAKES ANY SHAPE UNDERNEATH ──────────────────────────


DEFAULT_OBJECT_COUNT = 0


def test_open_global_takes_an_unknown_key(tmp_path):
    result = render_with_overlay(CHART, {"global": {"whatever": 1}}, tmp_path)
    assert result.returncode == 0, result.stderr
    assert object_count(result.stdout) == DEFAULT_OBJECT_COUNT


def test_open_nats_section_takes_an_unknown_key(tmp_path):
    result = render_with_overlay(CHART, {"nats": {"whatever": 1}}, tmp_path)
    assert result.returncode == 0, result.stderr
    assert object_count(result.stdout) == DEFAULT_OBJECT_COUNT


def test_open_valkey_resources_takes_an_unknown_shape(tmp_path):
    result = render_with_overlay(CHART, {"valkey": {"resources": {"foo": {"bar": 1}}}}, tmp_path)
    assert result.returncode == 0, result.stderr
    assert object_count(result.stdout) == DEFAULT_OBJECT_COUNT


def test_an_untyped_leaf_takes_a_string(tmp_path):
    """`valkey.port` carries no `type` in this schema (ADR-0847: types stay
    in `render-checks.yaml`), so `--set-string` forcing it to arrive as a
    string rather than a number is not this schema's refusal to make.
    """
    result = render(CHART, "--set-string", "valkey.port=6379")
    assert result.returncode == 0, result.stderr
    assert object_count(result.stdout) == DEFAULT_OBJECT_COUNT


# ── GREEN: THE EXTRAS ARE ACCEPTED ─────────────────────────────────────────


def test_enabled_true_at_the_root_is_accepted(tmp_path):
    result = render_with_overlay(CHART, {"enabled": True}, tmp_path)
    assert result.returncode == 0, result.stderr
    assert object_count(result.stdout) == DEFAULT_OBJECT_COUNT


def test_all_six_operator_create_keys_are_accepted(tmp_path):
    result = render_with_overlay(
        CHART,
        {
            "operators": {
                "certManager": {"create": False},
                "keda": {"create": False},
                "mariadbOperator": {"create": False},
                "envoyGateway": {"create": False},
                "argoCd": {"create": False},
                "prometheus": {"create": False},
            }
        },
        tmp_path,
    )
    assert result.returncode == 0, result.stderr
    assert object_count(result.stdout) == DEFAULT_OBJECT_COUNT


def test_preflight_probes_certmanager_false_beside_internal_ca_true_is_accepted(tmp_path):
    """The exact row the brief's correction 1 exists for: a FOUR-key closure
    of `preflight.probes` refuses this row by name. Five keys must not.
    """
    result = render_with_overlay(
        CHART,
        {
            "internalCA": {"create": True},
            "preflight": {"probes": {"certManager": False}},
        },
        tmp_path,
        "--api-versions",
        "cert-manager.io/v1",
    )
    assert result.returncode == 0, result.stderr
    assert "additional propert" not in result.stderr.lower(), result.stderr


def test_preflight_probes_keda_true_is_accepted(tmp_path):
    result = render_with_overlay(
        CHART,
        {"preflight": {"probes": {"keda": True}}},
        tmp_path,
    )
    assert result.returncode == 0, result.stderr
    assert object_count(result.stdout) == 4


# ── GREEN: THE RESIDUALS, UNREFUSABLE BY THIS SCHEMA ───────────────────────


def test_a_typo_under_nats_tls_is_refused_by_name(tmp_path):
    """`nats` is partly open, and `nats.tls` is the closed part."""
    result = render_with_overlay(CHART, {"nats": {"tls": {"enabeld": False}}}, tmp_path)
    assert result.returncode != 0, result.stdout
    assert_schema_refusal(result.stderr, "enabeld", "nats.tls")


def test_a_typo_under_valkey_tls_is_refused_by_name(tmp_path):
    result = render_with_overlay(CHART, {"valkey": {"tls": {"plaintxt": True}}}, tmp_path)
    assert result.returncode != 0, result.stdout
    assert_schema_refusal(result.stderr, "plaintxt", "valkey.tls")


def test_nats_create_typo_passes_this_schema_silently(tmp_path):
    """`nats` is an OPEN upstream section, so a typo'd SIBLING key under it —
    `creat`, beside the real `create` — is not a key this schema can see at
    all. `render-checks.yaml` DOES guard `nats.create` itself (a DELETED or
    non-bool `nats.create` is refused by name), but a `-f` overlay MERGES onto
    `chart/values.yaml`'s own `nats: {create: false, ...}` rather than
    replacing it, so `create` stays present and boolean here — the typo'd
    `creat` sits beside it, inert, read by nothing and refused by nothing.
    """
    result = render_with_overlay(CHART, {"nats": {"creat": True}}, tmp_path)
    assert result.returncode == 0, result.stderr
    assert object_count(result.stdout) == DEFAULT_OBJECT_COUNT


def test_prometheus_force_namespace_typo_passes_this_schema_silently(tmp_path):
    """`prometheus` is an OPEN upstream section. `prometheus.forceNamespac`
    (typo'd) is read by NOTHING: `templates/prometheus-namespace.yaml:20` is
    the one place `.Values.prometheus.forceNamespace` is read at all, and it
    reads the CORRECTLY SPELLED key. The render check that guards it (ledger
    1340) refuses an empty or null `forceNamespace`, and a `-f` overlay merges
    onto the shipped `forceNamespace: observability` rather than replacing it,
    so a typo here is not refused by this schema or by anything else.
    """
    result = render_with_overlay(CHART, {"prometheus": {"forceNamespac": "x"}}, tmp_path)
    assert result.returncode == 0, result.stderr
    assert object_count(result.stdout) == DEFAULT_OBJECT_COUNT


# ── RENDER-NEUTRALITY (ADR-0645): THE LIVE SOURCES THIS SCHEMA MUST NOT BREAK ──


def test_the_default_render_is_unchanged():
    result = render(CHART)
    assert result.returncode == 0, result.stderr
    assert object_count(result.stdout) == DEFAULT_OBJECT_COUNT


def test_the_committed_adopter_example_still_renders():
    """`example/values.yaml` IS LIVE, not a frozen copy — the same file
    `test_render_checks.py`, `test_ladder.py` and `test_bootstrap.py` already
    render, so this schema is checked against the real committed adopter
    input rather than a snapshot of it.
    """
    result = render(CHART, "-f", str(ADOPTER_VALUES), *CERT_MANAGER_AND_GATEWAY_API)
    assert result.returncode == 0, result.stderr


def argocd_platform_section() -> dict:
    """A FROZEN COPY of `applications/yadgar.yaml`'s `platform:` block as read
    from `yadgarhq/argocd` `origin/main` on 2026-10-07 (unchanged on 2026-10-09);
    it does not track the other repository."""
    return {
        "enabled": True,
        "valkey": {"create": True},
        "internalCA": {"create": True},
        "certificates": {"create": True},
        "nats": {"create": True},
        "edgeTLS": {
            "create": True,
            "issuerRef": {"name": "yadgar-dev-ca", "kind": "ClusterIssuer"},
        },
        "gatewayListener": {
            "create": True,
            "envoyProxy": {
                "serviceType": "NodePort",
                "httpsNodePort": 30443,
                "pod": {
                    "nodeSelector": {"node-role.kubernetes.io/control-plane": ""},
                    "tolerations": [
                        {
                            "key": "node-role.kubernetes.io/control-plane",
                            "operator": "Exists",
                            "effect": "NoSchedule",
                        }
                    ],
                },
            },
        },
        "bootstrap": {
            "create": True,
            "adminToken": {"secretName": "admin-bootstrap-token"},
            "iamKeys": {"create": False},
        },
        "operators": {"create": False},
        "preflight": {"enabled": True},
    }


def test_the_argocd_platform_section_still_renders_with_the_nats_tls_keys(tmp_path):
    """The argocd block PLUS the two NATS TLS keys at the off posture, which PB-3
    adds to `applications/yadgar.yaml` before argocd moves to a parent pinning
    this version (B-N2: they are required while `nats.create` is true). The live
    gate for argocd and parent inputs is the parent chart's suite plus the K-9
    valuesObject sweep before each pin bump.
    """
    body = argocd_platform_section()
    body["nats"]["tls"] = {"enabled": False, "clientAuth": "off"}
    result = render_with_overlay(CHART, body, tmp_path, *CERT_MANAGER_AND_GATEWAY_API)
    assert result.returncode == 0, result.stderr


def test_the_argocd_platform_section_as_it_stands_refuses_naming_the_nats_tls_keys(tmp_path):
    """WHY PB-3 MUST CARRY THE KEYS: the block as argocd holds it today names none."""
    result = render_with_overlay(
        CHART, argocd_platform_section(), tmp_path, *CERT_MANAGER_AND_GATEWAY_API
    )
    assert result.returncode != 0, result.stdout[:400]
    assert "`nats.tls.enabled` and `nats.tls.clientAuth` are absent" in result.stderr, result.stderr


def test_an_operator_application_values_block_still_renders(tmp_path):
    """A FROZEN COPY of `applications/cert-manager.yaml`'s `helm.valuesObject`
    as read from `yadgarhq/argocd` `origin/main` on 2026-10-07 — one of the
    five operator Applications sourced from this chart, each setting one
    `operators.<op>.create` true and the rest false. Representative rather
    than exhaustive: the other four differ only in which key is true and
    which upstream section they also set, both already covered by the
    `OPEN`/`EXTRAS` rows above.
    """
    body = {
        "operators": {
            "certManager": {"create": True},
            "argoCd": {"create": False},
            "envoyGateway": {"create": False},
            "keda": {"create": False},
            "mariadbOperator": {"create": False},
            "prometheus": {"create": False},
        },
        "cert-manager": {
            "crds": {"enabled": True, "keep": True},
            "resources": {"requests": {"cpu": "10m", "memory": "64Mi"}},
        },
    }
    result = render_with_overlay(CHART, body, tmp_path)
    assert result.returncode == 0, result.stderr


def test_the_suite_reads_the_schema_this_repository_ships():
    assert SCHEMA.exists(), SCHEMA
    schema = load_schema()
    assert schema["title"] == "yadgar/platform", schema["title"]
    assert schema["additionalProperties"] is False
