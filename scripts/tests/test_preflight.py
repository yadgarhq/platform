"""THE PREFLIGHT JOB'S GATES: the probe set, the denominator it asserts, and the tie.

WHAT THE PREFLIGHT IS FOR, AND WHAT THE RENDER CHECK CANNOT DO. A render check
answers "is this API registered on the target"; it NEVER answers "is a controller
running". A cluster carrying cert-manager's CRDs with no cert-manager pod renders,
installs, and then hangs forever on Certificates that never go Ready. The preflight
Job covers that second half: it probes each operator by an ACTION only that
operator's controller performs, waits a bounded time, cleans up, and ASSERTS the
number of operators it probed against the number of pre-install probes its values
enable.

EVERY PROBE'S DEFAULT IS TIED TO THE TOGGLE THAT RENDERS WHAT IT PROBES, AND NO
PROBE DEFAULTS TRUE ON ITS OWN. A diagnostic for a prerequisite this install does
not use must not run: a probe for an operator whose objects this install renders
none of proves nothing and can only fail for the wrong reason. So each
`preflight.probes.<operator>` key is UNSET in `values.yaml` and the template
resolves it.

AND THE UNSET TEST CANNOT BE SPRIG'S `default`. `default` treats `false` AS EMPTY —
it returns its fallback for `false` exactly as it does for an absent key — so a
`default` chain cannot tell an unset key from an explicit `false`, and the
false-direction override silently does not exist. The template uses `hasKey`, and
`test_implementing_the_tie_with_sprigs_default_reddens_the_override_gate` is the
mutation that proves it.

THE RENDERS THIS SUITE TAKES ITS COUNTS OVER, named as the plan names them, because
a count means nothing without the render it is taken over:

  R1  the chart's own shipped `values.yaml`, bare. Every `create` toggle is false,
      so every probe resolves false and NO Job renders at all.
  R2  `example/values.yaml` — every `platform.*.create` true, every
      `preflight.probes.*` key left UNSET so the tie resolves it. One probe:
      cert-manager.
  R3  R2 with whatever the case needs stated explicitly. R3 IS A FAMILY rather than
      one render, so every case below NAMES ITS VARIANT in its docstring.

WHAT THIS SUITE DOES NOT PROVE, stated so nobody reads more into a green run. Every
assertion here is taken over `helm template` output. That the probes actually go
red against a cluster whose operator is scaled to zero is a RUN-TIME verdict, and
the plan this chart is built from defers it to the bare-install proof. Nothing here
may be reported as proving it.

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

# The group the chart's render check demands before ANY object renders once a
# `create` toggle is true. Every render below that turns one on has to pass it, or
# `render-checks.yaml`'s `fail` aborts the whole render first and the case reads a
# refusal that has nothing to do with the preflight.
CERT_MANAGER_API = "cert-manager.io/v1"

# The RoleBinding's subject carries `{{ .Release.Namespace }}`, and a subject in the
# wrong namespace grants the Role to NOBODY. Rendering into a named namespace is
# what lets the wiring gate compare the subject against something.
RELEASE_NAMESPACE = "yadgar"

# ── THE EXPECTED NUMBERS, AND THEY ARE LITERALS ──────────────────────────────
# Derived from the thing under test they would agree with whatever it happens to
# be and detect nothing.

# R1. Every `create` toggle is false, so every probe resolves false, so no Job.
EXPECTED_PROBES_AT_R1 = 0

# R2. cert-manager ALONE: `probes.keda` and `probes.mariadb` resolve false when
# `platform` renders alone, because a subchart cannot read a sibling chart's key
# and this chart renders neither a ScaledObject nor a MariaDB CR.
EXPECTED_PROBES_AT_R2 = 1
EXPECTED_OPERATORS_AT_R2 = ["cert-manager"]

# R3 with `probes.keda` and `probes.mariadb` true — the variant step 4's KEDA and
# mariadb cases need, because under the probe-default rule those two resolve false
# when `platform` renders alone and a case built at R2 would never run them.
EXPECTED_PROBES_AT_R3_BOTH = 3
EXPECTED_OPERATORS_AT_R3_BOTH = ["cert-manager", "keda", "mariadb-operator"]

# The probe/toggle agreement test at R2, AT STEP 4. One pair — `probes.certManager`
# against the toggles that render what it probes — plus the two default-false
# assertions for `probes.keda` and `probes.mariadb`. The second pair arrives with
# the post-install Envoy Gateway probe at step 5b; the register's row is qualified
# "R2 at step 4" and "R2 from step 5b" for exactly that reason.
EXPECTED_AGREEMENT_PAIRS_AT_R2 = 1
EXPECTED_DEFAULT_FALSE_PROBES = ["keda", "mariadb"]

# The explicit-`true` outcomes at step 4: `probes.keda` and `probes.mariadb`
# HONOURED, `probes.certManager` REFUSED beside its own false toggle. The
# register's row names a second refused probe, `probes.envoyGateway`, whose key
# does not exist until step 5b builds the probe it enables.
EXPECTED_HONOURED_EXPLICIT_TRUES = 2
EXPECTED_REFUSED_EXPLICIT_TRUES = 1

# The explicit-`false` override, and only where it DISCRIMINATES. `probes.keda` and
# `probes.mariadb` cannot: their tie is the hard constant false, so an explicit
# `false` and the broken Sprig-`default` produce the SAME observation. Only
# `probes.certManager`, whose tie resolves TRUE at R2, can tell them apart — and
# `probes.envoyGateway`, the second discriminating case, arrives at step 5b.
EXPECTED_DISCRIMINATING_OVERRIDES = 1

# The preflight Role's verb set, as the plan states it: `create`, `get` and
# `delete`, and NEVER `list`. A different verb set on a different kind from the
# bootstrap triple's, which is why the preflight gets its own triple rather than
# sharing that one.
THE_PROBE_VERBS = ["create", "delete", "get"]

# Which API groups each probe's action needs, read as the mapping the Role must
# carry. KEDA needs two: its own group for the ScaledObject and `apps` for the
# Deployment the ScaledObject scales.
PROBE_RULES = {
    "cert-manager": {"cert-manager.io": ["certificates", "issuers"]},
    "keda": {"apps": ["deployments"], "keda.sh": ["scaledobjects"]},
    "mariadb-operator": {"k8s.mariadb.com": ["mariadbs"]},
}

EXPECTED_PREFLIGHT_SERVICE_ACCOUNTS = 1
EXPECTED_PREFLIGHT_ROLES = 1
EXPECTED_PREFLIGHT_ROLE_BINDINGS = 1
EXPECTED_PREFLIGHT_BINDING_SUBJECTS = 1
RBAC_API_GROUP = "rbac.authorization.k8s.io"

PREFLIGHT_JOB = "preflight"

# ── THE RENDERED SCRIPT'S CONTRACT ───────────────────────────────────────────
# Read off the RENDERED script rather than the template source, so a value reaches
# these gates as the value resolves it.

# The list the script iterates, and the denominator it is asserted against. TWO
# SEPARATE DERIVATIONS ON PURPOSE: the list is built from the per-probe blocks the
# template renders, the denominator from the count of enabled keys. A probe added
# to the template that no `probes.*` key enables moves the list and not the
# denominator, which is the register row's own red case.
PROBE_LIST = re.compile(r'^PROBES="(?P<probes>[^"]*)"$', re.MULTILINE)
DENOMINATOR = re.compile(r"^EXPECTED_PROBES=(?P<count>\d+)$", re.MULTILINE)

# THE EQUALITY, AND IT IS ASSERTED TO EXIST RATHER THAN ONLY TO BE CORRECT. A gate
# that reads the two numbers and compares them in Python still passes over a script
# that compares nothing at run time. `^` with no leading whitespace is the
# top-level requirement: inside a function, command substitution and `set -e`
# between them discard the status, which is the trap this chart already carries a
# comment about in `bootstrap-secrets.yaml`.
DENOMINATOR_EQUALITY = re.compile(
    r'^\[ "\$declared" -eq "\$EXPECTED_PROBES" \]', re.MULTILINE
)
PROBED_EQUALITY = re.compile(r'^\[ "\$probed" -eq "\$EXPECTED_PROBES" \]', re.MULTILINE)

# The mariadb probe's three message readings, named by the VALUES KEY that carries
# each one. The strings themselves are read out of `chart/values.yaml` rather than
# repeated here: they were measured off the operator, they live beside the probe
# that uses them, and a second copy in this file would be the one-source defect
# this estate keeps finding.
MARIADB_DENIED_BY = "deniedBy"
MARIADB_VALIDATION = "validationMessage"
MARIADB_UNREACHABLE = "unreachableWebhook"

DIGEST_PINNED = re.compile(r"^[^\s@]+@sha256:[0-9a-f]{64}$")

# Two for cert-manager (the Issuer and the Certificate it signs), two for KEDA (the
# Deployment and the ScaledObject that scales it), one for mariadb.
EXPECTED_REQUEST_BODIES = 5

# A heredoc body, so the generator-inside-`$( )` trap can be read off the script.
HEREDOC = re.compile(r"<<JSON\s*\n(?P<body>.*?)\n\s*JSON\s*$", re.MULTILINE | re.DOTALL)


def helm(*arguments: str) -> subprocess.CompletedProcess[str]:
    binary = shutil.which("helm")
    # NOT A SKIP, and ADR-0650 is why. Same wording as the three suites beside
    # this one, which made the same decision for the same reason.
    assert binary, (
        "helm is not on PATH. This suite renders the chart, and so does the "
        "`helm lint and render` pre-commit hook — install helm rather than "
        "letting either report a pass it did not earn."
    )
    return subprocess.run([binary, *arguments], capture_output=True, text=True)


def documents_of(stdout: str) -> list[dict]:
    return [
        document
        for document in yaml.safe_load_all(stdout)
        if isinstance(document, dict) and document.get("apiVersion")
    ]


def template(chart: Path, *arguments: str) -> subprocess.CompletedProcess[str]:
    return helm(
        "template", "platform", str(chart), "--namespace", RELEASE_NAMESPACE, *arguments
    )


def render(chart: Path, *arguments: str) -> list[dict]:
    result = template(chart, *arguments)
    assert result.returncode == 0, result.stderr
    return documents_of(result.stdout)


def defaults_render(chart: Path = CHART) -> list[dict]:
    """R1 — the chart's own shipped values, bare, with no `--api-versions` at all."""
    return render(chart)


def adopter_render(chart: Path = CHART, *arguments: str) -> list[dict]:
    """R2 — `example/values.yaml`, every `preflight.probes.*` key left UNSET."""
    return render(
        chart, "--api-versions", CERT_MANAGER_API, "-f", str(ADOPTER_VALUES), *arguments
    )


def overrides(destination: Path, body: str) -> Path:
    """One R3 variant, written as an overlay on R2 rather than as a second copy.

    R3 IS A FAMILY, NOT ONE RENDER, so each case names its own variant instead of
    a committed file pretending to be the whole family. Layering keeps `example/
    values.yaml` the one source for everything the variant does not change.
    """
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(body)
    return destination


def of_kind(documents: list[dict], kind: str) -> list[dict]:
    return [document for document in documents if document.get("kind") == kind]


def name_of(document: dict) -> str:
    return str((document.get("metadata") or {}).get("name"))


def annotations_of(document: dict) -> dict:
    return (document.get("metadata") or {}).get("annotations") or {}


def preflight_objects(documents: list[dict]) -> list[dict]:
    """The preflight's own objects: the Job and the triple that serves it.

    READ OFF THE NAME rather than off the hook annotation, because the hook
    annotation is shared with the bootstrap triple and the two Jobs beside it — and
    because the preflight's own hook shape is itself under test below, so a filter
    written on it would drop exactly the objects whose annotation went wrong.
    """
    return [
        document
        for document in documents
        if name_of(document) == PREFLIGHT_JOB or name_of(document).startswith("preflight-")
    ]


def preflight_job(documents: list[dict]) -> dict | None:
    jobs = [job for job in of_kind(documents, "Job") if name_of(job) == PREFLIGHT_JOB]
    return jobs[0] if len(jobs) == 1 else None


def preflight_script(documents: list[dict]) -> str:
    """The shell script the preflight Job's single container runs. PURE."""
    job = preflight_job(documents)
    assert job is not None, "the render carries no single preflight Job to read a script off"
    containers = (((job.get("spec") or {}).get("template") or {}).get("spec") or {}).get(
        "containers"
    ) or []
    assert len(containers) == 1, f"expected 1 container on the preflight Job, found {containers}"
    arguments = containers[0].get("args") or []
    assert len(arguments) == 1, f"expected 1 script argument, found {arguments}"
    return str(arguments[0])


def probe_list(script: str) -> list[str]:
    match = PROBE_LIST.search(script)
    assert match, "the rendered script declares no PROBES list, so there is nothing to count"
    return match.group("probes").split()


def denominator(script: str) -> int:
    match = DENOMINATOR.search(script)
    assert match, "the rendered script declares no EXPECTED_PROBES, so the list is counted against nothing"
    return int(match.group("count"))


def probe_set_failures(documents: list[dict], expected: list[str]) -> list[str]:
    """How the rendered probe list disagrees with its own denominator, or with `expected`. PURE.

    THREE CLAIMS, NOT ONE. That the list holds what this render should enable; that
    the denominator equals the list's length; and that the script CARRIES the
    equality that compares them at run time. The third is what stops a gate reading
    two numbers in Python while the Job itself checks nothing.
    """
    failures = []
    script = preflight_script(documents)

    found = probe_list(script)
    declared = denominator(script)

    if sorted(found) != sorted(expected):
        failures.append(
            f"expected the probes {sorted(expected)}, the render declares {sorted(found)}"
        )
    if len(found) != declared:
        failures.append(
            f"the rendered probe list holds {len(found)} probes against a denominator "
            f"of {declared}: {found}. The list is built from the blocks the template "
            f"renders and the denominator from the `probes.*` keys the values enable, "
            f"so the two disagreeing means a probe runs that nothing asked for, or a "
            f"key asks for a probe that does not run"
        )
    if declared != len(expected):
        failures.append(
            f"expected a denominator of {len(expected)}, the render declares {declared}"
        )

    if not DENOMINATOR_EQUALITY.search(script):
        failures.append(
            "the rendered script carries no top-level `[ \"$declared\" -eq "
            '"$EXPECTED_PROBES" ]`, so the Job would run whatever list it was given '
            "and report a pass having probed a number nothing checked"
        )
    if not PROBED_EQUALITY.search(script):
        failures.append(
            "the rendered script carries no top-level `[ \"$probed\" -eq "
            '"$EXPECTED_PROBES" ]`, so the Job asserts nothing about how many '
            "operators it actually probed"
        )
    return failures


# ── R1 — EVERY PROBE RESOLVES FALSE, SO NO JOB RENDERS AT ALL ────────────────


def test_the_defaults_render_no_preflight_object_at_all():
    """R1: 0 probes, and NOT an enabled preflight that probes nothing.

    `preflight.enabled` defaults TRUE — the one exception to this chart's
    default-false convention, because a diagnostic that is off by default is the
    silent hang it exists to prevent. What keeps R1 empty is the probe-default
    rule: every `create` toggle is false, so every probe resolves false, and a Job
    asserting `probed 0 operators` is the "cannot fail because it examined nothing"
    form this chart refuses to render.
    """
    rendered = preflight_objects(defaults_render())
    assert rendered == [], (
        f"expected {EXPECTED_PROBES_AT_R1} preflight objects at the chart's "
        f"defaults, found {len(rendered)}: "
        f"{sorted((document.get('kind'), name_of(document)) for document in rendered)}"
    )


def test_a_create_toggle_true_at_the_defaults_reddens_the_no_job_zero(tmp_path):
    """R1's red case, and it is a VALUES flip: make one probe resolve true.

    `internalCA.create` true is one of the three toggles `probes.certManager` ties
    to, so the probe resolves true and the Job must appear. The render passes
    `--api-versions` because `render-checks.yaml` refuses without it the moment a
    `create` toggle is on — without the flag this case would read that refusal
    instead of the zero it is trying to redden.
    """
    values = overrides(tmp_path / "one-create.yaml", "internalCA:\n  create: true\n")
    rendered = preflight_objects(
        render(CHART, "--api-versions", CERT_MANAGER_API, "-f", str(values))
    )
    assert rendered, (
        "a `create` toggle was turned true at the defaults, its probe should have "
        "resolved true and rendered a preflight Job, and the zero passed anyway"
    )


# ── R2 AND R3 — THE RENDERED PROBE LIST AND ITS DENOMINATOR ──────────────────


def test_the_probe_list_equals_its_denominator_at_the_adopter_values():
    """R2: cert-manager alone, because a subchart cannot read a sibling's key."""
    failures = probe_set_failures(adopter_render(), EXPECTED_OPERATORS_AT_R2)
    assert failures == [], "\n".join(failures)
    assert len(EXPECTED_OPERATORS_AT_R2) == EXPECTED_PROBES_AT_R2


def test_the_probe_list_equals_its_denominator_with_keda_and_mariadb_on(tmp_path):
    """R3 with `probes.keda` and `probes.mariadb` true — the step-4 variant.

    Those two are REQUIRED as explicit trues: `platform` renders neither a
    ScaledObject nor a MariaDB CR, so nothing in this chart can resolve them and
    an adopter's values are the only place the truth can come from.
    """
    values = overrides(
        tmp_path / "keda-and-mariadb.yaml",
        "preflight:\n  probes:\n    keda: true\n    mariadb: true\n",
    )
    failures = probe_set_failures(
        adopter_render(CHART, "-f", str(values)), EXPECTED_OPERATORS_AT_R3_BOTH
    )
    assert failures == [], "\n".join(failures)
    assert len(EXPECTED_OPERATORS_AT_R3_BOTH) == EXPECTED_PROBES_AT_R3_BOTH


def chart_with_an_unenabled_probe_in_the_job(destination: Path) -> Path:
    """The register row's red case at R2: a probe in the Job no `probes.*` key enables."""
    copy = destination / "chart"
    shutil.copytree(CHART, copy)
    job = copy / "templates" / "preflight.yaml"
    text = job.read_text()
    line = 'PROBES="{{ join " " $probes }}"'
    assert line in text, "the PROBES line moved; this red case is now testing nothing"
    job.write_text(text.replace(line, 'PROBES="{{ join " " $probes }} argo-cd"', 1))
    return copy


def test_a_probe_no_key_enables_reddens_the_denominator(tmp_path):
    failures = probe_set_failures(
        adopter_render(chart_with_an_unenabled_probe_in_the_job(tmp_path)),
        EXPECTED_OPERATORS_AT_R2,
    )
    message = "\n".join(failures)
    assert failures, "a probe nothing enables was added to the Job and the denominator passed"
    assert "holds 2 probes against a denominator of 1" in message, message


def chart_with_a_probe_dropped_from_the_job(destination: Path) -> Path:
    """The register row's red case at R3: a probe dropped while its key stays true."""
    copy = destination / "chart"
    shutil.copytree(CHART, copy)
    job = copy / "templates" / "preflight.yaml"
    text = job.read_text()
    line = 'PROBES="{{ join " " $probes }}"'
    assert line in text, "the PROBES line moved; this red case is now testing nothing"
    job.write_text(
        text.replace(line, 'PROBES="{{ join " " (without $probes "keda") }}"', 1)
    )
    return copy


def test_a_probe_dropped_while_its_key_stays_true_reddens_the_denominator(tmp_path):
    values = overrides(
        tmp_path / "keda-and-mariadb.yaml",
        "preflight:\n  probes:\n    keda: true\n    mariadb: true\n",
    )
    failures = probe_set_failures(
        adopter_render(chart_with_a_probe_dropped_from_the_job(tmp_path), "-f", str(values)),
        EXPECTED_OPERATORS_AT_R3_BOTH,
    )
    message = "\n".join(failures)
    assert failures, "a probe was dropped while its key stayed true and the denominator passed"
    assert "holds 2 probes against a denominator of 3" in message, message


def chart_without_the_denominator_equality(destination: Path) -> Path:
    """The gate's own red case: the run-time comparison deleted from the script."""
    copy = destination / "chart"
    shutil.copytree(CHART, copy)
    job = copy / "templates" / "preflight.yaml"
    text = job.read_text()
    equality = '[ "$declared" -eq "$EXPECTED_PROBES" ] || {'
    assert equality in text, "the equality moved; this red case is now testing nothing"
    end = text.index(equality)
    closing = text.index("}\n", end) + len("}\n")
    job.write_text(text[:end] + text[closing:])
    return copy


def test_deleting_the_run_time_equality_reddens_the_probe_set_gate(tmp_path):
    """A gate that reads two numbers in Python still passes over a Job that compares nothing."""
    failures = probe_set_failures(
        adopter_render(chart_without_the_denominator_equality(tmp_path)),
        EXPECTED_OPERATORS_AT_R2,
    )
    message = "\n".join(failures)
    assert failures, "the run-time equality was deleted and the probe-set gate passed"
    assert "carries no top-level" in message, message


# ── THE PROBE/TOGGLE AGREEMENT ───────────────────────────────────────────────


def agreement_failures(tmp_path: Path) -> list[str]:
    """Every pair, asserted as an EQUALITY across two renders, plus the two constants.

    A PAIR IS NOT ONE OBSERVATION. `probes.certManager` agreeing with its toggles
    at R2 alone is a gate whose one input is its own green case: the probe is true
    and the toggles are true, and a tie hardcoded to `true` passes it. So each pair
    is read at BOTH ends — the toggles true, where the probe must appear, and the
    toggles false, where it must not — and the failure names both keys.
    """
    failures = []
    pairs = 0

    on = probe_list(preflight_script(adopter_render()))
    off_values = overrides(
        tmp_path / "every-cert-toggle-off.yaml",
        "internalCA:\n  create: false\ncertificates:\n  create: false\n"
        "edgeTLS:\n  create: false\n",
    )
    off = preflight_objects(adopter_render(CHART, "-f", str(off_values)))

    if "cert-manager" not in on:
        failures.append(
            "preflight.probes.certManager is unset and `internalCA.create`, "
            "`certificates.create` and `edgeTLS.create` are true, so the probe "
            f"should resolve TRUE; the render declares {on}"
        )
    if off:
        failures.append(
            "preflight.probes.certManager is unset and `internalCA.create`, "
            "`certificates.create` and `edgeTLS.create` are all false, so the probe "
            "should resolve FALSE and no preflight Job should render; found "
            f"{sorted((document.get('kind'), name_of(document)) for document in off)}"
        )
    pairs += 1

    for probe in EXPECTED_DEFAULT_FALSE_PROBES:
        operator = {"keda": "keda", "mariadb": "mariadb-operator"}[probe]
        if operator in on:
            failures.append(
                f"preflight.probes.{probe} is unset and this chart renders nothing "
                f"{operator} reconciles, so it must resolve FALSE; the render "
                f"declares {on}"
            )

    if pairs != EXPECTED_AGREEMENT_PAIRS_AT_R2:
        failures.append(
            f"expected {EXPECTED_AGREEMENT_PAIRS_AT_R2} probe/toggle pairs at R2, "
            f"examined {pairs}"
        )
    return failures


def test_every_probe_agrees_with_the_toggle_that_renders_what_it_probes(tmp_path):
    """R2 at step 4: one pair, plus the two default-false assertions."""
    failures = agreement_failures(tmp_path)
    assert failures == [], "\n".join(failures)


def chart_with_the_tie_hardcoded_true(destination: Path) -> Path:
    """The pair's red case: the tie stops following the toggle it is tied to."""
    copy = destination / "chart"
    shutil.copytree(CHART, copy)
    partial = copy / "templates" / "_preflight.tpl"
    text = partial.read_text()
    line = (
        '{{- $certManager := or $context.Values.internalCA.create '
        "$context.Values.certificates.create $context.Values.edgeTLS.create -}}"
    )
    assert line in text, "the tie moved; this red case is now testing nothing"
    partial.write_text(text.replace(line, "{{- $certManager := true -}}", 1))
    return copy


def test_a_tie_that_stops_following_its_toggle_reddens_the_agreement_gate(tmp_path, monkeypatch):
    """Flip one member of the pair without the other; the failure names both keys."""
    copy = chart_with_the_tie_hardcoded_true(tmp_path)
    off_values = overrides(
        tmp_path / "every-cert-toggle-off.yaml",
        "internalCA:\n  create: false\ncertificates:\n  create: false\n"
        "edgeTLS:\n  create: false\n",
    )
    off = preflight_objects(adopter_render(copy, "-f", str(off_values)))
    assert off, (
        "the tie was hardcoded true, so the probe should have rendered a Job with "
        "every toggle it is tied to false, and the agreement gate saw nothing"
    )


# ── THE TWO OVERRIDE DIRECTIONS, WHICH ARE NOT SYMMETRIC ─────────────────────


def test_an_explicit_false_is_honoured_where_it_discriminates(tmp_path):
    """R3 with `probes.certManager` false. THE ONE DISCRIMINATING CASE AT STEP 4.

    An explicit `false` is always honoured: losing a diagnostic is a choice an
    adopter is entitled to make. It DISCRIMINATES only where the overridden tie can
    take the other value — `probes.certManager`'s resolves TRUE at R2, so an
    explicit `false` changes the observation. `probes.keda` and `probes.mariadb`
    cannot discriminate at all: their tie is the hard constant false, so an explicit
    `false` and a broken Sprig-`default` produce the SAME observation for both.
    """
    values = overrides(
        tmp_path / "cert-manager-off.yaml", "preflight:\n  probes:\n    certManager: false\n"
    )
    rendered = preflight_objects(adopter_render(CHART, "-f", str(values)))
    assert rendered == [], (
        f"`preflight.probes.certManager: false` was not honoured — it is the only "
        f"probe this render enables, so no preflight object should remain; found "
        f"{sorted((document.get('kind'), name_of(document)) for document in rendered)}"
    )
    assert EXPECTED_DISCRIMINATING_OVERRIDES == 1


def chart_with_a_sprig_default_tie(destination: Path) -> Path:
    """The register row's own red case: implement the tie with Sprig's `default`.

    `default` treats `false` AS EMPTY, so the explicit `false` reads as unset and
    the override vanishes — silently, with no message.
    """
    copy = destination / "chart"
    shutil.copytree(CHART, copy)
    partial = copy / "templates" / "_preflight.tpl"
    text = partial.read_text()
    line = "{{- if hasKey $probes .probe -}}"
    assert line in text, "the `hasKey` test moved; this red case is now testing nothing"
    partial.write_text(
        text.replace(line, "{{- if (index $probes .probe | default false) -}}", 1)
    )
    return copy


def test_implementing_the_tie_with_sprigs_default_reddens_the_override_gate(tmp_path):
    values = overrides(
        tmp_path / "cert-manager-off.yaml", "preflight:\n  probes:\n    certManager: false\n"
    )
    rendered = preflight_objects(
        adopter_render(chart_with_a_sprig_default_tie(tmp_path), "-f", str(values))
    )
    assert rendered, (
        "the tie was implemented with Sprig's `default`, so the explicit `false` "
        "should have read as unset and rendered the probe anyway, and the override "
        "gate saw nothing"
    )


def test_an_explicit_true_is_honoured_for_the_probes_no_sibling_can_resolve(tmp_path):
    """R3 with `probes.keda` true, and R3 with `probes.mariadb` true. OBSERVED, not assumed.

    Honouring is read as the DENOMINATOR MOVING and the operator entering the
    rendered probe list, because the first form of this assertion said only what a
    refusal looks like and nothing about what honouring looks like.
    """
    honoured = 0
    for probe, operator in (("keda", "keda"), ("mariadb", "mariadb-operator")):
        values = overrides(
            tmp_path / f"{probe}-on.yaml", f"preflight:\n  probes:\n    {probe}: true\n"
        )
        script = preflight_script(adopter_render(CHART, "-f", str(values)))
        found = probe_list(script)
        assert operator in found, (
            f"`preflight.probes.{probe}: true` was not honoured: {operator} is absent "
            f"from the rendered probe list {found}. A subchart cannot resolve this "
            f"one from a sibling's key, so the adopter's values are the only place "
            f"the truth can come from"
        )
        assert denominator(script) == EXPECTED_PROBES_AT_R2 + 1, (
            f"`preflight.probes.{probe}: true` left the denominator at "
            f"{denominator(script)}; it should have moved to {EXPECTED_PROBES_AT_R2 + 1}"
        )
        honoured += 1
    assert honoured == EXPECTED_HONOURED_EXPLICIT_TRUES


def chart_with_the_explicit_true_anded_with_the_tie(destination: Path) -> Path:
    """The honoured half's red case: the explicit key ANDed with the default it overrides."""
    copy = destination / "chart"
    shutil.copytree(CHART, copy)
    partial = copy / "templates" / "_preflight.tpl"
    text = partial.read_text()
    line = "{{- if index $probes .probe -}}"
    assert line in text, "the explicit read moved; this red case is now testing nothing"
    partial.write_text(text.replace(line, "{{- if and (index $probes .probe) .tied -}}", 1))
    return copy


def test_anding_the_explicit_true_with_the_tie_reddens_the_honoured_gate(tmp_path):
    values = overrides(tmp_path / "keda-on.yaml", "preflight:\n  probes:\n    keda: true\n")
    script = preflight_script(
        adopter_render(chart_with_the_explicit_true_anded_with_the_tie(tmp_path), "-f", str(values))
    )
    found = probe_list(script)
    assert "keda" not in found, (
        "the explicit `true` was ANDed with the tie it overrides, so the key should "
        f"have been dropped and the denominator stayed at {EXPECTED_PROBES_AT_R2}; "
        f"the render declares {found}"
    )
    assert denominator(script) == EXPECTED_PROBES_AT_R2


def test_an_explicit_true_beside_its_own_false_toggle_is_refused(tmp_path):
    """R3 with `probes.certManager` true AND all three of its toggles false.

    THIS IS THE FAILURE CLASS THE PROBE-DEFAULT RULE EXISTS FOR, not an escape
    hatch: a probe for an operator whose objects this install renders none of
    proves nothing and can only fail for the wrong reason. It is REFUSED rather
    than blessed, and the refusal names BOTH keys — a refusal naming one leaves the
    reader to guess which side to change.

    "R2 with one thing changed" cannot express this variant: at R2 the probe's own
    toggle is true and the probe is HONOURED.
    """
    values = overrides(
        tmp_path / "cert-manager-true-toggles-false.yaml",
        "internalCA:\n  create: false\ncertificates:\n  create: false\n"
        "edgeTLS:\n  create: false\n"
        "preflight:\n  probes:\n    certManager: true\n",
    )
    result = template(
        CHART, "--api-versions", CERT_MANAGER_API, "-f", str(ADOPTER_VALUES), "-f", str(values)
    )
    assert result.returncode != 0, (
        "`preflight.probes.certManager: true` beside three false toggles rendered "
        "cleanly; it must be refused, because the probe would create objects for an "
        "operator this install renders nothing for"
    )
    assert "preflight.probes.certManager" in result.stderr, result.stderr
    assert "internalCA.create" in result.stderr, result.stderr
    assert EXPECTED_REFUSED_EXPLICIT_TRUES == 1


def chart_whose_refusal_names_one_key(destination: Path) -> Path:
    """The refusal's red case: a message naming the probe and not the toggle."""
    copy = destination / "chart"
    shutil.copytree(CHART, copy)
    partial = copy / "templates" / "_preflight.tpl"
    text = partial.read_text()
    opening = text.index("{{- fail (printf (join")
    closing = text.index(".probe .owner) -}}", opening) + len(".probe .owner) -}}")
    partial.write_text(
        text[:opening]
        + '{{- fail (printf "platform: preflight.probes.%s is refused here." .probe) -}}'
        + text[closing:]
    )
    return copy


def test_a_refusal_that_names_one_key_reddens_the_refusal_gate(tmp_path):
    values = overrides(
        tmp_path / "cert-manager-true-toggles-false.yaml",
        "internalCA:\n  create: false\ncertificates:\n  create: false\n"
        "edgeTLS:\n  create: false\n"
        "preflight:\n  probes:\n    certManager: true\n",
    )
    result = template(
        chart_whose_refusal_names_one_key(tmp_path),
        "--api-versions",
        CERT_MANAGER_API,
        "-f",
        str(ADOPTER_VALUES),
        "-f",
        str(values),
    )
    assert result.returncode != 0, result.stdout
    assert "internalCA.create" not in result.stderr, (
        "the refusal was rewritten to name one key and it still named the toggle, "
        "so this red case is testing nothing"
    )


# ── THE PREFLIGHT'S OWN RBAC TRIPLE ──────────────────────────────────────────


def rbac_failures(documents: list[dict], expected: list[str]) -> list[str]:
    """Every way the preflight's RBAC widens, or stops being wired to its own Job. PURE.

    THE WIRING, NOT A CENSUS. An earlier gate in this repository counted objects and
    three mutations walked through it green — the worst being a `roleRef` pointed at
    the built-in `ClusterRole/cluster-admin`, which renders NO object at all, so an
    object count stays exactly where it was while the identity becomes cluster-admin.
    So the terms are compared AGAINST EACH OTHER, off the render:

      - `roleRef` names `Role` in `rbac.authorization.k8s.io`, and its `name` is the
        Role this render produced.
      - the binding carries one subject, and it is the ServiceAccount this render
        produced, in the namespace this render was made for.
      - the Job's `serviceAccountName` is that same ServiceAccount.

    BY LENGTH AS WELL AS BY CONTENT on the verbs, because a verb ADDED later has to
    turn this red and a subset check would not.
    """
    failures = []
    mine = preflight_objects(documents)

    cluster_scoped = of_kind(mine, "ClusterRole") + of_kind(mine, "ClusterRoleBinding")
    if cluster_scoped:
        failures.append(
            f"expected 0 cluster-scoped RBAC objects from the preflight, found "
            f"{len(cluster_scoped)}: {sorted(name_of(document) for document in cluster_scoped)}"
        )

    accounts = of_kind(mine, "ServiceAccount")
    if len(accounts) != EXPECTED_PREFLIGHT_SERVICE_ACCOUNTS:
        failures.append(
            f"expected {EXPECTED_PREFLIGHT_SERVICE_ACCOUNTS} preflight "
            f"ServiceAccount, found {len(accounts)}: "
            f"{sorted(name_of(account) for account in accounts)}"
        )
    identity = name_of(accounts[0]) if len(accounts) == 1 else None

    roles = of_kind(mine, "Role")
    if len(roles) != EXPECTED_PREFLIGHT_ROLES:
        failures.append(
            f"expected {EXPECTED_PREFLIGHT_ROLES} preflight Role, found "
            f"{len(roles)}: {sorted(name_of(role) for role in roles)}"
        )
    role_name = name_of(roles[0]) if len(roles) == 1 else None

    bindings = of_kind(mine, "RoleBinding")
    if len(bindings) != EXPECTED_PREFLIGHT_ROLE_BINDINGS:
        failures.append(
            f"expected {EXPECTED_PREFLIGHT_ROLE_BINDINGS} preflight RoleBinding, "
            f"found {len(bindings)}: {sorted(name_of(binding) for binding in bindings)}"
        )

    for binding in bindings:
        reference = binding.get("roleRef") or {}
        if reference.get("kind") != "Role" or reference.get("apiGroup") != RBAC_API_GROUP:
            failures.append(
                f"{name_of(binding)}: expected roleRef "
                f"{{'apiGroup': {RBAC_API_GROUP!r}, 'kind': 'Role'}}, found "
                f"{{'apiGroup': {reference.get('apiGroup')!r}, 'kind': "
                f"{reference.get('kind')!r}}}. A ClusterRole here binds this identity "
                f"in EVERY namespace, and a built-in one renders no object for any "
                f"census to see"
            )
        if role_name is None:
            failures.append(
                f"{name_of(binding)}: the render carries no single preflight Role, so "
                f"roleRef.name {reference.get('name')!r} was compared against nothing"
            )
        elif reference.get("name") != role_name:
            failures.append(
                f"{name_of(binding)}: expected roleRef.name to be the rendered Role's "
                f"name {role_name!r}, found {reference.get('name')!r}"
            )

        subjects = binding.get("subjects") or []
        if len(subjects) != EXPECTED_PREFLIGHT_BINDING_SUBJECTS:
            failures.append(
                f"{name_of(binding)}: expected "
                f"{EXPECTED_PREFLIGHT_BINDING_SUBJECTS} subject, found {subjects}"
            )
            continue
        if identity is None:
            failures.append(
                f"{name_of(binding)}: the render carries no single preflight "
                f"ServiceAccount, so the subject {subjects[0]} was compared against nothing"
            )
            continue
        wanted = {"kind": "ServiceAccount", "name": identity, "namespace": RELEASE_NAMESPACE}
        if subjects[0] != wanted:
            failures.append(
                f"{name_of(binding)}: expected the subject to be the rendered "
                f"ServiceAccount {wanted}, found {subjects[0]}"
            )

    job = preflight_job(documents)
    if job is None:
        failures.append("the render carries no single preflight Job to check an identity on")
    else:
        pod = ((job.get("spec") or {}).get("template") or {}).get("spec") or {}
        runs_as = pod.get("serviceAccountName")
        if identity is None:
            failures.append(
                f"the render carries no single preflight ServiceAccount, so the Job's "
                f"serviceAccountName {runs_as!r} was compared against nothing"
            )
        elif runs_as != identity:
            failures.append(
                f"{PREFLIGHT_JOB}: expected serviceAccountName to be the rendered "
                f"ServiceAccount {identity!r}, found {runs_as!r}. A Job left on another "
                f"account runs as an identity this Role was never bound to, and every "
                f"request it makes answers 403"
            )

    if role_name is None:
        return failures

    wanted_rules = {}
    for operator in expected:
        for group, resources in PROBE_RULES[operator].items():
            wanted_rules.setdefault(group, set()).update(resources)

    rules = roles[0].get("rules") or []
    found_rules = {}
    for rule in rules:
        verbs = sorted(rule.get("verbs") or [])
        if verbs != THE_PROBE_VERBS:
            failures.append(
                f"expected {len(THE_PROBE_VERBS)} verbs on every preflight rule, "
                f"exactly {THE_PROBE_VERBS}, found {len(verbs)}: {verbs}. The probe "
                f"creates an object, reads it and deletes it; `list` would let it "
                f"enumerate every object of that kind in the namespace and it needs none"
            )
        for group in rule.get("apiGroups") or []:
            found_rules.setdefault(group, set()).update(rule.get("resources") or [])

    if found_rules != wanted_rules:
        failures.append(
            f"expected the preflight Role scoped to {ded(wanted_rules)}, found "
            f"{ded(found_rules)}. The rules follow the probes this render enables, so "
            f"a rule left behind grants a permission no probe uses"
        )
    return failures


def ded(rules: dict[str, set[str]]) -> dict[str, list[str]]:
    return {group: sorted(resources) for group, resources in sorted(rules.items())}


def test_the_preflight_role_carries_create_get_delete_and_never_list():
    failures = rbac_failures(adopter_render(), EXPECTED_OPERATORS_AT_R2)
    assert failures == [], "\n".join(failures)


def test_the_preflight_role_follows_the_probes_the_render_enables(tmp_path):
    """R3 with `probes.keda` and `probes.mariadb` true: three probes, four rules."""
    values = overrides(
        tmp_path / "keda-and-mariadb.yaml",
        "preflight:\n  probes:\n    keda: true\n    mariadb: true\n",
    )
    failures = rbac_failures(
        adopter_render(CHART, "-f", str(values)), EXPECTED_OPERATORS_AT_R3_BOTH
    )
    assert failures == [], "\n".join(failures)


def chart_with_list_on_the_preflight_role(destination: Path) -> Path:
    """The verb gate's red case: `list` added back."""
    copy = destination / "chart"
    shutil.copytree(CHART, copy)
    rbac = copy / "templates" / "preflight-rbac.yaml"
    text = rbac.read_text()
    line = '    verbs: ["create", "get", "delete"]'
    assert line in text, "the verb list moved; this red case is now testing nothing"
    rbac.write_text(text.replace(line, '    verbs: ["create", "get", "delete", "list"]'))
    return copy


def test_a_fourth_verb_reddens_the_preflight_rbac_gate(tmp_path):
    failures = rbac_failures(
        adopter_render(chart_with_list_on_the_preflight_role(tmp_path)),
        EXPECTED_OPERATORS_AT_R2,
    )
    message = "\n".join(failures)
    assert failures, "`list` was added to the preflight Role and the verb gate passed"
    assert "exactly ['create', 'delete', 'get']" in message, message


def chart_with_the_preflight_bound_to_cluster_admin(destination: Path) -> Path:
    """The wiring gate's red case, and it renders NO extra object at all.

    `cluster-admin` is a BUILT-IN ClusterRole, so pointing `roleRef` at it adds
    nothing to the render. An object census stays exactly where it was while the
    preflight identity becomes cluster-admin, which is why the gate compares the
    references between the rendered objects rather than counting them.
    """
    copy = destination / "chart"
    shutil.copytree(CHART, copy)
    rbac = copy / "templates" / "preflight-rbac.yaml"
    text = rbac.read_text()
    block = "  kind: Role\n  name: {{ $preflight.serviceAccountName }}"
    assert block in text, "the roleRef moved; this red case is now testing nothing"
    rbac.write_text(text.replace(block, "  kind: ClusterRole\n  name: cluster-admin", 1))
    return copy


def test_binding_the_preflight_to_cluster_admin_reddens_the_wiring_gate(tmp_path):
    documents = adopter_render(chart_with_the_preflight_bound_to_cluster_admin(tmp_path))
    census = of_kind(preflight_objects(documents), "ClusterRole")
    assert census == [], (
        "binding to the built-in `cluster-admin` rendered a ClusterRole object, so "
        "this red case no longer demonstrates what it was written for"
    )
    failures = rbac_failures(documents, EXPECTED_OPERATORS_AT_R2)
    message = "\n".join(failures)
    assert failures, "the preflight was bound to cluster-admin and the wiring gate passed"
    assert "'kind': 'Role'" in message, message


# ── THE MARIADB PROBE'S TWO MESSAGE READINGS ─────────────────────────────────


def mariadb_failures(script: str) -> list[str]:
    """The mariadb probe requires the MESSAGE, and refuses the API server's own. PURE.

    A REJECTION CANNOT DISCRIMINATE. With the operator at zero replicas and
    `failurePolicy: Fail`, the API SERVER also rejects the request, because it
    cannot reach the webhook. Both the healthy and the dead cluster answer with a
    non-2xx, so a probe that requires "a rejection" reads green in both.

    SO THERE ARE TWO ASSERTIONS AND THE SECOND IS EXPLICIT. The rejection must carry
    the OPERATOR-AUTHORED text, and a rejection whose message is the API server's
    `failed calling webhook … connection refused` is a FAILURE BY NAME rather than
    by falling out of the first assertion — which would report the operator's
    absence as "the message did not match" and name nothing.
    """
    failures = []
    measured = yaml.safe_load((CHART / "values.yaml").read_text())["preflight"]["mariadb"]

    for reading, why in (
        (
            MARIADB_DENIED_BY,
            "the webhook's own refusal, which is what proves the operator's "
            "admission path is live",
        ),
        (
            MARIADB_VALIDATION,
            "the operator's own validation text, which is what tells its refusal "
            "apart from CRD schema validation",
        ),
        (
            MARIADB_UNREACHABLE,
            "the API server's unreachable-webhook message, refused BY NAME",
        ),
    ):
        string = measured[reading]
        # READ OUT OF `values.yaml` AND LOOKED FOR IN THE RENDER, so the gate
        # follows the value rather than a copy of it. A string edited in
        # `values.yaml` and not reaching the script is exactly the drift the
        # measurement was recorded to catch.
        if string not in script:
            failures.append(
                f"the mariadb probe does not carry `preflight.mariadb.{reading}` "
                f"({string!r}) — {why}"
            )

    # AND THE UNREACHABLE READING IS A REFUSAL, NOT ONE MORE THING THE MESSAGE
    # MUST CONTAIN. Falling out of the other two would report a dead operator as
    # "the message did not match", which names a string comparison where the
    # answer is "mariadb-operator is not running".
    use = '"$MARIADB_UNREACHABLE"'
    if measured[MARIADB_UNREACHABLE] in script and use in script:
        window = script[script.index(use) : script.index(use) + 500]
        if "CONTROLLER is not running" not in window:
            failures.append(
                f"the mariadb probe carries `preflight.mariadb.{MARIADB_UNREACHABLE}` "
                f"but does not refuse on it by name: nothing within its block says "
                f"the controller is not running, so an absent operator is reported "
                f"as a failed string match"
            )
    return failures


def test_the_mariadb_probe_requires_the_operators_message_and_refuses_the_api_servers(tmp_path):
    """R3 with `probes.mariadb` true: the probe only renders where its key is true."""
    values = overrides(tmp_path / "mariadb-on.yaml", "preflight:\n  probes:\n    mariadb: true\n")
    script = preflight_script(adopter_render(CHART, "-f", str(values)))
    failures = mariadb_failures(script)
    assert failures == [], "\n".join(failures)


def chart_without_the_unreachable_webhook_arm(destination: Path) -> Path:
    """The second assertion's red case: the API-server refusal deleted."""
    copy = destination / "chart"
    shutil.copytree(CHART, copy)
    job = copy / "templates" / "preflight.yaml"
    text = job.read_text()
    marker = "MARIADB_UNREACHABLE="
    assert marker in text, "the unreachable reading moved; this red case is now testing nothing"
    job.write_text(re.sub(r"^.*MARIADB_UNREACHABLE.*$\n?", "", text, flags=re.MULTILINE))
    return copy


def test_dropping_the_unreachable_webhook_refusal_reddens_the_mariadb_gate(tmp_path):
    values = overrides(tmp_path / "mariadb-on.yaml", "preflight:\n  probes:\n    mariadb: true\n")
    script = preflight_script(
        adopter_render(chart_without_the_unreachable_webhook_arm(tmp_path), "-f", str(values))
    )
    failures = mariadb_failures(script)
    message = "\n".join(failures)
    assert failures, (
        "the API-server unreachable-webhook refusal was deleted and the mariadb gate "
        "passed, so a dead operator would read as a green probe"
    )
    assert MARIADB_UNREACHABLE in message, message


def chart_whose_unreachable_arm_names_no_operator(destination: Path) -> Path:
    """The SECOND assertion's own red case: the check kept, the naming removed.

    Deleting the reading altogether (above) is the coarse mutation. This is the
    fine one, and it is the failure the plan names explicitly: the probe still
    notices that the API server could not reach the webhook, and reports it as a
    string that did not match. An operator reading that message learns nothing
    about mariadb-operator being absent, which is the whole answer.
    """
    copy = destination / "chart"
    shutil.copytree(CHART, copy)
    job = copy / "templates" / "preflight.yaml"
    text = job.read_text()
    line = "preflight: the CRDs are registered and the webhook is configured, so mariadb-operator's CONTROLLER is not running."
    assert line in text, "the unreachable refusal's wording moved; this red case is now testing nothing"
    job.write_text(text.replace(line, "preflight: the message did not match.", 1))
    return copy


def test_an_unreachable_arm_that_names_no_operator_reddens_the_mariadb_gate(tmp_path):
    values = overrides(tmp_path / "mariadb-on.yaml", "preflight:\n  probes:\n    mariadb: true\n")
    script = preflight_script(
        adopter_render(chart_whose_unreachable_arm_names_no_operator(tmp_path), "-f", str(values))
    )
    failures = mariadb_failures(script)
    message = "\n".join(failures)
    assert failures, (
        "the unreachable-webhook arm stopped naming the operator and the mariadb "
        "gate passed, so an absent mariadb-operator would be reported as a failed "
        "string comparison"
    )
    assert "does not refuse on it by name" in message, message


# ── THE SCRIPT'S OWN SHAPE ───────────────────────────────────────────────────


def test_no_request_body_generates_anything_inside_itself(tmp_path):
    """THE TRAP THIS CHART HAS ALREADY MET ONCE, asserted rather than commented.

    A generator called as `$(...)` INSIDE A HEREDOC cannot fail the run. Command
    substitution DISCARDS the exit status, so `set -e` never sees it, and a pipeline
    reports only its LAST element's status. Every value a request body carries is
    therefore assigned to a variable and validated at the TOP LEVEL first.
    """
    values = overrides(
        tmp_path / "every-probe.yaml",
        "preflight:\n  probes:\n    keda: true\n    mariadb: true\n",
    )
    script = preflight_script(adopter_render(CHART, "-f", str(values)))
    bodies = [match.group("body") for match in HEREDOC.finditer(script)]
    # THE COUNT IS ASSERTED, because a gate that finds no body to examine reports
    # a pass having proved nothing — and this gate would do exactly that if the
    # bodies stopped being heredocs. Four: two for cert-manager, one Deployment
    # and one ScaledObject for KEDA, one for mariadb.
    assert len(bodies) == EXPECTED_REQUEST_BODIES, (
        f"expected {EXPECTED_REQUEST_BODIES} request bodies with every probe "
        f"enabled, found {len(bodies)}. A gate examining none of them passes "
        f"whatever the script does"
    )
    offenders = [body.strip() for body in bodies if "$(" in body]
    assert offenders == [], (
        f"{len(offenders)} request bodies generate inside themselves: {offenders}. "
        f"Command substitution discards the exit status, so a generator that fails "
        f"there posts an empty value and the Job reports success"
    )


def test_the_preflight_image_is_pinned_by_digest():
    """A tag is a MOVING pointer: the same string resolves to different bytes over time."""
    job = preflight_job(adopter_render())
    assert job is not None
    containers = (((job.get("spec") or {}).get("template") or {}).get("spec") or {})[
        "containers"
    ]
    for container in containers:
        assert DIGEST_PINNED.match(container["image"]), (
            f"the preflight image {container['image']!r} is not pinned by digest"
        )


def chart_with_the_preflight_image_pinned_by_tag(destination: Path) -> Path:
    copy = destination / "chart"
    shutil.copytree(CHART, copy)
    values = copy / "values.yaml"
    text = values.read_text()
    line = [
        candidate
        for candidate in text.splitlines()
        if candidate.strip().startswith("image: curlimages/curl@sha256:")
    ]
    assert len(line) == 2, f"expected the two pinned images, found {len(line)}"
    values.write_text(text.replace(line[-1], "  image: curlimages/curl:8.16.0"))
    return copy


def test_pinning_the_preflight_image_by_tag_reddens_the_digest_gate(tmp_path):
    job = preflight_job(adopter_render(chart_with_the_preflight_image_pinned_by_tag(tmp_path)))
    assert job is not None
    containers = (((job.get("spec") or {}).get("template") or {}).get("spec") or {})[
        "containers"
    ]
    assert not any(DIGEST_PINNED.match(container["image"]) for container in containers), (
        "the preflight image was pinned by tag and the digest gate passed"
    )


def test_the_preflight_and_its_triple_are_hooks_at_ordered_weights():
    """The Job is a `pre-install` hook and its triple sits BELOW it.

    Helm applies plain resources AFTER the pre-install hooks have run, so a
    ServiceAccount rendered as an ordinary object DOES NOT EXIST when a
    `pre-install` Job tries to use it — the Job is admitted against an identity that
    is not there and the preflight fails on a healthy cluster for a reason that has
    nothing to do with any operator.

    AND THE PREFLIGHT RUNS BEFORE THE BOOTSTRAP JOBS, because the whole point of it
    is to refuse before anything else acts.
    """
    documents = adopter_render()
    mine = preflight_objects(documents)
    assert mine, "the adopter render carries no preflight objects at all"

    weights = {}
    for document in mine:
        annotations = annotations_of(document)
        assert annotations.get("helm.sh/hook") == "pre-install,pre-upgrade", (
            f"{name_of(document)} ({document.get('kind')}) is a hook in phase "
            f"{annotations.get('helm.sh/hook')!r}; the preflight is pre-install,pre-upgrade"
        )
        assert annotations.get("helm.sh/hook-delete-policy") == "before-hook-creation", (
            f"{name_of(document)} does not carry `hook-delete-policy: "
            f"before-hook-creation`, so its second install meets an immutable object"
        )
        weight = annotations.get("helm.sh/hook-weight")
        assert isinstance(weight, str), (
            f"{name_of(document)} renders a hook-weight of type "
            f"{type(weight).__name__}, not str. Annotations are map[string]string, so "
            f"an unquoted integer does not decode — and the failure arrives at apply time"
        )
        weights[(document.get("kind"), name_of(document))] = int(weight)

    job_weight = weights[("Job", PREFLIGHT_JOB)]
    triple = {
        weight
        for (kind, _), weight in weights.items()
        if kind in {"ServiceAccount", "Role", "RoleBinding"}
    }
    assert triple and max(triple) < job_weight, (
        f"the preflight triple's weights {sorted(triple)} do not all sit BELOW the "
        f"Job's {job_weight}, so the Job can be admitted before its identity exists"
    )

    bootstrap = [
        int(annotations_of(job)["helm.sh/hook-weight"])
        for job in of_kind(documents, "Job")
        if name_of(job) != PREFLIGHT_JOB
    ]
    assert bootstrap and job_weight < min(bootstrap), (
        f"the preflight Job's weight {job_weight} does not sit below the bootstrap "
        f"Jobs' {sorted(bootstrap)}; the preflight exists to refuse before anything "
        f"else acts"
    )


# ── THE CENSUS, PRINTED AS WELL AS ASSERTED ──────────────────────────────────


def test_the_census_of_what_this_suite_examined(tmp_path, capsys):
    """Every number the gates above assert, gathered in one place and PRINTED.

    PRINTING IS NOT ASSERTING, and this test does not pretend otherwise — every
    number here is asserted by the gate it belongs to, and repeating the assertion
    is what makes this a gate rather than a log line. What printing adds is that a
    reader of a CI log can see WHAT WAS EXAMINED without reproducing the renders,
    which is the half a green tick never shows.
    """
    both = overrides(
        tmp_path / "keda-and-mariadb.yaml",
        "preflight:\n  probes:\n    keda: true\n    mariadb: true\n",
    )

    at_r1 = len(preflight_objects(defaults_render()))
    r2 = adopter_render()
    r3 = adopter_render(CHART, "-f", str(both))
    r2_script = preflight_script(r2)
    r3_script = preflight_script(r3)

    census = {
        "preflight objects at R1": at_r1,
        "probes at R2": len(probe_list(r2_script)),
        "denominator at R2": denominator(r2_script),
        "probes at R3 (keda+mariadb true)": len(probe_list(r3_script)),
        "denominator at R3 (keda+mariadb true)": denominator(r3_script),
        "probe/toggle pairs at R2": EXPECTED_AGREEMENT_PAIRS_AT_R2,
        "default-false probes asserted at R2": len(EXPECTED_DEFAULT_FALSE_PROBES),
        "discriminating explicit-false overrides": EXPECTED_DISCRIMINATING_OVERRIDES,
        "honoured explicit trues": EXPECTED_HONOURED_EXPLICIT_TRUES,
        "refused explicit trues": EXPECTED_REFUSED_EXPLICIT_TRUES,
        "preflight Role rules at R3": len(of_kind(preflight_objects(r3), "Role")[0]["rules"]),
        "request bodies at R3": len(HEREDOC.findall(r3_script)),
    }
    with capsys.disabled():
        print("\n  preflight census")
        for label, count in census.items():
            print(f"    {label}: {count}")

    assert census == {
        "preflight objects at R1": EXPECTED_PROBES_AT_R1,
        "probes at R2": EXPECTED_PROBES_AT_R2,
        "denominator at R2": EXPECTED_PROBES_AT_R2,
        "probes at R3 (keda+mariadb true)": EXPECTED_PROBES_AT_R3_BOTH,
        "denominator at R3 (keda+mariadb true)": EXPECTED_PROBES_AT_R3_BOTH,
        "probe/toggle pairs at R2": 1,
        "default-false probes asserted at R2": 2,
        "discriminating explicit-false overrides": 1,
        "honoured explicit trues": 2,
        "refused explicit trues": 1,
        # cert-manager one, KEDA two (its own group and `apps`), mariadb one.
        "preflight Role rules at R3": 4,
        "request bodies at R3": EXPECTED_REQUEST_BODIES,
    }
