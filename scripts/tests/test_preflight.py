"""THE PROBE JOBS' GATES: each phase's probe set, the denominator it asserts, and the tie.

TWO JOBS, AND EACH ASSERTS ITS OWN DENOMINATOR. The PRE-INSTALL preflight carries
cert-manager, KEDA and mariadb-operator. The POST-INSTALL `envoy-gateway-probe`
carries Envoy Gateway alone, because a pre-install probe of it cannot go red:
`Accepted=True` on a GatewayClass is a condition already persisted in etcd and stays
there with the controller at zero replicas, and on a fresh install the class the
probe binds to does not exist yet. The two sets are DISJOINT and
`test_the_two_probe_jobs_own_disjoint_object_sets` asserts it, because every gate
below that says "the preflight" would silently mean both the day they overlapped.


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

R2 CARRIES THE POST-INSTALL PROBE TOO, because `gatewayListener.create` is true
there and `probes.envoyGateway` ties to it — one probe in each Job, one denominator
each.

WHAT THIS SUITE DOES NOT PROVE, stated so nobody reads more into a green run. Every
assertion here is taken over `helm template` output. That the probes actually go
red against a cluster whose operator is scaled to zero is a RUN-TIME verdict, and
the plan this chart is built from defers it to the bare-install proof. Nothing here
may be reported as proving it.

Run: python3 -m pytest scripts/tests/ -q
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import textwrap
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parents[2]
CHART = REPO / "chart"
README = REPO / "README.md"
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

# The RoleBinding's subject carries `{{ .Release.Namespace }}`, and a subject in the
# wrong namespace grants the Role to NOBODY. Rendering into a named namespace is
# what lets the wiring gate compare the subject against something.
RELEASE_NAMESPACE = "yadgar"

# ── THE EXPECTED NUMBERS, AND THEY ARE LITERALS ──────────────────────────────
# Derived from the thing under test they would agree with whatever it happens to
# be and detect nothing.

# R1. Every `create` toggle is false, so every probe resolves false, so no Job.
EXPECTED_PROBES_AT_R1 = 0

# AND A SECOND ZERO, WHICH MEANS SOMETHING ELSE. The line above counts PROBES; this
# one counts the OBJECTS the preflight renders. They are both zero at R1 and they
# are not the same claim: step 5b adds a probe and the first may move while the
# second must not. One literal serving both would let the object assertion follow a
# probe count it has nothing to do with.
EXPECTED_PREFLIGHT_OBJECTS_AT_R1 = 0

# R2. cert-manager ALONE: `probes.keda` and `probes.mariadb` resolve false when
# `platform` renders alone, because a subchart cannot read a sibling chart's key
# and this chart renders neither a ScaledObject nor a MariaDB CR.
EXPECTED_PROBES_AT_R2 = 1
EXPECTED_OPERATORS_AT_R2 = ["cert-manager"]

# ── THE POST-INSTALL JOB, WHOSE NUMBERS ARE ITS OWN ──────────────────────────
# A SEPARATE DENOMINATOR RATHER THAN A FOURTH ENTRY IN THE ONE ABOVE. The two Jobs
# run in different phases and each counts only what its own phase enables, so a
# probe counted by the wrong Job is a Job reporting a pass over a number that was
# never its own.
#
# ONE PROBE AT R2, because `gatewayListener.create` is true there and
# `probes.envoyGateway` ties to it. ZERO at R1, where that toggle is false — and at
# R1 no Job renders at all, exactly as the pre-install one does not.
EXPECTED_POST_INSTALL_PROBES_AT_R2 = 1
EXPECTED_POST_INSTALL_OPERATORS_AT_R2 = ["envoy-gateway"]
EXPECTED_POST_INSTALL_OBJECTS_AT_R1 = 0

# The probe Gateway's own triple: `create`, `get` and `delete` on GATEWAYS and
# nothing else. A DIFFERENT KIND from the preflight Role's, which is why this Job
# has a triple rather than sharing one.
POST_INSTALL_PROBE_RULES = {"envoy-gateway": {"gateway.networking.k8s.io": ["gateways"]}}
EXPECTED_POST_INSTALL_PROBE_OBJECTS_AT_R2 = 4  # the Job, and its SA, Role and RoleBinding

# R3 with `probes.keda` and `probes.mariadb` true — the variant step 4's KEDA and
# mariadb cases need, because under the probe-default rule those two resolve false
# when `platform` renders alone and a case built at R2 would never run them.
EXPECTED_PROBES_AT_R3_BOTH = 3
EXPECTED_OPERATORS_AT_R3_BOTH = ["cert-manager", "keda", "mariadb-operator"]

# The probe/toggle agreement test at R2, FROM STEP 5b. TWO pairs —
# `probes.certManager` against the three toggles that render what it probes, and
# `probes.envoyGateway` against `gatewayListener.create` — plus the two
# default-false assertions for `probes.keda` and `probes.mariadb`. The register's
# row is qualified "R2 at step 4" and "R2 from step 5b", and this is the second of
# those two numbers.
EXPECTED_AGREEMENT_PAIRS_AT_R2 = 2
EXPECTED_DEFAULT_FALSE_PROBES = ["keda", "mariadb"]

# The explicit-`true` outcomes from step 5b: `probes.keda` and `probes.mariadb`
# HONOURED, `probes.certManager` and `probes.envoyGateway` REFUSED beside their own
# false toggles. The honoured number does NOT move with this step — the fourth probe
# ties to one of this chart's own toggles, so its explicit `true` is refused rather
# than honoured.
EXPECTED_HONOURED_EXPLICIT_TRUES = 2
EXPECTED_REFUSED_EXPLICIT_TRUES = 2

# The explicit-`false` override, and only where it DISCRIMINATES. `probes.keda` and
# `probes.mariadb` cannot: their tie is the hard constant false, so an explicit
# `false` and the broken Sprig-`default` produce the SAME observation. The two whose
# ties resolve TRUE at R2 can tell them apart — `probes.certManager` and, from step
# 5b, `probes.envoyGateway`.
EXPECTED_DISCRIMINATING_OVERRIDES = 2

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

# The post-install Job and its triple all carry this one name. It shares no prefix
# with the preflight's, which is what keeps `preflight_objects` and
# `post_install_probe_objects` disjoint — asserted rather than left to naming luck
# by `test_the_two_probe_jobs_own_disjoint_object_sets`.
POST_INSTALL_PROBE_JOB = "envoy-gateway-probe"

# The two phases this chart renders hooks in.
PRE_INSTALL = "pre-install,pre-upgrade"
POST_INSTALL = "post-install,post-upgrade"

# ── THE RENDERED SCRIPT'S CONTRACT ───────────────────────────────────────────
# Read off the RENDERED script rather than the template source, so a value reaches
# these gates as the value resolves it.

# The list the script iterates, and the denominator it is asserted against. NOT TWO
# INDEPENDENT DERIVATIONS — both resolve from the same `$probes`, and the per-probe
# blocks are GATED on that same list, so the denominator half is separate and the
# list half is not. What the equality catches is the `PROBES` line edited away from
# the count beside it: a probe added to the template that no `probes.*` key enables
# moves the list and not the denominator, which is the register row's own red case.
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

# The shell variable each reading is assigned to in the rendered script. The gates
# below read the needle OUT OF THE RENDER rather than out of `values.yaml`, so what
# they check is what `grep -qF` is actually handed at run time — after `squote` and
# after the template.
MARIADB_SHELL_VARIABLE = {
    MARIADB_DENIED_BY: "MARIADB_DENIED_BY",
    MARIADB_VALIDATION: "MARIADB_VALIDATION",
    MARIADB_UNREACHABLE: "MARIADB_UNREACHABLE",
}

# THE ORDER THE THREE ARMS ARE READ IN, which the template and `values.yaml` both
# state and which nothing asserted until this list existed. The unreachable reading
# is FIRST, so an absent operator is named as an absent operator; `deniedBy` second,
# which is also what keeps `denied the request` from ever meeting another webhook's
# refusal; `validationMessage` third, whose message presumes the arm above it passed.
MARIADB_ARM_ORDER = [MARIADB_UNREACHABLE, MARIADB_DENIED_BY, MARIADB_VALIDATION]

# ── TWO API-SERVER MESSAGES, AND WHAT IS UNDER TEST IS THE ENCODING ──────────
# THESE ARE TRANSCRIPTIONS, NOT CAPTURES, and this file says so rather than
# letting them read as measured — which is the exact fault the gate below exists
# to catch. The denial is transcribed from the message recorded beside
# `preflight.mariadb.deniedBy` in `chart/values.yaml`; the unreachable one is the
# API server's own wording for a webhook it could not reach.
#
# NEITHER TEXT IS THE ASSERTION. THE ENCODING IS: `metav1.Status.Message` is a
# JSON string, so the `"` the API server writes with `%q` reaches `curl` as `\"`,
# and a needle carrying a literal `"` cannot match one byte of it. So each message
# is trimmed to the part this estate can source. The unreachable one carries no
# request URL: the real message ends in the `Post "https://…": dial tcp …:
# connect: connection refused` that names the webhook's own Service, and no
# response body carrying it was captured here. Leaving an invented URL in would
# make a fixture read as measured, and none of the assertions need it.
MARIADB_DENIAL_MESSAGE = (
    'admission webhook "vmariadb-v1alpha1.kb.io" denied the request: '
    "spec.storage: Invalid value: {}: either storage size or "
    "volumeClaimTemplate must be provided"
)
MARIADB_UNREACHABLE_MESSAGE = (
    'Internal error occurred: failed calling webhook "vmariadb-v1alpha1.kb.io": '
    "failed to call webhook: connect: connection refused"
)

# Which body each reading has to be able to match. `deniedBy` and
# `validationMessage` are two halves of ONE message and share it; the unreachable
# reading is the other body entirely, and a probe whose readings were checked
# against the wrong one would prove nothing about either.
MARIADB_MESSAGE_FOR = {
    MARIADB_DENIED_BY: MARIADB_DENIAL_MESSAGE,
    MARIADB_VALIDATION: MARIADB_DENIAL_MESSAGE,
    MARIADB_UNREACHABLE: MARIADB_UNREACHABLE_MESSAGE,
}

DIGEST_PINNED = re.compile(r"^[^\s@]+@sha256:[0-9a-f]{64}$")

# Two for cert-manager (the Issuer and the Certificate it signs), two for KEDA (the
# Deployment and the ScaledObject that scales it), one for mariadb.
EXPECTED_REQUEST_BODIES = 5

# One container on the preflight Job, asserted so the image gate below cannot pass
# by examining an empty list.
EXPECTED_PREFLIGHT_CONTAINERS = 1

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
        chart, *API_VERSIONS, "-f", str(ADOPTER_VALUES), *arguments
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
    """The PRE-INSTALL preflight's own objects: the Job and the triple that serves it.

    READ OFF THE NAME rather than off the hook annotation, because the hook
    annotation is shared with the bootstrap triple and the two Jobs beside it — and
    because the preflight's own hook shape is itself under test below, so a filter
    written on it would drop exactly the objects whose annotation went wrong.

    THE POST-INSTALL PROBE'S OBJECTS ARE NOT HERE, and that is load-bearing rather
    than a side effect of what they happen to be called. Half the gates in this file
    read "the preflight's objects" and assert exactly one ServiceAccount, one Role
    and one RoleBinding among them; a second triple swept in here would redden them
    all for a reason none of their messages would name.
    `test_the_two_probe_jobs_own_disjoint_object_sets` asserts the separation instead
    of trusting the prefix.
    """
    return [
        document
        for document in documents
        if name_of(document) == PREFLIGHT_JOB or name_of(document).startswith("preflight-")
    ]


def post_install_probe_objects(documents: list[dict]) -> list[dict]:
    """The POST-INSTALL Envoy Gateway probe's objects: its Job and its own triple."""
    return [document for document in documents if name_of(document) == POST_INSTALL_PROBE_JOB]


def post_install_probe_job(documents: list[dict]) -> dict | None:
    jobs = [
        job for job in of_kind(documents, "Job") if name_of(job) == POST_INSTALL_PROBE_JOB
    ]
    return jobs[0] if len(jobs) == 1 else None


def post_install_probe_script(documents: list[dict]) -> str:
    """The shell script the post-install probe Job's single container runs. PURE."""
    job = post_install_probe_job(documents)
    assert job is not None, (
        "the render carries no single post-install probe Job to read a script off"
    )
    containers = (((job.get("spec") or {}).get("template") or {}).get("spec") or {}).get(
        "containers"
    ) or []
    assert len(containers) == 1, (
        f"expected 1 container on the post-install probe Job, found {containers}"
    )
    arguments = containers[0].get("args") or []
    assert len(arguments) == 1, f"expected 1 script argument, found {arguments}"
    return str(arguments[0])


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
    """The PRE-INSTALL Job's probe set, against its own denominator. PURE."""
    return script_probe_set_failures(preflight_script(documents), expected)


def post_install_probe_set_failures(documents: list[dict], expected: list[str]) -> list[str]:
    """The POST-INSTALL Job's probe set, against ITS own denominator. PURE.

    THE SAME HARDENED CHECK, NOT A SECOND ONE (ADR-0679). Both Jobs derive a list
    from the blocks their template renders and a denominator from the keys their
    phase's values resolve, and both compare the two at the top level — so a
    re-derivation here would be a second implementation of a gate this repository
    has already hardened once, and the two would drift.
    """
    return script_probe_set_failures(post_install_probe_script(documents), expected)


def script_probe_set_failures(script: str, expected: list[str]) -> list[str]:
    """How a rendered probe list disagrees with its own denominator, or with `expected`. PURE.

    THREE CLAIMS, NOT ONE. That the list holds what this render should enable; that
    the denominator equals the list's length; and that the script CARRIES the
    equality that compares them at run time. The third is what stops a gate reading
    two numbers in Python while the Job itself checks nothing.
    """
    failures = []

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
        f"expected {EXPECTED_PREFLIGHT_OBJECTS_AT_R1} preflight objects at the chart's "
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
        render(CHART, *API_VERSIONS, "-f", str(values))
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

    # ── PAIR 2: `probes.envoyGateway` AGAINST `gatewayListener.create` ────────
    # READ AT BOTH ENDS TOO, AND OVER THE POST-INSTALL JOB'S OBJECTS. That probe
    # enables the other Job, so a pair read over the preflight's render would be
    # green whatever the tie did — it would be examining a Job this key does not
    # enable. With the toggle true the probe must appear; with it false NO
    # post-install object may render, because a probe Gateway bound to a
    # GatewayClass this install never made is the failure class the tie exists for.
    post_on = post_install_probe_objects(adopter_render())
    listener_off_values = overrides(
        tmp_path / "gateway-listener-off.yaml", "gatewayListener:\n  create: false\n"
    )
    post_off = post_install_probe_objects(adopter_render(CHART, "-f", str(listener_off_values)))

    if not post_on:
        failures.append(
            "preflight.probes.envoyGateway is unset and `gatewayListener.create` is "
            "true, so the probe should resolve TRUE and the post-install Job should "
            "render; the render carries no object of that name"
        )
    if post_off:
        failures.append(
            "preflight.probes.envoyGateway is unset and `gatewayListener.create` is "
            "false, so the probe should resolve FALSE and no post-install object "
            "should render; found "
            f"{sorted((document.get('kind'), name_of(document)) for document in post_off)}"
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
    """R2 from step 5b: two pairs, plus the two default-false assertions."""
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
    """R3 with `probes.certManager` false; and R3 with `probes.envoyGateway` false.

    THE TWO DISCRIMINATING CASES FROM STEP 5b, and it is two rather than four. An
    explicit `false` is always honoured: losing a diagnostic is a choice an adopter
    is entitled to make. It DISCRIMINATES only where the overridden tie can take the
    other value — `probes.certManager`'s and `probes.envoyGateway`'s both resolve
    TRUE at R2, so an explicit `false` changes the observation. `probes.keda` and
    `probes.mariadb` cannot discriminate at all: their tie is the hard constant
    false, so an explicit `false` and a broken Sprig-`default` produce the SAME
    observation for both.

    EACH IS READ OVER ITS OWN JOB. `certManager` enables the pre-install preflight
    and `envoyGateway` the post-install probe, so one `preflight_objects` call for
    both would report the second probe's override as honoured while the Job it
    enables rendered untouched.
    """
    discriminating = 0
    for probe, objects, other in (
        ("certManager", preflight_objects, post_install_probe_objects),
        ("envoyGateway", post_install_probe_objects, preflight_objects),
    ):
        values = overrides(
            tmp_path / f"{probe}-off.yaml", f"preflight:\n  probes:\n    {probe}: false\n"
        )
        documents = adopter_render(CHART, "-f", str(values))
        rendered = objects(documents)
        assert rendered == [], (
            f"`preflight.probes.{probe}: false` was not honoured — it is the only "
            f"probe its Job carries at this render, so no object of that Job's should "
            f"remain; found "
            f"{sorted((document.get('kind'), name_of(document)) for document in rendered)}"
        )
        # AND THE OTHER JOB IS STILL THERE. Without this the assertion above would
        # also pass over an override that dropped BOTH probes, which is a wider
        # effect than the one being claimed.
        assert other(documents), (
            f"`preflight.probes.{probe}: false` also emptied the other Job's render, "
            f"so this case no longer shows that the override is scoped to one probe"
        )
        discriminating += 1
    assert discriminating == EXPECTED_DISCRIMINATING_OVERRIDES


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


REFUSED_EXPLICIT_TRUES = {
    # probe -> (the R3 overlay that turns its own toggle off, the toggle the
    # refusal must also name). BOTH ties are this chart's own, which is what makes
    # the explicit `true` a refusal rather than the only way to enable the probe.
    "certManager": (
        "internalCA:\n  create: false\ncertificates:\n  create: false\n"
        "edgeTLS:\n  create: false\n",
        "internalCA.create",
    ),
    # THE CASE THAT FORCED THE WHOLE RULE. `probes.envoyGateway: true` with
    # `gatewayListener.create: false` is the default adopter install that created a
    # probe Gateway bound to a GatewayClass nothing in the install renders: the
    # apply succeeded and the hook then failed, which is a clean install followed by
    # a failed release.
    "envoyGateway": ("gatewayListener:\n  create: false\n", "gatewayListener.create"),
}


def test_an_explicit_true_beside_its_own_false_toggle_is_refused(tmp_path):
    """R3 with `probes.certManager` true AND its three toggles false; and R3 with
    `probes.envoyGateway` true AND `gatewayListener.create` false.

    THIS IS THE FAILURE CLASS THE PROBE-DEFAULT RULE EXISTS FOR, not an escape
    hatch: a probe for an operator whose objects this install renders none of
    proves nothing and can only fail for the wrong reason. It is REFUSED rather
    than blessed, and the refusal names BOTH keys — a refusal naming one leaves the
    reader to guess which side to change.

    "R2 with one thing changed" cannot express either variant: at R2 each probe's
    own toggle is true and the probe is HONOURED.
    """
    refused = 0
    for probe, (toggles_off, toggle) in REFUSED_EXPLICIT_TRUES.items():
        values = overrides(
            tmp_path / f"{probe}-true-toggle-false.yaml",
            toggles_off + f"preflight:\n  probes:\n    {probe}: true\n",
        )
        result = template(CHART, *API_VERSIONS, "-f", str(ADOPTER_VALUES), "-f", str(values))
        assert result.returncode != 0, (
            f"`preflight.probes.{probe}: true` beside `{toggle}` false rendered "
            f"cleanly; it must be refused, because the probe would create objects "
            f"for an operator this install renders nothing for"
        )
        assert f"preflight.probes.{probe}" in result.stderr, result.stderr
        assert toggle in result.stderr, result.stderr
        refused += 1
    assert refused == EXPECTED_REFUSED_EXPLICIT_TRUES


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
        *API_VERSIONS,
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


def rbac_failures(
    documents: list[dict],
    expected: list[str],
    objects=preflight_objects,
    job_of=preflight_job,
    rules_for: dict | None = None,
    job_name: str = PREFLIGHT_JOB,
) -> list[str]:
    """Every way a probe Job's RBAC widens, or stops being wired to its own Job. PURE.

    PARAMETERISED RATHER THAN COPIED, and the four arguments are the only things
    that differ between the two triples. ADR-0679 says a matcher a sibling gate has
    hardened is copied rather than re-derived; here the sibling is in this same file
    and a copy would be two implementations of one check, drifting apart at the
    first mutation either one learns to catch. The defaults are the pre-install
    preflight's, so every existing call site reads as it did.

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
    mine = objects(documents)

    cluster_scoped = of_kind(mine, "ClusterRole") + of_kind(mine, "ClusterRoleBinding")
    if cluster_scoped:
        failures.append(
            f"expected 0 cluster-scoped RBAC objects from {job_name}, found "
            f"{len(cluster_scoped)}: {sorted(name_of(document) for document in cluster_scoped)}"
        )

    accounts = of_kind(mine, "ServiceAccount")
    if len(accounts) != EXPECTED_PREFLIGHT_SERVICE_ACCOUNTS:
        failures.append(
            f"expected {EXPECTED_PREFLIGHT_SERVICE_ACCOUNTS} {job_name} "
            f"ServiceAccount, found {len(accounts)}: "
            f"{sorted(name_of(account) for account in accounts)}"
        )
    identity = name_of(accounts[0]) if len(accounts) == 1 else None

    roles = of_kind(mine, "Role")
    if len(roles) != EXPECTED_PREFLIGHT_ROLES:
        failures.append(
            f"expected {EXPECTED_PREFLIGHT_ROLES} {job_name} Role, found "
            f"{len(roles)}: {sorted(name_of(role) for role in roles)}"
        )
    role_name = name_of(roles[0]) if len(roles) == 1 else None

    bindings = of_kind(mine, "RoleBinding")
    if len(bindings) != EXPECTED_PREFLIGHT_ROLE_BINDINGS:
        failures.append(
            f"expected {EXPECTED_PREFLIGHT_ROLE_BINDINGS} {job_name} RoleBinding, "
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
                f"{name_of(binding)}: the render carries no single {job_name} Role, so "
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
                f"{name_of(binding)}: the render carries no single {job_name} "
                f"ServiceAccount, so the subject {subjects[0]} was compared against nothing"
            )
            continue
        wanted = {"kind": "ServiceAccount", "name": identity, "namespace": RELEASE_NAMESPACE}
        if subjects[0] != wanted:
            failures.append(
                f"{name_of(binding)}: expected the subject to be the rendered "
                f"ServiceAccount {wanted}, found {subjects[0]}"
            )

    job = job_of(documents)
    if job is None:
        failures.append(f"the render carries no single {job_name} Job to check an identity on")
    else:
        pod = ((job.get("spec") or {}).get("template") or {}).get("spec") or {}
        runs_as = pod.get("serviceAccountName")
        if identity is None:
            failures.append(
                f"the render carries no single {job_name} ServiceAccount, so the Job's "
                f"serviceAccountName {runs_as!r} was compared against nothing"
            )
        elif runs_as != identity:
            failures.append(
                f"{job_name}: expected serviceAccountName to be the rendered "
                f"ServiceAccount {identity!r}, found {runs_as!r}. A Job left on another "
                f"account runs as an identity this Role was never bound to, and every "
                f"request it makes answers 403"
            )

    if role_name is None:
        return failures

    wanted_rules = {}
    for operator in expected:
        for group, resources in (rules_for or PROBE_RULES)[operator].items():
            wanted_rules.setdefault(group, set()).update(resources)

    rules = roles[0].get("rules") or []
    found_rules = {}
    for rule in rules:
        verbs = sorted(rule.get("verbs") or [])
        if verbs != THE_PROBE_VERBS:
            failures.append(
                f"expected {len(THE_PROBE_VERBS)} verbs on every {job_name} rule, "
                f"exactly {THE_PROBE_VERBS}, found {len(verbs)}: {verbs}. The probe "
                f"creates an object, reads it and deletes it; `list` would let it "
                f"enumerate every object of that kind in the namespace and it needs none"
            )
        for group in rule.get("apiGroups") or []:
            found_rules.setdefault(group, set()).update(rule.get("resources") or [])

    if found_rules != wanted_rules:
        failures.append(
            f"expected the {job_name} Role scoped to {ded(wanted_rules)}, found "
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
    line = "preflight: mariadb-operator configures a webhook on this kind, so its CONTROLLER is not running; the body below names the webhook that was unreachable."
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


# ── CAN EACH MARIADB STRING MATCH A REAL BODY, AND IN WHAT ORDER ARE THEY READ ─


def mariadb_needle(script: str, reading: str) -> str:
    """The value `grep -qF` is handed for `reading` at run time. PURE.

    READ OUT OF THE RENDER, NOT OUT OF `values.yaml`, and that is the whole point
    of this helper. `mariadb_failures` above asks whether the value REACHES the
    script; these gates ask what the script then DOES with it, so they have to read
    the needle after `squote` and after the template rather than the key it came
    from. It also removes the trap the red cases below would otherwise walk into: a
    helper reading `CHART` while the case renders a mutated copy reads the shipped
    value, passes, and asserts nothing.
    """
    variable = MARIADB_SHELL_VARIABLE[reading]
    match = re.search(r"^\s*" + variable + r"='(?P<needle>[^']*)'\s*$", script, re.MULTILINE)
    assert match, (
        f"the rendered script assigns no {variable}, so this gate has no needle to "
        f"check and would pass having examined nothing"
    )
    return match.group("needle")


def api_server_body(message: str) -> str:
    """The bytes `curl` writes to `$body` when the API server refuses with `message`. PURE.

    NOT A STRING THIS SUITE CHOSE. A refused admission is answered with a
    `metav1.Status`, and `message` is one JSON STRING FIELD of it — so what the
    probe greps is the JSON ENCODING of the message and never the message.
    `json.dumps` applies exactly that encoding, which is the one step the whole gate
    turns on: a `"` in the message becomes `\\"` in the body.
    """
    return json.dumps(
        {
            "kind": "Status",
            "apiVersion": "v1",
            "metadata": {},
            "status": "Failure",
            "message": message,
            "reason": "BadRequest",
            "code": 400,
        },
        separators=(",", ":"),
    )


def mariadb_escaping_failures(script: str) -> list[str]:
    """Whether each mariadb needle CAN MATCH the body it is greped against. PURE.

    THE GAP THIS CLOSES SHIPPED A REAL DEFECT ON THIS BRANCH. `mariadb_failures`
    asserts a string REACHES the script; nothing asserted it could match a body.
    `deniedBy` carried `admission webhook "vmariadb-v1alpha1.kb.io" denied the
    request`, which is how `kubectl` prints the message and not what is on the
    wire: the API server builds that prefix with `%q` into
    `metav1.Status.Message`, a JSON string, so the quotes arrive as `\\"` and
    `grep -F` for a literal `"` matches nothing. The probe therefore MISSED ON A
    HEALTHY CLUSTER — the Job exits 1, `backoffLimit: 0` forbids the retry, and
    the `pre-install` hook aborts the install naming a string comparison.

    So the check is the probe's own operation, run in Python: `grep -qF "$X"
    "$body"` is a fixed-string search for the needle in the body's bytes, which is
    `in`. The red case is a needle carrying an unescaped `"`.
    """
    failures = []
    for reading in MARIADB_ARM_ORDER:
        needle = mariadb_needle(script, reading)
        body = api_server_body(MARIADB_MESSAGE_FOR[reading])
        if needle not in body:
            failures.append(
                f"`preflight.mariadb.{reading}` reaches the script as {needle!r} and "
                f"cannot match one byte of the body the API server writes for it, "
                f"{body}. `grep -qF` searches the RAW response, where a `\"` in the "
                f"message is `\\\"`, so a needle carrying a literal `\"` misses on a "
                f"HEALTHY cluster and aborts the install naming a string comparison"
            )
    return failures


def test_every_mariadb_string_can_match_an_api_server_body(tmp_path):
    """R3 with `probes.mariadb` true: the three needles, against real response bodies."""
    values = overrides(tmp_path / "mariadb-on.yaml", "preflight:\n  probes:\n    mariadb: true\n")
    script = preflight_script(adopter_render(CHART, "-f", str(values)))
    failures = mariadb_escaping_failures(script)
    assert failures == [], "\n".join(failures)


def chart_with_the_webhooks_name_back_in_denied_by(destination: Path) -> Path:
    """The escaping gate's red case: the value this branch shipped, restored.

    NOT AN INVENTED MUTATION. This is the exact string the branch carried and the
    exact defect it caused, so the case is at once the permanent red case and the
    demonstration against the real bug.
    """
    copy = destination / "chart"
    shutil.copytree(CHART, copy)
    values = copy / "values.yaml"
    text = values.read_text()
    line = "    deniedBy: denied the request\n"
    assert line in text, (
        "`preflight.mariadb.deniedBy` no longer reads `denied the request`; this red "
        "case is now testing nothing"
    )
    quoted = "    deniedBy: 'admission webhook \"vmariadb-v1alpha1.kb.io\" denied the request'\n"
    values.write_text(text.replace(line, quoted, 1))
    return copy


def test_an_unescaped_quote_in_a_mariadb_string_reddens_the_escaping_gate(tmp_path):
    """The webhook's name put back in `deniedBy`: it renders, and it can never match."""
    values = overrides(tmp_path / "mariadb-on.yaml", "preflight:\n  probes:\n    mariadb: true\n")
    script = preflight_script(
        adopter_render(chart_with_the_webhooks_name_back_in_denied_by(tmp_path), "-f", str(values))
    )
    failures = mariadb_escaping_failures(script)
    message = "\n".join(failures)
    assert failures, (
        "`deniedBy` carried an unescaped `\"` and the escaping gate passed, so a "
        "needle that cannot match a single byte of a real body would ship again"
    )
    assert MARIADB_DENIED_BY in message, message


def mariadb_arm_position(script: str, reading: str) -> int:
    """Where `reading`'s arm stands in the rendered script. PURE."""
    variable = MARIADB_SHELL_VARIABLE[reading]
    match = re.search(r'grep -qF "\$' + variable + r'" "\$body"', script)
    assert match, (
        f"the rendered script greps no {variable}, so there is no arm to place and "
        f"this gate would pass having examined nothing"
    )
    return match.start()


def mariadb_order_failures(script: str) -> list[str]:
    """Whether the three arms are read in the order the chart documents. PURE.

    THE ORDER IS LOAD-BEARING AND WAS ASSERTED BY NOTHING. The reviewer moved the
    unreachable block BELOW the `deniedBy` block: 65 passed and `sh -n` was clean,
    because `mariadb_failures` searches 500 characters after the FIRST use of
    `"$MARIADB_UNREACHABLE"` and that window travels with the block.

    Against an unreachable-webhook body the documented order answers "the API
    server could not reach the admission webhook … its CONTROLLER is not running".
    The swapped order answers "the rejection did not come from mariadb-operator's
    admission webhook" — a string comparison standing where the operator's absence
    belongs, which is the plan's own red case landing silently.

    AND THE ORDER IS WHAT MAKES `denied the request` SAFE, not only what makes the
    message good. Now that the needle no longer carries the webhook's name it would
    also match another webhook's refusal; it never meets one, because the
    unreachable reading is read first and the validation reading follows.
    """
    failures = []
    placed = [(reading, mariadb_arm_position(script, reading)) for reading in MARIADB_ARM_ORDER]
    for (earlier, first), (later, second) in zip(placed, placed[1:]):
        if first >= second:
            failures.append(
                f"the mariadb probe reads `preflight.mariadb.{later}` at character "
                f"{second} and `preflight.mariadb.{earlier}` at {first}, so {earlier} "
                f"is no longer read first. The order is what decides which failure a "
                f"body is reported AS, and every arm below one of these presumes the "
                f"arm above it did not fire"
            )
    return failures


def test_the_mariadb_arms_read_the_unreachable_webhook_first(tmp_path):
    """R3 with `probes.mariadb` true: unreachable, then the refusal, then the validation."""
    values = overrides(tmp_path / "mariadb-on.yaml", "preflight:\n  probes:\n    mariadb: true\n")
    script = preflight_script(adopter_render(CHART, "-f", str(values)))
    failures = mariadb_order_failures(script)
    assert failures == [], "\n".join(failures)


def arm_block(text: str, variable: str) -> str:
    """One `if … grep -qF "$VARIABLE" … fi` arm, whole, out of the template."""
    match = re.search(
        r"^[ ]*if (?:! )?grep -qF \"\$" + variable + r"\" \"\$body\"; then\n.*?^[ ]*fi\n",
        text,
        re.DOTALL | re.MULTILINE,
    )
    assert match, (
        f"the {variable} arm is no longer an `if grep -qF` block; this red case is "
        f"now testing nothing"
    )
    return match.group(0)


def chart_with_the_mariadb_arms_swapped(destination: Path) -> Path:
    """The ordering gate's red case: the unreachable arm moved BELOW the refusal.

    The reviewer's own mutation, committed as a case. It leaves the script valid —
    `sh -n` is clean and every other gate here stays green — and changes only which
    failure an unreachable-webhook body is reported as.
    """
    copy = destination / "chart"
    shutil.copytree(CHART, copy)
    job = copy / "templates" / "preflight.yaml"
    text = job.read_text()
    unreachable = arm_block(text, "MARIADB_UNREACHABLE")
    denied = arm_block(text, "MARIADB_DENIED_BY")
    assert text.index(unreachable) < text.index(denied), (
        "the unreachable arm already stands below the refusal in the template, so "
        "this red case would restore the documented order rather than break it"
    )
    placeholder = "@@SWAP@@\n"
    assert placeholder not in text
    swapped = text.replace(unreachable, placeholder, 1)
    swapped = swapped.replace(denied, unreachable, 1)
    swapped = swapped.replace(placeholder, denied, 1)
    job.write_text(swapped)
    return copy


def test_swapping_the_mariadb_arms_reddens_the_ordering_gate(tmp_path):
    values = overrides(tmp_path / "mariadb-on.yaml", "preflight:\n  probes:\n    mariadb: true\n")
    script = preflight_script(
        adopter_render(chart_with_the_mariadb_arms_swapped(tmp_path), "-f", str(values))
    )
    failures = mariadb_order_failures(script)
    message = "\n".join(failures)
    assert failures, (
        "the unreachable-webhook arm was moved below the refusal and the ordering "
        "gate passed, so an absent mariadb-operator would again be reported as a "
        "rejection that came from the wrong place"
    )
    assert MARIADB_UNREACHABLE in message, message


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
    """A tag is a MOVING pointer: the same string resolves to different bytes over time.

    THE COUNT IS ASSERTED BEFORE THE PATTERN IS. A loop over `containers` examines
    whatever it is handed, so a Job rendering none of them — or a second container
    added beside the first — would walk through this green having checked nothing
    or having checked only half. One container, one image, and the pattern on it.
    """
    job = preflight_job(adopter_render())
    assert job is not None
    containers = (((job.get("spec") or {}).get("template") or {}).get("spec") or {})[
        "containers"
    ]
    assert len(containers) == EXPECTED_PREFLIGHT_CONTAINERS, (
        f"expected {EXPECTED_PREFLIGHT_CONTAINERS} container on the preflight Job, "
        f"found {len(containers)}: "
        f"{[container.get('name') for container in containers]}"
    )
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
        assert annotations.get("helm.sh/hook") == PRE_INSTALL, (
            f"{name_of(document)} ({document.get('kind')}) is a hook in phase "
            f"{annotations.get('helm.sh/hook')!r}; the preflight is {PRE_INSTALL}"
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

    # SCOPED TO THE PRE-INSTALL JOBS, and that is not tidiness. A `hook-weight`
    # orders hooks WITHIN one phase and means nothing across two, so the
    # post-install probe's weight compared here would be an ordering claim about two
    # Jobs that can never run in the same phase — and it would raise `KeyError`
    # rather than fail readably for any hook Job that carried no weight at all.
    bootstrap = [
        int(annotations_of(job)["helm.sh/hook-weight"])
        for job in of_kind(documents, "Job")
        if name_of(job) != PREFLIGHT_JOB
        and annotations_of(job).get("helm.sh/hook") == PRE_INSTALL
    ]
    assert bootstrap and job_weight < min(bootstrap), (
        f"the preflight Job's weight {job_weight} does not sit below the bootstrap "
        f"Jobs' {sorted(bootstrap)}; the preflight exists to refuse before anything "
        f"else acts"
    )


# ── THE POST-INSTALL ENVOY GATEWAY PROBE ─────────────────────────────────────
# WHAT THIS SECTION CANNOT PROVE, said once and not repeated per case. Every
# assertion here is taken over `helm template` output. That the probe actually goes
# RED against a cluster whose Envoy Gateway controller is scaled to zero is a
# RUN-TIME verdict, and the plan this chart is built from defers it to the
# bare-install proof — as it does the assertion that no Gateway of the probe's name
# survives a failing case. Nothing here may be reported as proving either.
#
# WHAT IT DOES PROVE is everything the scaled-to-zero verdict RESTS ON, each of
# which is a render-time property with a mutation that breaks it: that the probe
# waits for `Programmed` and not for `Accepted`, that it deletes any object of its
# fixed name and waits for it to be GONE before creating its own — so the status it
# reads can only have been written by this run — and that it deletes what it made on
# every exit path. A probe missing any one of those reads green with the controller
# at zero.

# The `await` call the probe makes, read off the RENDERED script: which condition it
# waits for, which status it accepts, which MESSAGE it requires alongside them, and
# which operator it names when it gives up.
AWAIT_CALL = re.compile(
    r'^\s*await\s+"(?P<path>[^"]+)"\s+(?P<condition>\w+)\s+(?P<status>\S+)\s+'
    r'"(?P<message>[^"]*)"\s+"(?P<operator>[^"]+)"\s*$',
    re.MULTILINE,
)

# The condition the probe must take, and the weaker one it must never take.
THE_PROGRAMMED_CONDITION = "Programmed"
THE_WEAKER_CONDITION = "Accepted"

# The matcher itself, and the needle the probe hands it. Both read off the RENDERED
# script, because the gate below RUNS them rather than reading them.
CONDITION_MATCHER = re.compile(
    r"^(?P<indent>[ ]*)condition_matches\(\) \{\n(?:.*\n)*?(?P=indent)\}$",
    re.MULTILINE,
)
PROGRAMMED_MESSAGE_ASSIGNMENT = re.compile(r"^[ ]*PROGRAMMED_MESSAGE=.*$", re.MULTILINE)

# `trap cleanup EXIT` at the TOP LEVEL. Inside a function it is scoped to that
# function's shell and never fires for the Job.
CLEANUP_TRAP = re.compile(r"^\s*trap cleanup EXIT\s*$", re.MULTILINE)

# The `create()` wrapper's body, to read whether it removes before it creates.
CREATE_FUNCTION = re.compile(r"^\s*create\(\) \{\n(?P<body>(?:.*\n)*?)\s*\}\s*$", re.MULTILINE)

# One request body: the probe Gateway. Asserted so the body gates below cannot pass
# by examining none.
EXPECTED_PROBE_REQUEST_BODIES = 1


def probe_gateway_body(script: str) -> dict:
    """The Gateway the probe POSTs, parsed. PURE.

    PARSED RATHER THAN GREPED, because the claims here are structural — which class,
    which EnvoyProxy, which listener protocol — and a regex over the rendered text
    would pass on a body that is no longer valid JSON at all.
    """
    bodies = [match.group("body") for match in HEREDOC.finditer(script)]
    assert len(bodies) == EXPECTED_PROBE_REQUEST_BODIES, (
        f"expected {EXPECTED_PROBE_REQUEST_BODIES} request body in the probe script, "
        f"found {len(bodies)}. A gate examining none of them passes whatever the "
        f"script does"
    )
    return json.loads(bodies[0])


def test_the_two_probe_jobs_own_disjoint_object_sets():
    """THE SEPARATION IS ASSERTED, NOT LEFT TO WHAT THE OBJECTS HAPPEN TO BE CALLED.

    Half the gates in this file say "the preflight's objects" and assert exactly one
    ServiceAccount, one Role and one RoleBinding among them. If the post-install
    probe's triple were ever swept into that set, every one of them would redden for
    a reason none of their messages would name — so the two sets are read at R2,
    required to be non-empty, and required to share nothing.
    """
    documents = adopter_render()
    pre = {(document.get("kind"), name_of(document)) for document in preflight_objects(documents)}
    post = {
        (document.get("kind"), name_of(document))
        for document in post_install_probe_objects(documents)
    }
    assert pre, "R2 carries no pre-install preflight objects, so this gate compares nothing"
    assert post, "R2 carries no post-install probe objects, so this gate compares nothing"
    assert pre & post == set(), (
        f"the two probe Jobs' object sets overlap on {sorted(pre & post)}. Every gate "
        f"in this file that says `the preflight` would then silently mean both"
    )
    assert len(post) == EXPECTED_POST_INSTALL_PROBE_OBJECTS_AT_R2, (
        f"expected {EXPECTED_POST_INSTALL_PROBE_OBJECTS_AT_R2} post-install probe "
        f"objects at R2 — the Job and its own triple — found {len(post)}: {sorted(post)}"
    )


def test_the_defaults_render_no_post_install_probe_object_at_all():
    """R1: `gatewayListener.create` is false, so the probe resolves false and no Job."""
    rendered = post_install_probe_objects(defaults_render())
    assert rendered == [], (
        f"expected {EXPECTED_POST_INSTALL_OBJECTS_AT_R1} post-install probe objects at "
        f"the chart's defaults, found {len(rendered)}: "
        f"{sorted((document.get('kind'), name_of(document)) for document in rendered)}"
    )


def test_the_listener_toggle_true_at_the_defaults_reddens_the_post_install_zero(tmp_path):
    """R1's red case, and it is a VALUES flip: make the fourth probe resolve true.

    `--api-versions` is passed because `render-checks.yaml` refuses the moment
    `gatewayListener.create` is on — without it this case would read that refusal
    instead of the zero it is trying to redden.
    """
    values = overrides(tmp_path / "listener-on.yaml", "gatewayListener:\n  create: true\n")
    rendered = post_install_probe_objects(render(CHART, *API_VERSIONS, "-f", str(values)))
    assert rendered, (
        "`gatewayListener.create` was turned true at the defaults, its probe should "
        "have resolved true and rendered the post-install Job, and the zero passed anyway"
    )


def test_the_post_install_probe_list_equals_its_denominator_at_the_adopter_values():
    """R2 from step 5b: Envoy Gateway alone, in a Job whose denominator is its own."""
    failures = post_install_probe_set_failures(
        adopter_render(), EXPECTED_POST_INSTALL_OPERATORS_AT_R2
    )
    assert failures == [], "\n".join(failures)
    assert len(EXPECTED_POST_INSTALL_OPERATORS_AT_R2) == EXPECTED_POST_INSTALL_PROBES_AT_R2


def chart_with_a_second_gateway_in_the_probe(destination: Path) -> Path:
    """The register row's red case: a second Gateway in the Job that no key enables."""
    copy = destination / "chart"
    shutil.copytree(CHART, copy)
    job = copy / "templates" / "envoy-gateway-probe.yaml"
    text = job.read_text()
    line = 'PROBES="{{ join " " $probes }}"'
    assert line in text, "the PROBES line moved; this red case is now testing nothing"
    job.write_text(text.replace(line, 'PROBES="{{ join " " $probes }} envoy-gateway-second"', 1))
    return copy


def test_a_second_gateway_no_key_enables_reddens_the_post_install_denominator(tmp_path):
    failures = post_install_probe_set_failures(
        adopter_render(chart_with_a_second_gateway_in_the_probe(tmp_path)),
        EXPECTED_POST_INSTALL_OPERATORS_AT_R2,
    )
    message = "\n".join(failures)
    assert failures, "a second probe nothing enables was added and the denominator passed"
    assert "holds 2 probes against a denominator of 1" in message, message


def chart_without_the_post_install_denominator_equality(destination: Path) -> Path:
    """The gate's own red case: the run-time comparison deleted from the probe script."""
    copy = destination / "chart"
    shutil.copytree(CHART, copy)
    job = copy / "templates" / "envoy-gateway-probe.yaml"
    text = job.read_text()
    equality = '[ "$declared" -eq "$EXPECTED_PROBES" ] || {'
    assert equality in text, "the equality moved; this red case is now testing nothing"
    end = text.index(equality)
    closing = text.index("}\n", end) + len("}\n")
    job.write_text(text[:end] + text[closing:])
    return copy


def test_deleting_the_post_install_run_time_equality_reddens_the_gate(tmp_path):
    failures = post_install_probe_set_failures(
        adopter_render(chart_without_the_post_install_denominator_equality(tmp_path)),
        EXPECTED_POST_INSTALL_OPERATORS_AT_R2,
    )
    message = "\n".join(failures)
    assert failures, "the run-time equality was deleted and the post-install gate passed"
    assert "carries no top-level" in message, message


def await_call(script: str):
    match = AWAIT_CALL.search(script)
    assert match, (
        "the rendered probe script makes no `await` call, so it waits for no "
        "condition and this gate would pass having examined nothing"
    )
    return match


def condition_choice_failures(script: str) -> list[str]:
    """`Programmed`, NOT `Accepted`, AND THE DIFFERENCE IS THE WHOLE PROBE. PURE.

    `Accepted=True` means the controller validated the Gateway's spec against its
    GatewayClass; `Programmed=True` means the data plane for it exists. A controller
    that accepts and never programs is the half-dead case this probe is for.

    THE WEAKER CONDITION IS REFUSED BY NAME rather than left out of the check, so a
    silent downgrade to `Accepted` fails here instead of shipping as a probe that
    still says it proves a running data plane.

    A HELPER RATHER THAN A TEST BODY, so the red case below can CALL THIS GATE and
    assert the message it produces. A red case that only re-reads the mutation it
    applied proves the mutation landed and says nothing about whether anything would
    have caught it — which is the shape the denominator and RBAC gates in this file
    already avoid.
    """
    failures = []
    call = await_call(script)
    if call.group("condition") != THE_PROGRAMMED_CONDITION:
        failures.append(
            f"the probe waits for {call.group('condition')!r}; it must wait for "
            f"{THE_PROGRAMMED_CONDITION!r}. If that condition turns out not to be set "
            f"at the pinned Envoy Gateway version, that is a measurement that changes "
            f"this probe and is recorded with its reason — never a silent downgrade"
        )
    if call.group("status") != "True":
        failures.append(f"the probe accepts status {call.group('status')!r}: {call.group(0)}")
    if THE_WEAKER_CONDITION in script:
        failures.append(
            f"the probe script mentions {THE_WEAKER_CONDITION!r}, which a Gateway "
            f"carries with the controller at zero replicas once it has ever been "
            f"reconciled"
        )
    if "Envoy Gateway" not in call.group("operator"):
        failures.append(
            f"the probe's timeout names {call.group('operator')!r} rather than the "
            f"operator, so a failure would report a condition instead of an absent "
            f"controller"
        )
    return failures


def test_the_probe_waits_for_programmed_and_never_for_accepted():
    failures = condition_choice_failures(post_install_probe_script(adopter_render()))
    assert failures == [], "\n".join(failures)


def chart_whose_probe_waits_for_accepted(destination: Path) -> Path:
    """The condition gate's red case: the stronger condition swapped for the weaker."""
    copy = destination / "chart"
    shutil.copytree(CHART, copy)
    job = copy / "templates" / "envoy-gateway-probe.yaml"
    text = job.read_text()
    line = 'await "$gateways/$PROBE_NAME" Programmed True "$PROGRAMMED_MESSAGE" "Envoy Gateway"'
    assert line in text, "the await call moved; this red case is now testing nothing"
    swapped = 'await "$gateways/$PROBE_NAME" Accepted True "$PROGRAMMED_MESSAGE" "Envoy Gateway"'
    job.write_text(text.replace(line, swapped, 1))
    return copy


def test_waiting_for_accepted_reddens_the_condition_gate(tmp_path):
    """THE GATE IS CALLED, not the mutation re-read."""
    script = post_install_probe_script(
        adopter_render(chart_whose_probe_waits_for_accepted(tmp_path))
    )
    failures = condition_choice_failures(script)
    message = "\n".join(failures)
    assert failures, "the probe was changed to wait for the weaker condition and the gate passed"
    assert "the probe waits for 'Accepted'" in message, message


def freshness_failures(script: str) -> list[str]:
    """FRESHNESS IS WHAT MAKES THE SCALED-TO-ZERO CASE RED, and it is a line of shell.

    A Gateway left behind by a killed run carries a status a PREVIOUS reconcile
    wrote. Reading that back is exactly the already-persisted-condition defect the
    pre-install Envoy Gateway probe was dropped for, reappearing on the post-install
    side: with the controller at zero the probe would read a stale `Programmed=True`
    and report a pass. So the script deletes any object of its fixed name and waits
    for it to be GONE before creating its own.

    A HELPER RATHER THAN A TEST BODY, for the reason `condition_choice_failures`
    states: the red case below calls this and asserts the message. PURE.
    """
    failures = []
    match = CREATE_FUNCTION.search(script)
    assert match, "the probe script defines no `create()`, so there is nothing to place"
    body = match.group("body")
    if 'remove "$1"' not in body:
        failures.append(
            "the probe's `create()` does not remove the object of its fixed name "
            "first, so a Gateway left by a killed run is read back with the status an "
            f"earlier reconcile wrote: {body}"
        )
        return failures
    if body.index('remove "$1"') >= body.index("request POST"):
        failures.append(
            f"the probe removes AFTER it creates, which collides with the leftover "
            f"rather than replacing it: {body}"
        )
    return failures


def test_the_probe_removes_any_prior_gateway_before_creating_its_own():
    failures = freshness_failures(post_install_probe_script(adopter_render()))
    assert failures == [], "\n".join(failures)


def chart_whose_probe_does_not_remove_first(destination: Path) -> Path:
    """The freshness gate's red case: the remove-before-create deleted."""
    copy = destination / "chart"
    shutil.copytree(CHART, copy)
    job = copy / "templates" / "envoy-gateway-probe.yaml"
    text = job.read_text()
    line = '                remove "$1"\n'
    assert line in text, "the remove-before-create moved; this red case is now testing nothing"
    job.write_text(text.replace(line, "", 1))
    return copy


def test_dropping_the_remove_before_create_reddens_the_freshness_gate(tmp_path):
    """THE GATE IS CALLED, not the mutation re-read."""
    script = post_install_probe_script(
        adopter_render(chart_whose_probe_does_not_remove_first(tmp_path))
    )
    failures = freshness_failures(script)
    message = "\n".join(failures)
    assert failures, "the remove-before-create was deleted and the freshness gate passed"
    assert "does not remove the object of its fixed name first" in message, message


def cleanup_failures(script: str) -> list[str]:
    """`hook-delete-policy` DOES NOT DO THIS, and a Gateway is not inert. PURE.

    `before-hook-creation` deletes the JOB before the next hook run; it never touches
    objects that Job created. Envoy Gateway provisions a Deployment and a Service per
    Gateway, so a probe that times out and exits 1 would leave real proxy
    infrastructure standing. The trap runs on EXIT — success and failure alike — and
    it runs at the TOP LEVEL, because a trap set inside a function is scoped to that
    function's shell and never fires for the Job.

    A HELPER RATHER THAN A TEST BODY, for the reason `condition_choice_failures`
    states: the red case below calls this and asserts the message.
    """
    failures = []
    if not CLEANUP_TRAP.search(script):
        failures.append(
            "the probe script carries no top-level `trap cleanup EXIT`, so a probe "
            "that times out leaves its Gateway — and the proxy Deployment and Service "
            "Envoy Gateway provisioned for it — standing"
        )
    if 'request DELETE "$path" ""' not in script:
        failures.append(
            "the probe's cleanup issues no DELETE, so the trap fires and removes nothing"
        )
    if 'CREATED="$CREATED $1"' not in script:
        failures.append(
            "the probe never records what it created, so the cleanup walks an empty "
            "list and passes having deleted nothing"
        )
    return failures


def test_the_probe_deletes_its_gateway_on_every_exit_path():
    failures = cleanup_failures(post_install_probe_script(adopter_render()))
    assert failures == [], "\n".join(failures)


def chart_without_the_probe_cleanup_trap(destination: Path) -> Path:
    """The cleanup assertion's own red case: the trap deleted."""
    copy = destination / "chart"
    shutil.copytree(CHART, copy)
    job = copy / "templates" / "envoy-gateway-probe.yaml"
    text = job.read_text()
    line = "              trap cleanup EXIT\n"
    assert line in text, "the trap moved; this red case is now testing nothing"
    job.write_text(text.replace(line, "", 1))
    return copy


def test_deleting_the_cleanup_trap_reddens_the_cleanup_gate(tmp_path):
    """THE GATE IS CALLED, not the mutation re-read."""
    script = post_install_probe_script(
        adopter_render(chart_without_the_probe_cleanup_trap(tmp_path))
    )
    failures = cleanup_failures(script)
    message = "\n".join(failures)
    assert failures, "the trap was deleted and the cleanup gate passed"
    assert "carries no top-level `trap cleanup EXIT`" in message, message


def probe_gateway_failures(documents: list[dict]) -> list[str]:
    """THE CLASS IS WHAT MAKES THIS ENVOY GATEWAY'S PROBE, not the API group. PURE.

    A Gateway is `gateway.networking.k8s.io`, a SPECIFICATION every implementation
    registers. What names the operator is the GatewayClass, whose `controllerName` is
    Envoy Gateway's own — so a probe bound to any other class proves nothing about
    Envoy Gateway, and a probe bound to a class this chart does not render proves
    nothing at all.

    AND IT INHERITS THE REAL LISTENER'S INFRASTRUCTURE. The `parametersRef` names the
    EnvoyProxy `gatewayListener.create` renders, so the probe's data plane is placed
    and exposed exactly as the estate's own edge is. A probe provisioned from the
    controller's defaults could fail where the real Gateway succeeds, which would be
    a probe reporting on a Gateway nobody installed.

    A HELPER RATHER THAN A TEST BODY, for the reason `condition_choice_failures`
    states: the two red cases below call this and assert the message each produces.
    """
    failures = []
    body = probe_gateway_body(post_install_probe_script(documents))

    classes = of_kind(documents, "GatewayClass")
    assert len(classes) == 1, f"expected 1 rendered GatewayClass, found {classes}"
    if body["spec"]["gatewayClassName"] != name_of(classes[0]):
        failures.append(
            f"the probe Gateway binds to class {body['spec']['gatewayClassName']!r} "
            f"and this chart renders {name_of(classes[0])!r}. A class nothing created "
            f"leaves the probe `Accepted=False` forever, with no controller ever "
            f"looking at it"
        )

    proxies = of_kind(documents, "EnvoyProxy")
    assert len(proxies) == 1, f"expected 1 rendered EnvoyProxy, found {proxies}"
    reference = body["spec"]["infrastructure"]["parametersRef"]
    if reference != {
        "group": "gateway.envoyproxy.io",
        "kind": "EnvoyProxy",
        "name": name_of(proxies[0]),
    }:
        failures.append(
            f"the probe Gateway's parametersRef is {reference}; it must name the "
            f"EnvoyProxy this chart renders, {name_of(proxies[0])!r}, so that whether "
            f"a Gateway can be programmed on this cluster is one question rather than two"
        )

    listeners = body["spec"]["listeners"]
    if len(listeners) != 1 or listeners[0]["protocol"] != "HTTP":
        failures.append(
            f"the probe Gateway's listeners are {listeners}; one plain HTTP listener "
            f"is what keeps the probe free of a TLS Secret, a ReferenceGrant and "
            f"cert-manager, so that a red here is Envoy Gateway and nothing else"
        )
    return failures


def test_the_probe_gateway_binds_to_the_class_and_the_infrastructure_this_chart_renders():
    failures = probe_gateway_failures(adopter_render())
    assert failures == [], "\n".join(failures)


def chart_whose_probe_binds_to_another_class(destination: Path) -> Path:
    """The class gate's red case: the probe bound to a class this chart never renders."""
    copy = destination / "chart"
    shutil.copytree(CHART, copy)
    job = copy / "templates" / "envoy-gateway-probe.yaml"
    text = job.read_text()
    line = '"gatewayClassName":"{{ $listener.className }}",'
    assert line in text, "the class reference moved; this red case is now testing nothing"
    job.write_text(text.replace(line, '"gatewayClassName":"istio",', 1))
    return copy


def test_a_probe_bound_to_another_class_reddens_the_class_gate(tmp_path):
    """THE GATE IS CALLED, not the mutation re-read."""
    failures = probe_gateway_failures(
        adopter_render(chart_whose_probe_binds_to_another_class(tmp_path))
    )
    message = "\n".join(failures)
    assert failures, "the probe was bound to another class and the gate passed"
    assert "binds to class 'istio'" in message, message


def chart_whose_probe_names_no_infrastructure(destination: Path) -> Path:
    """The infrastructure gate's red case: the parametersRef pointed at nothing."""
    copy = destination / "chart"
    shutil.copytree(CHART, copy)
    job = copy / "templates" / "envoy-gateway-probe.yaml"
    text = job.read_text()
    line = '"name":"{{ $listener.envoyProxy.name }}"}},'
    assert line in text, "the parametersRef moved; this red case is now testing nothing"
    job.write_text(text.replace(line, '"name":"no-such-envoyproxy"}},', 1))
    return copy


def test_a_probe_whose_infrastructure_names_nothing_reddens_the_gate(tmp_path):
    """THE GATE IS CALLED, not the mutation re-read."""
    failures = probe_gateway_failures(
        adopter_render(chart_whose_probe_names_no_infrastructure(tmp_path))
    )
    message = "\n".join(failures)
    assert failures, "the parametersRef was pointed at nothing and the gate passed"
    assert "'name': 'no-such-envoyproxy'" in message, message


# ── THE CONDITION READING, RUN RATHER THAN READ ──────────────────────────────
# A GATEWAY CARRIES TWO CONDITIONS NAMED `Programmed`, AND THEY ARE DIFFERENT FACTS.
# The OBJECT's means an address was assigned and the proxy replicas are available;
# each LISTENER's means its configuration was translated and sent to the data plane.
# Measured on kind-yadgar against `docker.io/envoyproxy/gateway:v1.9.1`, read-only:
#
#   object-level     Programmed=True  "Address assigned to the Gateway, 2/2 envoy
#                                      replicas available"
#   listener-level   Programmed=True  "Sending translated listener configuration to
#                                      the data plane"
#
# and `Programmed` appears four times in one Gateway's status. The matcher greps the
# whole response, so `Programmed=True` ALONE is satisfied by either.
#
# THE TWO COME APART ON THE PROOF'S OWN CLUSTER. `envoyProxy.serviceType` defaults to
# `LoadBalancer`, `example/values.yaml` deliberately does not restate it, and the
# bare-install proof runs where no load-balancer controller exists — so the OBJECT's
# `Programmed` goes False with reason `AddressNotAssigned`, the probe inherits that
# same EnvoyProxy and so inherits that same failure, and the listener still
# translates. A probe keyed on the condition alone reports SUCCESS there while the
# real `edge` Gateway stalls.
#
# THESE GATES RUN THE RENDERED MATCHER rather than reading it. A Python restatement
# of `sed | grep | grep | grep` is a second implementation, and a gate that agrees
# with its own restatement proves nothing about the shell that ships. So the function
# is lifted out of the rendered script verbatim, handed the needles the rendered
# `await` call hands it, and executed against constructed bodies.
#
# STIPULATED RATHER THAN MEASURED, and stated here as well as in the values file:
# that v1.9.1 sets the LISTENER's `Programmed=True` while address assignment fails
# was NOT reproduced. Closing it needs a Gateway created on a cluster with no
# load-balancer controller, which no read-only observation can stand in for. What IS
# measured is that both conditions exist under one name with the two messages above.


def gateway_body(
    object_status: str, object_message: str, listener_status: str, listener_message: str
) -> str:
    """The bytes `curl` writes to `$body` for a Gateway carrying these conditions. PURE.

    COMPACT JSON, as the API server writes it — `separators=(",", ":")` — because the
    matcher's first step splits on the literal `},{` and a body with spaces in it
    would not split at all. Same reasoning as `api_server_body` above.
    """
    return json.dumps(
        {
            "apiVersion": "gateway.networking.k8s.io/v1",
            "kind": "Gateway",
            "metadata": {"name": "envoy-gateway-probe", "namespace": "yadgar"},
            "spec": {"gatewayClassName": "eg"},
            "status": {
                "conditions": [
                    {
                        "type": "Accepted",
                        "status": "True",
                        "reason": "Accepted",
                        "message": "The Gateway has been scheduled by Envoy Gateway",
                    },
                    {
                        "type": "Programmed",
                        "status": object_status,
                        "reason": "Programmed" if object_status == "True" else "AddressNotAssigned",
                        "message": object_message,
                    },
                ],
                "listeners": [
                    {
                        "name": "probe",
                        "attachedRoutes": 0,
                        "conditions": [
                            {
                                "type": "Accepted",
                                "status": "True",
                                "reason": "Accepted",
                                "message": "Listener is accepted",
                            },
                            {
                                "type": "Programmed",
                                "status": listener_status,
                                "reason": "Programmed",
                                "message": listener_message,
                            },
                        ],
                    }
                ],
            },
        },
        separators=(",", ":"),
    )


ADDRESS_ASSIGNED = "Address assigned to the Gateway, 2/2 envoy replicas available"
LISTENER_TRANSLATED = "Sending translated listener configuration to the data plane"
NO_ADDRESS = "No addresses have been assigned to the Gateway"

# A FRESH GATEWAY WITH THE CONTROLLER AT ZERO: admitted, and never given a status.
FRESH_GATEWAY_BODY = json.dumps(
    {
        "apiVersion": "gateway.networking.k8s.io/v1",
        "kind": "Gateway",
        "metadata": {"name": "envoy-gateway-probe", "namespace": "yadgar"},
        "spec": {"gatewayClassName": "eg"},
        "status": {},
    },
    separators=(",", ":"),
)

# Each case is (name, body, must the matcher ACCEPT it, why it is here).
CONDITION_READING_CASES = (
    (
        "programmed",
        gateway_body("True", ADDRESS_ASSIGNED, "True", LISTENER_TRANSLATED),
        True,
        "the status a healthy cluster writes. A matcher that refuses this is red on a "
        "healthy cluster, which is the class this chart refuses",
    ),
    (
        "listener-only",
        gateway_body("False", NO_ADDRESS, "True", LISTENER_TRANSLATED),
        False,
        "the OBJECT's `Programmed` False for want of an address and the LISTENER's "
        "True. `envoyProxy.serviceType` defaults to `LoadBalancer` and the proof runs "
        "where nothing provides one, so this is the proof's own configuration — a "
        "matcher that accepts it reports success while the real `edge` Gateway stalls",
    ),
    (
        "no-status",
        FRESH_GATEWAY_BODY,
        False,
        "the scaled-to-zero case: a fresh Gateway the controller never touched. A "
        "matcher that accepts it is the whole probe reading green with no controller",
    ),
)


def matcher_harness(script: str) -> str:
    """The rendered matcher, the needle the rendered script hands it, and nothing else.

    THE NEEDLES ARE TAKEN FROM THE `await` CALL SITE rather than retyped here, so a
    probe changed to demand something else is exercised as changed. PURE.
    """
    call = await_call(script)
    function = CONDITION_MATCHER.search(script)
    assert function, (
        "the rendered script defines no `condition_matches()`, so there is nothing to "
        "run and this gate would pass having executed nothing"
    )
    assignment = PROGRAMMED_MESSAGE_ASSIGNMENT.search(script)
    assert assignment, (
        "the rendered script assigns no PROGRAMMED_MESSAGE, so the probe requires no "
        "message and this gate would run a matcher the probe does not use"
    )
    return "\n".join(
        [
            "set -u",
            'body="$1"',
            assignment.group(0).strip(),
            textwrap.dedent(function.group(0)),
            " ".join(
                [
                    "condition_matches",
                    call.group("condition"),
                    call.group("status"),
                    '"' + call.group("message") + '"',
                ]
            ),
            "",
        ]
    )


def matcher_verdict(harness: Path, body: Path) -> int:
    """Whether the rendered matcher ACCEPTS `body`: its exit status, 0 for yes."""
    binary = shutil.which("sh")
    # NOT A SKIP, and ADR-0650 is why — the same decision `helm()` above makes.
    assert binary, (
        "no POSIX shell is on PATH. This gate RUNS the probe's own matcher, and the "
        "probe's container runs it under `sh` too — install one rather than letting "
        "this report a pass it did not earn"
    )
    return subprocess.run(
        [binary, str(harness), str(body)], capture_output=True, text=True
    ).returncode


def condition_reading_failures(script: str, tmp_path: Path) -> list[str]:
    """Every constructed body the rendered matcher reads the wrong way."""
    harness = tmp_path / "matcher.sh"
    harness.write_text(matcher_harness(script))
    failures = []
    for name, body, must_accept, why in CONDITION_READING_CASES:
        path = tmp_path / f"body-{name}.json"
        path.write_text(body)
        accepted = matcher_verdict(harness, path) == 0
        if accepted == must_accept:
            continue
        verb = "ACCEPTS" if accepted else "REFUSES"
        failures.append(
            f"the rendered matcher {verb} the {name} body and must not: {why}. The "
            f"body it read was {body}"
        )
    return failures


def test_the_probe_refuses_a_body_carrying_only_the_listeners_programmed(tmp_path):
    """R2: the three readings, through the shell the probe actually ships."""
    failures = condition_reading_failures(post_install_probe_script(adopter_render()), tmp_path)
    assert failures == [], "\n".join(failures)


def chart_whose_matcher_drops_the_message_stage(destination: Path) -> Path:
    """The reading gate's red case, and NOT AN INVENTED MUTATION.

    This restores the matcher exactly as it stood when the review found the defect:
    `Programmed=True` with no message required. It is at once the permanent red case
    and the demonstration against the real bug.
    """
    copy = destination / "chart"
    shutil.copytree(CHART, copy)
    job = copy / "templates" / "envoy-gateway-probe.yaml"
    text = job.read_text()
    three_stage = (
        "                  | grep -E '\"status\":\"('\"$2\"')\"' \\\n"
        '                  | grep -qF "$3"\n'
    )
    assert three_stage in text, "the matcher moved; this red case is now testing nothing"
    two_stage = "                  | grep -Eq '\"status\":\"('\"$2\"')\"'\n"
    job.write_text(text.replace(three_stage, two_stage, 1))
    return copy


def test_a_matcher_without_the_message_stage_reddens_the_reading_gate(tmp_path):
    """The wide matcher put back: it accepts the body the real cluster produces."""
    script = post_install_probe_script(
        adopter_render(chart_whose_matcher_drops_the_message_stage(tmp_path))
    )
    failures = condition_reading_failures(script, tmp_path)
    message = "\n".join(failures)
    assert failures, (
        "the message stage was deleted and the reading gate passed, so a probe that "
        "reports success off the listener's condition would ship again"
    )
    assert "ACCEPTS the listener-only body" in message, message


def chart_with_an_empty_programmed_message(destination: Path) -> Path:
    """The key's own weakening direction: `grep -F ""` matches every line.

    A VALUES EDIT, NOT A TEMPLATE ONE, which is the objection to making a message a
    key at all. The gate answers it by BEHAVIOUR rather than by a literal: an empty
    needle cannot refuse anything, so the reading gate reddens on the same three
    bodies it always reads.
    """
    copy = destination / "chart"
    shutil.copytree(CHART, copy)
    values = copy / "values.yaml"
    text = values.read_text()
    line = "    programmedMessage: Address assigned to the Gateway\n"
    assert line in text, (
        "`preflight.envoyGateway.programmedMessage` moved; this red case is now "
        "testing nothing"
    )
    values.write_text(text.replace(line, '    programmedMessage: ""\n', 1))
    return copy


def test_an_empty_programmed_message_reddens_the_reading_gate(tmp_path):
    script = post_install_probe_script(
        adopter_render(chart_with_an_empty_programmed_message(tmp_path))
    )
    failures = condition_reading_failures(script, tmp_path)
    message = "\n".join(failures)
    assert failures, (
        "`programmedMessage` was emptied and the reading gate passed, so the third "
        "stage can be turned into a no-op by a values edit nothing catches"
    )
    assert "ACCEPTS the listener-only body" in message, message


# ── THE PROBE'S BOUND AND HELM'S HOOK BUDGET, WHICH ARE ONE CONSTRAINT ────────
# MEASURED ON BOTH PINS — helm 3.18.4 and 4.3.0 — `--timeout` is documented as "time
# to wait for any individual Kubernetes operation (like Jobs for hooks)" and defaults
# to `5m0s`. Helm's clock starts when the hook Job is CREATED, so scheduling and
# image pull come out of the same budget before the script's own clock starts.
#
# AND THE SCRIPT'S WORST CASE IS TWICE ITS BOUND. `create()` calls `remove()` first,
# and `remove()` loops to the SAME `TIMEOUT_SECONDS` that `await()` then loops to. So
# two bounded loops compose, plus the request time of the calls themselves, which no
# value bounds.
#
# WHAT IS LOST WHEN HELM GIVES UP FIRST IS THE MESSAGE, NOT THE GATEWAY. The Job
# carries `backoffLimit: 0` and no `activeDeadlineSeconds`, so the pod runs on and
# the trap still deletes what it made. The operator reads `timed out waiting for the
# condition` instead of the probe naming Envoy Gateway, which is exactly what ruling
# 10 asks the probe to do.
#
# THE BOUND IS NOT LOWERED TO FIT. `Programmed` includes replica availability, so a
# cold cluster may genuinely need 300s, and a bound cut to fit helm's default would
# reintroduce red-on-healthy. The budget is documented instead, and this gate is what
# stops the two diverging in silence.
BOUNDED_LOOPS_PER_RUN = 2
INSTALL_BUDGET_MARGIN_SECONDS = 300

# The bound, read off the RENDERED script, never off the values literal beside it.
PROBE_BOUND = re.compile(r"^\s*TIMEOUT_SECONDS=(?P<seconds>\d+)\s*$", re.MULTILINE)

# `--timeout <duration>` as helm takes it. A bare `--timeout` with no duration after
# it — the prose mentioning the flag — is not a statement of a budget and is skipped.
TIMEOUT_FLAG = re.compile(r"--timeout\s+(?P<budget>\d+)(?P<unit>[smh])\b")
SECONDS_PER_UNIT = {"s": 1, "m": 60, "h": 3600}

# Where the budget must be stated, and the least number of statements each file must
# carry. A MINIMUM rather than an equality, so prose may repeat it — but zero is
# refused, because a gate that found no statement would pass having compared nothing.
BUDGET_IS_STATED_IN = {"README.md": 1, "example/values.yaml": 1}


def install_budget_failures(script: str, stated: dict[str, str]) -> list[str]:
    """Whether every documented `--timeout` covers the probe's composed bound. PURE.

    `stated` maps each file's name to its text, so the red cases below can hand this
    a mutated document without writing one to disk.
    """
    failures = []
    bound = PROBE_BOUND.search(script)
    assert bound, (
        "the rendered probe script sets no TIMEOUT_SECONDS, so it carries no bound "
        "and this gate would pass having compared nothing"
    )
    seconds = int(bound.group("seconds"))
    required = BOUNDED_LOOPS_PER_RUN * seconds + INSTALL_BUDGET_MARGIN_SECONDS

    for name, minimum in BUDGET_IS_STATED_IN.items():
        found = list(TIMEOUT_FLAG.finditer(stated[name]))
        if len(found) < minimum:
            failures.append(
                f"{name} states `--timeout <duration>` {len(found)} times and must "
                f"state it at least {minimum}. The probe bounds itself at {seconds}s "
                f"and helm's own default is 300s, so an install that is handed no "
                f"budget aborts before the probe can name Envoy Gateway"
            )
            continue
        for match in found:
            budget = int(match.group("budget")) * SECONDS_PER_UNIT[match.group("unit")]
            if budget >= required:
                continue
            failures.append(
                f"{name} documents `--timeout {match.group('budget')}"
                f"{match.group('unit')}` = {budget}s, and the probe needs "
                f"{required}s: {BOUNDED_LOOPS_PER_RUN} composed loops of {seconds}s "
                f"plus {INSTALL_BUDGET_MARGIN_SECONDS}s for scheduling, image pull "
                f"and request time. Helm aborts first, and the operator reads `timed "
                f"out waiting for the condition` instead of the probe's diagnostic"
            )
    return failures


def documented_budgets() -> dict[str, str]:
    """The two files the budget is stated in, as they stand."""
    return {
        "README.md": README.read_text(),
        "example/values.yaml": ADOPTER_VALUES.read_text(),
    }


def test_the_documented_install_budget_covers_the_probes_bound():
    """R2: the bound off the rendered script, the budget off the two documents."""
    failures = install_budget_failures(
        post_install_probe_script(adopter_render()), documented_budgets()
    )
    assert failures == [], "\n".join(failures)


def test_documenting_helms_own_default_reddens_the_budget_gate():
    """The red case: the budget cut to the default the measurement says is too small."""
    stated = documented_budgets()
    original = stated["README.md"]
    stated["README.md"] = original.replace("--timeout 15m", "--timeout 5m")
    assert stated["README.md"] != original, (
        "README.md no longer spells the budget `--timeout 15m`, so this red case "
        "replaced nothing and is now testing whatever the unmutated file says"
    )
    failures = install_budget_failures(post_install_probe_script(adopter_render()), stated)
    message = "\n".join(failures)
    assert failures, "the documented budget was cut to helm's default and the gate passed"
    assert "README.md documents `--timeout 5m` = 300s" in message, message


def test_a_budget_stated_nowhere_reddens_the_budget_gate():
    """The gate cannot pass having found no statement."""
    stated = documented_budgets()
    original = stated["example/values.yaml"]
    stated["example/values.yaml"] = original.replace("--timeout 15m", "")
    assert stated["example/values.yaml"] != original, (
        "example/values.yaml no longer spells the budget `--timeout 15m`, so this red "
        "case deleted nothing and is now testing whatever the unmutated file says"
    )
    failures = install_budget_failures(post_install_probe_script(adopter_render()), stated)
    message = "\n".join(failures)
    assert failures, "the budget was deleted from example/values.yaml and the gate passed"
    assert "example/values.yaml states `--timeout <duration>` 0 times" in message, message


def chart_whose_probe_outlives_the_documented_budget(destination: Path) -> Path:
    """The other knob: the bound raised past what the documented budget covers."""
    copy = destination / "chart"
    shutil.copytree(CHART, copy)
    values = copy / "values.yaml"
    text = values.read_text()
    line = "    timeoutSeconds: 300\n"
    assert line in text, (
        "`preflight.envoyGateway.timeoutSeconds` moved; this red case is now testing "
        "nothing"
    )
    values.write_text(text.replace(line, "    timeoutSeconds: 600\n", 1))
    return copy


def test_raising_the_bound_past_the_documented_budget_reddens_the_gate(tmp_path):
    """THE CONSTRAINT HAS TWO KNOBS, and moving either one alone must redden."""
    script = post_install_probe_script(
        adopter_render(chart_whose_probe_outlives_the_documented_budget(tmp_path))
    )
    failures = install_budget_failures(script, documented_budgets())
    message = "\n".join(failures)
    assert failures, "the probe's bound was doubled and the documented budget still passed"
    assert "the probe needs 1500s" in message, message


def post_install_rbac_failures(documents: list[dict], expected: list[str]) -> list[str]:
    """The post-install triple, through the SAME hardened check the preflight's uses."""
    return rbac_failures(
        documents,
        expected,
        objects=post_install_probe_objects,
        job_of=post_install_probe_job,
        rules_for=POST_INSTALL_PROBE_RULES,
        job_name=POST_INSTALL_PROBE_JOB,
    )


def test_the_post_install_probe_role_carries_create_get_delete_and_never_list():
    """`create`, `get`, `delete` on GATEWAYS — a different kind from the preflight's."""
    failures = post_install_rbac_failures(adopter_render(), EXPECTED_POST_INSTALL_OPERATORS_AT_R2)
    assert failures == [], "\n".join(failures)


def chart_with_list_on_the_probe_role(destination: Path) -> Path:
    """The verb gate's red case: `list` added back."""
    copy = destination / "chart"
    shutil.copytree(CHART, copy)
    rbac = copy / "templates" / "envoy-gateway-probe-rbac.yaml"
    text = rbac.read_text()
    line = '    verbs: ["create", "get", "delete"]'
    assert line in text, "the verb list moved; this red case is now testing nothing"
    rbac.write_text(text.replace(line, '    verbs: ["create", "get", "delete", "list"]'))
    return copy


def test_a_fourth_verb_reddens_the_post_install_rbac_gate(tmp_path):
    failures = post_install_rbac_failures(
        adopter_render(chart_with_list_on_the_probe_role(tmp_path)),
        EXPECTED_POST_INSTALL_OPERATORS_AT_R2,
    )
    message = "\n".join(failures)
    assert failures, "`list` was added to the probe Role and the verb gate passed"
    assert "exactly ['create', 'delete', 'get']" in message, message


def chart_with_the_probe_bound_to_cluster_admin(destination: Path) -> Path:
    """The wiring gate's red case, and it renders NO extra object at all."""
    copy = destination / "chart"
    shutil.copytree(CHART, copy)
    rbac = copy / "templates" / "envoy-gateway-probe-rbac.yaml"
    text = rbac.read_text()
    block = "  kind: Role\n  name: {{ $probe.serviceAccountName }}"
    assert block in text, "the roleRef moved; this red case is now testing nothing"
    rbac.write_text(text.replace(block, "  kind: ClusterRole\n  name: cluster-admin", 1))
    return copy


def test_binding_the_probe_to_cluster_admin_reddens_the_wiring_gate(tmp_path):
    documents = adopter_render(chart_with_the_probe_bound_to_cluster_admin(tmp_path))
    census = of_kind(post_install_probe_objects(documents), "ClusterRole")
    assert census == [], (
        "binding to the built-in `cluster-admin` rendered a ClusterRole object, so "
        "this red case no longer demonstrates what it was written for"
    )
    failures = post_install_rbac_failures(documents, EXPECTED_POST_INSTALL_OPERATORS_AT_R2)
    message = "\n".join(failures)
    assert failures, "the probe was bound to cluster-admin and the wiring gate passed"
    assert "'kind': 'Role'" in message, message


def test_the_probe_and_its_triple_are_post_install_hooks_at_ordered_weights():
    """The Job is a `post-install` hook and its own triple sits BELOW it.

    THE PHASE IS THE ORDERING. This Job runs once the release's objects exist,
    the GatewayClass among them — which a weight cannot express, and which is the
    whole reason a pre-install Envoy Gateway probe could not be built.

    `test_bootstrap.py`'s chart-wide hook gate owns the COUNTS of Jobs, RBAC objects
    and weight positions per phase. What is asserted here is this Job's own shape.
    """
    mine = post_install_probe_objects(adopter_render())
    assert mine, "the adopter render carries no post-install probe objects at all"

    weights = {}
    for document in mine:
        annotations = annotations_of(document)
        assert annotations.get("helm.sh/hook") == POST_INSTALL, (
            f"{name_of(document)} ({document.get('kind')}) is a hook in phase "
            f"{annotations.get('helm.sh/hook')!r}; this probe is {POST_INSTALL}"
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

    job_weight = weights[("Job", POST_INSTALL_PROBE_JOB)]
    triple = {
        weight
        for (kind, _), weight in weights.items()
        if kind in {"ServiceAccount", "Role", "RoleBinding"}
    }
    assert triple and max(triple) < job_weight, (
        f"the probe triple's weights {sorted(triple)} do not all sit BELOW the Job's "
        f"{job_weight}, so the Job can be admitted before its identity exists"
    )


def test_the_probe_body_generates_nothing_inside_itself():
    """The trap this chart has met once, asserted for the second Job too.

    A generator called as `$(...)` INSIDE A HEREDOC cannot fail the run: command
    substitution DISCARDS the exit status, so `set -e` never sees it.
    """
    body = probe_gateway_body(post_install_probe_script(adopter_render()))
    assert "$(" not in json.dumps(body), (
        f"the probe's request body generates inside itself: {body}. Command "
        f"substitution discards the exit status, so a generator that fails there "
        f"posts an empty value and the Job reports success"
    )


def test_the_probe_image_is_pinned_by_digest_and_is_the_preflights_own():
    """ONE IMAGE KEY FOR BOTH JOBS, and it is pinned by digest.

    A tag is a MOVING pointer. A second key would be two sources for one decision
    and the digest pin would have to be moved twice.
    """
    documents = adopter_render()
    job = post_install_probe_job(documents)
    assert job is not None
    containers = (((job.get("spec") or {}).get("template") or {}).get("spec") or {})["containers"]
    assert len(containers) == EXPECTED_PREFLIGHT_CONTAINERS, (
        f"expected {EXPECTED_PREFLIGHT_CONTAINERS} container on the probe Job, found "
        f"{[container.get('name') for container in containers]}"
    )
    assert DIGEST_PINNED.match(containers[0]["image"]), (
        f"the probe image {containers[0]['image']!r} is not pinned by digest"
    )
    preflight = preflight_job(documents)
    assert preflight is not None
    assert containers[0]["image"] == (
        ((preflight["spec"]["template"]["spec"])["containers"][0]["image"])
    ), "the two probe Jobs no longer read one image key, so a digest bump moves one of them"


def test_preflight_enabled_false_drops_both_jobs(tmp_path):
    """ONE KEY DROPS BOTH, and `README.md` and `example/values.yaml` both say so.

    A CLAIM IN PROSE THAT NO RENDER CHECKS IS THE SHAPE THIS REPOSITORY EXISTS TO
    CATCH. `preflight.enabled` guards the pre-install Job, its triple, the
    post-install Job and its triple, and an adopter reading either file is told that
    setting it false is how the diagnostic is dropped. Asserted over R2, where both
    Jobs otherwise render, so the zero here is the key's doing and not the tie's.

    ITS RED CASE IS THE KEY AT ITS DEFAULT, which every other case in this file
    renders: `test_the_two_probe_jobs_own_disjoint_object_sets` requires both sets
    NON-EMPTY over exactly this render with the key untouched, so a guard that
    stopped gating either Job reddens there.
    """
    values = overrides(tmp_path / "preflight-off.yaml", "preflight:\n  enabled: false\n")
    documents = adopter_render(CHART, "-f", str(values))
    assert preflight_objects(documents) == [], (
        "`preflight.enabled: false` left pre-install preflight objects in the render: "
        f"{sorted((document.get('kind'), name_of(document)) for document in preflight_objects(documents))}"
    )
    assert post_install_probe_objects(documents) == [], (
        "`preflight.enabled: false` left post-install probe objects in the render: "
        f"{sorted((document.get('kind'), name_of(document)) for document in post_install_probe_objects(documents))}"
    )


def chart_with_the_gateway_tie_hardcoded_true(destination: Path) -> Path:
    """The second pair's red case: the tie stops following `gatewayListener.create`."""
    copy = destination / "chart"
    shutil.copytree(CHART, copy)
    partial = copy / "templates" / "_preflight.tpl"
    text = partial.read_text()
    line = '      "tied" $context.Values.gatewayListener.create'
    assert line in text, "the gateway tie moved; this red case is now testing nothing"
    partial.write_text(text.replace(line, '      "tied" true', 1))
    return copy


def test_a_gateway_tie_that_stops_following_its_toggle_reddens_the_agreement_gate(tmp_path):
    """Flip one member of the second pair without the other."""
    copy = chart_with_the_gateway_tie_hardcoded_true(tmp_path)
    off_values = overrides(
        tmp_path / "gateway-listener-off.yaml", "gatewayListener:\n  create: false\n"
    )
    off = post_install_probe_objects(adopter_render(copy, "-f", str(off_values)))
    assert off, (
        "the tie was hardcoded true, so the probe should have rendered a Job with "
        "`gatewayListener.create` false, and the agreement gate saw nothing"
    )


# ── THE RESPONSE THE MATCHER READS, AND WHO DECIDES ITS SHAPE ────────────────
# THE API SERVER PRETTY-PRINTS FOR ANY CLIENT WHOSE `User-Agent` BEGINS WITH
# `curl`, AND `preflight.image` IS `curlimages/curl`. Measured in-cluster against
# kind-yadgar (Kubernetes v1.36.1), one pod, three requests to one URL:
#
#   default agent (curl/…)   12 lines
#   ?pretty=false             1 line
#   a non-curl agent          1 line
#
# WHAT IT COST. cert-manager issued the probe Certificate in about one second —
# `Ready=True` at t=1s, Secret created — and the preflight Job still failed at its
# 120-second bound reporting that cert-manager's CONTROLLER was not running. The
# post-install probe failed identically beside an `edge` Gateway reading
# `Programmed=True`. Both Jobs report the one thing that was not wrong.
#
# THE MATCHER IS NOT AT FAULT AND IS NOT WHAT CHANGES. `condition_matches` is a
# LINE matcher over a body it splits on the literal `},{`, and a pretty body
# defeats it TWICE OVER with no grep fix for either half:
#
#   1. `"type": "Ready"` carries a space after the colon, so the needle
#      `'"type":"Ready"'` matches nothing at all.
#   2. `type` and `status` land on SEPARATE LINES, so no single line the pipeline
#      sees can carry both — the `grep | grep` chain cannot succeed however the
#      needles are written.
#
# So the three gates below are three different jobs and only the middle one moves
# when the fix lands:
#
#   THE REASON      the lifted matcher REFUSES a pretty body whose condition is
#                   present. True before the fix and after it, forever. It is why
#                   the request layer has to guarantee compact.
#   THE END TO END  the lifted `request()` and the lifted `condition_matches()`
#                   run together against a fake `curl` that implements the API
#                   SERVER's own pretty rule. RED before the fix, green after.
#   THE ARGV        the properties the fix rests on, read off what `curl` was
#                   actually called with: an agent that cannot trigger the rule,
#                   `pretty=false` on every request, the right join character, and
#                   a URL that does not grow across polls.
#
# EVERY ONE OF THEM RUNS THE RENDERED SHELL. A grep for `pretty=false` in a
# template is not evidence the probe works: `case "$path" in *?*)` — the escape
# dropped — sends EVERY path down the `&` branch and requests
# `/apis/…&pretty=false`, and a template grep passes that.

# BOTH CALL SITES, BY NAME. `condition_matches` and `request` are DUPLICATED in the
# two templates rather than shared, so a fix in one leaves the class alive in the
# other. The gates below iterate this map and the count is asserted, so deleting
# half the fix reddens rather than quietly passing.
EXPECTED_MATCHING_SCRIPTS = 2

# The agent the templates set, read off the rendered script. Optional by design:
# the red cases below delete it.
USER_AGENT_ASSIGNMENT = re.compile(r"^[ ]*USER_AGENT=.*$", re.MULTILINE)


# The rendered `request()`, lifted the way `CONDITION_MATCHER` lifts the matcher.
REQUEST_FUNCTION = re.compile(
    r"^(?P<indent>[ ]*)request\(\) \{\n(?:.*\n)*?(?P=indent)\}$",
    re.MULTILINE,
)

# The preflight's `await` calls. A SECOND REGEX RATHER THAN A WIDENING OF
# `AWAIT_CALL`, which requires a quoted message and a quoted operator: the
# preflight passes no message at all, quotes its status on one arm
# (`"True|False"`) and not on the other, and quotes neither operator.
PREFLIGHT_AWAIT_CALL = re.compile(
    r'^[ ]*await\s+"(?P<path>[^"]+)"\s+(?P<condition>\w+)\s+'
    r'"?(?P<status>[^"\s]+)"?\s+(?P<operator>\S+)\s*$',
    re.MULTILINE,
)

# `curl`'s own default agent, restated so the fake below is the real client's
# stand-in rather than a convenient one. It is the value that triggers the rule.
CURLS_OWN_AGENT = "curl/8.16.0"

# The two agents the API server pretty-prints for. Asserted as PROPERTIES of
# whatever agent the templates choose rather than against a literal: a chart that
# picked `curl-platform-preflight` would satisfy any grep for its own new string
# and still be pretty-printed on every request.
PRETTY_PRINTING_AGENT_PREFIX = "curl"
PRETTY_PRINTING_AGENT_SUBSTRING = "mozilla"

# A path that already carries a query, and the one the probes actually use.
# `?dryRun=All` is the mariadb arm's, so the join character is a real case and not
# a hypothetical one.
PATH_WITH_A_QUERY = "/apis/k8s.mariadb.com/v1alpha1/namespaces/yadgar/mariadbs?dryRun=All"
PATH_WITHOUT_A_QUERY = "/apis/cert-manager.io/v1/namespaces/yadgar/certificates/preflight-probe"

# A message no implementation could plausibly contain, for the bodies this suite
# builds itself. The estate's fixture rule: never the real constant.
BODY_SENTINEL = "sentinel-of-the-body"

# One DELETE, two GETs of one path, and a POST to a path that already carries a
# query. Asserted, so a gate cannot report a pass having examined fewer.
EXPECTED_DRIVEN_REQUESTS = 4


def matching_scripts(documents: list[dict]) -> dict[str, str]:
    """The two rendered scripts that carry a `condition_matches`, BY NAME.

    Named rather than collected, so a gate cannot pass by having found one.
    """
    scripts = {
        "preflight": preflight_script(documents),
        "envoy-gateway-probe": post_install_probe_script(documents),
    }
    assert len(scripts) == EXPECTED_MATCHING_SCRIPTS, (
        f"this suite knows {len(scripts)} scripts carrying the matcher and the "
        f"chart has {EXPECTED_MATCHING_SCRIPTS}"
    )
    for name, script in scripts.items():
        assert CONDITION_MATCHER.search(script), (
            f"the rendered {name} script defines no `condition_matches()`, so the "
            f"gates below would examine nothing for it"
        )
        assert REQUEST_FUNCTION.search(script), (
            f"the rendered {name} script defines no `request()`, so the gates below "
            f"would examine nothing for it"
        )
    return scripts


def condition_body(condition: str, status: str, message: str) -> dict:
    """An object carrying the condition an `await` waits for, and a decoy beside it.

    THE DECOY IS NOT DECORATION. A body holding one condition is matched by a
    pipeline that ignores the type entirely, so it cannot tell a reader of `type`
    from a reader of nothing.
    """
    return {
        "apiVersion": "probe.invalid/v1",
        "kind": "Probe",
        "metadata": {"name": "preflight-probe", "namespace": RELEASE_NAMESPACE},
        "status": {
            "conditions": [
                {
                    "type": "NotTheOneWaitedFor",
                    "status": "Unknown",
                    "reason": "NotTheOneWaitedFor",
                    "message": BODY_SENTINEL,
                },
                {
                    "type": condition,
                    "status": status,
                    "reason": condition,
                    "message": message,
                },
            ]
        },
    }


def healthy_cases(name: str, script: str) -> list[tuple[str, str, dict]]:
    """For each `await` the script makes: (label, the matcher call, a body that satisfies it).

    THE NEEDLES ARE TAKEN FROM THE CALL SITE rather than retyped, so a probe changed
    to demand something else is exercised as changed. PURE.
    """
    if name == "envoy-gateway-probe":
        call = await_call(script)
        return [
            (
                f"{name}/{call.group('condition')}",
                " ".join(
                    [
                        "condition_matches",
                        call.group("condition"),
                        call.group("status"),
                        '"' + call.group("message") + '"',
                    ]
                ),
                json.loads(
                    gateway_body("True", ADDRESS_ASSIGNED, "True", LISTENER_TRANSLATED)
                ),
            )
        ]

    cases = []
    for call in PREFLIGHT_AWAIT_CALL.finditer(script):
        status = call.group("status")
        # `True|False` is an alternation the matcher hands to `grep -E`. The body
        # carries ONE of them, and the first is what a healthy cluster writes.
        cases.append(
            (
                f"{name}/{call.group('operator')}",
                " ".join(
                    [
                        "condition_matches",
                        call.group("condition"),
                        "'" + status + "'",
                    ]
                ),
                condition_body(call.group("condition"), status.split("|")[0], BODY_SENTINEL),
            )
        )
    assert cases, (
        f"the rendered {name} script makes no `await` call this suite can read, so "
        f"these gates would run the matcher against no needle at all"
    )
    return cases


def compact(body: dict) -> str:
    """The bytes the API server writes for a client it does not pretty-print for."""
    return json.dumps(body, separators=(",", ":"))


def pretty(body: dict) -> str:
    """The bytes it writes for one it does.

    `json.MarshalIndent(obj, "", "  ")` is what `k8s.io/apiserver` calls, and
    `indent=2` is its Python spelling: a space after every `:`, and one field per
    line. Both halves of the defect are in that sentence.
    """
    return json.dumps(body, indent=2)


def matcher_only_harness(script: str, call: str) -> str:
    """The lifted matcher and nothing else, run against a body named on argv."""
    function = CONDITION_MATCHER.search(script)
    assert function, "the rendered script defines no `condition_matches()`"
    lines = ["set -u", 'body="$1"']
    assignment = PROGRAMMED_MESSAGE_ASSIGNMENT.search(script)
    if assignment:
        lines.append(assignment.group(0).strip())
    lines += [textwrap.dedent(function.group(0)), call, ""]
    return "\n".join(lines)


# The fake `curl`, and it implements THE API SERVER'S RULE rather than the probe's
# wishes. `k8s.io/apiserver/pkg/endpoints/handlers/negotiation` reads an explicit
# `pretty` query parameter first and falls back to the agent, pretty-printing when
# it begins with `curl` or contains `mozilla` in any case. A fake that only honoured
# `pretty=false` would report the agent half of the fix as working whether it was
# there or not.
#
# A SHELL FUNCTION, so it shadows the real binary on PATH inside the lifted
# `request()` — including as the last element of its `printf | curl` pipeline.
FAKE_CURL = r"""
curl() {
  printf -- '--CALL--\n' >>"$RECORD"
  for word in "$@"; do printf '%s\n' "$word" >>"$RECORD"; done

  agent=''
  out=''
  url=''
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --user-agent|-A) agent="$2"; shift 2 ;;
      --header|-H)
        case "$2" in
          [Uu]ser-[Aa]gent:*) agent="${2#*:}"; agent="${agent# }" ;;
        esac
        shift 2 ;;
      --output|-o) out="$2"; shift 2 ;;
      --cacert|--request|-X|--write-out|-w|--data-binary|-d) shift 2 ;;
      -*) shift ;;
      *) url="$1"; shift ;;
    esac
  done

  [ -n "$out" ] || { printf '000'; return 1; }
  [ -n "$url" ] || { printf '000'; return 1; }
  [ -n "$agent" ] || agent="$CURLS_OWN_AGENT"

  chosen="$COMPACT_BODY"
  case "$url" in
    *pretty=false*) chosen="$COMPACT_BODY" ;;
    *pretty=true*) chosen="$PRETTY_BODY" ;;
    *)
      lowered="$(printf '%s' "$agent" | tr 'ABCDEFGHIJKLMNOPQRSTUVWXYZ' 'abcdefghijklmnopqrstuvwxyz')"
      case "$agent" in
        curl*) chosen="$PRETTY_BODY" ;;
        *) case "$lowered" in *mozilla*) chosen="$PRETTY_BODY" ;; esac ;;
      esac
      ;;
  esac

  cat "$chosen" >"$out"
  printf '200'
}
"""


def request_harness(script: str, driver: str) -> str:
    """The lifted `request()` and `condition_matches()` over the fake API server.

    Everything the lifted text reads — `$api`, `$sa`, `$token`, `$body` — is bound
    here exactly as the Job's own preamble binds it. PURE.
    """
    request = REQUEST_FUNCTION.search(script)
    matcher = CONDITION_MATCHER.search(script)
    assert request and matcher, "the rendered script is missing `request()` or the matcher"
    agent = USER_AGENT_ASSIGNMENT.search(script)
    lines = [
        "set -u",
        f'api="{THE_API}"',
        'sa="/var/run/secrets/kubernetes.io/serviceaccount"',
        f'ns="{RELEASE_NAMESPACE}"',
        'token="a-token-the-fake-never-reads"',
        'body="$SCRATCH/answer"',
        'STATUS=""',
        FAKE_CURL,
    ]
    # ABSENT IS NOT AN ERROR HERE. Before the fix there is no assignment, and this
    # harness has to RUN in that state — that is the whole point of the red case.
    if agent:
        lines.append(agent.group(0).strip())
    assignment = PROGRAMMED_MESSAGE_ASSIGNMENT.search(script)
    if assignment:
        lines.append(assignment.group(0).strip())
    lines += [
        textwrap.dedent(request.group(0)),
        textwrap.dedent(matcher.group(0)),
        driver,
        "",
    ]
    return "\n".join(lines)


def run_harness(harness: Path, scratch: Path, body: dict, *arguments: str):
    """Run a harness with the fake API server's two renderings of `body` in hand."""
    binary = shutil.which("sh")
    # NOT A SKIP, and ADR-0650 is why — the same decision `helm()` above makes.
    assert binary, (
        "no POSIX shell is on PATH. These gates RUN the probe's own request path, "
        "and the probe's container runs it under `sh` too"
    )
    scratch.mkdir(parents=True, exist_ok=True)
    (scratch / "compact.json").write_text(compact(body))
    (scratch / "pretty.json").write_text(pretty(body))
    record = scratch / "argv"
    record.write_text("")
    return subprocess.run(
        [binary, str(harness), *arguments],
        capture_output=True,
        text=True,
        env={
            "PATH": os.environ.get("PATH", ""),
            "SCRATCH": str(scratch),
            "RECORD": str(record),
            "COMPACT_BODY": str(scratch / "compact.json"),
            "PRETTY_BODY": str(scratch / "pretty.json"),
            "CURLS_OWN_AGENT": CURLS_OWN_AGENT,
        },
    )


def recorded_calls(scratch: Path) -> list[list[str]]:
    """What `curl` was invoked with, one list of words per call."""
    calls: list[list[str]] = []
    for line in (scratch / "argv").read_text().splitlines():
        if line == "--CALL--":
            calls.append([])
        elif calls:
            calls[-1].append(line)
    return calls


# The API the Jobs' own preamble binds `$api` to. `url_of` anchors on it rather
# than on `http`, which a future `--proxy` or `--referer` VALUE would also satisfy.
THE_API = "https://kubernetes.default.svc"


def url_of(words: list[str]) -> str:
    """The URL a recorded call requested: the one word that is the API's own."""
    urls = [word for word in words if word.startswith(THE_API)]
    assert len(urls) == 1, f"expected one {THE_API} word in {words}, found {urls}"
    return urls[0]


def agent_of(words: list[str]) -> str | None:
    for index, word in enumerate(words[:-1]):
        if word in ("--user-agent", "-A"):
            return words[index + 1]
        if word in ("--header", "-H") and words[index + 1].lower().startswith("user-agent:"):
            return words[index + 1].split(":", 1)[1].strip()
    return None


# ── THE REASON: THE MATCHER CANNOT READ A PRETTY BODY, AND NEVER WILL ────────


def matcher_shape_failures(name: str, script: str, tmp_path: Path) -> list[str]:
    """The lifted matcher over the same object in both renderings. PURE of the fix.

    THIS DOES NOT MOVE WHEN THE FIX LANDS, and that is what it is for. It states the
    standing fact the fix rests on: the matcher reads compact JSON and refuses the
    pretty rendering of the very same object. A future reader tempted to drop
    `pretty=false` because "the agent handles it" meets this case first.
    """
    tmp_path.mkdir(parents=True, exist_ok=True)
    failures = []
    for label, call, body in healthy_cases(name, script):
        harness = tmp_path / f"matcher-{label.replace('/', '-')}.sh"
        harness.write_text(matcher_only_harness(script, call))
        for shape, render_body, must_accept in (
            ("compact", compact(body), True),
            ("pretty", pretty(body), False),
        ):
            path = tmp_path / f"body-{label.replace('/', '-')}-{shape}.json"
            path.write_text(render_body)
            accepted = matcher_verdict(harness, path) == 0
            if accepted == must_accept:
                continue
            if must_accept:
                failures.append(
                    f"{label}: the rendered matcher REFUSES the compact body its own "
                    f"`await` asks for, so this gate is reading the wrong condition "
                    f"and proves nothing about the pretty one"
                )
            else:
                failures.append(
                    f"{label}: the rendered matcher ACCEPTS the PRETTY rendering of "
                    f"that body. It is a line matcher over a body split on `}}{{`, and "
                    f"a pretty body puts a space after every `:` and `type` and "
                    f"`status` on separate lines — if it accepts one, this gate has "
                    f"stopped describing the matcher that ships"
                )
    return failures


def test_the_matcher_reads_compact_json_and_refuses_the_pretty_rendering(tmp_path):
    """Why `request()` has to guarantee compact, stated as a property of the matcher."""
    documents = adopter_render()
    failures = []
    for name, script in matching_scripts(documents).items():
        failures += matcher_shape_failures(name, script, tmp_path / name)
    assert failures == [], "\n".join(failures)


# ── THE END TO END: THE PROBE'S OWN REQUEST PATH AGAINST THE API SERVER'S RULE ─


def probe_reading_failures(name: str, script: str, tmp_path: Path) -> list[str]:
    """Does the probe, making its own request, read a healthy cluster as healthy?

    THE FAILING CASE THIS SUITE WAS MISSING. `request()` and `condition_matches()`
    are lifted TOGETHER and run against a `curl` that pretty-prints by the API
    server's rule, so the verdict answers the question the Job answers: with
    cert-manager having written `Ready=True`, does the preflight pass?
    """
    failures = []
    for label, call, body in healthy_cases(name, script):
        scratch = tmp_path / label.replace("/", "-")
        harness = scratch / "probe.sh"
        scratch.mkdir(parents=True, exist_ok=True)
        harness.write_text(
            request_harness(
                script,
                "\n".join(
                    [
                        f'request GET "{PATH_WITHOUT_A_QUERY}" ""',
                        '[ "$STATUS" = "200" ] || exit 2',
                        call,
                    ]
                ),
            )
        )
        result = run_harness(harness, scratch, body)
        if result.returncode == 0:
            continue
        if result.returncode == 2:
            failures.append(f"{label}: the harness never got a 200 from the fake API server")
            continue
        calls = recorded_calls(scratch)
        requested = url_of(calls[-1]) if calls else "<no request was made>"
        failures.append(
            f"{label}: the probe REFUSES a healthy cluster. Its own `request()` "
            f"asked for {requested}, the API server pretty-printed the answer "
            f"because of it, and the matcher could not read a condition that IS "
            f"present. This is the preflight failing at its bound reporting that an "
            f"operator which answered in about one second is not running. "
            f"stderr: {result.stderr.strip()!r}"
        )
    return failures


def test_each_probe_reads_a_healthy_cluster_as_healthy(tmp_path):
    """R1 of this section: the defect itself, through the shell that ships."""
    documents = adopter_render()
    failures = []
    for name, script in matching_scripts(documents).items():
        failures += probe_reading_failures(name, script, tmp_path / name)
    assert failures == [], "\n".join(failures)


# ── THE ARGV: THE FOUR PROPERTIES THE FIX RESTS ON ───────────────────────────


def argv_failures(name: str, script: str, tmp_path: Path) -> list[str]:
    """Every property of what `curl` was actually called with. PURE of the template text.

    FOUR PROPERTIES, EACH WITH ITS OWN WAY OF BEING WRONG WHILE A TEMPLATE GREP
    PASSES:

      THE AGENT      must not begin with `curl` and must not contain `mozilla`.
                     Asserted as a property, never against a literal: the API
                     server reads both, and `curl-platform-preflight` satisfies any
                     grep for the chart's own new string and is still pretty-
                     printed.
      THE PARAMETER  `pretty=false` on EVERY request, both branches. Covering only
                     the POST leaves every GET pretty, and every condition the
                     probes read comes back on a GET.
      THE JOIN       `?dryRun=All&pretty=false`, never `?dryRun=All?pretty=false`.
                     `case "$path" in *?*)` with the escape dropped sends every
                     path down the `&` branch instead, and requests
                     `/apis/…&pretty=false`.
      IDEMPOTENCE    two successive calls with one path request byte-identical
                     URLs. POSIX `sh` has no locals and `await` re-calls `request`
                     with the same `path` on every poll, so a fix that appends to
                     `path` grows the query by one `&pretty=false` per second.
    """
    scratch = tmp_path / name
    harness = scratch / "argv.sh"
    scratch.mkdir(parents=True, exist_ok=True)
    harness.write_text(
        request_harness(
            script,
            "\n".join(
                [
                    # `remove()` DELETEs before anything is created and then GETs
                    # the same path until it answers 404, and `await` GETs it
                    # again on every poll. Driving only the two verbs the probe
                    # reads conditions with would let a join wrong on DELETE pass.
                    f'request DELETE "{PATH_WITHOUT_A_QUERY}" ""',
                    f'request GET "{PATH_WITHOUT_A_QUERY}" ""',
                    f'request GET "{PATH_WITHOUT_A_QUERY}" ""',
                    f'request POST "{PATH_WITH_A_QUERY}" \'{{"kind":"Probe"}}\'',
                ]
            ),
        )
    )
    body = condition_body("Ready", "True", BODY_SENTINEL)
    result = run_harness(harness, scratch, body)
    calls = recorded_calls(scratch)
    if len(calls) != EXPECTED_DRIVEN_REQUESTS:
        return [
            f"{name}: the harness made {len(calls)} requests where "
            f"{EXPECTED_DRIVEN_REQUESTS} were driven, so this gate would examine "
            f"less than it was asked to. stderr: {result.stderr.strip()!r}"
        ]

    failures = []
    delete, first_get, second_get, post = calls
    for label, words in (("DELETE", delete), ("GET", first_get), ("POST", post)):
        agent = agent_of(words)
        if agent is None:
            failures.append(
                f"{name}: the {label} branch sends no `User-Agent`, so `curl` sends "
                f"its own and the API server pretty-prints the answer"
            )
        else:
            if agent.startswith(PRETTY_PRINTING_AGENT_PREFIX):
                failures.append(
                    f"{name}: the {label} branch's agent {agent!r} BEGINS WITH "
                    f"{PRETTY_PRINTING_AGENT_PREFIX!r}, which is exactly what the API "
                    f"server pretty-prints for"
                )
            if PRETTY_PRINTING_AGENT_SUBSTRING in agent.lower():
                failures.append(
                    f"{name}: the {label} branch's agent {agent!r} contains "
                    f"{PRETTY_PRINTING_AGENT_SUBSTRING!r}, the API server's other "
                    f"pretty-print trigger"
                )
        url = url_of(words)
        if "pretty=false" not in url:
            failures.append(
                f"{name}: the {label} branch requested {url}, which carries no "
                f"`pretty=false`. The agent alone is the whole guarantee, and a "
                f"future agent change silently removes it"
            )

    bare_url = url_of(first_get)
    if "?pretty=false" not in bare_url:
        failures.append(
            f"{name}: a path carrying NO query was requested as {bare_url}. A path "
            f"with no query joins its first parameter with `?` — `&pretty=false` on "
            f"a bare path is not a query at all, it is part of the path, and the API "
            f"server pretty-prints the answer exactly as before. This is what "
            f"`case \"$path\" in *?*)` does with the escape dropped, and a template "
            f"grep for `pretty=false` passes it"
        )

    post_url = url_of(post)
    if "?dryRun=All&pretty=false" not in post_url:
        failures.append(
            f"{name}: a path that already carries a query was requested as "
            f"{post_url}. `?dryRun=All&pretty=false` is the only valid join — a "
            f"second `?` makes `dryRun=All?pretty=false` one opaque parameter value "
            f"and the dry run stops being a dry run"
        )

    if url_of(first_get) != url_of(second_get):
        failures.append(
            f"{name}: two successive requests with ONE path asked for "
            f"{url_of(first_get)} then {url_of(second_get)}. `await` polls with the "
            f"same `path` until the bound, so a URL that grows is a query that grows "
            f"once a second"
        )
    return failures


def test_every_request_asks_for_a_response_the_matcher_can_read(tmp_path):
    """The four properties, over both scripts."""
    documents = adopter_render()
    failures = []
    for name, script in matching_scripts(documents).items():
        failures += argv_failures(name, script, tmp_path)
    assert failures == [], "\n".join(failures)


def test_the_fix_covers_both_call_sites_and_this_suite_knows_how_many():
    """THE COUNT, SO DELETING HALF THE FIX REDDENS RATHER THAN QUIETLY PASSING.

    The matcher and the request function are duplicated across two templates. Every
    gate in this section iterates `matching_scripts`, and a gate that iterated ONE
    would pass with the other still broken — which is the shape that made this
    defect survive its own first fix elsewhere.
    """
    scripts = matching_scripts(adopter_render())
    assert sorted(scripts) == ["envoy-gateway-probe", "preflight"], sorted(scripts)


# ── THE CONSTRUCTED RED CASES, ONE PER TEMPLATE ──────────────────────────────
# ONE PER TEMPLATE AND NEVER BOTH AT ONCE. A red case that reverts the fix in both
# files proves only that the gate notices SOMETHING; it is satisfied by a gate
# reading one script. Reverting one at a time is what requires the gate to read
# each.

THE_FIXED_TEMPLATES = {
    "preflight": "preflight.yaml",
    "envoy-gateway-probe": "envoy-gateway-probe.yaml",
}


def chart_without_the_compact_response_guarantee(destination: Path, template_name: str) -> Path:
    """The chart as it stood when the defect was measured, in ONE of the two files."""
    copy = destination / "chart"
    shutil.copytree(CHART, copy)
    job = copy / "templates" / template_name
    text = job.read_text()

    agent = USER_AGENT_ASSIGNMENT.search(text)
    assert agent, f"{template_name} assigns no USER_AGENT; this red case is testing nothing"
    text = text.replace(agent.group(0) + "\n", "", 1)

    flag = '                    --user-agent "$USER_AGENT" \\\n'
    assert text.count(flag) == 2, (
        f"{template_name} passes `--user-agent` on {text.count(flag)} of its two curl "
        f"branches; this red case is testing nothing"
    )
    text = text.replace(flag, "")

    join = (
        '                case "$path" in\n'
        '                  *\\?*) query="&pretty=false" ;;\n'
        '                  *) query="?pretty=false" ;;\n'
        "                esac\n"
    )
    assert join in text, (
        f"{template_name}'s `pretty=false` join moved; this red case is testing nothing"
    )
    text = text.replace(join, "", 1)
    assert text.count('"$api$path$query")"') == 2, (
        f"{template_name} does not build both its URLs from `$query`; this red case is "
        f"testing nothing"
    )
    text = text.replace('"$api$path$query")"', '"$api$path")"')

    job.write_text(text)
    return copy


def red_case_failures(broken: str, tmp_path: Path) -> list[str]:
    """Every failure the three gates report with the fix reverted in `broken` only."""
    documents = adopter_render(
        chart_without_the_compact_response_guarantee(tmp_path / broken, THE_FIXED_TEMPLATES[broken])
    )
    failures = []
    for name, script in matching_scripts(documents).items():
        failures += probe_reading_failures(name, script, tmp_path / broken / "e2e" / name)
        failures += argv_failures(name, script, tmp_path / broken / "argv")
    return failures


def scripts_reported_broken(failures: list[str]) -> set[str]:
    """Which script each end-to-end refusal named. Its label is `<script>/<await>`."""
    return {
        failure.split("/", 1)[0]
        for failure in failures
        if "REFUSES a healthy cluster" in failure
    }


def test_reverting_the_fix_in_the_preflight_alone_reddens_the_gates(tmp_path):
    """The measured defect, put back in one file. It must be named, and alone."""
    failures = red_case_failures("preflight", tmp_path)
    message = "\n".join(failures)
    assert failures, (
        "the preflight's compact-response guarantee was deleted and every gate passed, "
        "so the Job that failed at its 120-second bound against a cert-manager which "
        "answered in one second would ship again"
    )
    assert scripts_reported_broken(failures) == {"preflight"}, (
        f"reverting the PREFLIGHT ALONE had the end-to-end gate name "
        f"{sorted(scripts_reported_broken(failures))}. Naming more is a gate that is "
        f"not reading the script it reports; naming fewer is a gate that would pass "
        f"with half the fix deleted.\n{message}"
    )


def test_reverting_the_fix_in_the_gateway_probe_alone_reddens_the_gates(tmp_path):
    """The same defect in the other copy — the half a single-file fix leaves alive."""
    failures = red_case_failures("envoy-gateway-probe", tmp_path)
    message = "\n".join(failures)
    assert failures, (
        "the post-install probe's compact-response guarantee was deleted and every "
        "gate passed, so the probe that failed beside an `edge` Gateway reading "
        "`Programmed=True` would ship again"
    )
    assert scripts_reported_broken(failures) == {"envoy-gateway-probe"}, (
        f"reverting the GATEWAY PROBE ALONE had the end-to-end gate name "
        f"{sorted(scripts_reported_broken(failures))}. Naming more is a gate that is "
        f"not reading the script it reports; naming fewer is a gate that would pass "
        f"with half the fix deleted.\n{message}"
    )


def chart_whose_join_glob_is_unescaped(destination: Path) -> Path:
    """The mutation a template grep for `pretty=false` cannot see.

    `*?*` is the shell's glob for "at least one character", so EVERY path takes the
    `&` branch and the probe requests `/apis/…&pretty=false`. The parameter is in
    the template, in the URL, and doing nothing.
    """
    copy = destination / "chart"
    shutil.copytree(CHART, copy)
    for template_name in THE_FIXED_TEMPLATES.values():
        job = copy / "templates" / template_name
        text = job.read_text()
        escaped = '                  *\\?*) query="&pretty=false" ;;\n'
        assert escaped in text, f"{template_name}'s join moved; this red case is testing nothing"
        job.write_text(text.replace(escaped, '                  *?*) query="&pretty=false" ;;\n', 1))
    return copy


def test_dropping_the_escape_from_the_join_glob_reddens_the_argv_gate(tmp_path):
    """A `pretty=false` that is present, requested, and joined to nothing."""
    documents = adopter_render(chart_whose_join_glob_is_unescaped(tmp_path))
    failures = []
    for name, script in matching_scripts(documents).items():
        failures += argv_failures(name, script, tmp_path / "argv")
    message = "\n".join(failures)
    assert failures, (
        "the escape was dropped from the join glob and the argv gate passed, so a "
        "probe requesting `/apis/...&pretty=false` — one path, no query at all — "
        "would ship with `pretty=false` visible in the template"
    )
    assert "a path carrying NO query was requested as" in message, message


def chart_whose_agent_still_begins_with_curl(destination: Path) -> Path:
    """The agent named for the chart and still triggering the rule.

    NOT AN INVENTED MUTATION. `curl-yadgar-platform` is what a reader who knew the
    image and not the rule would write, and it is why the gate asserts a PROPERTY.
    """
    copy = destination / "chart"
    shutil.copytree(CHART, copy)
    for template_name in THE_FIXED_TEMPLATES.values():
        job = copy / "templates" / template_name
        text = job.read_text()
        agent = USER_AGENT_ASSIGNMENT.search(text)
        assert agent, f"{template_name} assigns no USER_AGENT; this red case is testing nothing"
        indent = agent.group(0)[: len(agent.group(0)) - len(agent.group(0).lstrip())]
        job.write_text(
            text.replace(agent.group(0), f"{indent}USER_AGENT='curl-yadgar-platform'", 1)
        )
    return copy


def test_an_agent_that_still_begins_with_curl_reddens_the_argv_gate(tmp_path):
    documents = adopter_render(chart_whose_agent_still_begins_with_curl(tmp_path))
    failures = []
    for name, script in matching_scripts(documents).items():
        failures += argv_failures(name, script, tmp_path / "argv")
    message = "\n".join(failures)
    assert failures, (
        "the agent was renamed to one that still begins with `curl` and the argv gate "
        "passed, so the gate is reading the chart's own literal rather than the rule "
        "the API server applies"
    )
    assert "BEGINS WITH 'curl'" in message, message


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

    post_script = post_install_probe_script(r2)

    census = {
        "preflight objects at R1": at_r1,
        "post-install probe objects at R1": len(post_install_probe_objects(defaults_render())),
        "probes at R2": len(probe_list(r2_script)),
        "denominator at R2": denominator(r2_script),
        "post-install probes at R2": len(probe_list(post_script)),
        "post-install denominator at R2": denominator(post_script),
        "post-install probe objects at R2": len(post_install_probe_objects(r2)),
        "probes at R3 (keda+mariadb true)": len(probe_list(r3_script)),
        "denominator at R3 (keda+mariadb true)": denominator(r3_script),
        "probe/toggle pairs at R2": EXPECTED_AGREEMENT_PAIRS_AT_R2,
        "default-false probes asserted at R2": len(EXPECTED_DEFAULT_FALSE_PROBES),
        "discriminating explicit-false overrides": EXPECTED_DISCRIMINATING_OVERRIDES,
        "honoured explicit trues": EXPECTED_HONOURED_EXPLICIT_TRUES,
        "refused explicit trues": EXPECTED_REFUSED_EXPLICIT_TRUES,
        "preflight Role rules at R3": len(of_kind(preflight_objects(r3), "Role")[0]["rules"]),
        "post-install probe Role rules at R2": len(
            of_kind(post_install_probe_objects(r2), "Role")[0]["rules"]
        ),
        "request bodies at R3": len(HEREDOC.findall(r3_script)),
        "post-install request bodies at R2": len(HEREDOC.findall(post_script)),
        "scripts carrying the matcher and its request": len(matching_scripts(r2)),
    }
    with capsys.disabled():
        print("\n  preflight census")
        for label, count in census.items():
            print(f"    {label}: {count}")

    assert census == {
        "preflight objects at R1": EXPECTED_PREFLIGHT_OBJECTS_AT_R1,
        "post-install probe objects at R1": EXPECTED_POST_INSTALL_OBJECTS_AT_R1,
        "probes at R2": EXPECTED_PROBES_AT_R2,
        "denominator at R2": EXPECTED_PROBES_AT_R2,
        "post-install probes at R2": EXPECTED_POST_INSTALL_PROBES_AT_R2,
        "post-install denominator at R2": EXPECTED_POST_INSTALL_PROBES_AT_R2,
        "post-install probe objects at R2": EXPECTED_POST_INSTALL_PROBE_OBJECTS_AT_R2,
        "probes at R3 (keda+mariadb true)": EXPECTED_PROBES_AT_R3_BOTH,
        "denominator at R3 (keda+mariadb true)": EXPECTED_PROBES_AT_R3_BOTH,
        "probe/toggle pairs at R2": 2,
        "default-false probes asserted at R2": 2,
        "discriminating explicit-false overrides": 2,
        "honoured explicit trues": 2,
        "refused explicit trues": 2,
        # cert-manager one, KEDA two (its own group and `apps`), mariadb one.
        "preflight Role rules at R3": 4,
        # Gateways in the upstream Gateway API group, and nothing else.
        "post-install probe Role rules at R2": 1,
        "request bodies at R3": EXPECTED_REQUEST_BODIES,
        "post-install request bodies at R2": EXPECTED_PROBE_REQUEST_BODIES,
        # Duplicated rather than shared, so a fix in one leaves the class alive in
        # the other. Every gate in the compact-response section iterates both.
        "scripts carrying the matcher and its request": EXPECTED_MATCHING_SCRIPTS,
    }


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
