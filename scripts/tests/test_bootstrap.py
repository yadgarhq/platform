"""THE BOOTSTRAP GATE: ADR-0750's four properties, each with its own constructed red case.

WHAT THIS CHART RENDERS HERE, AND WHY IT IS A JOB AT ALL. `valkey-password`,
`nats-auth`, `nats-auth-gateway` and the administrative bootstrap token have no
source outside the installation — nothing an adopter can be asked to transcribe,
because the value is created once and everything derives from it. ADR-0750 rules
that such a secret is minted by an IDEMPOTENT JOB THE CHART RENDERS, into a Secret
that neither Helm nor Argo tracks. A template cannot hold this: D54 measured
`lookup` returning empty under template-only rendering, which is how Argo renders,
so a generate-if-absent template regenerates the key on every sync.

THREE SECRETS ALWAYS, AND `iam-keys` AS AN OPT-IN FOURTH. This paragraph used to
read "THREE SECRETS, NOT FOUR" and to require that `iam-keys` appear nowhere in
this chart. THAT REQUIREMENT IS DISCHARGED, NOT ABANDONED. `iam-keys` is
DATA-BEARING — AES-256-GCM ciphertext plus an HMAC blind index — so a cluster whose
Secret is gone but whose database survived used to get an `iam` that starts HEALTHY
and cannot decrypt the rows it already has. ADR-0753 never refused the fourth
`create` outright; it ORDERED it behind a key-identity marker in the `iam` binary,
in a change of its own, first. `iam` v0.8.43 shipped that marker, so the fourth
`create` is legal now, and it sits behind `bootstrap.iamKeys.create`, which
DEFAULTS FALSE.

BOTH ARMS ARE GATED, AND NEITHER ONE ALONE WOULD BE A PROPERTY. With the toggle off
the Job mints THREE Secrets and the render never names `iam-keys`. With it on the
Job mints FOUR, and the fourth carries exactly the two key files `make secrets`
mints. A gate on the off arm alone would pass a chart whose toggle did nothing, and
a gate on the on arm alone would pass a chart that minted the key by default.

THE FOUR PROPERTIES, AND WHICH HALF OF EACH IS CONSTRUCTIBLE HERE. ADR-0750
requires four properties of such a Job, and this suite renders — it does not
install. So each gate below states the RENDER-TIME half it proves and names the
run-time half it does not:

  1. GENERATES ONLY WHEN ABSENT. Render-time half: the script POSTs and classifies
     HTTP 409 as success, never reading first; and the Role (property 4) withholds
     every verb that could overwrite, so the API server enforces it even if the
     script were wrong — `deploy/infra/bootstrap/rbac.yaml`'s own words, "this Job
     could not overwrite a live credential even if the script were wrong". Run-time
     half — a pre-created Secret survives a run byte for byte — is the bare-install
     proof's case 4, against a live cluster, and is NOT asserted here.
  2. THE CHART NEVER TEMPLATES THE SECRET. Render-time half, and it is the whole
     property: `helm template` emits hook resources as well as ordinary ones, so a
     Secret templated ANYWHERE in this chart would appear in the render this gate
     reads. Zero of them is therefore discriminating rather than vacuous. Run-time
     half — that Argo attaches no `argocd.argoproj.io/tracking-id` to a Secret the
     Job created — was measured on the live cluster on 2026-09-23 and belongs to
     the bare-install proof, not to a render.
  3. THE VALUE STAYS EXPORTABLE AND THE RUNBOOK SAYS SO. Asserted against this
     repository's own `README.md`, beside the install command, for every Secret
     either Job mints. The estate-wide `INSTALL.md` gate is a later step's; this
     one is the copy that lives with the chart that does the minting.
  4. THE ROLE GRANTS `create` AND NOTHING ELSE, AND THE WIRING CARRIES IT.
     ADR-0750's property 4 said `get` and `create`; ADR-0753 NARROWED it to
     `create` alone, because the Job never reads and `get` would only add the
     ability to read credentials it did not mint. Asserted over the RENDERED Role,
     by LENGTH as well as by content, so a verb added later turns it red — and
     asserted over the BINDING too, because a narrow Role nobody is bound to is
     not a narrowing. `rbac_failures` has the measurement: an earlier form counted
     cluster-scoped OBJECTS and three mutations passed it green, the worst being
     `roleRef` pointed at the built-in `ClusterRole/cluster-admin`, which renders
     no object at all for such a count to see.

TWO GATES BEYOND ADR-0750'S FOUR, each closing a defect a review REPRODUCED rather
than a property an ADR named:

  - THE GENERATOR'S FAILURE REACHES THE JOB'S EXIT STATUS (`generation_failures`).
    A credential built as `$( )` inside a request body cannot fail the run:
    command substitution discards the exit status, and the pipeline inside it
    reports only its last element. Measured with `base64` absent from the image —
    three Secrets created holding `""`, all reported "created", exit 0.
  - THE IMAGE IS PINNED BY DIGEST (`image_failures`). A tag is a moving pointer,
    and these two Jobs mint every credential the installation cannot obtain from
    anywhere else.

EVERY GATE ASSERTS THE COUNT IT EXAMINED, and the numbers are LITERALS. A count
derived from the render agrees with whatever the render happens to be and detects
nothing; the whole value of these is that somebody looked at the number and wrote
it down. A gate that renders a set, finds no violation among zero members and
reports a pass has proved nothing — which is why every zero here is an EQUALITY
with a red case of its own.

THE HOOK COUNT IS THIS STEP'S, NOT THE FINISHED LAYER'S, AND IT HAS NOW MOVED
TWICE. FOUR hook Jobs render today — THREE `pre-install` across three hook-weight
positions (the two RBAC triples sharing the lowest, the preflight Job alone above
them, and the two bootstrap Jobs sharing the highest) and ONE `post-install`, the
Envoy Gateway probe, across two positions of its own with its triple below it. The
gate that accepted `pre-install,pre-upgrade` and nothing else reddened on the
probe's PHASE before any number moved, exactly as the previous revision of this
paragraph said it would, and widening it is this step's deliberate change.

THE TWO PHASES ARE COUNTED SEPARATELY, AND THAT IS NOT TIDINESS. A `hook-weight`
ORDERS HOOKS WITHIN ONE PHASE and means nothing across two, so a single set of
positions over both phases would report a collision that does not exist — and would
have let the post-install triple sit ABOVE its own Job while a pre-install weight
covered for it.

WHICH GATES HERE ARE SCOPED TO THE BOOTSTRAP AND WHICH ARE CHART-WIDE, because the
chart now renders a second hook Job with a triple of its own and the distinction
decides what each gate proves. `bootstrap_render` narrows to the three templates
this suite is about, by the `# Source:` marker helm emits — the script, image,
minted-set and RBAC-wiring gates all read that, because "the ServiceAccount" means
nothing over a render carrying two. Three claims stay over the WHOLE render and
must not be narrowed: that no Secret is templated ANYWHERE in this chart (property
2), that the render carries no cluster-scoped RBAC at all, and the hook set with
its weight positions. `hook_failures` is the chart-wide one, and the preflight's own
gates live in `test_preflight.py`.

EVERY RENDER HERE PASSES `--api-versions cert-manager.io/v1`, for the reason
`test_ladder.py` states: this chart's own render check refuses a bare render of
any values file that turns the certificate half on, before a single object exists
to count. `test_render_checks.py` is where that refusal is the subject.

NO SKIPS (ADR-0650). `helm` absent is a failure, not a skip.

Run: python3 -m pytest scripts/tests/ -q
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from collections import Counter
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parents[2]
CHART = REPO / "chart"
ADOPTER_VALUES = REPO / "example" / "values.yaml"
README = REPO / "README.md"

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

# EVERY RENDER HERE NAMES A NAMESPACE, AND IT IS NOT `default`. The RoleBinding's
# subject carries `{{ .Release.Namespace }}`, and a binding whose subject names the
# wrong namespace grants the Role to NOBODY — the Jobs then run with an identity
# that holds no permission, and the failure is a 403 at run time rather than
# anything a render shows. Rendering into a named namespace is what lets
# `rbac_failures` compare the subject against something; rendering at helm's
# default would make a hardcoded `namespace: default` indistinguishable from the
# value following `.Release.Namespace`.
RELEASE_NAMESPACE = "yadgar"

# ── THE EXPECTED NUMBERS, AND THEY ARE LITERALS ──────────────────────────────

# The three machine-only credentials the Job mints at EVERY render, named rather
# than counted, because a count alone would not notice one name being swapped for
# another. `iam-keys` is NOT among them: it is minted only when
# `bootstrap.iamKeys.create` is on, and that toggle defaults FALSE.
MACHINE_ONLY_SECRETS = {"valkey-password", "nats-auth", "nats-auth-gateway"}

# The human-facing one (ADR-0517's third category), minted by its own Job so that
# its retrieval contract reads on its own rather than folded into the other Job's
# "never read by a person" framing. Its NAME is a value — the parent must be able
# to make it agree with `gateway.adminBootstrap.tokenSecret` — and this is the
# chart's shipped default.
ADMIN_TOKEN_SECRET = "admin-bootstrap-token"

EVERY_MINTED_SECRET = MACHINE_ONLY_SECRETS | {ADMIN_TOKEN_SECRET}

# The key whose generation ADR-0753 ORDERED BEHIND a change to the `iam` binary.
# That change shipped in `iam` v0.8.43, so the fourth `create` exists — behind
# `bootstrap.iamKeys.create`, off by default. The name is here so BOTH arms are
# asserted rather than merely true: absent at the default render, present when the
# toggle is on.
THE_DATA_BEARING_KEY = "iam-keys"

# The values path that turns it on, and the `--set` that renders the on arm.
IAM_KEYS_TOGGLE = "bootstrap.iamKeys.create"
IAM_KEYS_ON = ("--set", f"{IAM_KEYS_TOGGLE}=true")

# WHAT `make secrets` MINTS INTO `iam-keys`, AND IT IS THE WHOLE COMPARISON. This
# organisation creates the Secret by hand in `yadgarhq/deploy`'s `Makefile`, with
# `--from-file=encryption.key=` and `--from-file=blind-index.key=` and nothing
# else. A Job-minted `iam-keys` that carried a different key set would hand `iam` a
# mount the hand-minted path never produces, so a cluster bootstrapped by the chart
# and a cluster bootstrapped by hand would not be the same cluster. Two, and both
# names, because a count alone would not notice one name swapped for another and a
# name list alone would not notice a third key added.
MAKE_SECRETS_IAM_KEYS = {"encryption.key", "blind-index.key"}
EXPECTED_IAM_KEYS = 2

# THE FIELD THAT CARRIES THEM, WHICH IS PART OF THE COMPARISON RATHER THAN A STYLE
# CHOICE. `make secrets` uses `--from-file=`, so each file holds RAW BYTES — 32 of
# them, which is the only length `iam`'s `read_key` accepts. `data` is the field
# the API server base64-DECODES, so a 44-character base64 value lands as 32 raw
# bytes. `stringData` would store those 44 characters AS the file, and `iam` would
# refuse to start on a wrong-length key. A gate that read whichever map the body
# carried would pass that body and ship a key `iam` rejects.
IAM_KEYS_FIELD = "data"
THE_WRONG_FIELD = "stringData"

# THE BOOTSTRAP'S OWN TWO JOBS, and the one triple they share. Every gate below
# that reads a script, an image or the RBAC wiring is scoped to the three templates
# that render them — `bootstrap_render` — so this number is the bootstrap's and
# does not move when another template adds a Job.
EXPECTED_BOOTSTRAP_JOBS = 2

# THE WHOLE CHART'S HOOK SET, WHICH IS A DIFFERENT CLAIM AND A DIFFERENT NUMBER.
# `hook_failures` below is the one gate here that is deliberately chart-wide: a Job
# outside the hook set runs in the wrong phase whatever template rendered it, and a
# weight position colliding across templates is exactly the kind of thing a scoped
# gate would never see. FOUR Jobs across THREE triples.
#
# PRE-INSTALL, THREE JOBS AND THREE WEIGHT POSITIONS: `preflight`,
# `bootstrap-secrets` and `admin-bootstrap-token`. The two triples that serve them
# share the lowest position, `preflight` runs alone above them because the whole
# point of it is to refuse before anything else acts, and the two bootstrap Jobs
# share the highest because they mint disjoint Secret names and nothing orders one
# against the other.
#
# POST-INSTALL, ONE JOB AND TWO WEIGHT POSITIONS: `envoy-gateway-probe` with its
# own triple below it. It is ordered by PHASE rather than by weight — it runs once
# the release's objects, the GatewayClass among them, already exist — and a weight
# orders hooks only within their own phase, which is why the positions are counted
# per phase rather than over the union.
EXPECTED_HOOK_JOBS = 4
EXPECTED_PRE_INSTALL_HOOK_JOBS = 3
EXPECTED_POST_INSTALL_HOOK_JOBS = 1
EXPECTED_RBAC_OBJECTS = 9
EXPECTED_PRE_INSTALL_WEIGHT_POSITIONS = 3
EXPECTED_POST_INSTALL_WEIGHT_POSITIONS = 2

# The two phases this chart renders hooks in, and the only two it may render.
PRE_INSTALL = "pre-install,pre-upgrade"
POST_INSTALL = "post-install,post-upgrade"
EXPECTED_HOOK_JOBS_IN = {
    PRE_INSTALL: EXPECTED_PRE_INSTALL_HOOK_JOBS,
    POST_INSTALL: EXPECTED_POST_INSTALL_HOOK_JOBS,
}
EXPECTED_WEIGHT_POSITIONS_IN = {
    PRE_INSTALL: EXPECTED_PRE_INSTALL_WEIGHT_POSITIONS,
    POST_INSTALL: EXPECTED_POST_INSTALL_WEIGHT_POSITIONS,
}

# ADR-0753's narrowing, as the exact list the Role must carry.
THE_ONLY_VERB = ["create"]

# THE WIRING BETWEEN THE THREE, counted as literals because a narrow Role is worth
# nothing when the binding points somewhere else. One ServiceAccount, one
# RoleBinding, and one subject on it — see `rbac_failures` for what each of those
# numbers buys.
EXPECTED_SERVICE_ACCOUNTS = 1
EXPECTED_ROLE_BINDINGS = 1
EXPECTED_BINDING_SUBJECTS = 1

# The one group a namespaced RoleBinding may reference.
RBAC_API_GROUP = "rbac.authorization.k8s.io"

# ADR-0750 property 3: one export command per minted Secret, beside the install
# command. Four, because both Jobs' output has to be exportable.
EXPECTED_EXPORT_COMMANDS = len(EVERY_MINTED_SECRET)


def helm(*arguments: str) -> subprocess.CompletedProcess[str]:
    binary = shutil.which("helm")
    # NOT A SKIP, and ADR-0650 is why. Same wording as `test_ladder.py`'s and
    # `test_render_checks.py`'s, which made the same decision for the same reason.
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


def render_text(chart: Path, *arguments: str) -> str:
    """R2 by default: the adopter values file, every `create` true.

    HOOKS INCLUDED. `helm template` emits hook resources alongside ordinary ones
    and every gate below depends on that: the two Jobs and their RBAC are hooks, so
    a render that dropped them would leave every count at zero.
    """
    result = helm(
        "template",
        "platform",
        str(chart),
        "--namespace",
        RELEASE_NAMESPACE,
        *API_VERSIONS,
        *arguments,
    )
    assert result.returncode == 0, result.stderr
    return result.stdout


def render(chart: Path, *arguments: str) -> list[dict]:
    return documents_of(render_text(chart, *arguments))


def adopter_render(chart: Path = CHART, *arguments: str) -> list[dict]:
    return render(chart, "-f", str(ADOPTER_VALUES), *arguments)


def adopter_render_text(chart: Path = CHART, *arguments: str) -> str:
    return render_text(chart, "-f", str(ADOPTER_VALUES), *arguments)


# The three templates this suite is about. Named rather than derived, so a fourth
# template added to the bootstrap has to be listed here before these gates see it —
# which is the moment somebody has to decide whether the counts above still hold.
BOOTSTRAP_TEMPLATES = {
    "platform/templates/admin-bootstrap-token.yaml",
    "platform/templates/bootstrap-rbac.yaml",
    "platform/templates/bootstrap-secrets.yaml",
}

SOURCE = re.compile(r"^# Source: (?P<source>\S+)$", re.MULTILINE)


def documents_by_source(stdout: str) -> list[tuple[str, dict]]:
    """Every rendered document paired with the template that produced it. PURE."""
    found = []
    for chunk in stdout.split("\n---\n"):
        source = SOURCE.search(chunk)
        for document in yaml.safe_load_all(chunk):
            if isinstance(document, dict) and document.get("apiVersion"):
                found.append((source.group("source") if source else "", document))
    return found


def bootstrap_render(chart: Path = CHART, *arguments: str) -> list[dict]:
    """R2, narrowed to the objects the three bootstrap templates render.

    SCOPED BY THE TEMPLATE THAT RENDERED IT, not by a name prefix and not by the
    hook annotation. The chart now carries a SECOND hook Job with its own triple —
    the preflight, whose Role is a different verb set on different kinds — so a
    gate reading "the ServiceAccount" off the whole render would find two and
    compare neither against anything.

    THE SCOPING IS NARROWER THAN THE GATES IT FEEDS, DELIBERATELY, AND TWO CLAIMS
    STAY CHART-WIDE BECAUSE NARROWING THEM WOULD NARROW WHAT THEY PROVE: that no
    Secret is templated ANYWHERE in this chart (ADR-0750 property 2), and that the
    render carries no cluster-scoped RBAC at all. Both read the whole render below.
    """
    return [
        document
        for source, document in documents_by_source(adopter_render_text(chart, *arguments))
        if source in BOOTSTRAP_TEMPLATES
    ]


def of_kind(documents: list[dict], kind: str) -> list[dict]:
    return [document for document in documents if document.get("kind") == kind]


def annotations_of(document: dict) -> dict:
    return (document.get("metadata") or {}).get("annotations") or {}


def name_of(document: dict) -> str:
    return str((document.get("metadata") or {}).get("name"))


def bootstrap_objects(documents: list[dict]) -> list[dict]:
    """Everything the bootstrap toggle renders, by the hook annotation that marks it.

    READ OFF THE HOOK ANNOTATION rather than off a name prefix, because the
    annotation is the property under test: an object that lost it is no longer a
    hook and must fall out of these counts, which is exactly the red case
    `test_a_job_that_is_not_a_hook_reddens_the_hook_count` constructs.
    """
    return [document for document in documents if "helm.sh/hook" in annotations_of(document)]


# ── THE JOB SCRIPTS, READ OFF THE RENDER ─────────────────────────────────────

# The `case` arm for each HTTP status the POST can answer with.
ARM = re.compile(r"^\s*(?P<code>201|409|\*)\)(?P<body>.*?);;\s*$", re.MULTILINE | re.DOTALL)


def job_scripts(documents: list[dict]) -> dict[str, str]:
    """Job name -> the shell script its single container runs. PURE."""
    scripts = {}
    for job in of_kind(documents, "Job"):
        containers = (((job.get("spec") or {}).get("template") or {}).get("spec") or {}).get(
            "containers"
        ) or []
        assert len(containers) == 1, (
            f"{name_of(job)} renders {len(containers)} containers; this gate reads "
            f"the script off the one container the precedent carries"
        )
        scripts[name_of(job)] = "\n".join(containers[0].get("args") or [])
    return scripts


def minted_by(script: str) -> list[str]:
    """Every Secret name this script CREATES, in order, read off the request body. PURE.

    NOT OFF THE `create <name>` ARGUMENT, and that argument is where this used to
    read. `$1` reaches the Job's LOG LINES and nothing else — `echo "$1: created"`,
    `"$1: already exists, left untouched"`, `"$1: refused with HTTP $code"` and the
    credential-length message — while the object the API server actually makes
    carries its name INDEPENDENTLY, inside the heredoc, as
    `"metadata":{"name":"..."}`. So a body renamed while the `create` line stayed
    put left every gate below answering a question about a log label.

    MEASURED RATHER THAN ARGUED, on d14753e: renaming the admin token's body name
    to `admin-bootstrap-token-typo` and touching neither the `mint` line nor the
    `create` line left THE WHOLE SUITE AT 107 PASSED, while
    `test_the_jobs_mint_exactly_the_three_secrets_and_the_token` reported
    `admin-bootstrap-token`. The install would hang: the gateway mounts a Secret
    nothing creates.

    THE MATCHER IS `test_shared_infrastructure.py`'s, SHARED RATHER THAN RESTATED,
    which is ADR-0679. That file hardened this exact question against this exact
    mutation one round ago; a second regex here would be the same matcher
    re-derived a third time in three rounds. Imported inside the function,
    following this file's existing precedent for `declared_checks`, so the suites
    stay free of a module-level dependency on each other.
    """
    from test_shared_infrastructure import minted_secret_names_in

    return minted_secret_names_in(script)


# ── PROPERTY 1 — IT GENERATES ONLY WHEN THE SECRET IS ABSENT ─────────────────


def idempotence_failures(documents: list[dict]) -> list[str]:
    """Every way the rendered scripts stop encoding ADR-0750 property 1. PURE.

    THE RENDER-TIME HALF ONLY, and the docstring at the top of this file says which
    half that is. What is checkable without a cluster is that the script POSTs and
    CLASSIFIES the answer: 201 is a first run, 409 is every run after it and is
    explicitly left untouched, and ANY OTHER CODE STOPS THE JOB. That last arm is
    as load-bearing as the 409 one — a 403 from a mis-bound Role read as "it
    already exists" reports a healthy bootstrap while every consumer waits on a
    Secret nobody created.
    """
    failures = []
    scripts = job_scripts(documents)
    if len(scripts) != EXPECTED_BOOTSTRAP_JOBS:
        failures.append(
            f"expected {EXPECTED_BOOTSTRAP_JOBS} Jobs carrying a script, found "
            f"{len(scripts)}: {sorted(scripts)}"
        )
    for job, script in sorted(scripts.items()):
        arms = {match.group("code"): match.group("body") for match in ARM.finditer(script)}
        if set(arms) != {"201", "409", "*"}:
            failures.append(
                f"{job}: expected the POST's answer classified into 3 arms "
                f"201, 409 and *, found {len(arms)}: {sorted(arms)}"
            )
            continue
        if "left untouched" not in arms["409"] or "exit 1" in arms["409"]:
            failures.append(
                f"{job}: HTTP 409 is not treated as success — a re-run would fail "
                f"on a Secret that already exists, which is the opposite of "
                f"ADR-0750 property 1. The arm reads:{arms['409']}"
            )
        if "exit 1" not in arms["*"]:
            failures.append(
                f"{job}: an unexpected HTTP status does not stop the Job, so a 403 "
                f"from a mis-bound Role would report a healthy bootstrap. The arm "
                f"reads:{arms['*']}"
            )
    return failures


def test_the_jobs_classify_409_as_success_and_anything_else_as_failure():
    """Property 1's render-time half, over both Jobs."""
    failures = idempotence_failures(bootstrap_render())
    assert failures == [], "\n".join(failures)


def chart_with_409_treated_as_a_failure(destination: Path) -> Path:
    """Property 1's red case: the 409 arm deleted, so a second run fails.

    An edit somebody could actually make while "tidying" the script, and the whole
    idempotence claim goes with it. The `*)` arm then catches 409 and exits 1.
    """
    copy = destination / "chart"
    shutil.copytree(CHART, copy)
    template = copy / "templates" / "bootstrap-secrets.yaml"
    text = template.read_text()
    arm = '                  409) echo "$1: already exists, left untouched" ;;\n'
    assert arm in text, "the 409 arm moved; this red case is now testing nothing"
    template.write_text(text.replace(arm, ""))
    return copy


def test_deleting_the_409_arm_reddens_the_idempotence_gate(tmp_path):
    failures = idempotence_failures(
        bootstrap_render(chart_with_409_treated_as_a_failure(tmp_path))
    )
    message = "\n".join(failures)
    assert failures, "409 stopped being success and the idempotence gate passed"
    assert "found 2: ['*', '201']" in message, message


# ── THE GENERATOR'S FAILURE HAS TO REACH THE JOB'S EXIT STATUS ───────────────

# ONE LENGTH FOR TWO WIDTHS, AND THAT IS WHY THE CHECK STAYS SINGLE. 33 random
# bytes as base64 is 44 characters with no `=` padding, which is why 33 was chosen
# for a password. 32 random bytes as base64 is 44 characters with one `=` of
# padding, and 32 is the only length `iam` accepts for a key file. So both widths
# check against the same number, and the script needs ONE length check rather than
# one per width. An EXACT length rather than a minimum, as before.
EXPECTED_CREDENTIAL_LENGTH = 44

# Four request bodies across the two scripts at the DEFAULT render, one per minted
# Secret. Asserted, because a body regex that silently matched none would make the
# check below vacuous — which is the defect this whole gate exists to stop
# repeating. The on arm of the toggle adds a fifth, and `generation_failures` takes
# the number it expects as an argument rather than reading this constant, so the
# two renders are counted against their own numbers instead of one of them being
# excused.
EXPECTED_REQUEST_BODIES = len(EVERY_MINTED_SECRET)
EXPECTED_REQUEST_BODIES_WITH_IAM_KEYS = EXPECTED_REQUEST_BODIES + 1

# The JSON body of each POST, read between its heredoc delimiters.
BODY = re.compile(r"<<JSON\s*\n(?P<body>.*?)\n\s*JSON\s*$", re.MULTILINE | re.DOTALL)

# `mint <name> <bytes>` — the generator, called as a STATEMENT so its exit status is
# the script's. At least one per `create <name>`, and in the same order.
#
# THE WIDTH IS AN ARGUMENT NOW, and this matcher had to widen with it. The script
# mints two kinds of thing: a 33-byte password and a 32-byte key file, and `iam`
# refuses any key length but 32. A matcher still anchored on `mint <name>$` would
# have matched NOTHING after that change and reported every Secret ungenerated —
# loudly, which is why the widening is safe, but it is stated here so the next
# reader does not narrow it back.
GENERATES = re.compile(
    r"^\s*mint\s+(?P<name>[a-z0-9][a-z0-9.-]*)\s+(?P<width>\d+)\s*$", re.MULTILINE
)

# Every shell variable a request body interpolates. The count of DISTINCT ones is
# how many generated values that body carries, which is what the `mint` statements
# for its Secret have to match — see `generation_failures`.
INTERPOLATED = re.compile(r"\$(?P<variable>[A-Za-z_][A-Za-z0-9_]*)")

# The length check on what the generator produced, and the arm it takes when the
# length is wrong.
LENGTH_CHECK = re.compile(
    r'\[\s*"\$\{#(?P<variable>[A-Za-z_][A-Za-z0-9_]*)\}"\s*-ne\s*(?P<length>\d+)\s*\]'
    r"(?P<arm>.*?)\bfi\b",
    re.DOTALL,
)


def generation_failures(
    documents: list[dict], expected_bodies: int = EXPECTED_REQUEST_BODIES
) -> list[str]:
    """Every way a degraded image could mint an EMPTY credential and report success. PURE.

    THE DEFECT THIS CLOSES, MEASURED RATHER THAN SUPPOSED. With `base64` absent
    from the image's PATH, the earlier shape — `"password":"$(password)"` inside
    the heredoc — created three Secrets holding `""`, reported all three "created",
    and exited 0. `set -e` cannot see it: COMMAND SUBSTITUTION DISCARDS the
    function's exit status, so the status never becomes the `create` command's. The
    pipeline `head | base64 | tr` masks it a second time, because a pipeline
    reports only its LAST element's status.

    AND IT WOULD BE STICKY, which is what makes it worth a gate rather than a
    comment. The Role grants `create` alone and a 409 is success, so every run
    after the first reports "already exists, left untouched". Re-running never
    repairs it. Recovery needs `kubectl delete secret` first, and nobody reaches
    for that against a green Job.

    SO THE RENDER-TIME PROPERTY IS: the value is generated into a variable, its
    LENGTH is checked at the top level of the script where `exit` ends the run, and
    no request body carries a `$( )` at all. Each of those three is checkable
    without a cluster, and the red case beside this one reverts the third.

    It does not fire as shipped — `curlimages/curl` is Alpine and busybox provides
    `base64`. `bootstrap.image` is a value, which is the exposure.

    ONE SECRET MAY CARRY MORE THAN ONE GENERATED VALUE, WHICH IS WHY THE ORDERING
    COMPARISON DEDUPLICATES. `iam-keys` holds TWO key files and so takes two `mint`
    statements against one `create`, and a strict `generated == created` would have
    called that a disagreement. Deduplicating IN ORDER keeps everything that
    comparison bought — a `mint` label renamed away from the body it feeds, a
    `mint` dropped entirely, two Secrets generated in the wrong order — and gives up
    only multiplicity, which the check below replaces with something stronger:
    EVERY VARIABLE A BODY INTERPOLATES IS COUNTED AGAINST THE `mint` STATEMENTS FOR
    THAT SECRET. Drop one of the two `iam-keys` draws and the body still names two
    variables while the script generates one, so the count disagrees and this list
    reports it.
    """
    failures = []
    scripts = job_scripts(documents)
    bodies = 0

    for job, script in sorted(scripts.items()):
        generated = [match.group("name") for match in GENERATES.finditer(script)]
        created = minted_by(script)
        if list(dict.fromkeys(generated)) != created:
            failures.append(
                f"{job}: expected at least one `mint <name> <bytes>` statement per "
                f"POSTed Secret, in the same order — the script creates {created} "
                f"and generates {generated}. A credential built anywhere but a "
                f"statement cannot fail the run. `created` is read off the REQUEST "
                f"BODY, so a `mint` label that no longer names the Secret its body "
                f"makes is a disagreement this list reports too"
            )

        checks = list(LENGTH_CHECK.finditer(script))
        if len(checks) != 1:
            failures.append(
                f"{job}: expected 1 length check on the generated credential, "
                f"found {len(checks)}. Without it an empty value is POSTed, "
                f"answered 201, and reported as created"
            )
        else:
            check = checks[0]
            if int(check.group("length")) != EXPECTED_CREDENTIAL_LENGTH:
                failures.append(
                    f"{job}: expected the generated credential checked against "
                    f"{EXPECTED_CREDENTIAL_LENGTH} characters, found "
                    f"{check.group('length')}. 33 random bytes as base64 is "
                    f"{EXPECTED_CREDENTIAL_LENGTH} characters with no padding, and "
                    f"32 is {EXPECTED_CREDENTIAL_LENGTH} characters with one `=` — "
                    f"both widths this script mints check against the same number"
                )
            if "exit 1" not in check.group("arm"):
                failures.append(
                    f"{job}: the length check does not stop the Job when it fails. "
                    f"The arm reads:{check.group('arm')}"
                )

        draws = Counter(generated)
        for name, match in zip(created, BODY.finditer(script)):
            bodies += 1
            body = match.group("body")
            variables = {
                found.group("variable") for found in INTERPOLATED.finditer(body)
            }
            if len(variables) != draws.get(name, 0):
                failures.append(
                    f"{job}: {name}'s request body interpolates "
                    f"{len(variables)} generated value(s), {sorted(variables)}, and "
                    f"the script mints {draws.get(name, 0)} for it. Every value a "
                    f"body carries has to come from a `mint` statement whose failure "
                    f"stops the run — a body naming one the script never generated "
                    f"POSTs an empty string under `set -u`'s nose or, worse, a value "
                    f"left over from the Secret before it"
                )
            if "$(" in body:
                failures.append(
                    f"{job}: a request body interpolates a command substitution: "
                    f"{' '.join(body.split())}. A generator called there CANNOT "
                    f"fail the run — command substitution discards its exit status "
                    f"so `set -e` never sees it, and a pipeline inside it reports "
                    f"only its last element. A degraded image mints an EMPTY "
                    f"credential, the POST answers 201, and no later run repairs it "
                    f"because `create` is the only verb and a 409 is success"
                )

    if bodies != expected_bodies:
        failures.append(
            f"expected {expected_bodies} request bodies across the two "
            f"scripts, found {bodies}. A body this gate did not read is a body it "
            f"did not check, and a zero here would be vacuous rather than a property"
        )
    return failures


def test_an_empty_credential_stops_the_job_instead_of_being_posted():
    """The generator's failure reaches the exit status, on both Jobs."""
    failures = generation_failures(bootstrap_render())
    assert failures == [], "\n".join(failures)


def test_the_data_bearing_keys_are_generated_the_same_way_the_passwords_are():
    """The same gate over the on arm, where the fifth body and its two draws live.

    THE ON ARM NEEDS ITS OWN RUN BECAUSE THE DEFAULT RENDER CANNOT SEE IT. The
    `iam-keys` block is inside `{{- if .Values.bootstrap.iamKeys.create }}`, so at
    the default render it is not in the script at all and every clause above reads
    three bodies and three draws. This call is what puts the fourth body, its two
    `mint` statements and its two interpolated variables under the same checks.
    """
    failures = generation_failures(
        bootstrap_render(CHART, *IAM_KEYS_ON),
        expected_bodies=EXPECTED_REQUEST_BODIES_WITH_IAM_KEYS,
    )
    assert failures == [], "\n".join(failures)


def chart_with_one_iam_key_draw_dropped(destination: Path) -> Path:
    """One of the two `mint iam-keys 32` statements deleted, its body left alone.

    THE MUTATION THE DEDUPLICATED ORDERING COMPARISON CANNOT SEE, which is why the
    per-body variable count exists beside it. Delete one draw and the generated
    list still deduplicates to the created list, so the ordering clause stays
    quiet — while the body goes on naming a variable nothing assigns.
    """
    copy = destination / "chart"
    shutil.copytree(CHART, copy)
    template = copy / "templates" / "bootstrap-secrets.yaml"
    text = template.read_text()
    draw = '              mint iam-keys 32\n              blind_index_key="$value"\n'
    assert draw in text, "the blind-index draw moved; this red case is now testing nothing"
    template.write_text(text.replace(draw, ""))
    return copy


def test_dropping_one_iam_key_draw_reddens_the_generation_gate(tmp_path):
    """The per-body variable count's red case, and the ordering clause stays silent."""
    failures = generation_failures(
        bootstrap_render(chart_with_one_iam_key_draw_dropped(tmp_path), *IAM_KEYS_ON),
        expected_bodies=EXPECTED_REQUEST_BODIES_WITH_IAM_KEYS,
    )
    message = "\n".join(failures)
    assert failures, "a generated value lost its `mint` statement and the gate passed"
    assert "iam-keys's request body interpolates 2 generated value(s)" in message, message
    assert "the script mints 1 for it" in message, message
    assert "expected at least one `mint" not in message, (
        f"the ordering clause fired, so this case is not witnessing the per-body "
        f"count it was built for: {message}"
    )


def chart_that_generates_inside_the_request_body(destination: Path) -> Path:
    """The red case, and it is the shape that shipped: generate inside the heredoc.

    One body reverted, so the gate has to name the body rather than notice a count.
    """
    copy = destination / "chart"
    shutil.copytree(CHART, copy)
    template = copy / "templates" / "bootstrap-secrets.yaml"
    text = template.read_text()
    interpolation = '"stringData":{"password":"$value"}}'
    assert interpolation in text, "the body moved; this red case is now testing nothing"
    template.write_text(
        text.replace(
            interpolation,
            '"stringData":{"password":"$(head -c 33 /dev/urandom | base64 | tr -d \'\\n\')"}}',
            1,
        )
    )
    return copy


def test_generating_inside_the_request_body_reddens_the_generation_gate(tmp_path):
    failures = generation_failures(
        bootstrap_render(chart_that_generates_inside_the_request_body(tmp_path))
    )
    message = "\n".join(failures)
    assert failures, (
        "a credential was generated inside the request body, where its failure "
        "cannot reach the Job's exit status, and the gate passed"
    )
    assert "bootstrap-secrets: a request body interpolates a command substitution" in message, (
        message
    )


# ── THE IMAGE THAT MINTS THE ESTATE'S ROOT CREDENTIALS IS PINNED EXACTLY ─────

# A digest reference: `<repository>@sha256:<64 hex>`. A tag is a MOVING pointer, so
# a tag here leaves the code that mints the three machine-only credentials and the
# administrative bootstrap token as whatever the registry last published under that
# name. Both Jobs are checked, and the number is a literal.
DIGEST_PINNED = re.compile(r"^[^\s@]+@sha256:[0-9a-f]{64}$")

# One container per Job, so one image per Job. Counted rather than iterated,
# because two Jobs rendering no container at all would otherwise find no violation
# among zero images and report a pass.
EXPECTED_BOOTSTRAP_IMAGES = EXPECTED_BOOTSTRAP_JOBS


def image_failures(documents: list[dict]) -> list[str]:
    """Every Job whose image is not pinned by digest. PURE.

    THE HIGHEST-VALUE IMAGE IN THE ESTATE TO HOLD EXACT, which is the whole of the
    argument: these two Jobs mint every credential that has no source outside the
    installation. `bootstrap.image` stays a VALUE so a mirrored registry needs no
    fork — the pin is what the shipped default is, not what the key can hold.
    """
    failures = []
    jobs = of_kind(documents, "Job")
    if len(jobs) != EXPECTED_BOOTSTRAP_JOBS:
        failures.append(
            f"expected {EXPECTED_BOOTSTRAP_JOBS} Jobs to check an image on, found "
            f"{len(jobs)}: {sorted(name_of(job) for job in jobs)}"
        )
    images = 0
    for job in sorted(jobs, key=name_of):
        containers = (((job.get("spec") or {}).get("template") or {}).get("spec") or {}).get(
            "containers"
        ) or []
        for container in containers:
            images += 1
            image = str(container.get("image"))
            if not DIGEST_PINNED.match(image):
                failures.append(
                    f"{name_of(job)}: image {image!r} is not pinned by digest. A tag "
                    f"is a moving pointer, and this Job mints the credentials "
                    f"nothing outside the installation can supply — pin "
                    f"`<repository>@sha256:<digest>`, and keep the tag beside it as "
                    f"a comment"
                )
    if images != EXPECTED_BOOTSTRAP_IMAGES:
        failures.append(
            f"expected {EXPECTED_BOOTSTRAP_IMAGES} images across the bootstrap "
            f"Jobs, found {images}. An image this gate did not read is an image it "
            f"did not check, and a zero here would be vacuous rather than a property"
        )
    return failures


def test_both_bootstrap_jobs_are_pinned_by_digest():
    failures = image_failures(bootstrap_render())
    assert failures == [], "\n".join(failures)


def chart_pinned_by_tag(destination: Path) -> Path:
    """The red case: the digest replaced by the tag that names the same bytes today."""
    copy = destination / "chart"
    shutil.copytree(CHART, copy)
    values = copy / "values.yaml"
    text = values.read_text()
    pinned = "  image: curlimages/curl@sha256:"
    assert pinned in text, "the image pin moved; this red case is now testing nothing"
    line = next(line for line in text.splitlines() if line.startswith(pinned))
    values.write_text(text.replace(line, "  image: curlimages/curl:8.16.0"))
    return copy


def test_pinning_the_image_by_tag_reddens_the_digest_gate(tmp_path):
    failures = image_failures(bootstrap_render(chart_pinned_by_tag(tmp_path)))
    message = "\n".join(failures)
    assert failures, "the image went back to a moving tag and the digest gate passed"
    assert "image 'curlimages/curl:8.16.0' is not pinned by digest" in message, message


# ── PROPERTY 2 — THE CHART NEVER TEMPLATES THE SECRET ────────────────────────


def untracked_secret_failures(documents: list[dict]) -> list[str]:
    """Every way a minted Secret leaks into the render. PURE.

    WHY ZERO IS DISCRIMINATING HERE. `helm template` emits hooks, so this render
    carries every object this chart produces in either phase. A Secret templated
    anywhere — ordinary resource or hook — would land in Helm's release manifest
    and in Argo's tracked set, and then an uninstall or a prune would take the
    estate's credentials with it. That is the failure ADR-0750 property 2 exists
    to prevent, and its render-time form is exactly this count.
    """
    failures = []
    if not documents:
        failures.append(
            "the render produced no object at all, so a zero Secret count here "
            "would be vacuous rather than a property"
        )
    secrets = of_kind(documents, "Secret")
    if secrets:
        failures.append(
            f"expected 0 Secret objects in the render, found {len(secrets)}: "
            f"{sorted(name_of(secret) for secret in secrets)}. A templated Secret "
            f"is in Helm's release manifest and in Argo's tracked set, so an "
            f"uninstall or a prune deletes the credential (ADR-0750 property 2)"
        )
    return failures


def test_the_render_carries_no_secret_object():
    """Property 2: every minted Secret is POSTed by a Job, never templated."""
    failures = untracked_secret_failures(adopter_render())
    assert failures == [], "\n".join(failures)


def chart_that_templates_a_secret(destination: Path) -> Path:
    """Property 2's red case, and it is the plan's own: template one and see it listed."""
    copy = destination / "chart"
    shutil.copytree(CHART, copy)
    (copy / "templates" / "a-templated-secret.yaml").write_text(
        "{{- if .Values.bootstrap.create }}\n"
        "apiVersion: v1\n"
        "kind: Secret\n"
        "metadata:\n"
        "  name: valkey-password\n"
        "type: Opaque\n"
        "stringData:\n"
        "  password: not-a-secret-this-is-a-red-case\n"
        "{{- end }}\n"
    )
    return copy


def test_templating_a_secret_reddens_the_untracked_gate(tmp_path):
    failures = untracked_secret_failures(adopter_render(chart_that_templates_a_secret(tmp_path)))
    message = "\n".join(failures)
    assert failures, "a Secret was templated into the release manifest and the gate passed"
    assert "expected 0 Secret objects in the render, found 1" in message, message
    assert "valkey-password" in message, message


# ── PROPERTY 3 — THE VALUE STAYS EXPORTABLE AND THE RUNBOOK SAYS SO ──────────

INSTALL_COMMAND = "helm install"


def export_command_failures(readme: str) -> list[str]:
    """Every minted Secret whose export command is missing from the install section. PURE.

    SCOPED TO THE SECTION THE INSTALL COMMAND IS IN, because ADR-0750 property 3
    says the export command appears NEXT TO the install command rather than
    somewhere in the document. A command an operator meets three sections after
    they have finished installing is the paragraph asking for care that the ADR's
    own consequences say is worth less than a gate.
    """
    failures = []
    sections = re.split(r"^## ", readme, flags=re.MULTILINE)
    holding = [section for section in sections if INSTALL_COMMAND in section]
    if len(holding) != 1:
        failures.append(
            f"expected exactly 1 section of README.md to carry `{INSTALL_COMMAND}`, "
            f"found {len(holding)}"
        )
        return failures
    missing = sorted(
        secret
        for secret in EVERY_MINTED_SECRET
        if f"get secret {secret} -o yaml" not in holding[0]
    )
    found = EXPECTED_EXPORT_COMMANDS - len(missing)
    if missing:
        failures.append(
            f"expected {EXPECTED_EXPORT_COMMANDS} export commands beside the "
            f"install command, found {found}: missing {missing}. ADR-0750 "
            f"property 3 — a generated credential nobody can export is a "
            f"credential that is lost with the cluster"
        )
    return failures


def test_the_readme_states_an_export_command_for_every_minted_secret():
    """Property 3, against the runbook that ships with the chart that mints them."""
    failures = export_command_failures(README.read_text())
    assert failures == [], "\n".join(failures)


def test_dropping_an_export_command_reddens_the_runbook_gate():
    """Property 3's red case: the gate names the number and the Secret it lost."""
    without = README.read_text().replace(
        f"get secret {ADMIN_TOKEN_SECRET} -o yaml", "get pods"
    )
    failures = export_command_failures(without)
    message = "\n".join(failures)
    assert failures, "an export command was dropped from the runbook and the gate passed"
    assert "expected 4 export commands beside the install command, found 3" in message, message
    assert ADMIN_TOKEN_SECRET in message, message


def toggled_export_failures(readme: str) -> list[str]:
    """Whether the runbook exports the key the toggle mints. PURE.

    A SEPARATE GATE BECAUSE IT IS A SEPARATE CLAIM, and folding it into
    `EVERY_MINTED_SECRET` would have been wrong in the other direction: that set is
    what the Job mints at the DEFAULT render, and the minted-set census compares
    against it. `iam-keys` is minted only when `bootstrap.iamKeys.create` is on, and
    it is the one Secret here whose loss destroys data rather than costing a
    rotation — so the runbook command for it is the one that matters most, and a
    runbook line nothing asserted is a runbook line that rots.
    """
    sections = re.split(r"^## ", readme, flags=re.MULTILINE)
    holding = [section for section in sections if INSTALL_COMMAND in section]
    if len(holding) != 1:
        return [
            f"expected exactly 1 section of README.md to carry `{INSTALL_COMMAND}`, "
            f"found {len(holding)}"
        ]
    if f"get secret {THE_DATA_BEARING_KEY} -o yaml" in holding[0]:
        return []
    return [
        f"the install section states no export command for {THE_DATA_BEARING_KEY}. "
        f"It is minted only when {IAM_KEYS_TOGGLE} is on, and it is the one Secret "
        f"whose loss destroys data — a database that outlives it holds rows nothing "
        f"can decrypt"
    ]


def test_the_readme_states_an_export_command_for_the_toggled_key():
    failures = toggled_export_failures(README.read_text())
    assert failures == [], "\n".join(failures)


def test_dropping_the_toggled_export_command_reddens_its_gate():
    without = README.read_text().replace(
        f"get secret {THE_DATA_BEARING_KEY} -o yaml", "get pods"
    )
    failures = toggled_export_failures(without)
    message = "\n".join(failures)
    assert failures, "the data-bearing key's export command was dropped and the gate passed"
    assert f"no export command for {THE_DATA_BEARING_KEY}" in message, message


# ── PROPERTY 4 — THE ROLE GRANTS `create` AND NOTHING ELSE ───────────────────


def rbac_failures(documents: list[dict], whole: list[dict]) -> list[str]:
    """Every way the rendered RBAC widens past ADR-0753's narrowing. PURE.

    TWO ARGUMENTS, AND THE SPLIT IS THE POINT. `documents` is the BOOTSTRAP's own
    objects — the chart now renders a second hook Job with its own triple, and a
    gate reading "the ServiceAccount" off the whole render would find two and
    compare neither against anything. `whole` is the entire render, because the
    cluster-scoped zero below is a claim about the CHART and not about these three
    templates: a ClusterRole rendered by any other template must still redden
    something here.

    BY LENGTH AS WELL AS BY CONTENT, which the plan states as the register row's
    own terms: a verb ADDED later has to turn this red, and an equality on a sorted
    list would do that while a subset check would not.

    AND THE WIRING, BECAUSE A NARROW ROLE NOBODY IS BOUND TO IS NOT A NARROWING.
    An earlier form of this gate counted cluster-scoped OBJECTS and stopped there,
    and three mutations passed it green: pointing `roleRef` at the built-in
    `ClusterRole/cluster-admin` (which renders NO ClusterRole object, so the zero
    stayed zero while the bootstrap identity became cluster-admin), naming a
    different ServiceAccount in `subjects`, and setting both Jobs'
    `serviceAccountName` to `default`. So the four terms are asserted AGAINST EACH
    OTHER, off the render, never against a literal also written into the template:

      - `roleRef` names `Role` in `rbac.authorization.k8s.io`, and its `name` is
        the name of the Role this render produced.
      - the binding carries exactly one subject, and it is the ServiceAccount this
        render produced, in the namespace this render was made for. A subject in
        the wrong namespace grants the Role to nobody.
      - every Job's `serviceAccountName` is that same ServiceAccount. A Job left on
        `default` runs as an identity this Role was never bound to.

    The cluster-scoped zero is kept, because it is a different claim —
    `resourceNames` cannot scope a `create`, the authorizer runs before the request
    body is decoded, so the Role being NAMESPACED is the only thing that bounds
    this identity. It is necessary and it was never sufficient.
    """
    failures = []

    cluster_scoped = of_kind(whole, "ClusterRole") + of_kind(whole, "ClusterRoleBinding")
    if cluster_scoped:
        failures.append(
            f"expected 0 cluster-scoped RBAC objects, found {len(cluster_scoped)}: "
            f"{sorted(name_of(document) for document in cluster_scoped)}. "
            f"`resourceNames` cannot scope a `create`, so the Role being NAMESPACED "
            f"is the only thing that bounds this identity"
        )

    # THE THREE RENDERED NAMES, EACH READ ONCE AND THEN COMPARED WITH THE OTHERS.
    # `None` where the render did not produce exactly one, so a missing object is
    # reported as the comparison it made impossible rather than skipping the
    # comparisons below in silence.
    accounts = of_kind(documents, "ServiceAccount")
    if len(accounts) != EXPECTED_SERVICE_ACCOUNTS:
        failures.append(
            f"expected {EXPECTED_SERVICE_ACCOUNTS} ServiceAccount, found "
            f"{len(accounts)}: {sorted(name_of(account) for account in accounts)}. "
            f"Both Jobs run as one identity — see `templates/bootstrap-rbac.yaml` "
            f"for why a second one would narrow nothing"
        )
    identity = name_of(accounts[0]) if len(accounts) == EXPECTED_SERVICE_ACCOUNTS else None

    roles = of_kind(documents, "Role")
    if len(roles) != 1:
        failures.append(
            f"expected 1 Role, found {len(roles)}: "
            f"{sorted(name_of(role) for role in roles)}"
        )
    role_name = name_of(roles[0]) if len(roles) == 1 else None

    bindings = of_kind(documents, "RoleBinding")
    if len(bindings) != EXPECTED_ROLE_BINDINGS:
        failures.append(
            f"expected {EXPECTED_ROLE_BINDINGS} RoleBinding, found {len(bindings)}: "
            f"{sorted(name_of(binding) for binding in bindings)}"
        )

    for binding in bindings:
        reference = binding.get("roleRef") or {}
        if reference.get("kind") != "Role" or reference.get("apiGroup") != RBAC_API_GROUP:
            failures.append(
                f"{name_of(binding)}: expected roleRef "
                f"{{'apiGroup': {RBAC_API_GROUP!r}, 'kind': 'Role'}}, found "
                f"{{'apiGroup': {reference.get('apiGroup')!r}, 'kind': "
                f"{reference.get('kind')!r}}}. A ClusterRole here binds this "
                f"identity in EVERY namespace, and a built-in one renders no object "
                f"for the cluster-scoped count above to see"
            )
        if role_name is None:
            failures.append(
                f"{name_of(binding)}: the render carries no single Role, so "
                f"roleRef.name {reference.get('name')!r} was compared against nothing"
            )
        elif reference.get("name") != role_name:
            failures.append(
                f"{name_of(binding)}: expected roleRef.name to be the rendered "
                f"Role's name {role_name!r}, found {reference.get('name')!r}. The "
                f"Role's `create`-only rule bounds nothing the binding does not "
                f"point at"
            )

        subjects = binding.get("subjects") or []
        if len(subjects) != EXPECTED_BINDING_SUBJECTS:
            failures.append(
                f"{name_of(binding)}: expected {EXPECTED_BINDING_SUBJECTS} subject, "
                f"found {len(subjects)}: {subjects}"
            )
            continue
        if identity is None:
            failures.append(
                f"{name_of(binding)}: the render carries no single ServiceAccount, "
                f"so the subject {subjects[0]} was compared against nothing"
            )
            continue
        expected = {
            "kind": "ServiceAccount",
            "name": identity,
            "namespace": RELEASE_NAMESPACE,
        }
        if subjects[0] != expected:
            failures.append(
                f"{name_of(binding)}: expected the subject to be the rendered "
                f"ServiceAccount {expected}, found {subjects[0]}. A subject naming "
                f"another account, or another namespace, leaves the identity the "
                f"Jobs actually run as holding NOTHING"
            )

    jobs = of_kind(documents, "Job")
    if len(jobs) != EXPECTED_BOOTSTRAP_JOBS:
        failures.append(
            f"expected {EXPECTED_BOOTSTRAP_JOBS} Jobs to check `serviceAccountName` on, "
            f"found {len(jobs)}: {sorted(name_of(job) for job in jobs)}"
        )
    for job in jobs:
        pod = ((job.get("spec") or {}).get("template") or {}).get("spec") or {}
        runs_as = pod.get("serviceAccountName")
        if identity is None:
            failures.append(
                f"{name_of(job)}: the render carries no single ServiceAccount, so "
                f"its serviceAccountName {runs_as!r} was compared against nothing"
            )
        elif runs_as != identity:
            failures.append(
                f"{name_of(job)}: expected serviceAccountName to be the rendered "
                f"ServiceAccount {identity!r}, found {runs_as!r}. A Job left on "
                f"another account runs as an identity this Role was never bound to, "
                f"and every POST it makes answers 403"
            )

    if len(roles) != 1:
        return failures

    rules = roles[0].get("rules") or []
    if len(rules) != 1:
        failures.append(f"expected 1 rule on the Role, found {len(rules)}: {rules}")
        return failures

    rule = rules[0]
    verbs = rule.get("verbs") or []
    if verbs != THE_ONLY_VERB:
        failures.append(
            f"expected {len(THE_ONLY_VERB)} verb on the Role, exactly "
            f"{THE_ONLY_VERB}, found {len(verbs)}: {verbs}. ADR-0753 narrowed "
            f"ADR-0750 property 4 to `create` alone — the Job POSTs and reads "
            f"nothing, so `get` would add only the ability to read credentials it "
            f"did not mint"
        )
    if (rule.get("resources") or []) != ["secrets"]:
        failures.append(f"expected the rule scoped to secrets, found {rule.get('resources')}")
    if (rule.get("apiGroups") or []) != [""]:
        failures.append(f"expected the rule in the core API group, found {rule.get('apiGroups')}")
    if "resourceNames" in rule:
        failures.append(
            "the rule carries `resourceNames`, which does nothing on `create`: the "
            "authorizer runs before the body is decoded, so this reads as a scope "
            "that is not there"
        )
    return failures


def test_the_role_grants_create_and_nothing_else():
    """Property 4 as ADR-0753 narrowed it, over the RENDERED Role."""
    failures = rbac_failures(bootstrap_render(), adopter_render())
    assert failures == [], "\n".join(failures)


def chart_with_a_second_verb(destination: Path) -> Path:
    """Property 4's red case, and it is the register row's: add `get` back."""
    copy = destination / "chart"
    shutil.copytree(CHART, copy)
    template = copy / "templates" / "bootstrap-rbac.yaml"
    text = template.read_text()
    assert '    verbs: ["create"]\n' in text, (
        "the Role's verb list moved; this red case is now testing nothing"
    )
    template.write_text(text.replace('    verbs: ["create"]\n', '    verbs: ["create", "get"]\n'))
    return copy


def test_a_second_verb_reddens_the_rbac_gate(tmp_path):
    copy = chart_with_a_second_verb(tmp_path)
    failures = rbac_failures(bootstrap_render(copy), adopter_render(copy))
    message = "\n".join(failures)
    assert failures, "the Role gained a second verb and the RBAC gate passed"
    assert "expected 1 verb on the Role, exactly ['create'], found 2" in message, message


def chart_bound_to_cluster_admin(destination: Path) -> Path:
    """The wiring's red case, and it is the one that passed the earlier gate green.

    `cluster-admin` EXISTS IN EVERY CLUSTER, so binding to it renders no ClusterRole
    object at all — the cluster-scoped count stays zero while the bootstrap identity
    becomes cluster-admin. That is why the four terms are compared against each
    other rather than counted.
    """
    copy = destination / "chart"
    shutil.copytree(CHART, copy)
    template = copy / "templates" / "bootstrap-rbac.yaml"
    text = template.read_text()
    reference = (
        "roleRef:\n"
        "  apiGroup: rbac.authorization.k8s.io\n"
        "  kind: Role\n"
        "  name: {{ $bootstrap.serviceAccountName }}\n"
    )
    assert reference in text, "the roleRef moved; this red case is now testing nothing"
    template.write_text(
        text.replace(
            reference,
            "roleRef:\n"
            "  apiGroup: rbac.authorization.k8s.io\n"
            "  kind: ClusterRole\n"
            "  name: cluster-admin\n",
        )
    )
    return copy


def test_binding_to_cluster_admin_reddens_the_rbac_gate(tmp_path):
    """The mutation that made this round necessary: green before, red now.

    Asserted on BOTH halves — the kind and the name — and on the cluster-scoped
    count staying zero, because the zero staying zero is the whole finding.
    """
    copy = chart_bound_to_cluster_admin(tmp_path)
    documents = bootstrap_render(copy)
    whole = adopter_render(copy)
    assert of_kind(whole, "ClusterRole") == [], (
        "binding to cluster-admin rendered a ClusterRole object, so this red case "
        "is no longer the one that slipped past a count of cluster-scoped objects"
    )
    failures = rbac_failures(documents, whole)
    message = "\n".join(failures)
    assert failures, "the bootstrap identity became cluster-admin and the RBAC gate passed"
    assert "'kind': 'ClusterRole'" in message, message
    assert "found 'cluster-admin'" in message, message


# ── THREE SECRETS, AND THE FOURTH THAT `bootstrap.iamKeys.create` ADMITS ─────


def minted_set_failures(
    documents: list[dict], expected: set[str] = MACHINE_ONLY_SECRETS
) -> list[str]:
    """Every way the set of minted Secrets stops being the expected one plus the token. PURE.

    THE EXPECTED SET IS AN ARGUMENT BECAUSE THE TOGGLE MOVES IT, and passing it in
    is what keeps both arms honest. At the default render it is the three
    machine-only names; with `bootstrap.iamKeys.create` on it is those three and
    `iam-keys`. A gate that read one constant would have to excuse the other render
    rather than count it.
    """
    failures = []
    scripts = job_scripts(documents)

    machine_only = minted_by(scripts.get("bootstrap-secrets", ""))
    if sorted(machine_only) != sorted(expected):
        failures.append(
            f"expected bootstrap-secrets to mint {len(expected)} "
            f"Secrets, {sorted(expected)}, found {len(machine_only)}: "
            f"{sorted(machine_only)}"
        )

    token = minted_by(scripts.get(ADMIN_TOKEN_SECRET, ""))
    if token != [ADMIN_TOKEN_SECRET]:
        failures.append(
            f"expected the admin-token Job to mint exactly 1 Secret, "
            f"[{ADMIN_TOKEN_SECRET!r}], found {len(token)}: {token}"
        )
    return failures


def test_the_jobs_mint_exactly_the_three_secrets_and_the_token():
    failures = minted_set_failures(bootstrap_render())
    assert failures == [], "\n".join(failures)


def test_the_toggle_admits_the_data_bearing_key_as_a_fourth_create():
    """The on arm's census: four minted, and `iam-keys` is the fourth.

    THE COMPANION THE OFF ARM NEEDS. A suite that only asserted three-at-the-default
    would pass a chart whose toggle rendered nothing at all, which is the failure
    mode a default-false feature is most likely to ship with.
    """
    failures = minted_set_failures(
        bootstrap_render(CHART, *IAM_KEYS_ON),
        expected=MACHINE_ONLY_SECRETS | {THE_DATA_BEARING_KEY},
    )
    assert failures == [], "\n".join(failures)


def chart_with_the_iam_keys_guard_stripped(destination: Path) -> Path:
    """The fourth `create` with its `{{- if }}` removed, so it renders at the default.

    THE RED CASE THAT REPLACES "A FOURTH `create` IS FORBIDDEN". A fourth `create`
    is legal now — behind `bootstrap.iamKeys.create`. What is still forbidden is
    minting the data-bearing key WITHOUT BEING ASKED, and this fixture constructs
    exactly that: the block stays, its guard goes, and the DEFAULT render mints
    four. It is an edit somebody could plausibly make while tidying a template, and
    it is the one that turns an opt-in into an estate-wide default.
    """
    copy = destination / "chart"
    shutil.copytree(CHART, copy)
    template = copy / "templates" / "bootstrap-secrets.yaml"
    text = template.read_text()
    guard = "{{- if $bootstrap.iamKeys.create }}\n"
    closing = "              JSON\n{{- end }}\n          resources:\n"
    assert guard in text, "the iamKeys guard moved; this red case is now testing nothing"
    assert closing in text, "the guard's `end` moved; this red case is now testing nothing"
    template.write_text(
        text.replace(guard, "").replace(closing, "              JSON\n          resources:\n")
    )
    return copy


def test_minting_the_data_bearing_key_unguarded_reddens_the_minted_set(tmp_path):
    failures = minted_set_failures(
        bootstrap_render(chart_with_the_iam_keys_guard_stripped(tmp_path))
    )
    message = "\n".join(failures)
    assert failures, "a fourth Secret was minted at the default render and the gate passed"
    assert "expected bootstrap-secrets to mint 3 Secrets" in message, message
    assert "found 4" in message, message
    assert THE_DATA_BEARING_KEY in message, message


def chart_with_a_duplicate_body_name(destination: Path) -> Path:
    """A fourth `create` whose body carries a name the Job ALREADY mints.

    THE RED CASE FOR THE ONE PROPERTY A LIST HAS AND A SET DOES NOT. The fixture
    above adds a fourth Secret under a NEW name, which a set and a list both
    report. This one adds a second body under `nats-auth`, and the set of names is
    then still the three this chart is allowed to mint — so the census reddens only
    because `minted_secret_names_in` counts the name twice.

    IT IS A SHAPE THE CHART CAN REACH. The blocks are copy-pasted from each other
    and the name appears in the block four times; a fourth credential added by
    copying the `nats-auth` block and renaming three of them leaves a Job that
    POSTs `nats-auth` twice, is answered 201 then 409, and reports both created.
    """
    copy = destination / "chart"
    shutil.copytree(CHART, copy)
    template = copy / "templates" / "bootstrap-secrets.yaml"
    text = template.read_text()
    anchor = "              create nats-auth-gateway <<JSON\n"
    assert anchor in text, "the third mint moved; this red case is now testing nothing"
    template.write_text(
        text.replace(
            anchor,
            "              create nats-auth <<JSON\n"
            '              {"apiVersion":"v1","kind":"Secret","type":"Opaque",\n'
            '               "metadata":{"name":"nats-auth"},\n'
            '               "stringData":{"password":"$value"}}\n'
            "              JSON\n" + anchor,
        )
    )
    return copy


def test_a_duplicate_body_name_reddens_the_minted_set(tmp_path):
    """THE WITNESS THAT `minted_secret_names_in` RETURNS A LIST RATHER THAN A SET.

    The guard-stripping fixture above this one adds a fourth Secret under a NEW
    name, which a set and a list both report. This case adds a SECOND BODY under a
    name the Job already mints, so the set of names stays the three the default
    render allows and the census reddens only because the helper counts the name
    twice. That is the one property a list has here, and until this case it had no
    red.

    MEASURED, at this branch's head, on both helm binaries. Deduplicate
    `minted_secret_names_in` — `list(dict.fromkeys(...))` — and THE WHOLE SUITE
    GOES `1 failed, 107 passed`, the one failure being this case. Every other gate
    reads the SHIPPED chart, which carries no duplicate, so that mutation is silent
    everywhere else. This case is the only thing standing between the helper and a
    set.

    AND IT IS ASSERTED ON THE MESSAGE, NOT ONLY ON `failures` BEING NON-EMPTY.
    Return a bare `set` rather than deduplicating and `failures` is STILL non-empty
    here, on a failure about the OTHER Job: `sorted(a_set)` equals the literal so
    the census clause goes quiet, while `token != [ADMIN_TOKEN_SECRET]` compares a
    set against a list and can never be equal. A lone `assert failures` would pass
    under that mutation, so the duplicate name is asserted directly and early.
    """
    failures = minted_set_failures(bootstrap_render(chart_with_a_duplicate_body_name(tmp_path)))
    message = "\n".join(failures)
    assert failures, "a Secret was POSTed twice under one name and the gate passed"
    assert "'nats-auth', 'nats-auth'" in message, (
        f"the census reported the duplicate name once, so it is counting NAMES "
        f"rather than BODIES and a set would read the same: {message}"
    )
    assert "expected bootstrap-secrets to mint 3 Secrets" in message, message
    assert "found 4" in message, message


def data_bearing_key_failures(rendered: str) -> list[str]:
    """Whether the data-bearing key reaches the render at all. PURE.

    ASSERTED OVER THE RENDER RATHER THAN OVER THE SOURCE TEXT, and the difference
    matters in both directions. A gate reading the files would refuse the comments
    that EXPLAIN the toggle — `values.yaml` and `templates/bootstrap-secrets.yaml`
    both argue at length about the fourth `create`, its ordering and the gap it
    leaves open, and a default nobody explained is the one somebody flips. What the
    default forbids is the key being MINTED, and what gets minted is what renders.

    THE SAME FUNCTION READS BOTH ARMS, in opposite directions. The default render
    must produce NO failures here; the render with `bootstrap.iamKeys.create` on
    must produce one, or the toggle does nothing. Two callers, one measurement.
    """
    naming = [
        line.strip()
        for line in rendered.splitlines()
        if THE_DATA_BEARING_KEY in line
    ]
    if not naming:
        return []
    return [
        f"the render names {THE_DATA_BEARING_KEY} on {len(naming)} lines: {naming}. "
        f"`bootstrap.iamKeys.create` defaults FALSE, and the data-bearing key is "
        f"minted only when an adopter asks for it — a cluster whose Secret is gone "
        f"but whose database survived gets a key that `iam` v0.8.43 refuses, and an "
        f"estate that already mints the pair by hand must not get a second one"
    ]


def test_the_data_bearing_key_is_absent_until_it_is_asked_for():
    """The off arm: the adopter render never names the key.

    A secret whose LOSS DESTROYS DATA is minted only when an adopter asks for it.
    ADR-0753 ordered the asking behind a key-identity marker in the `iam` binary
    that refuses a wrong key; `iam` v0.8.43 shipped that marker, which is what makes
    the toggle admissible at all. The DEFAULT stays false, and this is that default
    asserted rather than left as an intention.
    """
    failures = data_bearing_key_failures(adopter_render_text())
    assert failures == [], "\n".join(failures)


def test_turning_the_toggle_on_puts_the_data_bearing_key_in_the_render():
    """The on arm, and it is what stops the off arm being vacuous.

    A TOGGLE THAT RENDERED NOTHING WOULD PASS EVERY OTHER GATE IN THIS FILE. The
    census above reads the Job's script; this reads the render as text, from the
    same direction the off arm does, so the two answers cannot both come from a
    template that ignores its own guard.
    """
    failures = data_bearing_key_failures(adopter_render_text(CHART, *IAM_KEYS_ON))
    assert failures, (
        f"{IAM_KEYS_TOGGLE} was set true and the render still never names "
        f"{THE_DATA_BEARING_KEY}"
    )


def test_minting_the_data_bearing_key_unguarded_reddens_the_default(tmp_path):
    """The default's red case: the guard stripped, so the key renders unasked."""
    failures = data_bearing_key_failures(
        adopter_render_text(chart_with_the_iam_keys_guard_stripped(tmp_path))
    )
    message = "\n".join(failures)
    assert failures, f"the render minted {THE_DATA_BEARING_KEY} unasked and the gate passed"
    assert f"the render names {THE_DATA_BEARING_KEY} on" in message, message


# ── THE KEY SET, AGAINST WHAT `make secrets` MINTS ───────────────────────────


def body_of(script: str, secret: str) -> dict | None:
    """The POSTed JSON body for one Secret, parsed. PURE.

    PARSED RATHER THAN SEARCHED, because the question is about the body's SHAPE —
    which map holds the key files, and which names it carries — and a substring
    search cannot tell `"data"` from `"stringData"` in a body that contains both
    strings. The bodies are ordinary JSON once the shell variables are left as the
    string values they already are.
    """
    for name, match in zip(minted_by(script), BODY.finditer(script)):
        if name == secret:
            return json.loads(match.group("body"))
    return None


def iam_key_set_failures(documents: list[dict]) -> list[str]:
    """Whether the Job-minted `iam-keys` carries what `make secrets` mints. PURE.

    THE ONE PROPERTY THAT SPANS TWO WAYS OF CREATING THE SAME SECRET. `iam-keys`
    can arrive two ways on this estate: by this Job, or by `make secrets` in
    `yadgarhq/deploy`, which runs `kubectl create secret generic iam-keys` with
    `--from-file=encryption.key=` and `--from-file=blind-index.key=`. `iam` reads
    the mount and nothing tells it which path produced it. So a Job that minted a
    different key set would give a cluster bootstrapped by the chart a mount the
    hand-minted path never produces, and the service that refuses to start would
    name a missing file rather than the chart that omitted it.

    THE COUNT AS WELL AS THE NAMES. A name list alone would not notice a third key
    added beside the two, and a count alone would not notice one name swapped for
    another. Both are asserted, and both numbers reach the message.

    THE FIELD IS PART OF THE COMPARISON. `make secrets` uses `--from-file=`, so
    each key is RAW BYTES on disk — 32 of them, the only length `iam`'s `read_key`
    accepts. `data` is the field the API server base64-DECODES, so a 44-character
    base64 value lands as those 32 bytes. `stringData` would store the 44
    characters themselves and `iam` would refuse to start on a wrong-length key. A
    gate that read whichever map the body carried would pass that body, and the
    defect would surface as a boot failure on a live cluster rather than here.
    """
    failures = []
    body = body_of(job_scripts(documents).get("bootstrap-secrets", ""), THE_DATA_BEARING_KEY)
    if body is None:
        return [
            f"the Job POSTs no body for {THE_DATA_BEARING_KEY}, so this gate read "
            f"nothing. It is called on a render with {IAM_KEYS_TOGGLE} true, where "
            f"the fourth `create` is the whole subject"
        ]

    if THE_WRONG_FIELD in body:
        failures.append(
            f"{THE_DATA_BEARING_KEY}'s body carries `{THE_WRONG_FIELD}`. `iam` reads "
            f"each key file with `std::fs::read` and refuses any length but 32 "
            f"BYTES, so `{THE_WRONG_FIELD}` would store the 44 base64 CHARACTERS as "
            f"the file and `iam` would refuse to start. `{IAM_KEYS_FIELD}` is the "
            f"field the API server decodes"
        )
    if IAM_KEYS_FIELD not in body:
        return failures + [
            f"{THE_DATA_BEARING_KEY}'s body carries no `{IAM_KEYS_FIELD}` map, so "
            f"there is no key set to compare against `make secrets`"
        ]

    minted = set(body[IAM_KEYS_FIELD])
    if minted != MAKE_SECRETS_IAM_KEYS:
        failures.append(
            f"expected {THE_DATA_BEARING_KEY} to carry the {EXPECTED_IAM_KEYS} keys "
            f"`make secrets` mints, {sorted(MAKE_SECRETS_IAM_KEYS)}, found "
            f"{len(minted)}: {sorted(minted)}. Missing "
            f"{sorted(MAKE_SECRETS_IAM_KEYS - minted)}; unexpected "
            f"{sorted(minted - MAKE_SECRETS_IAM_KEYS)}. A Job-minted key set that "
            f"differs from the hand-minted one hands `iam` a mount `make secrets` "
            f"never produces"
        )
    return failures


def test_the_job_mints_the_key_set_make_secrets_mints():
    """The register's key-set gate: the Job's JSON against `make secrets`."""
    failures = iam_key_set_failures(bootstrap_render(CHART, *IAM_KEYS_ON))
    assert failures == [], "\n".join(failures)


def chart_with_one_iam_key_removed(destination: Path) -> Path:
    """The register's red case: one key removed from the Job's JSON."""
    copy = destination / "chart"
    shutil.copytree(CHART, copy)
    template = copy / "templates" / "bootstrap-secrets.yaml"
    text = template.read_text()
    key = '"encryption.key":"$encryption_key",'
    assert key in text, "the key set moved; this red case is now testing nothing"
    template.write_text(text.replace(key, ""))
    return copy


def test_removing_a_key_from_the_job_reddens_the_key_set_gate(tmp_path):
    """The failure names the missing key AND both counts, which the register asks for."""
    failures = iam_key_set_failures(
        bootstrap_render(chart_with_one_iam_key_removed(tmp_path), *IAM_KEYS_ON)
    )
    message = "\n".join(failures)
    assert failures, "a key was dropped from the Job's JSON and the key-set gate passed"
    assert f"the {EXPECTED_IAM_KEYS} keys `make secrets` mints" in message, message
    assert "found 1:" in message, message
    assert "Missing ['encryption.key']" in message, message


def chart_that_posts_the_keys_as_stringdata(destination: Path) -> Path:
    """`data` swapped for `stringData`, which is the mutation that ships a dead `iam`.

    IT IS SILENT EVERYWHERE ELSE. The Secret name is unchanged, the key names are
    unchanged, the count is unchanged, and every other gate in this file reads one
    of those three. The only symptom is on a live cluster: `iam` reads a
    44-character file where it demands 32 bytes and refuses to start.
    """
    copy = destination / "chart"
    shutil.copytree(CHART, copy)
    template = copy / "templates" / "bootstrap-secrets.yaml"
    text = template.read_text()
    field = '"data":{"encryption.key"'
    assert field in text, "the key map moved; this red case is now testing nothing"
    template.write_text(text.replace(field, '"stringData":{"encryption.key"'))
    return copy


def test_posting_the_keys_as_stringdata_reddens_the_key_set_gate(tmp_path):
    failures = iam_key_set_failures(
        bootstrap_render(chart_that_posts_the_keys_as_stringdata(tmp_path), *IAM_KEYS_ON)
    )
    message = "\n".join(failures)
    assert failures, "the keys were POSTed as text and the key-set gate passed"
    assert f"carries `{THE_WRONG_FIELD}`" in message, message
    assert "refuses any length but 32 BYTES" in message, message


# ── THE HOOKS, AND THE WEIGHTS THAT ORDER THEM ───────────────────────────────


def hook_failures(documents: list[dict]) -> list[str]:
    """Every way the hook set or its ordering stops being this step's. PURE.

    WHY THESE MUST BE HOOKS AT ALL. Rendered as plain resources a failing Job
    DECORATES the install: `helm install` returns success, the estate is half-up,
    and the failure is a red Job somebody may or may not read. As a `pre-install`
    hook Helm waits for it and ABORTS, and under Argo the same annotation becomes a
    `PreSync` hook whose failure fails the sync.

    AND WHY THE RBAC IS A HOOK TOO, AT A LOWER WEIGHT. Helm applies plain resources
    AFTER the pre-install hooks have run, so a ServiceAccount rendered as an
    ordinary object DOES NOT EXIST when a `pre-install` Job tries to use it — the
    Job is then admitted against an identity that is not there, and it fails on a
    healthy cluster for a reason that has nothing to do with this chart.

    AND THE POSITIONS ARE COUNTED PER PHASE. A `hook-weight` orders hooks WITHIN
    one phase; it says nothing across two. Counted over the union, the post-install
    triple's weight would be indistinguishable from a pre-install one — a collision
    reported where none exists, and worse, a post-install triple left ABOVE its own
    Job while a pre-install weight covered for it.

    THE WEIGHT IS A STRING. Annotations are `map[string]string`, so an unquoted
    integer is a manifest that does not decode; the type is asserted here because
    the failure otherwise arrives at apply time.
    """
    failures = []
    hooks = bootstrap_objects(documents)

    jobs = [document for document in hooks if document.get("kind") == "Job"]
    if len(jobs) != EXPECTED_HOOK_JOBS:
        failures.append(
            f"expected {EXPECTED_HOOK_JOBS} hook Jobs, found {len(jobs)}: "
            f"{sorted(name_of(job) for job in jobs)}. A Job outside the hook set "
            f"runs in the wrong phase, and its ServiceAccount does not exist when "
            f"it is admitted"
        )

    rbac = [
        document
        for document in hooks
        if document.get("kind") in {"ServiceAccount", "Role", "RoleBinding"}
    ]
    if len(rbac) != EXPECTED_RBAC_OBJECTS:
        failures.append(
            f"expected {EXPECTED_RBAC_OBJECTS} hook RBAC objects, found "
            f"{len(rbac)}: {sorted(name_of(document) for document in rbac)}"
        )

    for phase, expected in EXPECTED_HOOK_JOBS_IN.items():
        found = [job for job in jobs if annotations_of(job).get("helm.sh/hook") == phase]
        if len(found) != expected:
            failures.append(
                f"expected {expected} {phase} hook Jobs, found {len(found)}: "
                f"{sorted(name_of(job) for job in found)}. The phase is what orders "
                f"a Job against the install, and a weight cannot express it"
            )

    weights = {}
    for document in hooks:
        annotations = annotations_of(document)
        phase = annotations.get("helm.sh/hook")
        if phase not in EXPECTED_HOOK_JOBS_IN:
            failures.append(
                f"{name_of(document)} ({document.get('kind')}) is a hook in phase "
                f"{phase!r}; this chart renders hooks in "
                f"{sorted(EXPECTED_HOOK_JOBS_IN)} and in no other"
            )
        if annotations.get("helm.sh/hook-delete-policy") != "before-hook-creation":
            failures.append(
                f"{name_of(document)} ({document.get('kind')}) does not carry "
                f"`hook-delete-policy: before-hook-creation`, so its second install "
                f"meets an immutable object that is already there"
            )
        weight = annotations.get("helm.sh/hook-weight")
        if not isinstance(weight, str):
            failures.append(
                f"{name_of(document)} ({document.get('kind')}) renders a "
                f"hook-weight of type {type(weight).__name__}, not str. Annotations "
                f"are map[string]string, so an unquoted integer does not decode"
            )
            continue
        weights[(phase, document.get("kind"), name_of(document))] = int(weight)

    for phase, expected in EXPECTED_WEIGHT_POSITIONS_IN.items():
        rbac_weights = {
            weight
            for (at, kind, _), weight in weights.items()
            if at == phase and kind in {"ServiceAccount", "Role", "RoleBinding"}
        }
        job_weights = {
            weight for (at, kind, _), weight in weights.items() if at == phase and kind == "Job"
        }
        positions = rbac_weights | job_weights
        if len(positions) != expected:
            failures.append(
                f"expected {expected} {phase} hook-weight positions, found "
                f"{len(positions)}: {sorted(positions)}"
            )
        if rbac_weights and job_weights and max(rbac_weights) >= min(job_weights):
            failures.append(
                f"the {phase} RBAC triples' weights {sorted(rbac_weights)} do not all "
                f"sit BELOW the Jobs' {sorted(job_weights)}, so a Job can be admitted "
                f"before the identity it runs as exists"
            )
    return failures


def test_both_jobs_and_their_shared_rbac_are_hooks_at_ordered_weights():
    failures = hook_failures(adopter_render())
    assert failures == [], "\n".join(failures)


def chart_with_a_job_that_is_not_a_hook(destination: Path) -> Path:
    """The register row's own red case: one Job renders as a plain resource."""
    copy = destination / "chart"
    shutil.copytree(CHART, copy)
    template = copy / "templates" / "admin-bootstrap-token.yaml"
    text = template.read_text()
    line = "    helm.sh/hook: pre-install,pre-upgrade\n"
    assert line in text, "the hook annotation moved; this red case is now testing nothing"
    template.write_text(text.replace(line, "", 1))
    return copy


def test_a_job_that_is_not_a_hook_reddens_the_hook_count(tmp_path):
    failures = hook_failures(adopter_render(chart_with_a_job_that_is_not_a_hook(tmp_path)))
    message = "\n".join(failures)
    assert failures, "a Job left the hook set and the hook gate passed"
    assert "expected 4 hook Jobs, found 3" in message, message


def chart_with_the_probe_moved_into_the_pre_install_phase(destination: Path) -> Path:
    """The per-phase count's own red case: the post-install Job moved a phase.

    THE TOTAL DOES NOT MOVE, and that is the point. Four hook Jobs still render and
    nine hook RBAC objects still render, so the two chart-wide counts above stay
    green — only the per-phase split sees it. A probe that ran pre-install would bind
    to a GatewayClass the install has not created yet, which is one of the two
    defects the pre-install Envoy Gateway probe was dropped for.
    """
    copy = destination / "chart"
    shutil.copytree(CHART, copy)
    template = copy / "templates" / "envoy-gateway-probe.yaml"
    text = template.read_text()
    line = "    helm.sh/hook: post-install,post-upgrade\n"
    assert line in text, "the probe's hook annotation moved; this red case is now testing nothing"
    template.write_text(text.replace(line, "    helm.sh/hook: pre-install,pre-upgrade\n", 1))
    return copy


def test_moving_the_probe_into_the_pre_install_phase_reddens_the_per_phase_count(tmp_path):
    documents = adopter_render(chart_with_the_probe_moved_into_the_pre_install_phase(tmp_path))
    hooks = bootstrap_objects(documents)
    assert len([document for document in hooks if document.get("kind") == "Job"]) == (
        EXPECTED_HOOK_JOBS
    ), "the mutation changed the total hook-Job count, so it no longer isolates the phase"

    failures = hook_failures(documents)
    message = "\n".join(failures)
    assert failures, "the probe Job changed phase and the hook gate passed"
    assert f"expected {EXPECTED_POST_INSTALL_HOOK_JOBS} {POST_INSTALL} hook Jobs, found 0" in (
        message
    ), message


def chart_with_the_probe_triple_above_its_job(destination: Path) -> Path:
    """The post-install ordering's red case: the triple lifted above the Job it serves."""
    copy = destination / "chart"
    shutil.copytree(CHART, copy)
    template = copy / "templates" / "envoy-gateway-probe-rbac.yaml"
    text = template.read_text()
    line = '    helm.sh/hook-weight: "-10"'
    assert line in text, "the probe triple's weight moved; this red case is now testing nothing"
    template.write_text(text.replace(line, '    helm.sh/hook-weight: "-1"'))
    return copy


def test_lifting_the_probe_triple_above_its_job_reddens_the_ordering(tmp_path):
    failures = hook_failures(adopter_render(chart_with_the_probe_triple_above_its_job(tmp_path)))
    message = "\n".join(failures)
    assert failures, "the probe's triple was lifted above its Job and the ordering gate passed"
    assert f"the {POST_INSTALL} RBAC triples' weights" in message, message


# ── R1 — THE DEFAULTS RENDER NOTHING, AND THAT IS AN EQUALITY ────────────────


def test_the_defaults_render_no_bootstrap_object_at_all():
    """`bootstrap.create` is false, so the count is zero and it is asserted as one.

    ADR-0752's contract: this chart installs on a bare cluster rendering nothing.
    A Job that rendered at the defaults would POST four Secrets into an adopter's
    namespace on an install that asked for none of this layer.
    """
    defaults = helm("template", "platform", str(CHART))
    assert defaults.returncode == 0, defaults.stderr
    rendered = bootstrap_objects(documents_of(defaults.stdout))
    assert rendered == [], (
        f"expected 0 bootstrap objects at the chart's defaults, found "
        f"{len(rendered)}: "
        f"{sorted((document.get('kind'), name_of(document)) for document in rendered)}"
    )


def chart_with_an_unguarded_bootstrap_template(destination: Path) -> Path:
    """R1's red case: the toggle's `if` deleted, so the RBAC renders unasked."""
    copy = destination / "chart"
    shutil.copytree(CHART, copy)
    template = copy / "templates" / "bootstrap-rbac.yaml"
    text = template.read_text()
    guard = "{{- if .Values.bootstrap.create }}\n"
    assert guard in text, "the toggle's guard moved; this red case is now testing nothing"
    template.write_text(text.replace(guard, "", 1).replace("\n{{- end }}\n", "\n", 1))
    return copy


def test_an_unguarded_bootstrap_template_reddens_the_defaults_zero(tmp_path):
    copy = chart_with_an_unguarded_bootstrap_template(tmp_path)
    defaults = helm("template", "platform", str(copy))
    assert defaults.returncode == 0, defaults.stderr
    rendered = bootstrap_objects(documents_of(defaults.stdout))
    assert rendered, "the bootstrap toggle stopped gating its objects and the zero passed"


# ── THE ADMIN TOKEN'S NAME IS A VALUE, BECAUSE THE PARENT MUST MATCH IT ──────


def test_the_admin_token_secret_name_follows_its_value(tmp_path):
    """`bootstrap.adminToken.secretName` reaches the Secret the Job POSTs.

    THE PARENT MAKES THIS AGREE WITH `gateway.adminBootstrap.tokenSecret` (ruling
    5), so a name the template hardcoded would leave the gateway mounting a Secret
    nothing mints. That agreement check is the parent's, at a later step; what this
    chart owes it is a name that actually follows the value.
    """
    overridden = tmp_path / "renamed.yaml"
    overridden.write_text("bootstrap:\n  adminToken:\n    secretName: a-different-name\n")
    scripts = job_scripts(bootstrap_render(CHART, "-f", str(overridden)))
    minted = minted_by(scripts[ADMIN_TOKEN_SECRET])
    assert minted == ["a-different-name"], (
        f"expected the admin-token Job to mint ['a-different-name'] once "
        f"`bootstrap.adminToken.secretName` was overridden, found {minted}. A "
        f"hardcoded name leaves the gateway mounting a Secret nothing mints"
    )


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
