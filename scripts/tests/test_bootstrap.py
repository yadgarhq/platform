"""THE BOOTSTRAP GATE: ADR-0750's four properties, each with its own constructed red case.

WHAT THIS CHART RENDERS HERE, AND WHY IT IS A JOB AT ALL. `valkey-password`,
`nats-auth`, `nats-auth-gateway` and the administrative bootstrap token have no
source outside the installation — nothing an adopter can be asked to transcribe,
because the value is created once and everything derives from it. ADR-0750 rules
that such a secret is minted by an IDEMPOTENT JOB THE CHART RENDERS, into a Secret
that neither Helm nor Argo tracks. A template cannot hold this: D54 measured
`lookup` returning empty under template-only rendering, which is how Argo renders,
so a generate-if-absent template regenerates the key on every sync.

THREE SECRETS, NOT FOUR, AND THAT IS ADR-0753 RATHER THAN AN OMISSION. `iam-keys`
is DATA-BEARING — AES-256-GCM ciphertext plus an HMAC blind index — so a cluster
whose Secret is gone but whose database survived would get an `iam` that starts
HEALTHY and cannot decrypt the rows it already has. ADR-0753 orders the
generation behind a key-identity marker in the `iam` binary that refuses the wrong
key, and the marker lands FIRST, in its own change. `test_no_data_bearing_key_is_minted_yet`
is that ordering written down: `iam-keys` must appear nowhere in this chart.

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

THE HOOK COUNT IS THIS STEP'S, NOT THE FINISHED LAYER'S, AND IT HAS ALREADY MOVED
ONCE. Three hook Jobs render today, all `pre-install`, across three hook-weight
positions: the two RBAC triples sharing the lowest, the preflight Job alone above
them, and the two bootstrap Jobs sharing the highest. The post-install Envoy
Gateway probe arrives in a later pull request and moves both numbers again — AND IT
WILL REDDEN THIS GATE ON ITS PHASE BEFORE IT MOVES ANY NUMBER, because
`hook_failures` accepts `pre-install,pre-upgrade` and nothing else. That is not an
oversight to route around: the phase set is a claim about what this chart renders,
and widening it is the change that step makes deliberately rather than discovers.

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

import re
import shutil
import subprocess
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parents[2]
CHART = REPO / "chart"
ADOPTER_VALUES = REPO / "example" / "values.yaml"
README = REPO / "README.md"

# The group this chart's render check demands before anything renders. See
# `test_render_checks.py`; here it is only the reason for the flag.
CERT_MANAGER_API = "cert-manager.io/v1"

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

# The three machine-only credentials, named rather than counted, because a count
# alone would not notice one name being swapped for another. ADR-0753: three, and
# `iam-keys` is not among them until the `iam` binary can refuse a wrong key.
MACHINE_ONLY_SECRETS = {"valkey-password", "nats-auth", "nats-auth-gateway"}

# The human-facing one (ADR-0517's third category), minted by its own Job so that
# its retrieval contract reads on its own rather than folded into the other Job's
# "never read by a person" framing. Its NAME is a value — the parent must be able
# to make it agree with `gateway.adminBootstrap.tokenSecret` — and this is the
# chart's shipped default.
ADMIN_TOKEN_SECRET = "admin-bootstrap-token"

EVERY_MINTED_SECRET = MACHINE_ONLY_SECRETS | {ADMIN_TOKEN_SECRET}

# The key whose generation ADR-0753 ORDERS BEHIND a change to the `iam` binary.
# It is absent from this chart on purpose, and this name is here so the absence is
# asserted rather than merely true.
THE_DATA_BEARING_KEY = "iam-keys"

# THE BOOTSTRAP'S OWN TWO JOBS, and the one triple they share. Every gate below
# that reads a script, an image or the RBAC wiring is scoped to the three templates
# that render them — `bootstrap_render` — so this number is the bootstrap's and
# does not move when another template adds a Job.
EXPECTED_BOOTSTRAP_JOBS = 2

# THE WHOLE CHART'S HOOK SET, WHICH IS A DIFFERENT CLAIM AND A DIFFERENT NUMBER.
# `hook_failures` below is the one gate here that is deliberately chart-wide: a Job
# outside the hook set runs in the wrong phase whatever template rendered it, and a
# weight position colliding across templates is exactly the kind of thing a scoped
# gate would never see. THREE Jobs — `preflight`, `bootstrap-secrets` and
# `admin-bootstrap-token` — across TWO triples and THREE weight positions: the
# triples share the lowest, `preflight` runs alone above them because the whole
# point of it is to refuse before anything else acts, and the two bootstrap Jobs
# share the highest because they mint disjoint Secret names and nothing orders one
# against the other.
EXPECTED_HOOK_JOBS = 3
EXPECTED_RBAC_OBJECTS = 6
EXPECTED_PRE_INSTALL_WEIGHT_POSITIONS = 3

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
        "--api-versions",
        CERT_MANAGER_API,
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

# `create <name> <<JSON` — the one call in either script that mints a Secret. Read
# from the RENDERED script rather than from the template source, so a name that
# arrives through a value is read as the value resolves it.
MINTS = re.compile(r"^\s*create\s+(?P<name>[a-z0-9][a-z0-9.-]*)\s+<<JSON\s*$", re.MULTILINE)

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
    return [match.group("name") for match in MINTS.finditer(script)]


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

# 33 random bytes of base64 is 44 characters and carries no `=` padding, which is
# why 33 was chosen. An EXACT length rather than a minimum, for the same reason.
EXPECTED_CREDENTIAL_LENGTH = 44

# Four request bodies across the two scripts, one per minted Secret. Asserted,
# because a body regex that silently matched none would make the check below
# vacuous — which is the defect this whole gate exists to stop repeating.
EXPECTED_REQUEST_BODIES = len(EVERY_MINTED_SECRET)

# The JSON body of each POST, read between its heredoc delimiters.
BODY = re.compile(r"<<JSON\s*\n(?P<body>.*?)\n\s*JSON\s*$", re.MULTILINE | re.DOTALL)

# `mint <name>` — the generator, called as a STATEMENT so its exit status is the
# script's. One per `create <name>`, and in the same order.
GENERATES = re.compile(r"^\s*mint\s+(?P<name>[a-z0-9][a-z0-9.-]*)\s*$", re.MULTILINE)

# The length check on what the generator produced, and the arm it takes when the
# length is wrong.
LENGTH_CHECK = re.compile(
    r'\[\s*"\$\{#(?P<variable>[A-Za-z_][A-Za-z0-9_]*)\}"\s*-ne\s*(?P<length>\d+)\s*\]'
    r"(?P<arm>.*?)\bfi\b",
    re.DOTALL,
)


def generation_failures(documents: list[dict]) -> list[str]:
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
    """
    failures = []
    scripts = job_scripts(documents)
    bodies = 0

    for job, script in sorted(scripts.items()):
        generated = [match.group("name") for match in GENERATES.finditer(script)]
        created = minted_by(script)
        if generated != created:
            failures.append(
                f"{job}: expected one `mint <name>` statement before each `create "
                f"<name>`, in the same order — the script creates {created} and "
                f"generates {generated}. A credential built anywhere but a "
                f"statement cannot fail the run"
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
                    f"{EXPECTED_CREDENTIAL_LENGTH} characters with no padding"
                )
            if "exit 1" not in check.group("arm"):
                failures.append(
                    f"{job}: the length check does not stop the Job when it fails. "
                    f"The arm reads:{check.group('arm')}"
                )

        for match in BODY.finditer(script):
            bodies += 1
            body = match.group("body")
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

    if bodies != EXPECTED_REQUEST_BODIES:
        failures.append(
            f"expected {EXPECTED_REQUEST_BODIES} request bodies across the two "
            f"scripts, found {bodies}. A body this gate did not read is a body it "
            f"did not check, and a zero here would be vacuous rather than a property"
        )
    return failures


def test_an_empty_credential_stops_the_job_instead_of_being_posted():
    """The generator's failure reaches the exit status, on both Jobs."""
    failures = generation_failures(bootstrap_render())
    assert failures == [], "\n".join(failures)


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


# ── THREE SECRETS, AND THE FOURTH THAT ADR-0753 ORDERS BEHIND `iam` ──────────


def minted_set_failures(documents: list[dict]) -> list[str]:
    """Every way the set of minted Secrets stops being the three plus the token. PURE."""
    failures = []
    scripts = job_scripts(documents)

    machine_only = minted_by(scripts.get("bootstrap-secrets", ""))
    if sorted(machine_only) != sorted(MACHINE_ONLY_SECRETS):
        failures.append(
            f"expected bootstrap-secrets to mint {len(MACHINE_ONLY_SECRETS)} "
            f"Secrets, {sorted(MACHINE_ONLY_SECRETS)}, found {len(machine_only)}: "
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


def chart_with_a_fourth_create(destination: Path) -> Path:
    """The red case ADR-0753 exists to make impossible: a fourth `create` in the same Job."""
    copy = destination / "chart"
    shutil.copytree(CHART, copy)
    template = copy / "templates" / "bootstrap-secrets.yaml"
    text = template.read_text()
    anchor = "              create nats-auth-gateway <<JSON\n"
    assert anchor in text, "the third mint moved; this red case is now testing nothing"
    template.write_text(
        text.replace(
            anchor,
            "              create iam-keys <<JSON\n"
            '              {"apiVersion":"v1","kind":"Secret","type":"Opaque",\n'
            '               "metadata":{"name":"iam-keys"},\n'
            '               "stringData":{"key":"$(password)"}}\n'
            "              JSON\n" + anchor,
        )
    )
    return copy


def test_a_fourth_create_reddens_the_minted_set(tmp_path):
    failures = minted_set_failures(bootstrap_render(chart_with_a_fourth_create(tmp_path)))
    message = "\n".join(failures)
    assert failures, "a fourth Secret was minted and the gate passed"
    assert "expected bootstrap-secrets to mint 3 Secrets" in message, message
    assert "found 4" in message, message
    assert THE_DATA_BEARING_KEY in message, message


def data_bearing_key_failures(rendered: str) -> list[str]:
    """Whether the data-bearing key reaches the render at all. PURE.

    ASSERTED OVER THE RENDER RATHER THAN OVER THE SOURCE TEXT, and the difference
    matters in both directions. A gate reading the files would refuse the comments
    that EXPLAIN the absence — `values.yaml` and `templates/bootstrap-secrets.yaml`
    both argue at length why the fourth `create` is missing, and an absence nobody
    explained is the one somebody fills in. What ADR-0753 forbids is the key being
    MINTED, and what gets minted is what renders.
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
        f"ADR-0753 orders its generation behind a key-identity marker in the `iam` "
        f"binary that refuses a wrong key, and that marker lands in its own change, "
        f"first — until then a regenerated key gives an `iam` that starts healthy "
        f"and cannot decrypt the rows it already has"
    ]


def test_no_data_bearing_key_is_minted_yet():
    """ADR-0753's ORDERING, asserted rather than left as an intention.

    A secret whose LOSS DESTROYS DATA is generated only once its consuming service
    can REFUSE THE WRONG KEY. That refusal is a change to the `iam` binary, it ships
    on its own, and it ships FIRST.
    """
    failures = data_bearing_key_failures(adopter_render_text())
    assert failures == [], "\n".join(failures)


def test_minting_the_data_bearing_key_reddens_the_ordering_gate(tmp_path):
    """The ordering's red case, on the same mutation the minted-set gate uses."""
    failures = data_bearing_key_failures(
        adopter_render_text(chart_with_a_fourth_create(tmp_path))
    )
    message = "\n".join(failures)
    assert failures, f"the render minted {THE_DATA_BEARING_KEY} and the ordering gate passed"
    assert f"the render names {THE_DATA_BEARING_KEY} on" in message, message


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

    weights = {}
    for document in hooks:
        annotations = annotations_of(document)
        phase = annotations.get("helm.sh/hook")
        if phase != "pre-install,pre-upgrade":
            failures.append(
                f"{name_of(document)} ({document.get('kind')}) is a hook in phase "
                f"{phase!r}; every hook this step renders is pre-install,pre-upgrade"
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
        weights[(document.get("kind"), name_of(document))] = int(weight)

    if weights:
        rbac_weights = {
            weight
            for (kind, _), weight in weights.items()
            if kind in {"ServiceAccount", "Role", "RoleBinding"}
        }
        job_weights = {weight for (kind, _), weight in weights.items() if kind == "Job"}
        positions = rbac_weights | job_weights
        if len(positions) != EXPECTED_PRE_INSTALL_WEIGHT_POSITIONS:
            failures.append(
                f"expected {EXPECTED_PRE_INSTALL_WEIGHT_POSITIONS} pre-install "
                f"hook-weight positions, found {len(positions)}: {sorted(positions)}"
            )
        if rbac_weights and job_weights and max(rbac_weights) >= min(job_weights):
            failures.append(
                f"the RBAC triple's weights {sorted(rbac_weights)} do not all sit "
                f"BELOW the Jobs' {sorted(job_weights)}, so a Job can be admitted "
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
    assert "expected 3 hook Jobs, found 2" in message, message


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
