"""Every hook Job ends on its own clock, and every curl in a hook script ends too.

LEDGER 1224. Before this suite, no hook Job this chart renders carried
`activeDeadlineSeconds` and no `curl` in a hook script carried `--max-time`. A Job
in `ImagePullBackOff`, or a request to an API server that accepts the connection
and never answers, therefore held its sync open for as long as the caller would
wait — and under Argo CD the caller's only bound is `controller.sync.timeout.seconds`
(ADR-0830), set at 25200 s (chart#25 dc1556f merged; argocd#58).

WHAT IS CHECKED, AND WHERE EACH NUMBER COMES FROM.

  1. THE GATE. Both releases this chart serves are rendered — the estate with every
     probe and every bootstrap Secret on, and the operators — and every Job carrying
     a `helm.sh/hook` or `argocd.argoproj.io/hook` annotation must carry
     `activeDeadlineSeconds`. The three upstream hook Jobs whose charts expose no
     key for it are EXEMPT BY NAME AND BY PINNED VERSION, so a subchart bump expires
     the exemption and forces somebody to look again.

  2. THE ARITHMETIC. Each deadline this chart writes is recomputed here from the
     RENDERED script, by counting the bounded loops and requests in it — never by
     reading the template's own count, which would agree with itself whatever it
     said. The margins and the Kubernetes constants are literals below.

  3. THE CURLS. Every `curl` invocation in every hook script carries both
     `--max-time` and `--connect-timeout`.

Each check is a PURE `*_failures` helper that the green test and its red case both
call, and every red case asserts the message — a red case that only proved its
mutation landed would prove nothing about the gate (`test_preflight.py` records why).
"""

from __future__ import annotations

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

RELEASE_NAMESPACE = "yadgar"
OPERATORS_NAMESPACE = "yadgar-operators"

# The render checks refuse without these groups the moment a create toggle is on;
# `test_preflight.py` owns the reasoning and this is the same independent restatement.
API_VERSIONS = (
    "--api-versions", "cert-manager.io/v1",
    "--api-versions", "gateway.envoyproxy.io/v1alpha1",
)

# EVERY SCRIPT VARIANT AT ONCE. The adopter values turn on cert-manager's probe and
# the post-install probe; these turn on the three preflight probes nothing ties on,
# and the fifth bootstrap Secret. The deadline gate needs the LARGEST script each Job
# can run, and the curl gate needs every curl that can render.
EVERY_VARIANT_ON = (
    "--set",
    "preflight.probes.keda=true,preflight.probes.mariadb=true,"
    "preflight.probes.prometheus=true,bootstrap.iamKeys.create=true",
)

HOOK_ANNOTATIONS = ("helm.sh/hook", "argocd.argoproj.io/hook")

# ── THE EXEMPTIONS: UPSTREAM HOOK JOBS WITH NO KEY FOR A DEADLINE ─────────────
# Read off each chart at the version `chart/Chart.yaml` pins, measured 2026-10-02:
# neither the Job spec nor the pod spec of any of the three renders
# `activeDeadlineSeconds` from a value, so no values file can bound them, and the
# estate does not fork upstream templates. Keyed by the template's path in the
# render AND the pinned version: a bump of the dependency fails
# `test_every_exemption_names_the_version_chart_yaml_pins` until somebody re-reads
# the new chart and either moves the version here or bounds the Job.
EXEMPT_UPSTREAM_HOOK_JOBS = {
    # `startupapicheck.timeout` (1m) is its `--wait`, and `backoffLimit` 4; the
    # pod's image pull is the part nothing bounds.
    "platform/charts/cert-manager/templates/startupapicheck-job.yaml": ("cert-manager", "v1.21.1"),
    # `backoffLimit: 1` is a literal in the template; no deadline key on Job or pod.
    "platform/charts/gateway-helm/templates/certgen.yaml": ("gateway-helm", "v1.9.1"),
    # `ttlSecondsAfterFinished: 60` is a literal; no deadline key on Job or pod.
    "platform/charts/argo-cd/templates/redis-secret-init/job.yaml": ("argo-cd", "8.6.1"),
}

# ── THE LITERALS THE ARITHMETIC IS CHECKED AGAINST ────────────────────────────
# The margin over a probe Job's composed loops: pod scheduling and the image pull.
# Since ledger 1235 the script keeps its own wall-clock budget of exactly the
# composed loops, so this margin also covers what runs past that budget — the
# requests in flight and the cleanup — which section 4 below checks it does.
# The same 300s README.md documents for the helm budget — a stated CEILING, not a
# measurement.
PROBE_DEADLINE_MARGIN_SECONDS = 300

# Kubernetes caps ONE admission webhook's `timeoutSeconds` at 30. Measured on
# kind-yadgar (2026-10-02): of what these probes create, cert-manager's Issuer
# and Certificate cross its VALIDATING webhook (30s); KEDA's ScaledObject and
# the mariadb dry-run cross validating-only webhooks at 10s. NO PROBED CREATE
# CROSSES A MUTATING WEBHOOK: cert-manager's matches `certificaterequests`
# only, which no probe creates directly. So today this is the largest SINGLE
# webhook any probed request can cross, not a sum over a mutating-then-
# validating chain; an adopter whose own admission webhooks also match these
# kinds could need more.
LARGEST_WEBHOOK_TIMEOUT_SECONDS = 30

# The Job controller's pod-failure backoff: 10s, doubled per failure, capped at six
# minutes (Kubernetes documentation, "Pod backoff failure policy").
JOB_BACKOFF_BASE_SECONDS = 10
JOB_BACKOFF_CAP_SECONDS = 360

# A bootstrap attempt's allowance for scheduling the pod and starting its container,
# before the script's first request. A stated ceiling.
BOOTSTRAP_ATTEMPT_START_SECONDS = 30

# The estate's own hook Jobs, which this suite checks the arithmetic of.
PROBE_JOBS = ("preflight", "envoy-gateway-probe")
BOOTSTRAP_JOBS = ("bootstrap-secrets", "admin-bootstrap-token")


# ── RENDERING ─────────────────────────────────────────────────────────────────

def helm(*arguments: str) -> subprocess.CompletedProcess[str]:
    binary = shutil.which("helm")
    # NOT A SKIP, and ADR-0650 is why — the same wording the suites beside this use.
    assert binary, (
        "helm is not on PATH. This suite renders the chart, and so does the "
        "`helm lint and render` pre-commit hook — install helm rather than "
        "letting either report a pass it did not earn."
    )
    return subprocess.run([binary, *arguments], capture_output=True, text=True)


SOURCE_LINE = re.compile(r"^# Source: (?P<source>\S+)\s*$", re.MULTILINE)


def sourced_documents(stdout: str) -> list[tuple[str, dict]]:
    """Each rendered document with the template it came from."""
    found = []
    for chunk in re.split(r"^---\s*$", stdout, flags=re.MULTILINE):
        source = SOURCE_LINE.search(chunk)
        document = yaml.safe_load(chunk)
        if source and isinstance(document, dict) and document.get("apiVersion"):
            found.append((source.group("source"), document))
    return found


def render(chart: Path, namespace: str, *arguments: str) -> list[tuple[str, dict]]:
    result = helm("template", "platform", str(chart), "--namespace", namespace, *arguments)
    assert result.returncode == 0, result.stderr
    return sourced_documents(result.stdout)


def estate_render(chart: Path = CHART) -> list[tuple[str, dict]]:
    return render(
        chart, RELEASE_NAMESPACE, *API_VERSIONS, "-f", str(ADOPTER_VALUES), *EVERY_VARIANT_ON
    )


def operators_render(chart: Path = CHART) -> list[tuple[str, dict]]:
    return render(chart, OPERATORS_NAMESPACE, "--set", "operators.create=true")


def every_render(chart: Path = CHART) -> list[tuple[str, dict]]:
    return estate_render(chart) + operators_render(chart)


def is_hook(document: dict) -> bool:
    annotations = (document.get("metadata") or {}).get("annotations") or {}
    return any(key in annotations for key in HOOK_ANNOTATIONS)


def hook_jobs(documents: list[tuple[str, dict]]) -> list[tuple[str, dict]]:
    return [(s, d) for s, d in documents if d.get("kind") == "Job" and is_hook(d)]


def job_named(documents: list[tuple[str, dict]], name: str) -> dict:
    found = [d for _, d in hook_jobs(documents) if d["metadata"]["name"] == name]
    assert len(found) == 1, f"expected one hook Job {name}, found {len(found)}"
    return found[0]


def script_of(job: dict) -> str:
    container = job["spec"]["template"]["spec"]["containers"][0]
    assert container.get("command") == ["sh", "-c"], (
        f"{job['metadata']['name']} no longer runs `sh -c`, so this suite reads no script"
    )
    return container["args"][0]


def chart_copy(destination: Path) -> Path:
    copy = destination / "chart"
    shutil.copytree(CHART, copy)
    return copy


def replace_once(path: Path, old: str, new: str) -> None:
    """Mutate a copied file, refusing a replacement that replaced nothing."""
    text = path.read_text()
    assert old in text, f"{path.name} no longer carries {old!r}; this red case tests nothing"
    path.write_text(text.replace(old, new, 1))


# ── 1. THE GATE ───────────────────────────────────────────────────────────────

def deadline_failures(documents: list[tuple[str, dict]]) -> list[str]:
    """Every hook Job carries a positive deadline unless it is exempt. PURE."""
    failures = []
    seen = []
    for source, job in hook_jobs(documents):
        seen.append(source)
        deadline = job["spec"].get("activeDeadlineSeconds")
        if source in EXEMPT_UPSTREAM_HOOK_JOBS:
            if deadline is not None:
                failures.append(
                    f"{source} now carries activeDeadlineSeconds: {deadline}; its "
                    f"exemption is stale and must be deleted"
                )
            continue
        if not isinstance(deadline, int) or deadline <= 0:
            failures.append(
                f"hook Job {job['metadata']['name']} ({source}) carries no positive "
                f"activeDeadlineSeconds (found {deadline!r}), so a pod that never "
                f"starts holds its sync open until the caller gives up"
            )
    missing = sorted(set(EXEMPT_UPSTREAM_HOOK_JOBS) - set(seen))
    if missing:
        failures.append(
            f"exempt hook Jobs no longer render: {missing}. Delete the exemption, or "
            f"the render this gate reads has stopped covering the operators"
        )
    return failures


def test_every_hook_job_carries_a_deadline():
    failures = deadline_failures(every_render())
    assert failures == [], "\n".join(failures)


def test_every_exemption_names_the_version_chart_yaml_pins():
    pinned = {
        dependency["name"]: dependency["version"]
        for dependency in yaml.safe_load((CHART / "Chart.yaml").read_text())["dependencies"]
    }
    stale = [
        f"{source}: exempted at {name} {version}, Chart.yaml pins {pinned.get(name)}"
        for source, (name, version) in EXEMPT_UPSTREAM_HOOK_JOBS.items()
        if pinned.get(name) != version
    ]
    assert stale == [], (
        "a subchart moved, so its exemption is for a chart nobody has read. Re-read "
        "the new chart for a deadline key, then bound the Job or move the version:\n"
        + "\n".join(stale)
    )


def test_deleting_a_deadline_reddens_the_gate(tmp_path):
    copy = chart_copy(tmp_path)
    replace_once(
        copy / "templates" / "bootstrap-secrets.yaml",
        "  activeDeadlineSeconds:",
        "  # activeDeadlineSeconds:",
    )
    failures = deadline_failures(every_render(copy))
    message = "\n".join(failures)
    assert failures, "bootstrap-secrets lost its deadline and the gate passed"
    assert "hook Job bootstrap-secrets (platform/templates/bootstrap-secrets.yaml)" in message, message


def test_a_new_unbounded_hook_job_reddens_the_gate(tmp_path):
    copy = chart_copy(tmp_path)
    (copy / "templates" / "zz-unbounded-hook.yaml").write_text(
        "apiVersion: batch/v1\nkind: Job\nmetadata:\n  name: unbounded\n"
        "  annotations:\n    argocd.argoproj.io/hook: PreSync\n"
        "spec:\n  template:\n    spec:\n      restartPolicy: Never\n"
        "      containers: [{name: c, image: busybox}]\n"
    )
    failures = deadline_failures(every_render(copy))
    message = "\n".join(failures)
    assert "hook Job unbounded (platform/templates/zz-unbounded-hook.yaml)" in message, message


# ── 2. THE ARITHMETIC ─────────────────────────────────────────────────────────

# `remove()` and `create()` (which calls `remove()`) each run one bounded loop. A
# path removed twice waits once — the second `remove` answers 404 on its first GET —
# so removals count by DISTINCT PATH; `test_preflight.py` documents the same rule.
REMOVAL_CALL = re.compile(r'^[ ]*(?:create|remove) "(?P<path>[^"]+)"', re.MULTILINE)
AWAIT_CALL = re.compile(r'^[ ]*await "', re.MULTILINE)
CREATE_CALL = re.compile(r'^[ ]*create "', re.MULTILINE)
# A bounded loop written out where it is used rather than reached through
# `remove()` or `await()` — the Prometheus probe's. The two helpers no longer
# carry this header: since ledger 1235 they loop on the wall clock (`while :;`
# ended by `in_time`), so every match of it is a loop of its own.
BOUNDED_WHILE = re.compile(r'^[ ]*while \[ "\$waited" -lt "\$TIMEOUT_SECONDS" \]; do$', re.MULTILINE)
HELPER_DEFINITIONS = ("remove() {", "await() {")
# An object recorded for cleanup outside `create()` — the Secret a Certificate writes.
EXTRA_CLEANUP = re.compile(r'^[ ]*CREATED="\$CREATED \$(?!1")\w+"$', re.MULTILINE)
BOOTSTRAP_CREATE = re.compile(r"^[ ]*create \S+ <<JSON$", re.MULTILINE)

# `cleanup()` MUST SWAP THE SHORTER TIMEOUT IN before it runs its DELETEs, or the
# pod's terminationGracePeriodSeconds — sized off CLEANUP_MAX_TIME — no longer
# covers what `request()` can actually take once a kill fires.
CLEANUP_SWAP = re.compile(r'cleanup\(\) \{\s*\n\s*REQUEST_MAX_TIME="\$CLEANUP_MAX_TIME"\s*\n')

# THE PROMETHEUS LOOP, ISOLATED SO ITS CURL AND ITS CHARGE CAN BE COMPARED. No
# other `{` appears inside the function, so a non-greedy DOTALL match to the
# first lone `}` is the whole body.
PROMETHEUS_FUNCTION = re.compile(r"probe_prometheus\(\) \{(?P<body>.*?)\n\s*\}\n", re.DOTALL)
PROMETHEUS_MAXTIME_FLAG = re.compile(r'--max-time "\$(?P<ref>[A-Za-z_]\w*)"')
PROMETHEUS_WAITED_CHARGE = re.compile(r"waited=\$\(\(waited \+ POLL_SECONDS \+ (?P<ref>[A-Za-z0-9_]+)\)\)")

# A LITERAL NUMBER ASSIGNED TO A SHELL VARIABLE, the same shape `script_number`
# reads one name of at a time. Built once per script so a curl's `--max-time
# "$VAR"` can be resolved to the number VAR actually holds, rather than only
# checked for presence.
VARIABLE_LITERAL = re.compile(r"^\s*(?P<name>[A-Z_][A-Z0-9_]*)=(?P<value>\d+)\s*$", re.MULTILINE)


def literal_values(script: str) -> dict[str, int]:
    return {m.group("name"): int(m.group("value")) for m in VARIABLE_LITERAL.finditer(script)}


def cleanup_swap_failures(name: str, script: str) -> list[str]:
    """`cleanup()` swaps CLEANUP_MAX_TIME in before its DELETEs. PURE."""
    if "cleanup() {" not in script:
        return []
    if not CLEANUP_SWAP.search(script):
        return [
            f"{name}: cleanup() does not swap REQUEST_MAX_TIME for CLEANUP_MAX_TIME before "
            f"its DELETEs, so a kill mid-cleanup can run past terminationGracePeriodSeconds"
        ]
    return []


def prometheus_charge_failures(script: str) -> list[str]:
    """The Prometheus loop charges waited its own curl's --max-time, not a guess. PURE."""
    if "probe_prometheus() {" not in script:
        return []
    match = PROMETHEUS_FUNCTION.search(script)
    if not match:
        return ["preflight: could not isolate probe_prometheus() to check its waited charge"]
    body = match.group("body")
    maxtime = PROMETHEUS_MAXTIME_FLAG.search(body)
    charge = PROMETHEUS_WAITED_CHARGE.search(body)
    if not maxtime or not charge:
        return [
            "preflight: probe_prometheus() no longer sets --max-time or charges waited the "
            "way this check expects"
        ]
    if maxtime.group("ref") != charge.group("ref"):
        return [
            f"preflight: the Prometheus loop charges waited += POLL_SECONDS + "
            f"{charge.group('ref')}, not the {maxtime.group('ref')} its own curl's "
            f"--max-time uses, so a hanging address is not bounded by its own request timeout"
        ]
    return []


def script_number(script: str, name: str) -> int:
    match = re.search(rf"^\s*{name}=(?P<n>\d+)\s*$", script, re.MULTILINE)
    assert match, f"the rendered script sets no {name}"
    return int(match.group("n"))


def bounded_loops(script: str) -> int:
    for helper in HELPER_DEFINITIONS:
        assert helper in script, f"the rendered script no longer defines {helper}"
    removed = {m.group("path") for m in REMOVAL_CALL.finditer(script) if m.group("path") != "$1"}
    inline = len(BOUNDED_WHILE.findall(script))
    return len(removed) + len(AWAIT_CALL.findall(script)) + inline


def cleanup_objects(script: str) -> int:
    return len(CREATE_CALL.findall(script)) + len(EXTRA_CLEANUP.findall(script))


def probe_job_failures(job: dict, expected_loops: int, expected_objects: int) -> list[str]:
    """A probe Job's deadline and grace, recomputed off its rendered script. PURE."""
    name = job["metadata"]["name"]
    script = script_of(job)
    failures = []
    loops = bounded_loops(script)
    objects = cleanup_objects(script)
    # THE COUNTS ARE ASSERTED AS WELL AS USED, so a script that stopped matching the
    # patterns above cannot pass by computing a smaller deadline from zero.
    if loops != expected_loops or objects != expected_objects:
        failures.append(
            f"{name}: the rendered script runs {loops} bounded loops and leaves "
            f"{objects} objects for its cleanup; this suite expects {expected_loops} "
            f"and {expected_objects}"
        )
    bound = script_number(script, "TIMEOUT_SECONDS")
    wanted = loops * bound + PROBE_DEADLINE_MARGIN_SECONDS
    deadline = job["spec"].get("activeDeadlineSeconds")
    if deadline != wanted:
        failures.append(
            f"{name}: activeDeadlineSeconds is {deadline!r} and its script needs "
            f"{wanted}s: {loops} bounded loops x {bound}s + "
            f"{PROBE_DEADLINE_MARGIN_SECONDS}s margin"
        )
    request = script_number(script, "REQUEST_MAX_TIME")
    cleanup = script_number(script, "CLEANUP_MAX_TIME")
    if request <= LARGEST_WEBHOOK_TIMEOUT_SECONDS:
        failures.append(
            f"{name}: REQUEST_MAX_TIME is {request}s, at or under the "
            f"{LARGEST_WEBHOOK_TIMEOUT_SECONDS}s an admission webhook may take"
        )
    # `sh` defers its TERM trap until the foreground command returns, so the pod
    # needs the request in flight plus one cleanup request per object it made.
    grace = request + objects * cleanup
    found = job["spec"]["template"]["spec"].get("terminationGracePeriodSeconds")
    if found != grace:
        failures.append(
            f"{name}: terminationGracePeriodSeconds is {found!r} and its cleanup "
            f"needs {grace}s: {request}s in flight + {objects} objects x {cleanup}s"
        )
    failures += cleanup_swap_failures(name, script)
    failures += prometheus_charge_failures(script)
    return failures


def job_backoff_seconds(limit: int) -> int:
    return sum(
        min(JOB_BACKOFF_BASE_SECONDS * 2 ** k, JOB_BACKOFF_CAP_SECONDS) for k in range(limit)
    )


def bootstrap_job_failures(job: dict, expected_requests: int) -> list[str]:
    """A bootstrap Job's deadline, recomputed off its rendered script. PURE."""
    name = job["metadata"]["name"]
    script = script_of(job)
    failures = []
    requests = len(BOOTSTRAP_CREATE.findall(script))
    if requests != expected_requests:
        failures.append(
            f"{name}: the rendered script makes {requests} requests; this suite "
            f"expects {expected_requests}"
        )
    limit = job["spec"]["backoffLimit"]
    request = script_number(script, "REQUEST_MAX_TIME")
    connect = script_number(script, "CONNECT_TIMEOUT")
    # A REQUEST CANNOT TAKE LESS THAN ITS OWN CONNECT PHASE. `REQUEST_MAX_TIME` at
    # or under `CONNECT_TIMEOUT` aborts a request that only just finished
    # connecting, so curl could never see a POST through — the arithmetic above
    # stays consistent at any value, which is why this floor is checked here and
    # not inferred from it.
    if request <= connect:
        failures.append(
            f"{name}: REQUEST_MAX_TIME is {request}s, at or under its own "
            f"{connect}s CONNECT_TIMEOUT"
        )
    attempt = BOOTSTRAP_ATTEMPT_START_SECONDS + requests * request
    wanted = job_backoff_seconds(limit) + (limit + 1) * attempt
    deadline = job["spec"].get("activeDeadlineSeconds")
    if deadline != wanted:
        failures.append(
            f"{name}: activeDeadlineSeconds is {deadline!r} and its attempts need "
            f"{wanted}s: {job_backoff_seconds(limit)}s pod backoff + {limit + 1} "
            f"attempts x ({BOOTSTRAP_ATTEMPT_START_SECONDS}s start + {requests} "
            f"requests x {request}s)"
        )
    return failures


# The largest scripts, as EVERY_VARIANT_ON renders them. cert-manager 4 loops and 3
# objects (Issuer, Certificate, its Secret), KEDA 3 and 2, Prometheus 1 and 0,
# mariadb-operator 0 and 0. The post-install probe: 3 loops, 2 objects.
EXPECTED_SHAPES = {"preflight": (8, 5), "envoy-gateway-probe": (3, 2)}
EXPECTED_REQUESTS = {"bootstrap-secrets": 4, "admin-bootstrap-token": 1}


def test_each_probe_deadline_is_its_scripts_composed_bound():
    documents = estate_render()
    failures = []
    for name, (loops, objects) in EXPECTED_SHAPES.items():
        failures += probe_job_failures(job_named(documents, name), loops, objects)
    assert failures == [], "\n".join(failures)


def test_each_bootstrap_deadline_covers_every_attempt():
    documents = estate_render()
    failures = []
    for name, requests in EXPECTED_REQUESTS.items():
        failures += bootstrap_job_failures(job_named(documents, name), requests)
    assert failures == [], "\n".join(failures)


def test_the_preflight_deadline_follows_the_probes_the_render_enables():
    """Only cert-manager on, as the adopter values leave it: 4 loops, 3 objects."""
    documents = render(CHART, RELEASE_NAMESPACE, *API_VERSIONS, "-f", str(ADOPTER_VALUES))
    failures = probe_job_failures(job_named(documents, "preflight"), 4, 3)
    assert failures == [], "\n".join(failures)


def test_the_deadline_follows_a_raised_bound(tmp_path):
    """The deadline is derived, so raising the loop bound cannot outrun it."""
    documents = render(
        CHART, RELEASE_NAMESPACE, *API_VERSIONS, "-f", str(ADOPTER_VALUES),
        *EVERY_VARIANT_ON, "--set", "preflight.timeoutSeconds=240",
    )
    failures = probe_job_failures(job_named(documents, "preflight"), 8, 5)
    assert failures == [], "\n".join(failures)


def test_an_undercounted_probe_reddens_the_deadline_arithmetic(tmp_path):
    copy = chart_copy(tmp_path)
    replace_once(
        copy / "templates" / "preflight.yaml",
        '"cert-manager" (list 4 3)',
        '"cert-manager" (list 3 3)',
    )
    documents = render(copy, RELEASE_NAMESPACE, *API_VERSIONS, "-f", str(ADOPTER_VALUES), *EVERY_VARIANT_ON)
    message = "\n".join(probe_job_failures(job_named(documents, "preflight"), 8, 5))
    assert "preflight: activeDeadlineSeconds is 1140 and its script needs 1260s" in message, message


def test_an_unrecorded_cleanup_object_reddens_the_grace_arithmetic(tmp_path):
    copy = chart_copy(tmp_path)
    replace_once(
        copy / "templates" / "preflight.yaml",
        '"keda" (list 3 2)',
        '"keda" (list 3 1)',
    )
    documents = render(copy, RELEASE_NAMESPACE, *API_VERSIONS, "-f", str(ADOPTER_VALUES), *EVERY_VARIANT_ON)
    message = "\n".join(probe_job_failures(job_named(documents, "preflight"), 8, 5))
    assert "preflight: terminationGracePeriodSeconds is 55 and its cleanup needs 60s" in message, message


def test_a_bootstrap_request_left_uncounted_reddens_the_deadline_arithmetic(tmp_path):
    copy = chart_copy(tmp_path)
    replace_once(
        copy / "templates" / "bootstrap-secrets.yaml",
        "{{- $requests := 3 }}",
        "{{- $requests := 2 }}",
    )
    documents = render(copy, RELEASE_NAMESPACE, *API_VERSIONS, "-f", str(ADOPTER_VALUES), *EVERY_VARIANT_ON)
    message = "\n".join(bootstrap_job_failures(job_named(documents, "bootstrap-secrets"), 4))
    assert "bootstrap-secrets: activeDeadlineSeconds is 450 and its attempts need 500s" in message, message


def test_a_request_timeout_under_a_webhooks_reddens_the_probe_gate(tmp_path):
    copy = chart_copy(tmp_path)
    replace_once(
        copy / "templates" / "_preflight.tpl",
        '"platform.hookRequest.maxTime" -}}35{{',
        '"platform.hookRequest.maxTime" -}}30{{',
    )
    documents = render(copy, RELEASE_NAMESPACE, *API_VERSIONS, "-f", str(ADOPTER_VALUES), *EVERY_VARIANT_ON)
    message = "\n".join(probe_job_failures(job_named(documents, "preflight"), 8, 5))
    assert "preflight: REQUEST_MAX_TIME is 30s, at or under the 30s" in message, message


def test_deleting_the_cleanup_swap_reddens_the_gate(tmp_path):
    copy = chart_copy(tmp_path)
    replace_once(
        copy / "templates" / "preflight.yaml",
        'REQUEST_MAX_TIME="$CLEANUP_MAX_TIME"',
        "NOOP_SWAP_REMOVED=1",
    )
    documents = render(copy, RELEASE_NAMESPACE, *API_VERSIONS, "-f", str(ADOPTER_VALUES), *EVERY_VARIANT_ON)
    message = "\n".join(probe_job_failures(job_named(documents, "preflight"), 8, 5))
    assert (
        "preflight: cleanup() does not swap REQUEST_MAX_TIME for CLEANUP_MAX_TIME"
        in message
    ), message


def test_the_envoy_probes_cleanup_swap_also_reddens_the_gate(tmp_path):
    copy = chart_copy(tmp_path)
    replace_once(
        copy / "templates" / "envoy-gateway-probe.yaml",
        'REQUEST_MAX_TIME="$CLEANUP_MAX_TIME"',
        "NOOP_SWAP_REMOVED=1",
    )
    documents = render(copy, RELEASE_NAMESPACE, *API_VERSIONS, "-f", str(ADOPTER_VALUES), *EVERY_VARIANT_ON)
    message = "\n".join(probe_job_failures(job_named(documents, "envoy-gateway-probe"), 3, 2))
    assert (
        "envoy-gateway-probe: cleanup() does not swap REQUEST_MAX_TIME for "
        "CLEANUP_MAX_TIME" in message
    ), message


def test_charging_the_prometheus_loop_a_constant_reddens_the_gate(tmp_path):
    copy = chart_copy(tmp_path)
    replace_once(
        copy / "templates" / "preflight.yaml",
        "waited=$((waited + POLL_SECONDS + PROMETHEUS_MAX_TIME))",
        "waited=$((waited + POLL_SECONDS + 1))",
    )
    documents = render(copy, RELEASE_NAMESPACE, *API_VERSIONS, "-f", str(ADOPTER_VALUES), *EVERY_VARIANT_ON)
    message = "\n".join(probe_job_failures(job_named(documents, "preflight"), 8, 5))
    assert (
        "preflight: the Prometheus loop charges waited += POLL_SECONDS + 1, not "
        "the PROMETHEUS_MAX_TIME" in message
    ), message


def test_a_bootstrap_request_at_its_connect_timeout_reddens_the_floor_gate(tmp_path):
    copy = chart_copy(tmp_path)
    replace_once(
        copy / "templates" / "_preflight.tpl",
        '"platform.hookRequest.bootstrapMaxTime" -}}10{{',
        '"platform.hookRequest.bootstrapMaxTime" -}}1{{',
    )
    documents = render(copy, RELEASE_NAMESPACE, *API_VERSIONS, "-f", str(ADOPTER_VALUES), *EVERY_VARIANT_ON)
    message = "\n".join(bootstrap_job_failures(job_named(documents, "bootstrap-secrets"), 4))
    assert (
        "bootstrap-secrets: REQUEST_MAX_TIME is 1s, at or under its own 5s CONNECT_TIMEOUT"
        in message
    ), message


# ── THE DEADLINES AGAINST THE DOCUMENTED HELM BUDGET ──────────────────────────
# Helm's `--timeout` covers each hook Job from its creation. A deadline (plus the
# grace its pod is given) at or past that budget means helm gives up first and
# reports `timed out waiting for the condition` instead of the Job's own failure.
TIMEOUT_FLAG = re.compile(r"--timeout\s+(?P<budget>\d+)m\b")


def budget_failures(documents: list[tuple[str, dict]], readme: str) -> list[str]:
    budgets = [int(m.group("budget")) * 60 for m in TIMEOUT_FLAG.finditer(readme)]
    assert budgets, "README.md states no `--timeout <n>m`; this gate compares nothing"
    failures = []
    for name in PROBE_JOBS + BOOTSTRAP_JOBS:
        job = job_named(documents, name)
        grace = job["spec"]["template"]["spec"].get("terminationGracePeriodSeconds", 30)
        ends = job["spec"]["activeDeadlineSeconds"] + grace
        if ends >= min(budgets):
            failures.append(
                f"{name}: deadline + grace = {ends}s, at or past the documented "
                f"`--timeout` of {min(budgets)}s"
            )
    return failures


def test_every_deadline_ends_inside_the_documented_helm_budget():
    failures = budget_failures(estate_render(), README.read_text())
    assert failures == [], "\n".join(failures)


def test_a_budget_cut_below_a_deadline_reddens_the_budget_gate():
    readme = README.read_text()
    assert "--timeout 25m" in readme, "README.md no longer says `--timeout 25m`"
    message = "\n".join(budget_failures(estate_render(), readme.replace("--timeout 25m", "--timeout 20m")))
    assert "preflight: deadline + grace = 1320s, at or past the documented `--timeout` of 1200s" in message, message


# ── THE SYNC-TIMEOUT FLOOR (ADR-0830) ─────────────────────────────────────────
# `controller.sync.timeout.seconds` is the ONE Argo-side backstop behind every
# hook deadline above, and ADR-0830 sizes it from the whole worst-case retry
# chain: a floor (Argo's own retry backoff, plus one more attempt) plus 7 ×
# the per-attempt allowance. This suite's own deadlines ARE that allowance's
# three largest pieces, so a change here that grows any of them can silently
# grow the floor past what both consumers of this one shared value carry —
# `yadgarhq/chart bootstrap/argocd-values.yaml` (kind installs) and
# `yadgarhq/argocd install/values.yaml` (this organisation) — without either
# of those repositories' own suites ever seeing this chart change at all.
#
# THE PER-ATTEMPT ALLOWANCE, counted the way ADR-0830 counts it: the
# preflight's deadline plus its pod's grace, the Envoy Gateway probe's
# deadline plus its grace, the LARGER of the two bootstrap Jobs' deadlines
# (they run in parallel, so the attempt waits on whichever is slower) plus
# the default 30s pod grace neither bootstrap Job overrides, plus the 270s
# Sync-phase health wait ADR-0830 measured (gitops-engine's PostSync wait,
# ≥90s per workload × 3).
#
# THE WINDOW DIFFERS BY CONSUMER, not by `iamKeys.create` itself — that flag
# only happens to key which of the two consumers each variant stands in for,
# since this suite renders neither `Application` manifest directly:
#   kind consumer (iamKeys on): 1200, `yadgarhq/chart`'s `RETRY_WINDOW_SECONDS`
#   gate ceiling (`scripts/tests/test_parent_chart.py`) — the UPPER bound that
#   gate allows any `retry.limit`/`backoff` in the kind example to reach, used
#   here rather than today's configured 1050s so a future edit still inside
#   that gate cannot silently outrun this floor.
#   org consumer (iamKeys off): 1050, `yadgarhq/argocd`'s REAL backoff —
#   30 + 60 + 120 + 240 + 300 + 300 (duration 15s, factor 2, maxDuration 5m,
#   limit 6) — because that repository carries no such range gate, so the one
#   configured value is the only one to count.
SYNC_TIMEOUT_WINDOW_SECONDS = {True: 1200, False: 1050}
POST_SYNC_HEALTH_WAIT_SECONDS = 270
BOOTSTRAP_DEFAULT_POD_GRACE_SECONDS = 30
CURRENT_SYNC_TIMEOUT_SECONDS = 25200
SYNC_TIMEOUT_CONSUMERS = (
    "yadgarhq/chart bootstrap/argocd-values.yaml",
    "yadgarhq/argocd install/values.yaml",
)


def job_total(job: dict) -> int:
    """A Job's activeDeadlineSeconds plus its pod's grace (default 30s, the
    bootstrap Jobs' own, since neither overrides terminationGracePeriodSeconds)."""
    grace = job["spec"]["template"]["spec"].get("terminationGracePeriodSeconds", 30)
    return job["spec"]["activeDeadlineSeconds"] + grace


def sync_timeout_floor_failures(iam_keys_create: bool, preflight_timeout_seconds: int | None = None) -> list[str]:
    """The ADR-0830 floor for one `iamKeys.create` variant, against the one
    `controller.sync.timeout.seconds` both consumers currently carry. PURE."""
    overrides = (
        "preflight.probes.keda=true,preflight.probes.mariadb=true,"
        f"preflight.probes.prometheus=true,bootstrap.iamKeys.create={str(iam_keys_create).lower()}"
    )
    if preflight_timeout_seconds is not None:
        overrides += f",preflight.timeoutSeconds={preflight_timeout_seconds}"
    documents = render(CHART, RELEASE_NAMESPACE, *API_VERSIONS, "-f", str(ADOPTER_VALUES), "--set", overrides)
    preflight_total = job_total(job_named(documents, "preflight"))
    probe_total = job_total(job_named(documents, "envoy-gateway-probe"))
    bootstrap_deadline = max(
        job_named(documents, "bootstrap-secrets")["spec"]["activeDeadlineSeconds"],
        job_named(documents, "admin-bootstrap-token")["spec"]["activeDeadlineSeconds"],
    )
    attempt = (
        preflight_total + probe_total + bootstrap_deadline
        + BOOTSTRAP_DEFAULT_POD_GRACE_SECONDS + POST_SYNC_HEALTH_WAIT_SECONDS
    )
    window = SYNC_TIMEOUT_WINDOW_SECONDS[iam_keys_create]
    floor = window + 7 * attempt
    if floor > CURRENT_SYNC_TIMEOUT_SECONDS:
        return [
            f"iamKeys.create={iam_keys_create}: the per-attempt allowance is {attempt}s "
            f"(preflight {preflight_total}s + probe {probe_total}s + bootstrap "
            f"{bootstrap_deadline}s + {BOOTSTRAP_DEFAULT_POD_GRACE_SECONDS}s pod grace + "
            f"{POST_SYNC_HEALTH_WAIT_SECONDS}s Sync-phase health), so the floor is "
            f"{window} + 7x{attempt} = {floor}s, past the {CURRENT_SYNC_TIMEOUT_SECONDS}s "
            f"controller.sync.timeout.seconds ADR-0830 sizes for BOTH "
            f"{SYNC_TIMEOUT_CONSUMERS[0]} and {SYNC_TIMEOUT_CONSUMERS[1]}, which share one value"
        ]
    return []


def test_the_sync_timeout_floor_holds_for_both_iamkeys_variants():
    failures = []
    for iam_keys_create in (True, False):
        failures += sync_timeout_floor_failures(iam_keys_create)
    assert failures == [], "\n".join(failures)


def test_a_raised_preflight_bound_reddens_the_sync_timeout_floor_gate():
    message = "\n".join(sync_timeout_floor_failures(True, preflight_timeout_seconds=600))
    assert "iamKeys.create=True" in message, message
    assert "past the 25200s controller.sync.timeout.seconds" in message, message
    assert SYNC_TIMEOUT_CONSUMERS[0] in message and SYNC_TIMEOUT_CONSUMERS[1] in message, message
    assert "ADR-0830" in message, message


# ── 3. THE CURLS ──────────────────────────────────────────────────────────────

CURL_COMMAND = re.compile(r"(?:^|[\s(|;&])curl(?=\s)")
REQUIRED_CURL_FLAGS = ("--max-time", "--connect-timeout")


def logical_lines(script: str) -> list[str]:
    """Comment lines dropped, backslash continuations joined."""
    lines = []
    pending = ""
    for raw in script.splitlines():
        if raw.lstrip().startswith("#"):
            continue
        if raw.rstrip().endswith("\\"):
            pending += raw.rstrip()[:-1] + " "
            continue
        lines.append(pending + raw)
        pending = ""
    if pending:
        lines.append(pending)
    return lines


def flag_reference(flag: str, invocation: str) -> re.Match[str] | None:
    """Where $(flag) points: a shell variable or a bare literal, either quoted."""
    return re.search(rf'(?:^|\s){re.escape(flag)}\s+"?\$?(?P<ref>[A-Za-z_]\w*|\d+)"?', invocation)


def curl_failures(scripts: dict[str, str]) -> list[str]:
    """Every curl in every hook script carries both timeouts, each a positive
    value. PURE. A flag that is merely PRESENT is not enough: `--max-time 0`
    means no limit at all, and `--max-time "$VAR"` where VAR resolves to 0 or
    less is the same defect spelled through a variable.
    """
    failures = []
    counted = 0
    for name, script in scripts.items():
        values = literal_values(script)
        for line in logical_lines(script):
            for match in CURL_COMMAND.finditer(line):
                counted += 1
                invocation = line[match.end():]
                for flag in REQUIRED_CURL_FLAGS:
                    flag_match = flag_reference(flag, invocation)
                    if not flag_match:
                        failures.append(
                            f"{name}: a curl carries no {flag}: {line.strip()[:160]}"
                        )
                        continue
                    ref = flag_match.group("ref")
                    value = int(ref) if ref.isdigit() else values.get(ref)
                    if value is None or value <= 0:
                        failures.append(
                            f"{name}: {flag} resolves to {ref}={value!r}, not a positive "
                            f"timeout: {line.strip()[:160]}"
                        )
    if counted == 0:
        failures.append("no curl found in any hook script; this gate compared nothing")
    return failures


def hook_scripts(documents: list[tuple[str, dict]]) -> dict[str, str]:
    scripts = {}
    for _, job in hook_jobs(documents):
        container = job["spec"]["template"]["spec"]["containers"][0]
        if container.get("command") == ["sh", "-c"]:
            scripts[job["metadata"]["name"]] = container["args"][0]
    return scripts


# preflight: request() twice + Prometheus; probe: request() twice; bootstrap 1 each.
EXPECTED_CURL_SCRIPTS = {"preflight", "envoy-gateway-probe", "bootstrap-secrets", "admin-bootstrap-token"}


def test_every_curl_in_a_hook_script_is_bounded():
    scripts = hook_scripts(every_render())
    assert set(scripts) == EXPECTED_CURL_SCRIPTS, sorted(scripts)
    failures = curl_failures(scripts)
    assert failures == [], "\n".join(failures)


def test_dropping_a_max_time_reddens_the_curl_gate():
    scripts = hook_scripts(every_render())
    original = scripts["admin-bootstrap-token"]
    mutated = original.replace('--max-time "$REQUEST_MAX_TIME" ', "", 1)
    assert mutated != original, "admin-bootstrap-token's curl no longer spells its --max-time"
    scripts["admin-bootstrap-token"] = mutated
    message = "\n".join(curl_failures(scripts))
    assert "admin-bootstrap-token: a curl carries no --max-time" in message, message


def test_dropping_a_connect_timeout_from_the_prometheus_curl_reddens_the_curl_gate():
    scripts = hook_scripts(every_render())
    original = scripts["preflight"]
    mutated = re.sub(
        r'--connect-timeout "\$CONNECT_TIMEOUT" \\\n\s*(--max-time "\$PROMETHEUS_MAX_TIME")',
        r"\1",
        original,
        count=1,
    )
    assert mutated != original, "the Prometheus curl no longer spells its timeouts this way"
    scripts["preflight"] = mutated
    message = "\n".join(curl_failures(scripts))
    assert "preflight: a curl carries no --connect-timeout" in message, message


def test_a_literal_zero_max_time_reddens_the_curl_value_gate():
    """`--max-time 0` means no limit at all. A flag that is merely present passes
    it, which is the gap this check exists to close."""
    scripts = hook_scripts(every_render())
    original = scripts["admin-bootstrap-token"]
    mutated = original.replace('--max-time "$REQUEST_MAX_TIME"', "--max-time 0", 1)
    assert mutated != original, "admin-bootstrap-token's curl no longer spells its --max-time this way"
    scripts["admin-bootstrap-token"] = mutated
    message = "\n".join(curl_failures(scripts))
    assert "admin-bootstrap-token: --max-time resolves to 0=0, not a positive timeout" in message, message


def test_a_zero_bootstrap_max_time_reddens_the_curl_value_gate(tmp_path):
    """The real-world shape of the same defect: the TEMPLATE value a curl's
    `--max-time "$REQUEST_MAX_TIME"` resolves through is zeroed, so the flag
    itself never changes and a presence-only check cannot see it."""
    copy = chart_copy(tmp_path)
    replace_once(
        copy / "templates" / "_preflight.tpl",
        '"platform.hookRequest.bootstrapMaxTime" -}}10{{',
        '"platform.hookRequest.bootstrapMaxTime" -}}0{{',
    )
    scripts = hook_scripts(every_render(copy))
    message = "\n".join(curl_failures(scripts))
    assert (
        "admin-bootstrap-token: --max-time resolves to REQUEST_MAX_TIME=0, not a "
        "positive timeout" in message
    ), message


# ── 4. THE WALL CLOCK: A SLOW API SERVER IS STILL NAMED BEFORE THE DEADLINE ──
#
# LEDGER 1235. `remove()` and `await()` used to bound their loops with a counter
# charged only the sleep between polls (`waited += POLL_SECONDS`), never the poll's
# own request. Against an API server that answers every poll in 34s, a 120s loop
# ran 40 polls — about 1480s of real time — so `activeDeadlineSeconds`, not the
# script, ended the Job, and the pod died with no operator named.
#
# The gates below RUN the rendered loops against a fake `curl` that advances a fake
# clock by SLOW_REQUEST_SECONDS per request, and fake `date` and `sleep` that read
# and advance the same clock. The clock lives in a FILE because `request()` runs
# `curl` inside `$( )`, a subshell, where a shell variable would not survive.
#
#   (a) THE LOOP'S OWN BOUND. One `remove` and one `await` against requests that
#       never succeed end within TIMEOUT_SECONDS + POLL_SECONDS + REQUEST_MAX_TIME
#       of their start, and the failure names what was slow.
#   (b) THE SCRIPT'S BUDGET. Started with less of SCRIPT_BUDGET_SECONDS left than
#       one loop's own bound, the loop ends by SCRIPT_DEADLINE + POLL_SECONDS +
#       2 x REQUEST_MAX_TIME, and says the BUDGET ended it rather than claiming the
#       operator is dead. A loop entered with no budget left does not poll at all.
#   (c) THE ARITHMETIC. SCRIPT_BUDGET_SECONDS is the recounted loops x
#       TIMEOUT_SECONDS, and the Job's deadline covers that budget, the worst
#       overrun past it, and the cleanup.

# Slow, and still under `--max-time`: the case a counter of sleeps cannot see.
SLOW_REQUEST_SECONDS = 34
CLOCK_START = 1_000_000

# A shell function the rendered script defines, lifted whole (the same shape
# `test_preflight.py`'s `REQUEST_FUNCTION` lifts `request()` with).
SHELL_FUNCTION = re.compile(
    r"^(?P<indent>[ ]*)(?P<name>[a-z_]+)\(\) \{\n(?:.*\n)*?(?P=indent)\}$",
    re.MULTILINE,
)
# Functions the harness must not lift: the probes themselves, and the cleanup,
# which reads a CREATED list the harness never builds.
NOT_LIFTED = re.compile(r"^(?:probe_\w+|cleanup)$")
QUOTED_ASSIGNMENT = re.compile(r"^[ ]*(?:USER_AGENT|PROGRAMMED_MESSAGE)=.*$", re.MULTILINE)
SCRIPT_DEADLINE_ASSIGNMENT = re.compile(r"^[ ]*SCRIPT_DEADLINE=.*$", re.MULTILINE)

FAKE_CLOCK = r"""
advance() {
  echo $(( $(cat "$CLOCK") + $1 )) >"$CLOCK"
}
date() {
  cat "$CLOCK"
}
sleep() {
  advance "$1"
}
curl() {
  calls=$(( $(cat "$CALLS") + 1 ))
  echo "$calls" >"$CALLS"
  if [ "$calls" -gt 10000 ]; then
    echo "harness: 10000 requests, the loop is unbounded" >&2
    exit 99
  fi
  advance "$SLOW"
  out=''
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --output|-o) out="$2"; shift 2 ;;
      *) shift ;;
    esac
  done
  printf '{}' >"$out"
  printf '200'
}
"""

# What each script's `await` is called with, by script: a needle the fake's `{}`
# body never satisfies, and the operator the failure must name.
AWAIT_DRIVERS = {
    "preflight": ('await "/apis/probe.invalid/v1/probes/slow" Ready True cert-manager', "cert-manager"),
    "envoy-gateway-probe": (
        'await "/apis/probe.invalid/v1/probes/slow" Programmed True "never written" "Envoy Gateway"',
        "Envoy Gateway",
    ),
}
REMOVE_PATH = "/apis/probe.invalid/v1/probes/stuck"


def slow_api_harness(script: str, driver: str, spend: str = "") -> str:
    """The rendered script's constants and helpers over a slow fake API server.

    `spend` is shell run after the script's own clock starts and before the driver,
    so a gate can use up part of the budget first. PURE.
    """
    lines = [
        "set -eu",
        'api="https://kubernetes.default.svc"',
        'sa="/var/run/secrets/kubernetes.io/serviceaccount"',
        'ns="yadgar"',
        'token="a-token-the-fake-never-reads"',
        'body="$SCRATCH/answer"',
        'STATUS=""',
        'CREATED=""',
        FAKE_CLOCK,
    ]
    lines += [m.group(0).strip() for m in VARIABLE_LITERAL.finditer(script)]
    lines += [m.group(0).strip() for m in QUOTED_ASSIGNMENT.finditer(script)]
    # ABSENT IS NOT AN ERROR HERE: before ledger 1235 there was no script clock, and
    # gate (a) has to RUN in that state to be red for the right reason.
    lines += [m.group(0).strip() for m in SCRIPT_DEADLINE_ASSIGNMENT.finditer(script)]
    for function in SHELL_FUNCTION.finditer(script):
        if not NOT_LIFTED.match(function.group("name")):
            lines.append(textwrap.dedent(function.group(0)))
    lines += [
        spend,
        'started_at="$(date)"',
        'status=0',
        f"{driver} || status=$?",
        'echo "$(( $(date) - started_at )) $status" >"$SCRATCH/result"',
        "",
    ]
    return "\n".join(lines)


def run_slow(script: str, driver: str, scratch: Path, spend: str = ""):
    """Run one driver; return (elapsed fake seconds, its status, stderr)."""
    scratch.mkdir(parents=True, exist_ok=True)
    (scratch / "clock").write_text(f"{CLOCK_START}\n")
    (scratch / "calls").write_text("0\n")
    harness = scratch / "harness.sh"
    harness.write_text(slow_api_harness(script, driver, spend))
    binary = shutil.which("sh")
    assert binary, "no POSIX shell is on PATH; the probe's container runs these loops under `sh`"
    result = subprocess.run(
        [binary, str(harness)],
        capture_output=True,
        text=True,
        env={
            "PATH": os.environ.get("PATH", ""),
            "SCRATCH": str(scratch),
            "CLOCK": str(scratch / "clock"),
            "CALLS": str(scratch / "calls"),
            "SLOW": str(SLOW_REQUEST_SECONDS),
        },
    )
    assert (scratch / "result").exists(), (
        f"the harness did not reach its driver: rc={result.returncode} {result.stderr}"
    )
    elapsed, status = (int(word) for word in (scratch / "result").read_text().split())
    return elapsed, status, result.stderr


def probe_scripts(chart: Path = CHART) -> dict[str, str]:
    documents = estate_render(chart)
    return {name: script_of(job_named(documents, name)) for name in PROBE_JOBS}


def loop_bound_failures(name: str, script: str, scratch: Path) -> list[str]:
    """(a): each loop ends on the wall clock, near its own bound. PURE but for scratch."""
    timeout = script_number(script, "TIMEOUT_SECONDS")
    poll = script_number(script, "POLL_SECONDS")
    request = script_number(script, "REQUEST_MAX_TIME")
    ceiling = timeout + poll + request
    failures = []
    driver, operator = AWAIT_DRIVERS[name]
    for label, call, needle in (
        ("remove", f'remove "{REMOVE_PATH}"', REMOVE_PATH),
        ("await", driver, operator),
    ):
        elapsed, status, stderr = run_slow(script, call, scratch / label)
        if status == 0:
            failures.append(f"{name}: {label} against a server that never answers succeeded")
        if elapsed > ceiling:
            failures.append(
                f"{name}: {label} ran {elapsed}s of real time against a {SLOW_REQUEST_SECONDS}s-"
                f"per-request API server; its own bound is {timeout}s, so it must end by "
                f"{ceiling}s ({timeout} + {poll}s poll + {request}s request in flight)"
            )
        if needle not in stderr:
            failures.append(f"{name}: {label}'s failure does not name {needle!r}: {stderr!r}")
    return failures


def test_each_loop_ends_on_the_wall_clock_against_a_slow_api_server(tmp_path):
    failures = []
    for name, script in probe_scripts().items():
        failures += loop_bound_failures(name, script, tmp_path / name)
    assert failures == [], "\n".join(failures)


def budget_clamp_failures(name: str, script: str, scratch: Path) -> list[str]:
    """(b): a loop started late ends at the script's budget, and says so."""
    assert SCRIPT_DEADLINE_ASSIGNMENT.search(script), (
        f"{name}: the rendered script sets no SCRIPT_DEADLINE, so no loop can be "
        f"bounded by the script's own budget"
    )
    budget = script_number(script, "SCRIPT_BUDGET_SECONDS")
    poll = script_number(script, "POLL_SECONDS")
    request = script_number(script, "REQUEST_MAX_TIME")
    left = 10
    ceiling = left + poll + 2 * request
    failures = []
    driver, operator = AWAIT_DRIVERS[name]
    elapsed, status, stderr = run_slow(script, driver, scratch / "late", spend=f"advance {budget - left}")
    if status == 0:
        failures.append(f"{name}: an await started {left}s before the budget ran out succeeded")
    if elapsed > ceiling:
        failures.append(
            f"{name}: an await started with {left}s of the {budget}s budget left ran "
            f"{elapsed}s; it must end by {ceiling}s ({left} + {poll}s poll + 2 x {request}s)"
        )
    if "budget" not in stderr or operator not in stderr:
        failures.append(
            f"{name}: an await ended by the script's budget must name {operator!r} and say "
            f"the budget ended it, not that the controller is dead: {stderr!r}"
        )
    if "CONTROLLER is not running" in stderr:
        failures.append(
            f"{name}: an await ended by the script's budget claims the controller is not "
            f"running, which an earlier slow probe can cause as well: {stderr!r}"
        )
    elapsed, status, stderr = run_slow(
        script, f'remove "{REMOVE_PATH}"', scratch / "spent", spend=f"advance {budget}"
    )
    if status == 0 or elapsed > 0:
        failures.append(
            f"{name}: a remove entered with the budget spent ran {elapsed}s and returned "
            f"{status}; it must fail at once, before its first request"
        )
    if "budget" not in stderr:
        failures.append(f"{name}: a remove refused for want of budget does not say so: {stderr!r}")
    return failures


def test_a_loop_started_late_ends_at_the_scripts_budget(tmp_path):
    failures = []
    for name, script in probe_scripts().items():
        failures += budget_clamp_failures(name, script, tmp_path / name)
    assert failures == [], "\n".join(failures)


def budget_arithmetic_failures(job: dict) -> list[str]:
    """(c): the budget is the recounted loops, and the deadline covers its overrun."""
    name = job["metadata"]["name"]
    script = script_of(job)
    loops = bounded_loops(script)
    timeout = script_number(script, "TIMEOUT_SECONDS")
    budget = script_number(script, "SCRIPT_BUDGET_SECONDS")
    poll = script_number(script, "POLL_SECONDS")
    request = script_number(script, "REQUEST_MAX_TIME")
    cleanup = script_number(script, "CLEANUP_MAX_TIME")
    objects = cleanup_objects(script)
    failures = []
    if budget != loops * timeout:
        failures.append(
            f"{name}: SCRIPT_BUDGET_SECONDS is {budget} and the script runs {loops} "
            f"bounded loops x {timeout}s = {loops * timeout}s"
        )
    needed = budget + poll + 2 * request + objects * cleanup
    deadline = job["spec"]["activeDeadlineSeconds"]
    if deadline <= needed:
        failures.append(
            f"{name}: activeDeadlineSeconds {deadline} does not exceed the script's "
            f"{budget}s budget + {poll}s poll + 2 x {request}s in flight + {objects} "
            f"objects x {cleanup}s cleanup = {needed}s, so the deadline can still end "
            f"the Job before the script names the slow operator"
        )
    return failures


def test_each_probe_deadline_covers_its_scripts_budget_and_overrun():
    documents = estate_render()
    failures = []
    for name in PROBE_JOBS:
        failures += budget_arithmetic_failures(job_named(documents, name))
    assert failures == [], "\n".join(failures)


# THE RED CASES, one per half of the fix. Each mutates BOTH templates, since the
# helpers are duplicated rather than shared, and asserts the message for each.

CLAMP = """                if [ "$ends" -gt "$SCRIPT_DEADLINE" ]; then
                  ends="$SCRIPT_DEADLINE"
                fi
"""
COUNTER_LOOP_PATTERN = ("                  in_time || break\n", "                  [ \"$((now=$(date +%s)))\" ] && [ \"$((polls=${polls:-0}+1))\" -le \"$((TIMEOUT_SECONDS / POLL_SECONDS))\" ] || break\n")


def chart_with_both_templates_mutated(destination: Path, old: str, new: str) -> Path:
    copy = chart_copy(destination)
    for template in ("preflight.yaml", "envoy-gateway-probe.yaml"):
        path = copy / "templates" / template
        text = path.read_text()
        assert old in text, f"{template} no longer carries {old!r}; this red case tests nothing"
        path.write_text(text.replace(old, new))
    return copy


def test_counting_polls_instead_of_the_clock_reddens_the_loop_gate(tmp_path):
    """The defect's own shape: a loop bounded by how many polls it made, which
    charges each poll only its sleep, however long its request took."""
    copy = chart_with_both_templates_mutated(tmp_path, *COUNTER_LOOP_PATTERN)
    failures = []
    for name, script in probe_scripts(copy).items():
        failures += loop_bound_failures(name, script, tmp_path / "run" / name)
    message = "\n".join(failures)
    assert re.search(r"preflight: await ran \d{4}s of real time .* must end by 158s", message), message
    assert re.search(r"envoy-gateway-probe: await ran \d{4}s of real time .* must end by 338s", message), message


def test_deleting_the_budget_clamp_reddens_the_budget_gate_alone(tmp_path):
    copy = chart_with_both_templates_mutated(tmp_path, CLAMP, "")
    scripts = probe_scripts(copy)
    clamp = []
    loop = []
    for name, script in scripts.items():
        clamp += budget_clamp_failures(name, script, tmp_path / "clamp" / name)
        loop += loop_bound_failures(name, script, tmp_path / "loop" / name)
    message = "\n".join(clamp)
    assert "preflight: an await started with 10s of the 960s budget left ran" in message, message
    assert "envoy-gateway-probe: an await started with 10s of the 900s budget left ran" in message, message
    assert loop == [], "\n".join(loop)


def test_dropping_the_entry_check_reddens_the_budget_gate(tmp_path):
    copy = chart_copy(tmp_path)
    for template in ("preflight.yaml", "envoy-gateway-probe.yaml"):
        path = copy / "templates" / template
        text = path.read_text()
        entry = re.compile(r"(remove\(\) \{\n\s*bound\n)\s*if ! in_time; then\n.*?\n\s*return 1\n\s*fi\n", re.DOTALL)
        assert entry.search(text), f"{template}: remove() no longer opens with the entry check"
        path.write_text(entry.sub(r"\1", text, count=1))
    failures = []
    for name, script in probe_scripts(copy).items():
        failures += budget_clamp_failures(name, script, tmp_path / "run" / name)
    message = "\n".join(failures)
    assert "preflight: a remove entered with the budget spent ran" in message, message
    assert "envoy-gateway-probe: a remove entered with the budget spent ran" in message, message


def test_a_budget_out_of_step_with_the_loops_reddens_the_arithmetic(tmp_path):
    copy = chart_copy(tmp_path)
    replace_once(
        copy / "templates" / "preflight.yaml",
        "SCRIPT_BUDGET_SECONDS={{ mul $loops $preflight.timeoutSeconds }}",
        "SCRIPT_BUDGET_SECONDS={{ mul (add $loops 3) $preflight.timeoutSeconds }}",
    )
    message = "\n".join(budget_arithmetic_failures(job_named(estate_render(copy), "preflight")))
    assert "preflight: SCRIPT_BUDGET_SECONDS is 1320 and the script runs 8 bounded loops x 120s = 960s" in message, message
    assert "preflight: activeDeadlineSeconds 1260 does not exceed" in message, message
