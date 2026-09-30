"""THE BUNDLED PROMETHEUS, AND THE PREFLIGHT ARM THAT ASKS IT TO ANSWER (ADR-0820).

WHY IT EXISTS. The parent chart's whole-estate defaults turn on seven KEDA
ScaledObjects, and every one queries `autoscaling.prometheusAddress`, which each
module chart defaults to `http://prometheus-server.observability.svc.cluster.local`.
MEASURED 2026-09-30 on a from-scratch kind install (parent 0.3.8): with no
Prometheus there, all seven ScaledObjects went `TriggerError`, Argo CD read the
Application `Degraded`, its sync retries ran out, and the PostSync hooks never ran.
ADR-0820 decision 1: platform installs a minimal Prometheus behind a toggle that
defaults on, and the preflight checks that it answers.

WHERE IT INSTALLS, AND WHY THAT HALF. `platform` is installed twice: once as the
operators release (`operators.create: true`, namespace `yadgar-operators`) and once
inside the parent as the estate. Prometheus rides with the OPERATORS, under the
same `condition:` shape the five operators carry —
`operators.prometheus.create,operators.create` — so "defaults on" means "on in every
release that installs the operators, unless `operators.prometheus.create: false`".
The estate half cannot carry it: its preflight is a pre-install hook, and it would
probe a Prometheus the same release has not applied yet.

WHERE THE SERVICE LANDS. `prometheus-server` in namespace `observability`, port 80
— the address the seven module charts already default to, so no module and no
parent value changes. `forceNamespace` moves every namespaced object there, and
the chart renders the Namespace itself, because Argo CD's `CreateNamespace` only
creates an Application's own destination namespace.

WHAT THIS SUITE DOES NOT PROVE. Every assertion is taken over `helm template`
output, or over the rendered shell run against a fake `curl`. That Prometheus
starts, and that KEDA reads it, are run-time verdicts left to the install proof.

Run: python3 -m pytest scripts/tests/ -q
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parents[2]
CHART = REPO / "chart"
ADOPTER_VALUES = REPO / "example" / "values.yaml"

OPERATORS_NAMESPACE = "yadgar-operators"
ESTATE_NAMESPACE = "yadgar"

# The address every module chart's `autoscaling.prometheusAddress` defaults to
# (gateway, iam, iam-db, task, task-db, project, project-db — read off parent
# 0.3.7's vendored subcharts, 2026-09-30). A LITERAL, because it is the other
# repositories' value this chart has to meet, not a value this chart owns.
MODULE_PROMETHEUS_ADDRESS = "http://prometheus-server.observability.svc.cluster.local"
PROMETHEUS_NAMESPACE = "observability"
PROMETHEUS_SERVICE = "prometheus-server"

# The components ADR-0820 calls minimal leaves out, by the name each renders under.
ABSENT_COMPONENTS = ("alertmanager", "pushgateway", "node-exporter", "kube-state-metrics")

# Prometheus v3's own `/-/ready` answer (`web/web.go`, `"%s is Ready.\n"` with
# AppName "Prometheus Server"), read at the tag the pinned chart's appVersion names.
READY_ANSWER = "Prometheus Server is Ready.\n"


def helm(*arguments: str) -> subprocess.CompletedProcess[str]:
    binary = shutil.which("helm")
    # NOT A SKIP (ADR-0650), as in every suite beside this one.
    assert binary, "helm is not on PATH. This suite renders the chart."
    return subprocess.run([binary, *arguments], capture_output=True, text=True)


def render(release: str, namespace: str, *arguments: str, chart: Path = CHART) -> list[dict]:
    result = helm("template", release, str(chart), "--namespace", namespace, *arguments)
    assert result.returncode == 0, result.stderr
    return [d for d in yaml.safe_load_all(result.stdout) if isinstance(d, dict) and d.get("apiVersion")]


def operators_render(release: str = "operators", *arguments: str, chart: Path = CHART) -> list[dict]:
    """The operators release, as `example/operators-application.yaml` in the chart repo installs it."""
    return render(
        release, OPERATORS_NAMESPACE, "--set", "operators.create=true",
        "--set", "operators.argoCd.create=false", *arguments, chart=chart,
    )


def prometheus_objects(documents: list[dict]) -> list[dict]:
    """Objects the prometheus subchart renders, by its own chart label."""
    return [
        d for d in documents
        if ((d.get("metadata") or {}).get("labels") or {}).get("helm.sh/chart", "").startswith("prometheus-")
    ]


def named(documents: list[dict], kind: str, name: str) -> list[dict]:
    return [d for d in documents if d.get("kind") == kind and d["metadata"].get("name") == name]


def placement_failures(documents: list[dict]) -> list[str]:
    """The Service the modules query exists where they query it, and nothing else ships. PURE."""
    failures = []
    mine = prometheus_objects(documents)
    if not mine:
        return ["the operators release renders no Prometheus at all"]

    services = named(mine, "Service", PROMETHEUS_SERVICE)
    if len(services) != 1:
        failures.append(
            f"expected one Service {PROMETHEUS_SERVICE!r}, found "
            f"{sorted((d['kind'], d['metadata']['name']) for d in mine if d['kind'] == 'Service')}"
        )
    else:
        service = services[0]
        namespace = service["metadata"].get("namespace")
        ports = [p.get("port") for p in service["spec"].get("ports", [])]
        address = f"http://{service['metadata']['name']}.{namespace}.svc.cluster.local"
        if 80 not in ports:
            failures.append(f"the Service serves ports {ports}; the modules' address carries no port, so it must serve 80")
        if address != MODULE_PROMETHEUS_ADDRESS:
            failures.append(
                f"the Service resolves as {address}, and the seven module charts query "
                f"{MODULE_PROMETHEUS_ADDRESS}"
            )

    elsewhere = sorted(
        (d["kind"], d["metadata"]["name"], d["metadata"].get("namespace"))
        for d in mine
        if d["kind"] not in ("ClusterRole", "ClusterRoleBinding")
        and d["metadata"].get("namespace") != PROMETHEUS_NAMESPACE
    )
    if elsewhere:
        failures.append(f"these Prometheus objects do not land in {PROMETHEUS_NAMESPACE!r}: {elsewhere}")

    namespaces = named(documents, "Namespace", PROMETHEUS_NAMESPACE)
    if len(namespaces) != 1:
        failures.append(
            f"expected the release to render Namespace {PROMETHEUS_NAMESPACE!r} once, found "
            f"{len(namespaces)}. Argo CD creates only the Application's destination namespace"
        )

    present = sorted(
        {c for c in ABSENT_COMPONENTS for d in documents if c in d["metadata"].get("name", "")}
    )
    if present:
        failures.append(f"components ADR-0820's minimal install leaves out render anyway: {present}")
    claims = [d["metadata"]["name"] for d in documents if d.get("kind") == "PersistentVolumeClaim"]
    if claims:
        failures.append(
            f"PersistentVolumeClaims render: {claims}. A claim on a cluster with no default "
            f"StorageClass leaves the server Pending, and this Prometheus only drives autoscaling"
        )
    return failures


def test_the_operators_release_installs_prometheus_where_the_modules_query_it():
    failures = placement_failures(operators_render())
    assert failures == [], "\n".join(failures)


def test_the_placement_does_not_depend_on_the_release_name():
    """The server's fullname derives from the release name unless overridden."""
    failures = placement_failures(operators_render("platform"))
    assert failures == [], "\n".join(failures)


def test_prometheus_follows_operators_create_and_its_own_key_wins():
    """`condition: operators.prometheus.create,operators.create` — both directions."""
    assert prometheus_objects(render("platform", ESTATE_NAMESPACE)) == [], (
        "the chart's own defaults render Prometheus; `operators.create` is false there"
    )
    off = operators_render("operators", "--set", "operators.prometheus.create=false")
    assert prometheus_objects(off) == [], "operators.prometheus.create=false left Prometheus in"
    assert named(off, "Namespace", PROMETHEUS_NAMESPACE) == [], (
        "operators.prometheus.create=false still renders Namespace observability"
    )
    alone = render(
        "operators", OPERATORS_NAMESPACE, "--set", "operators.prometheus.create=true"
    )
    assert named(prometheus_objects(alone), "Service", PROMETHEUS_SERVICE), (
        "operators.prometheus.create=true alone did not install Prometheus"
    )


def test_the_estates_adopter_render_carries_no_prometheus():
    """The estate half must not install it: its preflight would probe it before it exists."""
    documents = render(
        "platform", ESTATE_NAMESPACE, "--api-versions", "cert-manager.io/v1",
        "--api-versions", "gateway.envoyproxy.io/v1alpha1", "-f", str(ADOPTER_VALUES),
    )
    assert prometheus_objects(documents) == []


def test_prometheus_beside_the_estates_objects_is_the_mixed_release_refusal():
    result = helm(
        "template", "platform", str(CHART), "--namespace", ESTATE_NAMESPACE,
        "--set", "operators.prometheus.create=true", "--set", "valkey.create=true",
    )
    assert result.returncode != 0, "Prometheus and the estate's objects rendered in one release"
    assert "operators.prometheus.create asked for the operators" in result.stderr, result.stderr


def test_the_server_states_its_memory_request():
    """A request is what the scheduler reserves; the number is in the PR, measured from this render."""
    deployments = named(prometheus_objects(operators_render()), "Deployment", PROMETHEUS_SERVICE)
    assert len(deployments) == 1
    containers = deployments[0]["spec"]["template"]["spec"]["containers"]
    for container in containers:
        requests = (container.get("resources") or {}).get("requests") or {}
        assert requests.get("memory"), f"container {container['name']} requests no memory"


# ── THE PREFLIGHT ARM ────────────────────────────────────────────────────────


def preflight_script(*arguments: str, chart: Path = CHART) -> str:
    documents = render(
        "platform", ESTATE_NAMESPACE, "--api-versions", "cert-manager.io/v1",
        "--api-versions", "gateway.envoyproxy.io/v1alpha1", "-f", str(ADOPTER_VALUES),
        *arguments, chart=chart,
    )
    jobs = [d for d in documents if d.get("kind") == "Job" and d["metadata"]["name"] == "preflight"]
    assert len(jobs) == 1, "no single preflight Job rendered"
    return jobs[0]["spec"]["template"]["spec"]["containers"][0]["args"][0]


def probes_of(script: str) -> list[str]:
    match = re.search(r'^PROBES="([^"]*)"$', script, re.MULTILINE)
    assert match
    return match.group(1).split()


def test_the_prometheus_probe_is_off_unless_asked_for():
    """No sibling can resolve its tie: `platform` renders no ScaledObject, as with `keda`."""
    assert "prometheus" not in probes_of(preflight_script())
    assert "prometheus" in probes_of(preflight_script("--set", "preflight.probes.prometheus=true"))


def test_the_probe_address_is_the_modules_address():
    values = yaml.safe_load((CHART / "values.yaml").read_text())
    assert values["preflight"]["prometheus"]["address"] == MODULE_PROMETHEUS_ADDRESS


THE_PROBES_OWN_PREFIX_END = "# ── THE DENOMINATOR, CHECKED BEFORE ANYTHING IS PROBED"
THE_JOBS_SERVICE_ACCOUNT_LINE = 'sa="/var/run/secrets/kubernetes.io/serviceaccount"'
THE_JOBS_BODY_LINE = "body=/tmp/answer"

# A fake `curl` that answers `$ANSWER_CODE` with the body in `$ANSWER_BODY`, and
# records every argument it was given.
FAKE_CURL = r"""
curl() {
  printf -- '--CALL--\n' >>"$RECORD"
  out=''
  for word in "$@"; do printf '%s\n' "$word" >>"$RECORD"; done
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --output|-o) out="$2"; shift 2 ;;
      *) shift ;;
    esac
  done
  cat "$ANSWER_BODY" >"$out"
  printf '%s' "$ANSWER_CODE"
}
sleep() { :; }
"""


def run_probe(script: str, scratch: Path, code: str, answer: str):
    prefix = script.split(THE_PROBES_OWN_PREFIX_END)[0]
    assert THE_JOBS_SERVICE_ACCOUNT_LINE in prefix and THE_JOBS_BODY_LINE in prefix
    prefix = prefix.replace(THE_JOBS_SERVICE_ACCOUNT_LINE, 'sa="$SCRATCH/sa"').replace(
        THE_JOBS_BODY_LINE, 'body="$SCRATCH/answer"'
    )
    scratch.mkdir(parents=True, exist_ok=True)
    (scratch / "sa").mkdir(exist_ok=True)
    (scratch / "sa" / "namespace").write_text(ESTATE_NAMESPACE)
    (scratch / "sa" / "token").write_text("the-service-account-token")
    (scratch / "reply").write_text(answer)
    record = scratch / "record"
    record.write_text("")
    harness = scratch / "harness.sh"
    harness.write_text(FAKE_CURL + prefix + "\nprobe_prometheus\n")
    binary = shutil.which("sh")
    assert binary
    result = subprocess.run(
        [binary, str(harness)], capture_output=True, text=True,
        env={
            "PATH": os.environ.get("PATH", ""), "SCRATCH": str(scratch), "RECORD": str(record),
            "ANSWER_CODE": code, "ANSWER_BODY": str(scratch / "reply"),
        },
    )
    calls: list[list[str]] = []
    for line in record.read_text().splitlines():
        if line == "--CALL--":
            calls.append([])
        elif calls:
            calls[-1].append(line)
    return result, calls


def prometheus_probe_failures(script: str, scratch: Path) -> list[str]:
    failures = []
    ready, calls = run_probe(script, scratch / "ready", "200", READY_ANSWER)
    if ready.returncode != 0:
        failures.append(f"a Prometheus answering {READY_ANSWER!r} read as down: {ready.stderr}")
    if not calls:
        failures.append("the arm made no request at all")
    for words in calls:
        if f"{MODULE_PROMETHEUS_ADDRESS}/-/ready" not in words:
            failures.append(f"a request went somewhere other than {MODULE_PROMETHEUS_ADDRESS}/-/ready: {words}")
        leaked = [w for w in words if "the-service-account-token" in w or w.lower().startswith("authorization")]
        if leaked:
            failures.append(
                f"the request to Prometheus carries the Job's Kubernetes credentials: {leaked}. "
                f"The token is for the API server and nothing else"
            )

    for label, code, answer in (
        ("not ready", "503", "Service Unavailable"),
        ("something else answering 200", "200", "<html>not prometheus</html>"),
        ("nothing listening", "000", ""),
    ):
        result, _ = run_probe(script, scratch / label.replace(" ", "-"), code, answer)
        if result.returncode == 0:
            failures.append(f"{label}: the arm reported Prometheus up")
        elif "Prometheus" not in result.stderr or MODULE_PROMETHEUS_ADDRESS not in result.stderr:
            failures.append(f"{label}: the refusal names neither Prometheus nor its address: {result.stderr}")
    return failures


def test_the_prometheus_arm_requires_its_own_ready_answer(tmp_path):
    script = preflight_script("--set", "preflight.probes.prometheus=true")
    failures = prometheus_probe_failures(script, tmp_path)
    assert failures == [], "\n".join(failures)


def mutated_chart(destination: Path, template: str, old: str, new: str) -> Path:
    copy = destination / "chart"
    shutil.copytree(CHART, copy)
    path = copy / template
    text = path.read_text()
    assert text.count(old) == 1, f"{old!r} moved in {template}; this red case is testing nothing"
    path.write_text(text.replace(old, new))
    return copy


def test_dropping_the_message_check_reddens_the_arm(tmp_path):
    chart = mutated_chart(
        tmp_path, "templates/preflight.yaml",
        '[ "$code" = "200" ] && grep -qF "$PROMETHEUS_READY" "$body"', '[ "$code" = "200" ]',
    )
    script = preflight_script("--set", "preflight.probes.prometheus=true", chart=chart)
    message = "\n".join(prometheus_probe_failures(script, tmp_path / "run"))
    assert "something else answering 200: the arm reported Prometheus up" in message, message


def test_sending_the_token_to_prometheus_reddens_the_arm(tmp_path):
    chart = mutated_chart(
        tmp_path, "templates/preflight.yaml",
        '--max-time "$PROMETHEUS_MAX_TIME" --user-agent "$USER_AGENT"',
        '--max-time "$PROMETHEUS_MAX_TIME" --user-agent "$USER_AGENT" --header "Authorization: Bearer $token"',
    )
    script = preflight_script("--set", "preflight.probes.prometheus=true", chart=chart)
    message = "\n".join(prometheus_probe_failures(script, tmp_path / "run"))
    assert "carries the Job's Kubernetes credentials" in message, message


def test_moving_the_service_off_the_modules_address_reddens_placement(tmp_path):
    chart = mutated_chart(
        tmp_path, "values.yaml", "    fullnameOverride: prometheus-server\n", ""
    )
    message = "\n".join(placement_failures(operators_render(chart=chart)))
    assert "expected one Service 'prometheus-server'" in message, message


def test_dropping_the_forced_namespace_reddens_placement(tmp_path):
    chart = mutated_chart(tmp_path, "values.yaml", "  forceNamespace: observability\n", "")
    message = "\n".join(placement_failures(operators_render(chart=chart)))
    assert "do not land in 'observability'" in message or "resolves as" in message, message


# ── THE REVIEW'S FOUR: TIMING, THE NAMESPACE'S LIFE, THE SCRAPE INTERVAL ─────


def test_the_arm_counts_each_attempts_own_time_against_its_bound(tmp_path):
    """`waited` must grow by the poll AND by `--max-time`, or the bound is a fiction.

    Against an address that hangs, every attempt spends its whole `--max-time`
    before the `sleep`. A loop that counts only the `sleep` runs TIMEOUT/POLL
    attempts and outlives its stated bound by attempts x max-time. The fake `curl`
    answers at once, so the attempt count is what is measured: it must fit the
    bound when each attempt is charged its poll plus its max-time.
    """
    script = preflight_script("--set", "preflight.probes.prometheus=true")
    timeout = int(re.search(r"^TIMEOUT_SECONDS=(\d+)$", script, re.MULTILINE).group(1))
    poll = int(re.search(r"^POLL_SECONDS=(\d+)$", script, re.MULTILINE).group(1))
    max_time = int(re.search(r"^PROMETHEUS_MAX_TIME=(\d+)$", script, re.MULTILINE).group(1))
    result, calls = run_probe(script, tmp_path, "000", "")
    assert result.returncode != 0
    assert (len(calls) - 1) * (poll + max_time) < timeout, (
        f"{len(calls)} attempts at up to {poll + max_time}s each outlive the {timeout}s bound"
    )


def test_counting_only_the_sleep_reddens_the_timing_gate(tmp_path):
    chart = mutated_chart(
        tmp_path, "templates/preflight.yaml",
        "waited=$((waited + POLL_SECONDS + PROMETHEUS_MAX_TIME))",
        "waited=$((waited + POLL_SECONDS))",
    )
    script = preflight_script("--set", "preflight.probes.prometheus=true", chart=chart)
    timeout = int(re.search(r"^TIMEOUT_SECONDS=(\d+)$", script, re.MULTILINE).group(1))
    _, calls = run_probe(script, tmp_path / "run", "000", "")
    assert (len(calls) - 1) * 8 >= timeout, f"only {len(calls)} attempts; the mutation did not widen the loop"


KEEP = "helm.sh/resource-policy"
ARGO_SYNC_OPTIONS = "argocd.argoproj.io/sync-options"


def namespace_life_failures(documents: list[dict]) -> list[str]:
    """The `observability` Namespace outlives the release that rendered it. PURE.

    Deleting a Namespace deletes everything in it, and this one may already hold
    an adopter's own objects: helm and Argo CD both ADOPT an existing Namespace
    the release renders. So neither may ever delete it — `helm uninstall` honours
    `resource-policy: keep`, and Argo CD honours `Delete=false` on app deletion and
    `Prune=false` on a sync that no longer renders it.
    """
    namespaces = named(documents, "Namespace", PROMETHEUS_NAMESPACE)
    if len(namespaces) != 1:
        return [f"expected one Namespace {PROMETHEUS_NAMESPACE!r}, found {len(namespaces)}"]
    annotations = namespaces[0]["metadata"].get("annotations") or {}
    failures = []
    if annotations.get(KEEP) != "keep":
        failures.append(f"the Namespace carries no `{KEEP}: keep`, so `helm uninstall` deletes it and all it holds")
    options = {o.strip() for o in (annotations.get(ARGO_SYNC_OPTIONS) or "").split(",") if o.strip()}
    for wanted in ("Delete=false", "Prune=false"):
        if wanted not in options:
            failures.append(f"the Namespace's `{ARGO_SYNC_OPTIONS}` lacks {wanted}, found {sorted(options)}")
    return failures


def test_the_observability_namespace_is_never_deleted_by_helm_or_argo():
    failures = namespace_life_failures(operators_render())
    assert failures == [], "\n".join(failures)


def test_dropping_the_keep_policy_reddens_the_namespace_gate(tmp_path):
    chart = mutated_chart(tmp_path, "templates/prometheus-namespace.yaml", "    helm.sh/resource-policy: keep\n", "")
    message = "\n".join(namespace_life_failures(operators_render(chart=chart)))
    assert "no `helm.sh/resource-policy: keep`" in message, message


def test_dropping_argos_prune_guard_reddens_the_namespace_gate(tmp_path):
    chart = mutated_chart(
        tmp_path, "templates/prometheus-namespace.yaml",
        "argocd.argoproj.io/sync-options: Delete=false,Prune=false", "argocd.argoproj.io/sync-options: Delete=false",
    )
    message = "\n".join(namespace_life_failures(operators_render(chart=chart)))
    assert "lacks Prune=false" in message, message


# The module ScaledObjects query `rate(...[2m])`. At the chart's default 1m scrape
# interval a 2m window holds one or two samples, `rate` needs two, and KEDA's
# `ignoreNullValues` reads the empty result as 0 — a scaler that never scales up.
# 15s gives eight samples per window.
SCRAPE_INTERVAL = "15s"


def scrape_interval_of(documents: list[dict]) -> str | None:
    maps = named(prometheus_objects(documents), "ConfigMap", PROMETHEUS_SERVICE)
    assert len(maps) == 1, "no single server ConfigMap rendered"
    config = yaml.safe_load(maps[0]["data"]["prometheus.yml"])
    return (config.get("global") or {}).get("scrape_interval")


def test_the_server_scrapes_often_enough_for_the_modules_rate_windows():
    assert scrape_interval_of(operators_render()) == SCRAPE_INTERVAL


def test_the_charts_default_interval_reddens_the_scrape_gate(tmp_path):
    chart = mutated_chart(tmp_path, "values.yaml", "      scrape_interval: 15s\n", "")
    assert scrape_interval_of(operators_render(chart=chart)) != SCRAPE_INTERVAL


# ── THE WHOLE PREFLIGHT'S WORST CASE AGAINST THE DOCUMENTED INSTALL BUDGET ───
# Helm's `--timeout` bounds each hook Job, and the preflight is one Job running
# every enabled probe in sequence. Its worst case is the sum of its bounded loops,
# each capped at `TIMEOUT_SECONDS`: one per DISTINCT path a `create`/`remove`
# deletes-and-waits-for (a path removed twice waits once), one per `await`, and
# one per loop a probe runs itself — Prometheus's, now that it charges each
# attempt its `--max-time`. Counted at the render with EVERY probe on, which is
# the parent chart's whole-estate case, plus the same 300s margin the post-install
# gate leaves for scheduling, image pull and request time.
REMOVAL_CALL = re.compile(r'^[ ]*(?:create|remove) "(?P<path>[^"]+)"', re.MULTILINE)
AWAIT_CALL = re.compile(r'^[ ]*await "', re.MULTILINE)
BOUNDED_WHILE = re.compile(r'^[ ]*while \[ "\$waited" -lt "\$TIMEOUT_SECONDS" \]', re.MULTILINE)
# `remove()` and `await()` each own one `while`, counted through their calls.
HELPER_LOOPS = 2
BUDGET_MARGIN_SECONDS = 300
TIMEOUT_FLAG = re.compile(r"--timeout\s+(?P<budget>\d+)m\b")
BUDGET_FILES = (REPO / "README.md", ADOPTER_VALUES)


def preflight_worst_case(script: str) -> tuple[int, int]:
    timeout = int(re.search(r"^TIMEOUT_SECONDS=(\d+)$", script, re.MULTILINE).group(1))
    paths = {m.group("path") for m in REMOVAL_CALL.finditer(script) if m.group("path") != "$1"}
    loops = len(paths) + len(AWAIT_CALL.findall(script)) + len(BOUNDED_WHILE.findall(script)) - HELPER_LOOPS
    return loops, loops * timeout + BUDGET_MARGIN_SECONDS


def preflight_budget_failures(script: str, texts: dict[str, str]) -> list[str]:
    loops, required = preflight_worst_case(script)
    failures = []
    for name, text in texts.items():
        budgets = [int(m.group("budget")) * 60 for m in TIMEOUT_FLAG.finditer(text)]
        if not budgets:
            failures.append(f"{name} states no `--timeout <n>m`")
        for budget in budgets:
            if budget < required:
                failures.append(
                    f"{name} documents a {budget}s budget and the preflight with every probe on "
                    f"needs {required}s ({loops} bounded loops plus {BUDGET_MARGIN_SECONDS}s)"
                )
    return failures


def all_probes_script(chart: Path = CHART) -> str:
    return preflight_script(
        "--set", "preflight.probes.keda=true", "--set", "preflight.probes.mariadb=true",
        "--set", "preflight.probes.prometheus=true", chart=chart,
    )


def test_the_documented_budget_covers_the_whole_preflight():
    script = all_probes_script()
    loops, _ = preflight_worst_case(script)
    # Seven before #22; its Secret `remove` in the cert-manager arm is the eighth.
    assert loops == 8, f"expected 8 bounded loops with every probe on, counted {loops}"
    failures = preflight_budget_failures(script, {f.name: f.read_text() for f in BUDGET_FILES})
    assert failures == [], "\n".join(failures)


def test_the_old_twenty_minutes_reddens_the_preflight_budget_gate():
    texts = {f.name: f.read_text().replace("--timeout 25m", "--timeout 20m") for f in BUDGET_FILES}
    message = "\n".join(preflight_budget_failures(all_probes_script(), texts))
    assert "documents a 1200s budget" in message, message
