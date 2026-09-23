"""THE SHARED INFRASTRUCTURE: the Gateway listener, Valkey, NATS and the two ingress policies.

WHAT THIS SUITE IS FOR, AND WHY IT IS NOT A CENSUS. Every gate below asserts a
REFERENCE between two objects — a Gateway naming the class this chart renders, a
`parametersRef` resolving to the EnvoyProxy this chart renders, a NetworkPolicy
selecting the pod labels the workload it protects actually carries — and only then
asserts how many of each it examined. Counting objects is the failure this estate
has already shipped once: a binding to a built-in role renders no object, so a
census stays green while the reference is broken. A count is the denominator of a
reference assertion here, never the assertion itself.

THE ONE REFERENCE NO RENDER CAN CHECK, named rather than faked. Both ingress
policies name their CLIENTS by pod labels belonging to charts that are not this
one — `app: gateway` and `app: iam`, which the module charts stamp. Nothing this
chart renders carries those labels, so no render can resolve them. They are
asserted BY VALUE against literals written here, with the count asserted beside
them, and the honest limit of that is stated rather than dressed up: it catches a
label edited in this chart's templates, and it cannot catch a module chart
renaming its own.

WHY NEITHER POLICY TAKES A `clients` VALUES LIST, AND SO CARRIES NO ADR-0664
GUARD. The plan this chart is built from gives `gateway`'s policy — step 7, a
different repository — a `networkPolicy.clients` key and ADR-0664's `fail` beside
it, and gives these two no such key at all. That is the whole reason the guard is
absent here rather than forgotten: ADR-0664 exists for a values list that can
arrive empty and render an allow-all wearing a control's name. A selector written
in the template cannot arrive empty, so the hazard has no way in and a new `fail`
would be a refusal with nothing to refuse. The plan's standing rule — no new
`fail` except where a refusal is the point — is the other half of the same answer.

THE THREE RENDERS, in the plan's own names. R1 is the chart's shipped
`values.yaml`, where every `create` toggle is false and this step renders NOTHING.
R2 is `example/values.yaml`, every `create` true. R3 is R2 with whatever a red case
needs stated explicitly, layered as an overlay so `example/values.yaml` stays the
one source for everything the variant does not change.

EVERY RENDER BELOW THAT ENABLES A TOGGLE PASSES BOTH DECLARED API GROUPS. `fail`
aborts the whole render at the first failing check, so a render naming one group
refuses for the OTHER check's reason — which is the same defect
`test_render_checks.py`'s generalised red case exists to prevent, met here from the
consumer's side.

Run: python3 -m pytest scripts/tests/ -q
"""

from __future__ import annotations

import re
import shutil
import subprocess
import tarfile
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parents[2]
CHART = REPO / "chart"
ADOPTER_VALUES = REPO / "example" / "values.yaml"

# ── THE GROUPS EVERY ENABLED RENDER MUST NAME ────────────────────────────────
# A LITERAL, and deliberately not `sorted(declared_checks(CHART))` from
# `test_render_checks.py`. A list derived from the chart would follow a check
# deleted from the chart, so every render here would keep passing over one fewer
# group and this suite would stop discriminating at exactly the moment the render
# checks stopped existing. `test_render_checks.py` owns the count of what the
# chart declares; this is the independent restatement that disagrees with it when
# somebody moves one and not the other.
DECLARED_API_VERSIONS = ("cert-manager.io/v1", "gateway.envoyproxy.io/v1alpha1")

# ── WHAT THIS STEP ADDS, WRITTEN DOWN ────────────────────────────────────────
# Counts are LITERALS for the reason every expected number in this estate is one:
# a number derived from the render agrees with whatever the render happens to be.
EXPECTED_GATEWAY_LISTENER_OBJECTS = 3  # GatewayClass, Gateway, EnvoyProxy
EXPECTED_VALKEY_OBJECTS = 2  # Deployment, Service
EXPECTED_INGRESS_POLICIES = 2  # valkey-ingress, nats-ingress
EXPECTED_DECLARED_DEPENDENCIES = 1  # nats

# The clients each policy admits, by value, because they belong to other charts.
EXPECTED_VALKEY_CLIENTS = ["gateway"]
EXPECTED_NATS_CLIENTS = ["gateway", "iam"]

# ── THE PORTS ADMITTED FROM EVERY SOURCE, WRITTEN DOWN ───────────────────────
# An ingress rule with no `from` matches ALL sources — every namespace, and
# whatever else the CNI presents (ADR-0664). `nats-ingress` has exactly one such
# rule, on the monitoring port, and the reason it is not narrowed is argued in
# `templates/ingress-policies.yaml` beside the rule. `valkey-ingress` has none.
#
# THIS IS WHAT `EXPECTED_*_CLIENTS` CANNOT SEE. `client_names` walks each rule's
# `from`, so a rule carrying none contributes nothing to it and an allow-all
# leaves the client census reporting the same consumers it always did.
EXPECTED_ALLOW_ALL_PORTS = {"valkey-ingress": set(), "nats-ingress": {8222}}

# The two Secrets the bootstrap Job mints for the broker, by value, because the
# StatefulSet that reads them belongs to the upstream chart.
EXPECTED_NATS_SECRETS = {"nats-auth", "nats-auth-gateway"}

# The name inside a request body the bootstrap script POSTs, which is the only place
# a Secret is actually created. MEASURED, not assumed: renaming the created Secret to
# `nats-auth-typo` leaves the string `nats-auth-gateway` in that Job three times over
# — in a comment, in a `mint` line and in an echo — so a substring search over the
# Job's text answers "minted" for a Secret the install never creates. That is exactly
# the typo this gate exists to catch, so the name is read off the body.
MINTED_SECRET = re.compile(
    r'"kind"\s*:\s*"Secret".*?"metadata"\s*:\s*\{\s*"name"\s*:\s*"(?P<name>[^"]+)"',
    re.DOTALL,
)

# The three decoy groups this check could have been written against, and the two
# that would have been wrong. Kept as data so the reason travels with the test.
UPSTREAM_GATEWAY_API_GROUPS = (
    "gateway.networking.k8s.io/v1",
    "gateway.networking.x-k8s.io/v1alpha1",
)


def helm(*arguments: str) -> subprocess.CompletedProcess[str]:
    binary = shutil.which("helm")
    # NOT A SKIP, and ADR-0650 is why. Same wording as this repository's three
    # sibling suites, which made the same decision for the same reason.
    assert binary, (
        "helm is not on PATH. This suite renders the chart, and so does the "
        "`helm lint and render` pre-commit hook — install helm rather than "
        "letting either report a pass it did not earn."
    )
    return subprocess.run([binary, *arguments], capture_output=True, text=True)


def api_version_arguments() -> tuple[str, ...]:
    """`--api-versions <group>` for every group the chart's checks ask for. PURE."""
    return tuple(
        part for group in DECLARED_API_VERSIONS for part in ("--api-versions", group)
    )


def template(chart: Path, *arguments: str) -> subprocess.CompletedProcess[str]:
    return helm("template", "platform", str(chart), *arguments)


def documents(stdout: str) -> list[dict]:
    return [
        document
        for document in yaml.safe_load_all(stdout)
        if isinstance(document, dict) and document.get("apiVersion")
    ]


def render(chart: Path, *arguments: str) -> list[dict]:
    result = template(chart, *arguments)
    assert result.returncode == 0, result.stderr
    return documents(result.stdout)


def defaults_render(chart: Path = CHART) -> list[dict]:
    """R1 — the chart's shipped values, bare, with no `--api-versions` at all.

    BARE IS THE POINT. A render check may only sit behind a default-false toggle,
    so the defaults must render offline with no flag; passing one here would hide
    a check that had become reachable at the defaults.
    """
    return render(chart)


def adopter_render(chart: Path = CHART, *arguments: str) -> list[dict]:
    """R2 — `example/values.yaml`, every `create` toggle true."""
    return render(
        chart, *api_version_arguments(), "-f", str(ADOPTER_VALUES), *arguments
    )


def overrides(destination: Path, body: str) -> Path:
    """One R3 variant, written as an overlay on R2 rather than as a second copy."""
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(body)
    return destination


def of_kind(rendered: list[dict], kind: str) -> list[dict]:
    return [document for document in rendered if document.get("kind") == kind]


def one(rendered: list[dict], kind: str) -> dict:
    found = of_kind(rendered, kind)
    assert len(found) == 1, (
        f"expected exactly one {kind} in the render, found {len(found)}: "
        f"{[document['metadata']['name'] for document in found]}"
    )
    return found[0]


def by_name(rendered: list[dict], kind: str, name: str) -> dict:
    found = [
        document
        for document in of_kind(rendered, kind)
        if document["metadata"]["name"] == name
    ]
    assert len(found) == 1, (
        f"expected exactly one {kind} named {name}, found {len(found)} of "
        f"{[document['metadata']['name'] for document in of_kind(rendered, kind)]}"
    )
    return found[0]


def chart_values() -> dict:
    return yaml.safe_load((CHART / "values.yaml").read_text())


def pod_labels(workload: dict) -> dict:
    return workload["spec"]["template"]["metadata"]["labels"]


def client_names(policy: dict) -> list[str]:
    """Every `app:` label the policy's ingress rules admit, sorted. PURE."""
    names = set()
    for rule in policy["spec"]["ingress"]:
        for peer in rule.get("from", []):
            selector = peer.get("podSelector", {}).get("matchLabels", {})
            if "app" in selector:
                names.add(selector["app"])
    return sorted(names)


def from_less_rules(policy: dict) -> list[dict]:
    """Every ingress rule that names NO source, i.e. every rule admitting all of them. PURE.

    `not rule.get("from")` rather than `"from" not in rule`, and the difference is
    the whole gate. A rule carrying `from: []` is the SAME allow-all to the API
    server as a rule carrying no `from` key at all — ADR-0664 read it off the
    OpenAPI description compiled into the kubectl binary: "If this field is empty or
    missing, this rule matches all sources". The empty-list shape is also the one a
    values override or a `range` over an empty list produces, so a predicate keyed
    on the missing KEY would miss the shape most likely to arrive.
    """
    return [rule for rule in policy["spec"]["ingress"] if not rule.get("from")]


def minted_secret_names(rendered: list[dict]) -> set[str]:
    """Every Secret name a bootstrap Job actually CREATES, read off the request body. PURE.

    NOT A SUBSTRING SEARCH OVER THE JOB'S TEXT, and the difference was measured
    rather than argued: renaming the Secret the script creates to `nats-auth-typo`
    leaves the old name in the Job in a comment, in a `mint` line and in an echo, so
    a substring form reports it minted and the gate passes over an install whose
    broker waits forever on a Secret nothing creates. The request body is where a
    Secret is made, so the body is what this reads.

    READ OFF `command` AND `args`, NEVER OFF `yaml.dump(job)`. Measured: the dump
    escapes every quote in the script and wraps its lines, so the JSON bodies do not
    survive it and a pattern run over the dump matches NOTHING — a gate that reports
    every Secret as unminted, which is red for the wrong reason rather than green for
    the wrong reason, and just as useless.
    """
    script = "\n".join(
        part
        for job in of_kind(rendered, "Job")
        for container in job["spec"]["template"]["spec"]["containers"]
        for part in (container.get("command") or []) + (container.get("args") or [])
    )
    return {
        match.group("name")
        for match in MINTED_SECRET.finditer(script)
    }


def secret_names(workload: dict) -> set[str]:
    """Every Secret name the workload's containers read through `secretKeyRef`. PURE.

    Over ALL containers rather than the first: the broker's pod carries a `reloader`
    sidecar beside `nats`, and a credential moved onto a sidecar is still a
    credential this install has to mint.
    """
    return {
        variable["valueFrom"]["secretKeyRef"]["name"]
        for container in workload["spec"]["template"]["spec"]["containers"]
        for variable in container.get("env") or []
        if "secretKeyRef" in (variable.get("valueFrom") or {})
    }


def broker_ports(rendered: list[dict]) -> set[int]:
    """Every port the UPSTREAM chart's render serves on the broker. PURE.

    SERVICES AND `containerPorts` BOTH, through ONE function so the gate and its red
    case cannot come to read different things. A Service is not the whole list of
    what a pod serves: a listener opened on the pod with no Service in front of it is
    reachable at the pod IP, denied by a policy that does not name it, and invisible
    to a gate that reads Services alone.
    """
    return {
        port["port"]
        for service in of_kind(rendered, "Service")
        if service["metadata"]["name"] != chart_values()["valkey"]["name"]
        for port in service["spec"]["ports"]
    } | {
        port["containerPort"]
        for container in one(rendered, "StatefulSet")["spec"]["template"]["spec"][
            "containers"
        ]
        for port in container.get("ports") or []
    }


def policy_ports(policy: dict) -> set[int]:
    return {
        port["port"]
        for rule in policy["spec"]["ingress"]
        for port in rule.get("ports", [])
    }


def chart_with(destination: Path, relative: str, edit) -> Path:
    """A throwaway copy of the chart with one template rewritten. Red cases only.

    THE EDIT IS ASSERTED TO HAVE LANDED, and that is not ceremony. A `str.replace`
    whose pattern no longer matches the template returns the text UNCHANGED, so the
    red case would render the real chart, find the reference intact and report a
    pass — a red case that silently stopped constructing anything. Every caller
    below reaches this through one function so the tripwire cannot be forgotten in
    one of them.
    """
    copy = destination / "chart"
    shutil.copytree(CHART, copy)
    target = copy / relative
    before = target.read_text()
    after = edit(before)
    assert after != before, (
        f"the red case's edit to {relative} matched nothing, so this case is "
        f"rendering the chart unchanged and proving nothing"
    )
    target.write_text(after)
    return copy


# ── R1: THE CHART'S OWN DEFAULTS RENDER NONE OF THIS ─────────────────────────


def test_the_defaults_render_none_of_this_steps_objects():
    """R1 — asserted as an equality against zero, never as a skip.

    The chart installs on a bare cluster rendering nothing and requiring no CRD
    (ADR-0752), and that is a property of the RENDER rather than of the values
    file somebody read. The kinds are enumerated rather than counted in the
    aggregate so the failure names which one survived.
    """
    rendered = defaults_render()
    for kind in (
        "GatewayClass",
        "Gateway",
        "EnvoyProxy",
        "Deployment",
        "Service",
        "NetworkPolicy",
        "StatefulSet",
    ):
        found = of_kind(rendered, kind)
        assert found == [], (
            f"the chart's own defaults rendered {len(found)} {kind} objects, "
            f"{[document['metadata']['name'] for document in found]}; every "
            f"`create` toggle is false there and the render must be empty"
        )


def test_a_create_toggle_true_at_the_defaults_reddens_the_zero(tmp_path):
    """R1's red case, and it is a VALUES flip rather than a template edit.

    Without this the zero above is the "cannot fail because it examined nothing"
    form: a template that rendered no Gateway under any values at all would pass
    it. Each toggle is flipped on its own, so the failure names which one.
    """
    for toggle, kind in (
        ("gatewayListener", "Gateway"),
        ("valkey", "Deployment"),
        # THE THIRD TOGGLE, AND IT RENDERS THE MOST. `nats.create` is a dependency
        # `condition` rather than a template `if`, so it switches the whole subchart
        # on: six objects at the defaults, the StatefulSet among them. Left out, the
        # zero above passed over a chart whose `condition` had been deleted.
        ("nats", "StatefulSet"),
    ):
        values = overrides(
            tmp_path / f"{toggle}.yaml", f"{toggle}:\n  create: true\n"
        )
        rendered = render(CHART, *api_version_arguments(), "-f", str(values))
        assert of_kind(rendered, kind), (
            f"{toggle}.create was turned true over the chart's defaults and no "
            f"{kind} rendered, so the zero above is passing over a template that "
            f"cannot produce one"
        )


# ── THE GATEWAY LISTENER ─────────────────────────────────────────────────────


def test_the_gateway_names_the_class_this_chart_renders():
    """THE REFERENCE, not a census: a Gateway naming a class nobody created.

    A Gateway whose `gatewayClassName` matches no GatewayClass stays
    `Accepted=False` with no controller ever looking at it, which reads as a
    broken Gateway rather than a missing object. Counting the two objects would
    not see it — both render.
    """
    rendered = adopter_render()
    gateway_class = one(rendered, "GatewayClass")
    gateway = one(rendered, "Gateway")

    assert gateway["spec"]["gatewayClassName"] == gateway_class["metadata"]["name"], (
        f"the Gateway names class {gateway['spec']['gatewayClassName']} and this "
        f"chart renders {gateway_class['metadata']['name']}, so the Gateway would "
        f"sit Accepted=False with nothing reconciling it"
    )
    assert (
        gateway_class["spec"]["controllerName"]
        == chart_values()["gatewayListener"]["controllerName"]
    )


def test_a_gateway_naming_another_class_reddens_the_reference(tmp_path):
    """The red case, and it is a TEMPLATE edit by construction.

    Both names come from one values key, which is what makes the reference hold
    under every values file — so a values flip moves both and cannot break it.
    The constructible break is a template that stops reading that key, which is
    exactly the edit a reader tidying the template might make.
    """
    copy = chart_with(
        tmp_path,
        "templates/gateway-listener.yaml",
        lambda text: text.replace(
            "gatewayClassName: {{ $listener.className }}",
            "gatewayClassName: some-other-class",
        ),
    )
    rendered = render(copy, *api_version_arguments(), "-f", str(ADOPTER_VALUES))
    gateway = one(rendered, "Gateway")
    gateway_class = one(rendered, "GatewayClass")
    assert gateway["spec"]["gatewayClassName"] != gateway_class["metadata"]["name"], (
        "the red case rewrote the Gateway's class name and the render still "
        "agreed, so this construction is testing nothing"
    )


def test_the_parametersRef_resolves_to_the_envoyproxy_this_chart_renders():
    """THE GATE THAT A CENSUS CANNOT BE: group, kind AND name, all three.

    `spec.infrastructure.parametersRef` is a reference by group, kind and name to
    an object in the Gateway's own namespace. A ref naming an EnvoyProxy that does
    not exist leaves the Gateway provisioned with the chart's defaults — two
    replicas become one, the NodePort pinning is silently dropped — while both
    objects render and every count agrees.
    """
    rendered = adopter_render()
    gateway = one(rendered, "Gateway")
    envoy_proxy = one(rendered, "EnvoyProxy")
    reference = gateway["spec"]["infrastructure"]["parametersRef"]

    assert reference["kind"] == envoy_proxy["kind"], reference
    assert reference["name"] == envoy_proxy["metadata"]["name"], (
        f"the Gateway's parametersRef names EnvoyProxy {reference['name']} and this "
        f"chart renders {envoy_proxy['metadata']['name']}, so the Gateway would be "
        f"provisioned from the controller's defaults with nothing saying so"
    )
    assert reference["group"] == envoy_proxy["apiVersion"].split("/")[0], (
        f"the parametersRef group {reference['group']} is not the group the "
        f"rendered EnvoyProxy carries, {envoy_proxy['apiVersion']}"
    )
    # NEITHER CARRIES AN EXPLICIT NAMESPACE, which is what puts both in the
    # release namespace and makes the namespace-implicit `parametersRef` resolve.
    # A namespace pinned on one of the two would send the reference across a
    # boundary it cannot cross, and the Gateway would provision from the
    # controller's defaults with nothing saying so.
    assert "namespace" not in envoy_proxy["metadata"], envoy_proxy["metadata"]
    assert "namespace" not in gateway["metadata"], gateway["metadata"]


def test_a_parametersRef_naming_nothing_reddens_the_gate(tmp_path):
    """The red case: the ref points at a name the render does not produce."""
    copy = chart_with(
        tmp_path,
        "templates/gateway-listener.yaml",
        lambda text: text.replace(
            "      name: {{ $listener.envoyProxy.name }}",
            "      name: no-such-envoyproxy",
            1,
        ),
    )
    rendered = render(copy, *api_version_arguments(), "-f", str(ADOPTER_VALUES))
    gateway = one(rendered, "Gateway")
    envoy_proxy = one(rendered, "EnvoyProxy")
    assert (
        gateway["spec"]["infrastructure"]["parametersRef"]["name"]
        != envoy_proxy["metadata"]["name"]
    ), "the red case rewrote the parametersRef and the render still agreed"


def test_the_listener_serves_the_secret_the_edge_certificate_writes():
    """A REFERENCE ACROSS TWO TOGGLES, and the reason the two names are separate keys.

    The listener's `certificateRefs` names a SECRET; `edgeTLS` renders the
    Certificate that writes it. They are separate values keys on purpose — an
    adopter may terminate on a Secret their own tooling populates, with
    `edgeTLS.create` false and no Certificate in the render at all — so the
    agreement is an invariant that holds only when BOTH toggles are on, which is
    exactly the shape a gate has to carry rather than a template.
    """
    rendered = adopter_render()
    gateway = one(rendered, "Gateway")
    certificate = by_name(rendered, "Certificate", chart_values()["edgeTLS"]["name"])

    (listener,) = gateway["spec"]["listeners"]
    (certificate_ref,) = listener["tls"]["certificateRefs"]
    assert certificate_ref["kind"] == "Secret", certificate_ref
    assert certificate_ref["name"] == certificate["spec"]["secretName"], (
        f"the listener terminates on Secret {certificate_ref['name']} and the edge "
        f"Certificate writes {certificate['spec']['secretName']}, so the Gateway "
        f"would wait on a Secret nothing in this install produces"
    )
    assert listener["hostname"] in certificate["spec"]["dnsNames"], (
        f"the listener serves {listener['hostname']} and the edge certificate names "
        f"{certificate['spec']['dnsNames']}, so verification fails after signing "
        f"succeeds"
    )


def test_a_listener_secret_nothing_writes_reddens_the_gate(tmp_path):
    """The red case, and this one IS a values flip.

    Because the two names are separate keys, an adopter can put them out of step
    without touching a template — which is the failure this gate exists for.
    """
    values = overrides(
        tmp_path / "other-secret.yaml",
        "gatewayListener:\n  certificateSecretName: not-the-edge-secret\n",
    )
    rendered = adopter_render(CHART, "-f", str(values))
    gateway = one(rendered, "Gateway")
    certificate = by_name(rendered, "Certificate", chart_values()["edgeTLS"]["name"])
    (listener,) = gateway["spec"]["listeners"]
    (certificate_ref,) = listener["tls"]["certificateRefs"]
    assert certificate_ref["name"] != certificate["spec"]["secretName"], (
        "the red case pointed the listener at another Secret and the render still "
        "agreed, so this construction is testing nothing"
    )


def test_the_gateway_listener_renders_the_objects_it_counts():
    """The denominator, asserted rather than assumed."""
    rendered = adopter_render()
    found = (
        of_kind(rendered, "GatewayClass")
        + of_kind(rendered, "Gateway")
        + of_kind(rendered, "EnvoyProxy")
    )
    assert len(found) == EXPECTED_GATEWAY_LISTENER_OBJECTS, (
        f"expected {EXPECTED_GATEWAY_LISTENER_OBJECTS} listener objects, found "
        f"{len(found)}: {[document['kind'] for document in found]}"
    )


def test_the_listener_toggle_switches_every_one_of_them_off(tmp_path):
    """`gatewayListener.create` false removes all three and nothing else."""
    values = overrides(
        tmp_path / "listener-off.yaml", "gatewayListener:\n  create: false\n"
    )
    rendered = adopter_render(CHART, "-f", str(values))
    for kind in ("GatewayClass", "Gateway", "EnvoyProxy"):
        assert of_kind(rendered, kind) == [], (
            f"gatewayListener.create is false and a {kind} rendered anyway"
        )
    assert of_kind(rendered, "NetworkPolicy"), (
        "turning the listener off also removed the ingress policies, so the "
        "toggle reaches objects that are not its own"
    )


# ── VALKEY ───────────────────────────────────────────────────────────────────


def test_the_valkey_service_selects_the_pods_the_deployment_creates():
    """THE REFERENCE. A Service whose selector matches no pod has empty endpoints.

    `kubectl get svc` prints it, `kubectl describe` prints it, and every count
    agrees — the caller simply gets connection refused. Only comparing the
    selector with the pod template's own labels sees it.
    """
    rendered = adopter_render()
    deployment = by_name(rendered, "Deployment", chart_values()["valkey"]["name"])
    service = by_name(rendered, "Service", chart_values()["valkey"]["name"])

    labels = pod_labels(deployment)
    missing = {
        key: value
        for key, value in service["spec"]["selector"].items()
        if labels.get(key) != value
    }
    assert not missing, (
        f"the valkey Service selects {missing} and the Deployment's pods carry "
        f"{labels}, so the Service has no endpoints and every count still agrees"
    )
    assert deployment["spec"]["selector"]["matchLabels"].items() <= labels.items()


def test_the_valkey_deployment_mounts_the_secret_the_bootstrap_job_mints():
    """A REFERENCE ACROSS TWO TOGGLES AGAIN, and this one loses the cache when broken.

    `bootstrap.create` renders the Job that creates `valkey-password`; this
    Deployment consumes it by name. A disagreement leaves the pod in
    `ContainerCreating` for the lifetime of the install, which is the failure the
    bootstrap Jobs exist to move earlier.
    """
    rendered = adopter_render()
    deployment = by_name(rendered, "Deployment", chart_values()["valkey"]["name"])
    (container,) = deployment["spec"]["template"]["spec"]["containers"]

    referenced = {
        variable["valueFrom"]["secretKeyRef"]["name"]
        for variable in container["env"]
        if "secretKeyRef" in variable.get("valueFrom", {})
    }
    minted = {
        name
        for job in of_kind(rendered, "Job")
        for name in [chart_values()["valkey"]["passwordSecret"]["name"]]
        if name in yaml.dump(job)
    }
    assert referenced, "the valkey container reads no Secret, so the cache is open"
    assert referenced <= minted, (
        f"the valkey container mounts {sorted(referenced)} and the bootstrap Jobs "
        f"in this render mint {sorted(minted)}, so the pod waits on a Secret "
        f"nothing in this install creates"
    )


def test_a_valkey_secret_nothing_mints_reddens_the_gate(tmp_path):
    """The red case: a values flip that renames the Secret the container reads."""
    values = overrides(
        tmp_path / "other-password.yaml",
        "valkey:\n  passwordSecret:\n    name: nobody-mints-this\n",
    )
    rendered = adopter_render(CHART, "-f", str(values))
    deployment = by_name(rendered, "Deployment", chart_values()["valkey"]["name"])
    (container,) = deployment["spec"]["template"]["spec"]["containers"]
    referenced = {
        variable["valueFrom"]["secretKeyRef"]["name"]
        for variable in container["env"]
        if "secretKeyRef" in variable.get("valueFrom", {})
    }
    assert referenced == {"nobody-mints-this"}, referenced
    assert not any(
        "nobody-mints-this" in yaml.dump(job) for job in of_kind(rendered, "Job")
    ), "the red case renamed the Secret and a bootstrap Job minted it anyway"


def test_the_broker_reads_the_secrets_the_bootstrap_job_mints():
    """THE BROKER'S HALF OF THE GATE ABOVE, and it was the half that had none.

    `bootstrap.create` renders the Job that creates `valkey-password`, `nats-auth`
    AND `nats-auth-gateway`. The Deployment's reference to the first was gated; the
    StatefulSet's reference to the other two was not, and it is the SAME failure with
    the same shape — a values flip renaming either Secret leaves the broker in
    `ContainerCreating` for the lifetime of the install, which is exactly the failure
    the bootstrap Jobs exist to move earlier.

    IT CROSSES A CHART BOUNDARY, WHICH THE VALKEY TWIN DOES NOT. The StatefulSet is
    the upstream chart's, built from `nats.container.env` in this chart's
    `values.yaml`; the Job is this chart's, and mints the names as literals in its
    script. Nothing keeps the two in step but this comparison.

    TWO SECRETS AND NOT ONE, asserted as an equality. They are separate Secrets
    rather than two keys on one because the Job's Role grants `create` alone, so a
    second key on an already-created Secret would 409 forever; a gate satisfied by
    one of them would pass a render that had lost `gateway`'s credential.

    THE MINTED SIDE IS READ OFF THE REQUEST BODY, NOT OFF THE JOB'S TEXT, and that
    is the one place this gate is deliberately stricter than its valkey twin above.
    Measured while building it: renaming the created Secret to `nats-auth-typo`
    leaves the old name elsewhere in the same Job, so a substring search reports it
    minted and the gate passes over the failure it exists to catch.
    """
    rendered = adopter_render()
    stateful_set = one(rendered, "StatefulSet")
    referenced = secret_names(stateful_set)
    minted = minted_secret_names(rendered)

    assert referenced == EXPECTED_NATS_SECRETS, (
        f"the broker's containers read {sorted(referenced)} through secretKeyRef; "
        f"{sorted(EXPECTED_NATS_SECRETS)} is one account per service and a missing "
        f"one is a service whose access cannot be revoked on its own"
    )
    assert referenced <= minted, (
        f"the broker's containers read {sorted(referenced)} and the bootstrap Jobs "
        f"in this render mint {sorted(minted)}, so the pod waits in "
        f"ContainerCreating on a Secret nothing in this install creates"
    )


def test_a_broker_secret_nothing_mints_reddens_the_gate(tmp_path):
    """The red case: a values flip that renames one Secret the StatefulSet reads.

    A VALUES FLIP AND NOT A TEMPLATE EDIT, because that is the move an adopter
    actually makes — `nats.container.env` is a documented key of this chart's
    `values.yaml` and renaming a Secret there touches no template at all.
    """
    values = overrides(
        tmp_path / "other-broker-password.yaml",
        "nats:\n"
        "  container:\n"
        "    env:\n"
        "      NATS_PASSWORD:\n"
        "        valueFrom:\n"
        "          secretKeyRef:\n"
        "            name: nobody-mints-this\n",
    )
    rendered = adopter_render(CHART, "-f", str(values))
    stateful_set = one(rendered, "StatefulSet")
    referenced = secret_names(stateful_set)

    assert "nobody-mints-this" in referenced, referenced
    assert referenced != EXPECTED_NATS_SECRETS, referenced
    assert not any(
        "nobody-mints-this" in yaml.dump(job) for job in of_kind(rendered, "Job")
    ), "the red case renamed the Secret and a bootstrap Job minted it anyway"


def test_the_valkey_toggle_switches_its_objects_off(tmp_path):
    values = overrides(tmp_path / "valkey-off.yaml", "valkey:\n  create: false\n")
    rendered = adopter_render(CHART, "-f", str(values))
    name = chart_values()["valkey"]["name"]
    assert [
        document
        for document in rendered
        if document["metadata"]["name"] == name
    ] == [], "valkey.create is false and a valkey object rendered anyway"


# ── THE TWO INGRESS POLICIES ─────────────────────────────────────────────────


def test_the_valkey_policy_selects_the_pods_this_chart_renders():
    """THE REFERENCE. A podSelector matching nothing is accepted and protects nothing.

    ADR-0685 records that this estate has no control refusing a policy whose
    selector matches nothing, and ADR-0592 records that a passing kubelet probe
    carries no information either way. So the only instrument is this comparison
    against the pod template the same render produces.
    """
    rendered = adopter_render()
    policy = by_name(rendered, "NetworkPolicy", "valkey-ingress")
    deployment = by_name(rendered, "Deployment", chart_values()["valkey"]["name"])

    labels = pod_labels(deployment)
    selector = policy["spec"]["podSelector"]["matchLabels"]
    assert selector, "the valkey policy selects every pod in the namespace"
    assert selector.items() <= labels.items(), (
        f"valkey-ingress selects {selector} and the valkey pods carry {labels}, so "
        f"the policy is accepted, listed, describable and protects nothing"
    )
    assert policy_ports(policy) == {chart_values()["valkey"]["port"]}, policy_ports(
        policy
    )
    assert client_names(policy) == EXPECTED_VALKEY_CLIENTS, (
        f"valkey-ingress admits {client_names(policy)}; the one consumer is "
        f"{EXPECTED_VALKEY_CLIENTS} and a client added here is a client somebody "
        f"decided to admit"
    )


def test_the_nats_policy_selects_the_pods_the_SUBCHART_renders():
    """THE GATE THIS STEP EXISTS FOR, and the only one that crosses a chart boundary.

    `nats-ingress` is this estate's object; the pods it protects are the upstream
    chart's, labelled by the upstream chart's own helpers. Nothing keeps the two
    in step except this comparison — and the labels move with a values key an
    adopter can set (`nats.nameOverride`), so this is not a hypothetical drift.
    """
    rendered = adopter_render()
    policy = by_name(rendered, "NetworkPolicy", "nats-ingress")
    stateful_set = one(rendered, "StatefulSet")

    labels = pod_labels(stateful_set)
    selector = policy["spec"]["podSelector"]["matchLabels"]
    assert selector, "the nats policy selects every pod in the namespace"
    assert selector.items() <= labels.items(), (
        f"nats-ingress selects {selector} and the broker's pods, rendered by the "
        f"upstream chart, carry {labels} — the policy protects nothing"
    )
    assert client_names(policy) == EXPECTED_NATS_CLIENTS, client_names(policy)


def test_the_nats_policy_names_the_ports_the_SUBCHART_serves():
    """The second half of the same reference, and a policy gets this wrong silently.

    A NetworkPolicy with any ingress rule DENIES every port it does not name, so a
    policy naming only the client port cuts the monitoring endpoint the upstream
    chart's own probes use — restarting a healthy broker on the first CNI that
    enforces it. Every number is read off the upstream chart's own render rather
    than written here.

    SERVICES AND `containerPorts` BOTH, and the honest state of that widening is
    stated rather than implied. A NetworkPolicy admits traffic to the POD, and a pod
    IP is dialable whether or not a Service points at it — so the set of ports a
    policy has to name is the pod's, and a Service is the upstream chart's choice
    about how to reach them rather than a list of them.

    WHAT IT BUYS TODAY IS NOTHING, MEASURED. At 2.14.6 every listener the chart opens
    also lands on the headless Service: with `config.profiling.enabled` true the
    headless Service serves {4222, 8222, 65432} and the containers serve the same
    three, and with `service.enabled` false the headless Service survives and still
    serves both. So no values setting reachable today opens a pod port that no
    Service names, and the containerPort half adds no port to the comparison.

    IT IS STILL THE RIGHT SET TO READ. The claim "every listener also gets a Service"
    is a fact about this upstream chart at this version, not a property of
    NetworkPolicy, and it is the upstream chart's to change on any bump — silently,
    into a policy that denies a port the broker is serving. Reading the pod's own
    ports does not depend on that fact holding.

    The `nats.config.nats.port` red case below stays red either way: the containerPort
    follows that key exactly as the Service's port does, measured.
    """
    rendered = adopter_render()
    policy = by_name(rendered, "NetworkPolicy", "nats-ingress")
    served = broker_ports(rendered)
    assert served, "the render produced no broker port to read"
    assert served <= policy_ports(policy), (
        f"the broker serves {sorted(served)} and nats-ingress admits "
        f"{sorted(policy_ports(policy))}; every port the policy omits is denied"
    )


def test_the_policies_admit_from_every_source_only_where_written_down():
    """THE CENSUS THE CLIENT CENSUS CANNOT SEE, and the hole it exists to close.

    `client_names` walks `rule.get("from", [])`. A rule with NO `from` contributes
    nothing to that walk, so `client_names(policy) == EXPECTED_..._CLIENTS` passes
    unchanged over a policy admitting a port from EVERY source in the cluster. That
    is not a narrow rule read loosely — an ingress rule whose `from` is absent or
    empty matches all sources, every namespace included (ADR-0664). The two censuses
    are complementary and neither substitutes for the other: one names who is
    admitted by selector, this one names what is admitted to everybody.

    AN EQUALITY AGAINST PORTS WRITTEN DOWN, NOT A COUNT AND NOT A CEILING. A count
    passes when one from-less rule is deleted and another added on a different port.
    A ceiling passes when a from-less rule is added to a policy that had none. Only
    the equality names both the number and what each rule admits.

    `nats-ingress`'s one such rule is deliberate and argued beside it in
    `templates/ingress-policies.yaml`; this case does not judge that decision, it
    makes the decision VISIBLE so the next edit has to restate it here.
    """
    rendered = adopter_render()
    for name, expected in EXPECTED_ALLOW_ALL_PORTS.items():
        policy = by_name(rendered, "NetworkPolicy", name)
        rules = from_less_rules(policy)

        unbounded = [rule for rule in rules if not rule.get("ports")]
        assert not unbounded, (
            f"{name} carries {len(unbounded)} ingress rule(s) naming NEITHER a source "
            f"nor a port, and each admits every port from every source: {unbounded}"
        )
        admitted = {port["port"] for rule in rules for port in rule["ports"]}
        assert admitted == expected, (
            f"{name} carries {len(rules)} ingress rule(s) with no `from`, admitting "
            f"{sorted(admitted)} from ALL SOURCES — every namespace, not merely this "
            f"one; {sorted(expected)} is what was written down. A rule with no `from` "
            f"contributes nothing to `client_names`, so the client census above passes "
            f"over it in silence and this is the only case that sees it"
        )


def test_a_from_less_rule_added_to_a_policy_reddens_the_allow_all_census(tmp_path):
    """The red case, and it DEMONSTRATES the blindness as well as closing it.

    One from-less rule is added to `valkey-ingress`, which today carries none. The
    first assertion is the point of the whole case: `client_names` is UNCHANGED, so
    the client census keeps reporting the one consumer it expects while the policy
    admits a port from every source in the cluster. The second is this file's new
    census going red on that same render.
    """
    copy = chart_with(
        tmp_path,
        "templates/ingress-policies.yaml",
        lambda text: text.replace(
            "          port: {{ .Values.valkey.port }}\n",
            "          port: {{ .Values.valkey.port }}\n"
            "    - ports:\n"
            "        - protocol: TCP\n"
            "          port: 9121\n",
        ),
    )
    rendered = render(copy, *api_version_arguments(), "-f", str(ADOPTER_VALUES))
    policy = by_name(rendered, "NetworkPolicy", "valkey-ingress")

    assert client_names(policy) == EXPECTED_VALKEY_CLIENTS, (
        f"the added rule moved the client census to {client_names(policy)}, so this "
        f"case is no longer demonstrating the blindness it exists to demonstrate"
    )
    admitted = {
        port["port"] for rule in from_less_rules(policy) for port in rule["ports"]
    }
    assert admitted == {9121}, admitted
    assert admitted != EXPECTED_ALLOW_ALL_PORTS["valkey-ingress"], (
        "a from-less rule was added to valkey-ingress and the census above would "
        "still have passed, so it sees no more than `client_names` does"
    )


def test_a_from_less_rule_written_as_an_empty_list_is_seen_too(tmp_path):
    """The predicate's own red case: `from: []` is the SAME allow-all as no `from`.

    A gate written `"from" not in rule` passes this render and reports a policy with
    no allow-all rule, because the KEY is present. ADR-0664 measured that the API
    server treats the two identically, and the empty-list shape is the one a values
    override or a `range` over an empty list produces.
    """
    copy = chart_with(
        tmp_path,
        "templates/ingress-policies.yaml",
        lambda text: text.replace(
            "          port: {{ .Values.valkey.port }}\n",
            "          port: {{ .Values.valkey.port }}\n"
            "    - from: []\n"
            "      ports:\n"
            "        - protocol: TCP\n"
            "          port: 9121\n",
        ),
    )
    rendered = render(copy, *api_version_arguments(), "-f", str(ADOPTER_VALUES))
    policy = by_name(rendered, "NetworkPolicy", "valkey-ingress")

    seen = from_less_rules(policy)
    assert len(seen) == 1, (
        f"valkey-ingress carries a rule with `from: []` and `from_less_rules` "
        f"returned {seen} — a predicate keyed on the missing KEY rather than on the "
        f"missing VALUE reports this allow-all as a narrow rule, which is the "
        f"measurement ADR-0664 exists to stop being re-derived wrongly"
    )
    assert seen[0]["from"] == [], seen[0]
    assert client_names(policy) == EXPECTED_VALKEY_CLIENTS, client_names(policy)


def test_a_moved_subchart_label_reddens_the_nats_policy_gate(tmp_path):
    """The red case, and it is a VALUES flip against the UPSTREAM chart.

    `nats.nameOverride` moves `app.kubernetes.io/name` on the broker's pods
    without touching one line of this chart. That is precisely the drift the gate
    is for, and it proves the gate reads the subchart's real output rather than
    this chart's idea of it.
    """
    values = overrides(tmp_path / "renamed.yaml", "nats:\n  nameOverride: brokerx\n")
    rendered = adopter_render(CHART, "-f", str(values))
    policy = by_name(rendered, "NetworkPolicy", "nats-ingress")
    stateful_set = one(rendered, "StatefulSet")
    selector = policy["spec"]["podSelector"]["matchLabels"]
    assert not selector.items() <= pod_labels(stateful_set).items(), (
        "the broker's pod labels were moved by a values key and the policy's "
        "selector followed them, so this red case is testing nothing"
    )


def test_a_moved_subchart_port_reddens_the_nats_policy_gate(tmp_path):
    """The port half's red case, also a values flip against the upstream chart."""
    values = overrides(
        tmp_path / "moved-port.yaml", "nats:\n  config:\n    nats:\n      port: 4333\n"
    )
    rendered = adopter_render(CHART, "-f", str(values))
    policy = by_name(rendered, "NetworkPolicy", "nats-ingress")
    served = broker_ports(rendered)
    assert not served <= policy_ports(policy), (
        "the broker's client port moved and the policy's port list followed it, "
        "so this red case is testing nothing"
    )


def test_the_render_carries_the_policies_it_counts():
    rendered = adopter_render()
    policies = of_kind(rendered, "NetworkPolicy")
    assert len(policies) == EXPECTED_INGRESS_POLICIES, (
        f"expected {EXPECTED_INGRESS_POLICIES} ingress policies, found "
        f"{len(policies)}: {[document['metadata']['name'] for document in policies]}"
    )
    assert sorted(document["metadata"]["name"] for document in policies) == [
        "nats-ingress",
        "valkey-ingress",
    ]


def test_each_policy_follows_the_toggle_that_renders_what_it_protects(tmp_path):
    """A policy outliving its workload protects nothing and reads as a control.

    Each of the two is checked on its own, so the failure names which toggle left
    its policy standing.
    """
    for toggle, policy_name, survivor in (
        ("valkey", "valkey-ingress", "nats-ingress"),
        ("nats", "nats-ingress", "valkey-ingress"),
    ):
        values = overrides(
            tmp_path / f"{toggle}-off.yaml", f"{toggle}:\n  create: false\n"
        )
        rendered = adopter_render(CHART, "-f", str(values))
        names = [
            document["metadata"]["name"] for document in of_kind(rendered, "NetworkPolicy")
        ]
        assert policy_name not in names, (
            f"{toggle}.create is false and {policy_name} rendered anyway, so the "
            f"policy outlives the workload it selects"
        )
        assert survivor in names, (
            f"{toggle}.create false also removed {survivor}, so the toggle reaches "
            f"a policy that is not its own"
        )


# ── THE RENDER CHECK'S GROUP, AND THE TWO GROUPS IT IS NOT ───────────────────


def test_the_render_check_names_the_group_the_values_file_records():
    """ONE SOURCE FOR THE OPERATOR STRING, asserted across the two files that hold it.

    The plan requires the group-and-version string to be READ OFF the operator and
    RECORDED IN THE VALUES FILE beside the check that uses it, so an operator
    upgrade that moved the version turns the check red rather than silently
    weakening it. The check itself must pass a LITERAL — `test_render_checks.py`
    reads the invocation's arguments off the template — so the string exists in
    two places and this is the gate that keeps them one.
    """
    from test_render_checks import declared_checks

    recorded = chart_values()["gatewayListener"]["envoyGateway"]["apiVersion"]
    declared = declared_checks(CHART)
    assert recorded in declared, (
        f"values.yaml records {recorded} as Envoy Gateway's group and the chart's "
        f"checks ask for {sorted(declared)}; the two disagree, so the recorded "
        f"string is documentation rather than the thing under test"
    )
    assert declared[recorded] == "Envoy Gateway", declared[recorded]


def test_the_check_is_not_written_against_the_upstream_gateway_api():
    """THE TRAP THIS CHECK EXISTS TO AVOID, asserted rather than commented.

    `gateway.networking.k8s.io/v1` is the UPSTREAM Gateway API — a specification
    that Istio and every other implementation registers. A check written against
    it is green on a cluster carrying those CRDs with no Envoy Gateway anywhere,
    which is exactly the adopter state the check exists to refuse. The same
    cluster serves all three groups, so the wrong one is a plausible edit rather
    than an unlikely one.
    """
    from test_render_checks import declared_checks

    declared = declared_checks(CHART)
    for group in UPSTREAM_GATEWAY_API_GROUPS:
        assert group not in declared, (
            f"a render check asks for {group}, which is the Gateway API "
            f"specification rather than Envoy Gateway — it is satisfied by the "
            f"upstream CRDs alone and names no operator"
        )
    assert any(
        group.startswith("gateway.envoyproxy.io/") for group in declared
    ), sorted(declared)


def test_the_gateway_listener_renders_a_kind_from_the_checked_group():
    """The check guards SEVERAL kinds behind one toggle, and one of them is its own.

    `gateway.networking.k8s.io` kinds render here too and are deliberately NOT
    checked: that group names a specification, not an operator. What makes the one
    check legitimate is that the toggle also renders an EnvoyProxy, whose group no
    other implementation registers.
    """
    rendered = adopter_render()
    envoy_proxy = one(rendered, "EnvoyProxy")
    recorded = chart_values()["gatewayListener"]["envoyGateway"]["apiVersion"]
    assert envoy_proxy["apiVersion"] == recorded, (
        f"the EnvoyProxy renders as {envoy_proxy['apiVersion']} and the check asks "
        f"for {recorded}, so the check guards a group nothing in this render uses"
    )


# ── THE DEPENDENCY, AND THE TARBALL THAT MUST CARRY IT ───────────────────────


def declared_dependencies(chart: Path) -> list[str]:
    """Every dependency the chart declares, by name. PURE."""
    manifest = yaml.safe_load((chart / "Chart.yaml").read_text())
    return sorted(
        dependency["name"] for dependency in manifest.get("dependencies", [])
    )


def vendored_members(archive: Path) -> list[str]:
    """Every `<top>/charts/<name>/Chart.yaml` member of a packaged chart. PURE."""
    with tarfile.open(archive) as tarball:
        return sorted(
            name
            for name in tarball.getnames()
            if name.count("/") == 3
            and name.endswith("/Chart.yaml")
            and "/charts/" in name
        )


def vendoring_failures(declared: list[str], members: list[str]) -> list[str]:
    """How a packaged chart's vendored subcharts disagree with what it declares. PURE."""
    vendored = sorted(name.split("/charts/")[1].split("/")[0] for name in members)
    failures = []
    if len(vendored) != len(declared):
        failures.append(
            f"expected {len(declared)} vendored subchart Chart.yaml members, found "
            f"{len(vendored)}: declared {declared}, vendored {vendored}"
        )
    if vendored != declared:
        failures.append(f"declared {declared}, vendored {vendored}")
    return failures


def test_the_chart_declares_the_dependencies_this_suite_expects():
    declared = declared_dependencies(CHART)
    assert len(declared) == EXPECTED_DECLARED_DEPENDENCIES, declared
    assert declared == ["nats"], declared


def test_the_package_carries_every_declared_subchart(tmp_path):
    """THE TARBALL CLAIM, PROVED RATHER THAN ASSUMED.

    `helm install` does NOT resolve dependencies — it expects a self-contained
    package — so an adopter with zero helm repositories configured gets a broker
    only if `helm package -u` vendored the HTTP-sourced chart into the artifact.
    This estate had never published a chart with a non-yadgarhq dependency before,
    so the claim had no evidence behind it.
    """
    staged = tmp_path / "chart"
    shutil.copytree(CHART, staged, ignore=shutil.ignore_patterns("charts"))
    packaged = helm("package", "-u", str(staged), "--destination", str(tmp_path))
    assert packaged.returncode == 0, packaged.stderr

    (archive,) = sorted(tmp_path.glob("platform-*.tgz"))
    members = vendored_members(archive)
    failures = vendoring_failures(declared_dependencies(CHART), members)
    assert failures == [], "\n".join(failures)
    assert "platform/charts/nats/Chart.yaml" in members, members


def test_a_declared_dependency_that_is_not_vendored_is_named():
    """The vendoring gate's red case, constructed rather than packaged.

    PURE INPUTS, so the red case needs no network and cannot be the flaky half of
    this pair. What it proves is that the comparison NAMES the missing subchart —
    a gate reporting "counts differ" and not which one is the gate a reader cannot
    act on.
    """
    failures = vendoring_failures(
        ["nats", "valkey"], ["platform/charts/nats/Chart.yaml"]
    )
    message = "\n".join(failures)
    assert failures, "a declared dependency was not vendored and the gate said nothing"
    assert "expected 2 vendored subchart Chart.yaml members, found 1" in message
    assert "valkey" in message, message


def test_the_valkey_render_carries_the_objects_it_counts():
    """The denominator for the cache, asserted rather than assumed.

    Separate from the reference gates above on purpose: those compare a selector
    with a pod template and would still hold over a render carrying two
    Deployments and two Services, and a second cache is not a thing this chart may
    grow quietly.
    """
    rendered = adopter_render()
    name = chart_values()["valkey"]["name"]
    found = [
        document
        for document in rendered
        if document["metadata"]["name"] == name
        and document["kind"] in ("Deployment", "Service")
    ]
    assert len(found) == EXPECTED_VALKEY_OBJECTS, (
        f"expected {EXPECTED_VALKEY_OBJECTS} valkey objects, found {len(found)}: "
        f"{[document['kind'] for document in found]}"
    )


def test_a_moved_valkey_pod_label_reddens_the_policy_and_service_gates(tmp_path):
    """The cache's own red case, and it is a TEMPLATE edit by construction.

    The Service's selector, the policy's selector and the pod template's labels all
    read ONE values key, which is what makes them agree under every values file an
    adopter can write — so no values flip can separate them, and a gate whose only
    red case were a values flip would be asserting nothing here. What CAN separate
    them is an edit to one of the three templates, which is exactly the change a
    reader relabelling the workload would make. Both gates must see it.
    """
    copy = chart_with(
        tmp_path,
        "templates/valkey.yaml",
        lambda text: text.replace(
            "    metadata:\n      labels:\n        app.kubernetes.io/name: {{ $valkey.name }}",
            "    metadata:\n      labels:\n        app.kubernetes.io/name: relabelled",
            1,
        ),
    )
    rendered = render(copy, *api_version_arguments(), "-f", str(ADOPTER_VALUES))
    name = chart_values()["valkey"]["name"]
    deployment = by_name(rendered, "Deployment", name)
    labels = pod_labels(deployment)

    service = by_name(rendered, "Service", name)
    assert not service["spec"]["selector"].items() <= labels.items(), (
        "the pod labels were moved and the Service's selector followed them, so "
        "this red case is testing nothing"
    )
    policy = by_name(rendered, "NetworkPolicy", "valkey-ingress")
    assert not policy["spec"]["podSelector"]["matchLabels"].items() <= labels.items(), (
        "the pod labels were moved and the policy's selector followed them, so "
        "this red case is testing nothing"
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
