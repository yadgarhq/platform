# yadgar/platform

The shared platform layer of a yadgar installation, as a Helm chart with no binary (ADR-0752).

A bare cluster with the third-party operators already installed should become a running yadgar estate by helm alone. Until now the platform layer — the internal certificate authority and the leaves it issues, the edge leaf a different authority issues, the databases, the broker, the cache, the Gateway listener and the bootstrap Jobs — existed only as `yadgarhq/deploy`'s own Argo manifests, so an adopter got none of it and would have to write their own. This repository is where that layer becomes something an adopter renders from the same published artifact this organisation does.

**It renders NOTHING by default.** Every object sits behind a `create` toggle that defaults to false, so `helm template platform chart` on a bare cluster produces an empty render and needs no CRD at all. An adopter turns on what they want; this organisation keeps its `deploy` copies and turns nothing on.

## What is here today

The certificate half of the layer, and the Jobs that mint the credentials nothing outside the installation can supply.

| object set                                                                                                           | toggle                   | default |
| -------------------------------------------------------------------------------------------------------------------- | ------------------------ | ------- |
| Issuer `yadgar-internal-selfsign`, Certificate `yadgar-internal-ca` (`isCA`, ten years), Issuer `yadgar-internal-ca` | `internalCA.create`      | `false` |
| The ten internal leaf Certificates, each carrying its own `renewBefore`                                              | `certificates.create`    | `false` |
| The edge Certificate, whose issuer is an authority this chart does not own                                           | `edgeTLS.create`         | `false` |
| Jobs `bootstrap-secrets` and `admin-bootstrap-token`, and the ServiceAccount, Role and RoleBinding they share        | `bootstrap.create`       | `false` |
| GatewayClass `eg`, Gateway `edge` and the EnvoyProxy that places its data plane                                      | `gatewayListener.create` | `false` |
| The Valkey Deployment and Service, and the `valkey-ingress` NetworkPolicy                                            | `valkey.create`          | `false` |
| The upstream `nats` chart as a DEPENDENCY, and the `nats-ingress` NetworkPolicy this chart renders itself            | `nats.create`            | `false` |

The two probe Jobs are here too, on one toggle between them — the pre-install preflight and the post-install Envoy Gateway probe — and the sections on them below say what each does. The three MariaDB instances are the one part of the layer that is not here and will not be: each has exactly one consuming module, so each belongs to that module's own chart behind `database.create`.

## The broker is a dependency, not a copy

`chart/Chart.yaml` declares `nats` from `https://nats-io.github.io/k8s/helm/charts` at `2.14.6` — the version this organisation already runs — behind `condition: nats.create`. It is the estate's first non-yadgarhq chart dependency, and three things follow.

**Nothing is vendored into git** (ADR-0725). `chart/charts/` stays ignored and the release pipeline resolves the dependency before it packages or renders anything, because a STALE vendored subchart is silent on every tool this estate runs: `helm package`, `helm lint --strict` and `helm template` all exit 0 on a chart whose `Chart.yaml` pins one version while `charts/` holds another. **So run `helm dependency update chart` after cloning**, or every helm command here refuses with `found in Chart.yaml, but missing in charts/ directory: nats`.

**The condition is load-bearing.** A declared dependency renders unconditionally unless a `condition` names a values key that is false. Without it, the parent chart's default render would grow by the whole NATS release the day this chart is added, on every install, for every adopter.

**The published tarball carries the broker, and that is proved rather than assumed.** installing a chart does not resolve its dependencies — the install expects a self-contained package — so an adopter with no helm repositories configured gets a broker only if `helm package -u` vendored the HTTP-sourced chart into the artifact. `test_the_package_carries_every_declared_subchart` packages this chart and asserts `platform/charts/nats/Chart.yaml` is inside it, and that the number of vendored subcharts equals the number declared.

The broker's own values — the two accounts, their subject permissions and the `<< >>` escape that emits `$NATS_PASSWORD` unquoted — live under `nats:` in `chart/values.yaml`, moved from this organisation's Argo Application unchanged. The `nats-ingress` NetworkPolicy is NOT the upstream chart's: it is this estate's object and this chart renders it.

## The bootstrap Jobs, and the Secrets nothing owns

Four credentials have **no source outside the installation**: `valkey-password`, `nats-auth`, `nats-auth-gateway`, and the administrative bootstrap token that lets the first administrator exist before any administrator exists to create one. Their value is not a credential to some external system — it is created once, and everything derives from it. There is nobody to transcribe them from, so ADR-0750 rules that the chart mints them itself, with an **idempotent Job**, into a Secret that **neither Helm nor Argo tracks**.

Four properties make that safe rather than clever. `scripts/tests/test_bootstrap.py` asserts each of them, and each assertion has a constructed red case beside it.

1. **It never rewrites or rotates an existing Secret.** The script generates on _every_ run and POSTs — it does not read first, and it does not check whether the Secret is already there. The API server refuses the second POST and every one after it with `409 AlreadyExists`, the Job reads that answer as success, and the value it generated is discarded unused. There is no check-then-act window because there is no check, and the Role grants `create` alone, so the Job could not overwrite a live credential even if the script were wrong. **A restore is therefore ordinary:** create the Secret from your backup before you install, and the Job stands down.
2. **The chart never templates the Secret.** Because a Job POSTs it, the Secret is in neither Helm's release manifest nor Argo's tracked set. An uninstall does not delete it and a prune does not remove it, so the key outlives the release that created it.
3. **The value stays exportable.** The command is below, beside the install command rather than in a section somebody reaches later.
4. **The Role grants `create` and nothing else** — not `get`, not `list`, not `update`, not `patch`, not `delete`. That is ADR-0750's property 4 as ADR-0753 narrowed it. A compromised bootstrap pod learns nothing about the credentials it did not mint.

**`iam-keys` is deliberately not among them.** It is data-bearing: every stored name is AES-256-GCM ciphertext, and every username is found through an HMAC blind index. Generate it, and a cluster whose Secret is gone but whose database survived gets an `iam` that **starts healthy and cannot decrypt the rows it already has**. Leave it out, and the same cluster gets a pod that refuses to start and names the missing file — which is the only signal that the keys were lost at all. ADR-0753 puts its generation behind a key-identity marker in the `iam` binary that refuses a wrong key, and orders that marker first, in a change of its own. Until that ships, this chart never names `iam-keys`.

**Rotation is not provided.** Deleting a Secret and re-running the Job mints a _different_ value, which is destructive for anything already encrypted under the old one.

## The ladder, which is the reason these objects live together

`chart/values.yaml` carries the ten internal leaves as a **map keyed by name**, each entry with its own `renewBefore`. Those values are **one invariant, not ten settings**: they are distinct and six hours apart, so at most one service restarts per renewal instant. The edge leaf's 720h belongs to the same ladder and is held out of the map, because a different toggle renders it.

Every leaf has exactly one consuming module, so ADR-0752's rule that a single-consumer object stays with its module would put each of them in a different repository. ADR-0754 is the amendment that does not: **an object whose correctness depends on an invariant spanning its siblings belongs with the invariant, not with its consumer.** An invariant is checkable only where every one of its terms is visible at once. In one values file the ladder is a map with one gate over it; spread over seven repositories it is seven numbers nobody compares.

`scripts/tests/test_ladder.py` is that gate. It asserts the number of Certificate objects it examined and the set of ladder values it found, **per render**, and it fails with both numbers in the message. The count is asserted rather than printed, because a gate that renders a set, finds no violation among zero members and reports a pass has proved nothing.

## The render check, and the trap in testing it

`chart/templates/render-checks.yaml` refuses at render time when the target does not have the API a toggle asked for, naming the operator that provides it and the toggle that asked. Without it a toggle set true on a cluster with no cert-manager renders cleanly and fails at apply with `no matches for kind Certificate` — half-way through an install, naming a kind rather than a prerequisite.

**Two checks, one per operator rather than one per kind.** Everything the certificate half renders comes from `cert-manager.io/v1`, so those share a check. `gatewayListener.create` renders three kinds from TWO groups and also carries ONE check — and **which group it names is the whole decision**. The Gateway API's own `gateway.networking.k8s.io/v1` is a SPECIFICATION that Istio and every other implementation registers, so a check on it is green on a cluster with the Gateway API CRDs and no Envoy Gateway anywhere: it names a specification and can never be the refusal that names Envoy Gateway. The same cluster serves `gateway.networking.x-k8s.io/v1alpha1` too. Three plausible strings, one correct — the check targets `gateway.envoyproxy.io/v1alpha1`, the EnvoyProxy's own group, which no other implementation registers. The string is recorded in `chart/values.yaml` beside the toggle, read off Envoy Gateway at the version this estate pins, and a gate asserts the recorded string and the check's own literal agree.

**`helm template` does not populate `.Capabilities.APIVersions` with CRD-backed groups from anywhere but a live cluster.** So a bare render is refused whatever the target holds, and a red case built that way cannot tell "the check works" apart from "the renderer always answers false". `scripts/tests/test_render_checks.py` therefore constructs **both** halves of every pair with `--api-versions`: the red case names a group no check asks for, the green case names the group the check wants. It asserts how many pairs it exercised against the number of checks the chart declares, so a check deleted from the chart reddens the suite on the count.

**With more than one check the construction is not "name the group under test".** `fail` aborts the whole render at the FIRST failing check and the refusal names only that one, so a red case that leaves a second check unsatisfied refuses for THAT check's reason. The green case therefore names EVERY group the render's checks ask for, and the red case for a check names every one of those groups EXCEPT its own, plus a filler group no check asks for. Both halves of that are what make the refusal attributable to the check under test, and both are asserted rather than described.

## Layout

```
chart/Chart.yaml                           the chart
chart/values.yaml                          every toggle, every leaf and the ladder, with the reasoning beside each
chart/templates/_require_api.tpl           the render check's definition — a partial, which helm never renders
chart/templates/render-checks.yaml         where it is CALLED, which is what makes the refusal happen
chart/templates/internal-ca.yaml           the self-signed Issuer, the CA Certificate and the CA Issuer
chart/templates/certificates.yaml          the ten internal leaves, from the map in values.yaml
chart/templates/edge-certificate.yaml      the edge leaf, whose issuerRef is required with no default
chart/templates/bootstrap-rbac.yaml        the one identity both Jobs run as — `create` on secrets, nothing else
chart/templates/bootstrap-secrets.yaml     the three machine-only credentials, minted by a pre-install hook
chart/templates/admin-bootstrap-token.yaml the one credential an operator reads out, in its own file
chart/templates/gateway-listener.yaml       the GatewayClass, the Gateway and the EnvoyProxy that places its data plane
chart/templates/valkey.yaml                 the one shared cache — a Deployment and a Service, no persistence
chart/templates/ingress-policies.yaml       who may dial the cache and who may dial the broker
chart/templates/_preflight.tpl              the probe/toggle tie, and the refusal when the two disagree
chart/templates/preflight.yaml              the pre-install Job that proves a controller is running
chart/templates/preflight-rbac.yaml         the preflight's own identity, separate from the bootstrap's
chart/templates/envoy-gateway-probe.yaml    the post-install Job that proves Envoy Gateway programs a Gateway
chart/templates/envoy-gateway-probe-rbac.yaml  that Job's own identity — `create`, `get`, `delete` on Gateways
example/values.yaml                        what an adopter commits in their own repository
scripts/tests/                             the ladder gate, the render-check harness, the bootstrap, preflight and shared-infrastructure gates
```

## Adopting this in your own installation

You clone nothing and you fork nothing. Copy `example/values.yaml` into your own GitOps repository, set `edgeTLS.issuerRef.name` and `edgeTLS.issuerRef.kind` to your own certificate authority, and point your Application at the published chart.

```sh
helm install platform yadgar/platform --namespace yadgar --create-namespace -f values.yaml
```

**Then export what the bootstrap Jobs minted.** Nothing tracks those four Secrets, which is what keeps an uninstall or a prune from deleting them — and it is also what leaves nothing backing them up. A cluster deleted without an export loses the values for good. Run these five commands after the first install, and store the output where you store your other backups.

```sh
kubectl -n yadgar get secret valkey-password -o yaml
kubectl -n yadgar get secret nats-auth -o yaml
kubectl -n yadgar get secret nats-auth-gateway -o yaml
kubectl -n yadgar get secret admin-bootstrap-token -o yaml
kubectl -n yadgar get secret yadgar-internal-ca -o yaml
```

**The fifth is a different kind of Secret, and the difference is worth stating rather than blurring.** `yadgar-internal-ca` holds the internal authority's private key, and losing that material invalidates every certificate issued under it. It is written by cert-manager from the `isCA` Certificate in `chart/templates/internal-ca.yaml` — neither Job mints it — so ADR-0750's property 3 does not strictly bind it. It is listed here because the hazard is the same one, and naming a hazard while withholding its remedy helps nobody.

**What `helm uninstall` leaves behind, deliberately.** The ServiceAccount, the Role, the RoleBinding and the two completed Jobs carry `hook-delete-policy: before-hook-creation` and nothing else, so all five remain after the release is gone. The design asks for exactly that, and `hook-succeeded` is not an available alternative: it would delete the ServiceAccount before the Jobs it serves are finished with it. The residual grant is real and it is bounded. Anyone who can create a pod in that namespace can mount that ServiceAccount and `create` Secrets there — and nothing else, because the Role holds no `get`, no `list`, no `update` and no `delete`, and it is namespaced. Delete the triple by hand if the namespace outlives the release.

**And the two probe Jobs leave a triple each, with grants of their own.** The preflight Job runs as its own ServiceAccount under its own Role, and the post-install Envoy Gateway probe runs as a third — both residual for the same reason and by the same mechanism. The preflight's grant is `create`, `get` and `delete` — never `list` — on the probe kinds alone, and only on the kinds the probes this install enables actually touch; the probe's is the same three verbs on Gateways and nothing else. Both are namespaced like the bootstrap's. Delete them by hand alongside it.

**The preflight refuses the install rather than decorating it.** It runs before every other hook, creates one object per enabled operator, waits for that operator's controller to act on it, deletes it and reports how many operators it probed — asserting that number against how many its values enabled. A cluster whose CRDs are registered but whose controller is absent is the case it exists to name, and the install stops there instead of hanging later on objects that never go Ready. It probes only what the install actually renders: every probe's default follows the toggle that renders what it probes, so a bare `helm install` of this chart with no values runs no probe and renders no Job at all. Set `preflight.enabled: false` to drop it.

**Envoy Gateway is probed AFTER the install, in a Job of its own, and the phase is the whole reason.** A pre-install probe of it could not go red. `Accepted=True` on a GatewayClass is a condition already persisted in etcd, so it stays there with the controller at zero replicas; and `gatewayListener.create` renders the GatewayClass itself, so on a fresh install there is nothing to bind to yet. The post-install Job runs once the release's objects exist: it creates a Gateway the controller has never seen, on the class this chart rendered and inheriting that listener's EnvoyProxy, waits for Envoy Gateway to mark it `Programmed=True`, and deletes it on every exit path. A fresh object has no status, so only a running controller can give it one. Its default follows `gatewayListener.create` exactly as the other probes follow theirs, and `preflight.enabled: false` drops it too.

The administrative bootstrap token is the one of the four a person actually reads. Hand it to the first administrator with:

```sh
kubectl -n yadgar get secret admin-bootstrap-token -o jsonpath='{.data.token}' | base64 -d; echo
```

**Read it again after every cluster rebuild.** The Job mints a new token when the Secret is gone, so a value copied from before the rebuild agrees with nothing. The Secret is never _absent_ — it is present, ready, and wrong — and no existence check can tell the two apart.

**Envoy Gateway is your prerequisite too, if you turn the listener on.** `gatewayListener.envoyProxy.serviceType` defaults to `LoadBalancer`, which is the right answer on a cluster with a load-balancer controller. Without one, set it to `NodePort` and pin the port in your own values — this organisation does exactly that in `yadgarhq/deploy`, because under rootless podman the host cannot route to container IPs at all.

**cert-manager is your prerequisite and this chart never installs it.** That is the estate's standing rule for every operator — cert-manager, mariadb-operator, KEDA, Envoy Gateway and Argo CD are the adopter's to install, and a chart that needs one checks the API and refuses at render when it is absent.

## What this is NOT

**It is not a reference deployment.** `yadgarhq/deploy` is, and it stays opinionated on purpose. This chart is what an adopter with their own cluster renders; `deploy` is what this organisation runs.

**It does not install an operator, and it never will.** See above.

**It holds no secret.** This repository is public. The data-bearing secrets of the platform layer — the internal CA's private key among them — are cert-manager's or are minted inside the installation by a Job the chart renders (ADR-0750), and neither reaches a file here.
