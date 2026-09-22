# yadgar/platform

The shared platform layer of a yadgar installation, as a Helm chart with no binary (ADR-0752).

A bare cluster with the third-party operators already installed should become a running yadgar estate by helm alone. Until now the platform layer — the internal certificate authority and the leaves it issues, the edge leaf a different authority issues, the databases, the broker, the cache, the Gateway listener and the bootstrap Jobs — existed only as `yadgarhq/deploy`'s own Argo manifests, so an adopter got none of it and would have to write their own. This repository is where that layer becomes something an adopter renders from the same published artifact this organisation does.

**It renders NOTHING by default.** Every object sits behind a `create` toggle that defaults to false, so `helm template platform chart` on a bare cluster produces an empty render and needs no CRD at all. An adopter turns on what they want; this organisation keeps its `deploy` copies and turns nothing on.

## What is here today

This is the first commit, and it carries the certificate half of the layer.

| object set                                                                                                           | toggle                | default |
| -------------------------------------------------------------------------------------------------------------------- | --------------------- | ------- |
| Issuer `yadgar-internal-selfsign`, Certificate `yadgar-internal-ca` (`isCA`, ten years), Issuer `yadgar-internal-ca` | `internalCA.create`   | `false` |
| The ten internal leaf Certificates, each carrying its own `renewBefore`                                              | `certificates.create` | `false` |
| The edge Certificate, whose issuer is an authority this chart does not own                                           | `edgeTLS.create`      | `false` |

The rest of the layer — the databases, NATS, Valkey, the Gateway listener, the bootstrap Jobs and the preflight Job — arrives in later pull requests.

## The ladder, which is the reason these objects live together

`chart/values.yaml` carries the ten internal leaves as a **map keyed by name**, each entry with its own `renewBefore`. Those values are **one invariant, not ten settings**: they are distinct and six hours apart, so at most one service restarts per renewal instant. The edge leaf's 720h belongs to the same ladder and is held out of the map, because a different toggle renders it.

Every leaf has exactly one consuming module, so ADR-0752's rule that a single-consumer object stays with its module would put each of them in a different repository. ADR-0754 is the amendment that does not: **an object whose correctness depends on an invariant spanning its siblings belongs with the invariant, not with its consumer.** An invariant is checkable only where every one of its terms is visible at once. In one values file the ladder is a map with one gate over it; spread over seven repositories it is seven numbers nobody compares.

`scripts/tests/test_ladder.py` is that gate. It asserts the number of Certificate objects it examined and the set of ladder values it found, **per render**, and it fails with both numbers in the message. The count is asserted rather than printed, because a gate that renders a set, finds no violation among zero members and reports a pass has proved nothing.

## The render check, and the trap in testing it

`chart/templates/render-checks.yaml` refuses at render time when the target does not have `cert-manager.io/v1`, naming the operator and the toggle that asked for it. Without it a toggle set true on a cluster with no cert-manager renders cleanly and fails at apply with `no matches for kind Certificate` — half-way through an install, naming a kind rather than a prerequisite.

**`helm template` does not populate `.Capabilities.APIVersions` with CRD-backed groups from anywhere but a live cluster.** So a bare render is refused whatever the target holds, and a red case built that way cannot tell "the check works" apart from "the renderer always answers false". `scripts/tests/test_render_checks.py` therefore constructs **both** halves of every pair with `--api-versions`: the red case names a group no check asks for, the green case names the group the check wants. It asserts how many pairs it exercised against the number of checks the chart declares, so a check deleted from the chart reddens the suite on the count.

## Layout

```
chart/Chart.yaml                      the chart
chart/values.yaml                     every toggle, every leaf and the ladder, with the reasoning beside each
chart/templates/_require_api.tpl      the render check's definition — a partial, which helm never renders
chart/templates/render-checks.yaml    where it is CALLED, which is what makes the refusal happen
chart/templates/internal-ca.yaml      the self-signed Issuer, the CA Certificate and the CA Issuer
chart/templates/certificates.yaml     the ten internal leaves, from the map in values.yaml
chart/templates/edge-certificate.yaml the edge leaf, whose issuerRef is required with no default
example/values.yaml                   what an adopter commits in their own repository
scripts/tests/                        the ladder gate and the render-check harness
```

## Adopting this in your own installation

You clone nothing and you fork nothing. Copy `example/values.yaml` into your own GitOps repository, set `edgeTLS.issuerRef.name` and `edgeTLS.issuerRef.kind` to your own certificate authority, and point your Application at the published chart.

**cert-manager is your prerequisite and this chart never installs it.** That is the estate's standing rule for every operator — cert-manager, mariadb-operator, KEDA, Envoy Gateway and Argo CD are the adopter's to install, and a chart that needs one checks the API and refuses at render when it is absent.

## What this is NOT

**It is not a reference deployment.** `yadgarhq/deploy` is, and it stays opinionated on purpose. This chart is what an adopter with their own cluster renders; `deploy` is what this organisation runs.

**It does not install an operator, and it never will.** See above.

**It holds no secret.** This repository is public. The data-bearing secrets of the platform layer — the internal CA's private key among them — are cert-manager's or are minted inside the installation by a Job the chart renders (ADR-0750), and neither reaches a file here.
