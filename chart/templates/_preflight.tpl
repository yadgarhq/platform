{{/*
THE TIE: every probe's default follows the toggle that renders what it probes.

NO PROBE DEFAULTS TRUE ON ITS OWN, and that is a rule rather than a preference. A
diagnostic for a prerequisite this install does not use MUST NOT RUN: a probe for
an operator whose objects this install renders none of proves nothing and can only
fail for the wrong reason. The case that forced the rule is concrete — a probe
enabled beside a toggle that renders nothing creates an object bound to a class
this install never made, the apply succeeds and the hook then fails, which is a
clean install followed by a failed release.

THE TIE LIVES HERE AND NOT IN `values.yaml`, because helm's `values.yaml` holds
static YAML and a default cannot read another key. So each `preflight.probes.<name>`
key is UNSET by default and this partial resolves it.

AND THE UNSET TEST IS `hasKey`, NEVER SPRIG'S `default`. `default` treats `false`
AS EMPTY — it returns its fallback for `false` exactly as it does for an absent key
— so a `dig`/`default` chain cannot tell an unset key from an explicit `false`, and
the false-direction override silently would not exist: an adopter writing
`probes.certManager: false` beside `internalCA.create: true` would get the probe
anyway, with no message. `test_preflight.py`'s
`test_implementing_the_tie_with_sprigs_default_reddens_the_override_gate` makes that
exact mutation and requires it to redden.

THE TWO OVERRIDE DIRECTIONS ARE NOT SYMMETRIC, and treating them as one escape
hatch blesses exactly what the rule above forbids.

  - An explicit `false` is ALWAYS honoured. Losing a diagnostic is a choice an
    adopter is entitled to make, and it cannot produce the failure this rule
    exists to prevent.
  - An explicit `true` SPLITS. Where the probe has no tie a subchart can resolve —
    `keda` and `mariadb`, whose objects OTHER charts render — it is REQUIRED, and
    it is the only way to enable that probe at all. Where the probe ties to one of
    this chart's own toggles it is REFUSED while that toggle is false, and the
    refusal names BOTH keys, because a refusal naming one leaves the reader to
    guess which side to change.

`owner` IS WHAT SPLITS THEM. A probe called with an `owner` has a tie inside this
chart and is refused; a probe called with an empty `owner` has none and is
honoured. There is no third case, and a probe added later with a tie but no `owner`
would be honoured where it should be refused — which is why the caller below names
one for exactly the probes whose objects this chart renders.

RETURNS THE STRING `true`, OR NOTHING. Template actions return strings, so the
caller compares with `eq ... "true"` rather than using the result as a boolean.
*/}}
{{- define "platform.preflight.probe" -}}
{{- $context := .context -}}
{{- $probes := dict -}}
{{- if kindIs "map" $context.Values.preflight.probes -}}
{{- $probes = $context.Values.preflight.probes -}}
{{- end -}}
{{- if hasKey $probes .probe -}}
{{- if index $probes .probe -}}
{{- if and .owner (not .tied) -}}
{{- fail (printf (join "" (list
      "platform: preflight.probes.%s is true and %s is false, so this install renders "
      "nothing %s reconciles. A probe for an operator whose objects this install "
      "renders none of proves nothing and can only fail for the wrong reason, so it "
      "is refused rather than run. Set preflight.probes.%s false to drop the probe, "
      "or set %s true if you meant to install what it probes."))
      .probe .owner .operator .probe .owner) -}}
{{- end -}}
true
{{- end -}}
{{- else if .tied -}}
true
{{- end -}}
{{- end -}}

{{/*
THE PRE-INSTALL PROBE SET, RESOLVED ONCE AND READ BY BOTH TEMPLATES.

ONE SOURCE FOR THE JOB AND ITS RBAC. The Role's rules follow the probes this render
enables, so a second resolution in `preflight-rbac.yaml` would be an invariant
spanning two places — the shape that passes while the constraint is broken. Both
templates call this.

THE ORDER IS FIXED AND ALPHABETICAL BY OPERATOR, so the rendered list is stable
across renders and a diff of two renders shows a probe entering or leaving rather
than the whole line moving.

`probes.envoyGateway` IS NOT HERE, and its absence is the design rather than an
omission. It enables the POST-INSTALL Job, and the definition below this one
resolves it — a pre-install Envoy Gateway probe cannot go red, because
`Accepted=True` on a GatewayClass is a condition already persisted in etcd and
stays there with the controller at zero replicas. The denominator each Job asserts
is ITS OWN phase's probe set, so a key that enables one may never be counted by the
other.

RETURNS A SPACE-SEPARATED STRING, because a template action cannot return a list.
The caller splits it.
*/}}
{{- define "platform.preflight.probes" -}}
{{- $context := .context -}}
{{- $certManager := or $context.Values.internalCA.create $context.Values.certificates.create $context.Values.edgeTLS.create -}}
{{- $probes := list -}}
{{- if eq (include "platform.preflight.probe" (dict
      "context" $context
      "probe" "certManager"
      "tied" $certManager
      "owner" "internalCA.create, certificates.create or edgeTLS.create"
      "operator" "cert-manager")) "true" -}}
{{- $probes = append $probes "cert-manager" -}}
{{- end -}}
{{- if eq (include "platform.preflight.probe" (dict
      "context" $context
      "probe" "keda"
      "tied" false
      "owner" ""
      "operator" "KEDA")) "true" -}}
{{- $probes = append $probes "keda" -}}
{{- end -}}
{{- if eq (include "platform.preflight.probe" (dict
      "context" $context
      "probe" "mariadb"
      "tied" false
      "owner" ""
      "operator" "mariadb-operator")) "true" -}}
{{- $probes = append $probes "mariadb-operator" -}}
{{- end -}}
{{- if eq (include "platform.preflight.probe" (dict
      "context" $context
      "probe" "prometheus"
      "tied" false
      "owner" ""
      "operator" "Prometheus")) "true" -}}
{{- $probes = append $probes "prometheus" -}}
{{- end -}}
{{- join " " $probes -}}
{{- end -}}

{{/*
THE POST-INSTALL PROBE SET, RESOLVED ONCE AND READ BY BOTH TEMPLATES.

A SECOND SET RATHER THAN A SECOND ENTRY IN THE FIRST, because the two Jobs run in
different PHASES and each asserts its own denominator. A probe counted by the wrong
Job is a Job reporting a pass over a number that was never its own — and it is the
shape the pre-install set's own header warns about, reached from the other side.

`envoyGateway` TIES TO `gatewayListener.create`, which renders the GatewayClass the
probe Gateway binds to. It is called WITH an `owner`, so an explicit `true` beside
that toggle turned false is REFUSED and the refusal names both keys: a probe
Gateway bound to a class this install never made is the failure class the tie
exists to prevent, not an adopter's choice to make.

ONE MEMBER TODAY, AND IT IS STILL A LIST. The Job and its Role both read this, the
Job counts it, and a second post-install probe added later has a set to join rather
than a special case to become.

RETURNS A SPACE-SEPARATED STRING, because a template action cannot return a list.
The caller splits it.
*/}}
{{- define "platform.preflight.postInstallProbes" -}}
{{- $context := .context -}}
{{- $probes := list -}}
{{- if eq (include "platform.preflight.probe" (dict
      "context" $context
      "probe" "envoyGateway"
      "tied" $context.Values.gatewayListener.create
      "owner" "gatewayListener.create"
      "operator" "Envoy Gateway")) "true" -}}
{{- $probes = append $probes "envoy-gateway" -}}
{{- end -}}
{{- join " " $probes -}}
{{- end -}}

{{/*
HOW LONG ONE REQUEST FROM A HOOK SCRIPT MAY TAKE (ledger 1224). Before these, no
`curl` in a hook script carried a timeout, so an API server that accepted the
connection and never answered held the Job — and the sync behind it — open for as
long as the caller would wait.

`maxTime` IS 35 FOR THE PROBES, AND IT HAS TO EXCEED 30. The probes' POSTs pass
through admission webhooks — cert-manager's renders `timeoutSeconds: 30`, KEDA's
10, mariadb-operator's the API server's default of 10 — and Kubernetes caps a
webhook's timeout at 30. A request bound at or under that reads a healthy-but-slow
admission as a failure. The 5 seconds over it is for the API server's own work.

`cleanupMaxTime` IS 5. The cleanup only DELETEs, which no webhook here intercepts,
so a healthy answer takes milliseconds. It is small because it is paid INSIDE the
pod's termination grace period: `sh` defers its TERM trap until the foreground
command returns, so a pod killed at its deadline first waits out the request in
flight (up to `maxTime`), then runs one DELETE per object the probe made. Each Job's
`terminationGracePeriodSeconds` is that sum, computed beside it.

`bootstrapMaxTime` IS 10. The bootstrap Jobs only POST Secrets, which no webhook in
this estate intercepts; the whole script measured 3s for three requests on
kind-yadgar (2026-10-01, Job start to completion).

`connectTimeout` IS 5, for all of them. An in-cluster connection to the API server
or to Prometheus opens in milliseconds; a refused or blackholed one is the failure
this bounds.

A CURL TIMEOUT EXITS THE SCRIPT, on purpose. Every request sits under `set -e`, so
an exceeded `--max-time` ends the Job with curl's own message where it used to hang.
The cleanup's DELETEs carry `|| true` and still run.

LITERALS, NOT VALUES: `--max-time 0` means no limit at all, so a key would be a
weakening direction nothing here needs.
*/}}
{{- define "platform.hookRequest.maxTime" -}}35{{- end -}}
{{- define "platform.hookRequest.cleanupMaxTime" -}}5{{- end -}}
{{- define "platform.hookRequest.bootstrapMaxTime" -}}10{{- end -}}
{{- define "platform.hookRequest.connectTimeout" -}}5{{- end -}}

{{/*
THE MARGIN A PROBE JOB'S DEADLINE KEEPS OVER ITS COMPOSED LOOPS: pod scheduling,
image pull, and the request time of every poll (each loop counts only its sleeps).
The same 300 seconds `README.md` states for the helm budget — a stated CEILING,
not a measurement. The healthy runs measured on kind-yadgar took 10s (preflight)
and 15s (envoy-gateway-probe) in all.
*/}}
{{- define "platform.hookDeadline.probeMargin" -}}300{{- end -}}

{{/*
THE JOB CONTROLLER'S POD BACKOFF BEFORE ATTEMPT `limit + 1`: 10s, doubled after
each failure, capped at six minutes (Kubernetes, "Pod backoff failure policy").
`backoffLimit: 4` gives 10 + 20 + 40 + 80 = 150. Takes the limit; returns seconds.
*/}}
{{- define "platform.hookDeadline.jobBackoff" -}}
{{- $total := 0 -}}
{{- $delay := 10 -}}
{{- range until (int .) -}}
{{- $total = add $total (min $delay 360) -}}
{{- $delay = mul $delay 2 -}}
{{- end -}}
{{- $total -}}
{{- end -}}

{{/*
A BOOTSTRAP ATTEMPT'S ALLOWANCE BEFORE ITS FIRST REQUEST: scheduling the pod and
starting its container. A stated ceiling; the image is the preflight's, pinned by
digest and pulled `IfNotPresent`.
*/}}
{{- define "platform.hookDeadline.bootstrapStart" -}}30{{- end -}}
