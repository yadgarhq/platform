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
omission. It enables a POST-INSTALL Job — a pre-install Envoy Gateway probe cannot
go red, because `Accepted=True` on a GatewayClass is a condition already persisted
in etcd and stays there with the controller at zero replicas. That Job, and that
key, arrive with the Gateway listener they probe.

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
{{- join " " $probes -}}
{{- end -}}
