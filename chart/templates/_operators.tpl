{{/*
THE ONE EXPRESSION THAT READS `operators`, AND THE TWENTY SITES THAT CALL IT.

`plans/the-operators-toggle.md` asked for one shared helper between the
mixed-release guard of its step 3 and the vendored-CRD guards of its step 2, and
until now none existed: the same `dig` was pasted into `render-checks.yaml` and
into all eighteen files under `templates/vendored-crds/`. This is that helper.

WHAT IT RETURNS. The values key that turned this operator ON —
`operators.<name>.create`, `operators.create`, or `operators` itself when the
block is not a mapping (ADR-0873) — or the EMPTY STRING when the
operator is off, which every caller reads as false. A caller that only needs the
boolean tests the result for truth; the mixed-release guard uses the string
itself, so the key it names in its refusal is derived here rather than in a
second place.

WHY THE SUB-KEY COUNTS ONLY AS A BOOL INSIDE A MAP. It is helm's own resolution
of the `condition:` each of the five dependencies carries. `Chart.yaml` declares
`condition: operators.<op>.create,operators.create`, and helm reads each path in
turn and uses THE FIRST ONE THAT HOLDS A BOOL: a path that is absent, null, a
string, a number or a map is skipped (with at most a `returned non-bool value`
warning) and the register key decides. So an unset `operators.<op>.create`
defers to `operators.create` and a bool one wins, in either direction.

`dig .operator "create" $operators.create $operators` DID NOT REPRODUCE IT, and
that is ledger 1252, measured on helm v4.3.0 on 2026-10-03. `dig` reads the
sub-key by TRUTHINESS, so `operators: {create: false, keda: {create: "false"}}`
rendered KEDA's six vendored CRDs at exit 0 while helm, skipping the string,
left KEDA itself out. And `dig` walks into the sub-block, so `keda:` null or
`keda: true` RAISED. Nor does `or .Values.operators.keda.create
.Values.operators.create`: it is TRUE where the dependency's own condition is
false, which applies KEDA's CRDs to a cluster running no KEDA at all.

THE KEY NAMED IS THE KEY THAT DECIDED. The sub-key is named only when it holds a
bool; a `keda` block with no usable `create` in it is the register key's doing,
and the mixed-release refusal says so rather than pointing at a key that
decided nothing.

A PRESENT NON-BOOL SUB-KEY IS REFUSED BY NAME, AT THE ROOT ONLY, in
`templates/render-checks.yaml` — the per-operator create arm. Under a parent
this helper stays quiet and resolves it exactly as helm does, so the CRDs follow
the operator either way.

THE REGISTER KEY ITSELF NEEDS THE SAME `kindIs "bool"` GUARD, AND UNTIL LEDGER
1291 IT DID NOT HAVE ONE. `{{- else if $operators.create -}}` read the register
key by TRUTHINESS, so `operators.create: 0`, `""`, `{}` or `[]` — none of which
helm's own `condition:` resolution can read as a bool either — resolved to OFF
here while helm, finding no bool on ANY path, leaves the dependency ENABLED.
Under a parent with no refusal of its own (`render-checks.yaml`'s register arm
is root-only, same as the sub-key arm above) that is KEDA and mariadb-operator
installed with none of their vendored CRDs — the ledger-1252 defect reopened one
level down, in the one key its own fix still read by truthiness. A truthy
non-bool such as `"yes"` already agreed with helm by accident, since a non-empty
string is truthy either way; `or (not (kindIs "bool" $operators.create))
$operators.create` makes the agreement hold for the falsy ones too, by counting
ANY non-bool register key as the "on" that helm's fail-open gives it, rather than
reading it for truth.

── THE TYPE ARM, WHICH IS THE WHOLE REASON THIS FILE EXISTS ────────────────────

`kindIs "map"` ON THE RAW VALUE, BEFORE ANYTHING ELSE TOUCHES IT (ADR-0794).
Every one of the nineteen sites used to dereference `.Values.operators.create`
directly, which is a field access on a value of unknown type. An adopter who
wrote `operators: true` — the thing somebody writes who thinks the toggle IS the
block rather than a key inside it — got a Go stack trace from whichever of the
nineteen helm reached first, with no key name in it.

`default dict` WOULD NOT HAVE FIXED IT, and that is measured rather than
supposed. Sprig's `default` substitutes only on an EMPTY value, so `default dict
false` is `dict` — a `kindIs "map"` applied to the RESULT of a `default`
therefore catches the non-empty scalars alone and silently permits `false`, `0`,
`""`, `[]` and a deleted key. ADR-0794 records the measurement: that idiom
permitted five of the eight shapes an adopter can write.

AND THE SHAPES IT PERMITTED ARE EXACTLY THE DANGEROUS ONES. Helm LEAVES A
DEPENDENCY ENABLED when no path of a multi-path `condition:` resolves, so a
value this helper cannot read does not turn the operators off — it turns them
all on.

SO A PRESENT NON-MAP `operators` RESOLVES ON, FOR EVERY OPERATOR (ADR-0873,
ledger 1337), and the key named is `operators`, the key that decided. This
helper used to read that shape as OFF and lean on the refusal in
`templates/render-checks.yaml` to stop it. That refusal runs at the root only,
so under a parent with no refusal of its own the six operator subcharts went in
with none of the eighteen vendored CRDs and no prometheus Namespace — measured on
helm v4.3.0 against a bare parent, `operators: 5`: exit 0, 171 objects, 0
vendored CRDs. The root refusals still name the wrong shape; the CRDs no longer
depend on them. An ABSENT `operators` takes the same arm, and arm one of
`render-checks.yaml` still refuses it wherever this chart runs.

THE MIXED-RELEASE GUARD DOES NOT COUNT THIS ARM. It ranges over the helper only
for a mapping `operators`, because a non-map block is arm two's diagnosis at the
root and the parent's under one, and a mixed-release `fail` here would shadow
the parent's refusal.

CALL IT WITH A DICT:

  {{- if (include "platform.operator-create" (dict "context" $ "operator" "keda")) }}
*/}}
{{- define "platform.operator-create" -}}
{{- $operators := .context.Values.operators -}}
{{- if not (kindIs "map" $operators) -}}
operators
{{- else -}}
{{- $block := index $operators .operator -}}
{{- $own := "" -}}
{{- if kindIs "map" $block -}}
{{- $own = index $block "create" -}}
{{- end -}}
{{- if kindIs "bool" $own -}}
{{- if $own -}}
operators.{{ .operator }}.create
{{- end -}}
{{- else if or (not (kindIs "bool" $operators.create)) $operators.create -}}
operators.create
{{- end -}}
{{- end -}}
{{- end -}}
