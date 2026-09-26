{{/*
THE ONE EXPRESSION THAT READS `operators`, AND THE NINETEEN SITES THAT CALL IT.

`plans/the-operators-toggle.md` asked for one shared helper between the
mixed-release guard of its step 3 and the vendored-CRD guards of its step 2, and
until now none existed: the same `dig` was pasted into `render-checks.yaml` and
into all eighteen files under `templates/vendored-crds/`. This is that helper.

WHAT IT RETURNS. The values key that turned this operator ON — either
`operators.<name>.create` or `operators.create` — or the EMPTY STRING when the
operator is off, which every caller reads as false. A caller that only needs the
boolean tests the result for truth; the mixed-release guard uses the string
itself, so the key it names in its refusal is derived here rather than in a
second place.

WHY `dig` WITH THE REGISTER KEY AS THE FALLBACK. It is helm's own resolution of
the `condition:` each of the five dependencies carries. `Chart.yaml` declares
`condition: operators.<op>.create,operators.create`, and helm evaluates the
FIRST VALID path and stops — so an unset `operators.<op>.create` defers to
`operators.create` and a set one wins, in either direction. `or
.Values.operators.keda.create .Values.operators.create` does NOT reproduce it:
it is TRUE in the case where the dependency's own condition is false, which
applies KEDA's CRDs to a cluster running no KEDA at all.

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
value this helper cannot read does not turn the operators off — it turns all
five on. Coercing here would install five operators while skipping every CRD
this chart owns. The refusal in `templates/render-checks.yaml` is what stops
that, and this helper going quiet is only safe because that refusal exists.

WHAT IS STILL NOT GUARDED, STATED HERE SO NOBODY READS SILENCE AS COVERAGE.
`operators.<name>` set to a non-map is left alone — ADR-0794's knowingly-open
residual, because refusing present non-maps in that range would also have to
exclude `create` by name, and that enumeration is a design question nobody has
answered.

CALL IT WITH A DICT:

  {{- if (include "platform.operator-create" (dict "context" $ "operator" "keda")) }}
*/}}
{{- define "platform.operator-create" -}}
{{- $operators := .context.Values.operators -}}
{{- if kindIs "map" $operators -}}
{{- if (dig .operator "create" $operators.create $operators) -}}
{{- if hasKey $operators .operator -}}
operators.{{ .operator }}.create
{{- else -}}
operators.create
{{- end -}}
{{- end -}}
{{- end -}}
{{- end -}}
