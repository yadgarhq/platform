{{/*
THE ESTATE'S PUBLIC HOSTNAME, RESOLVED IN ONE PLACE (ADR-0808).

An adopter states the hostname once, as `global.hostname` in the parent chart.
Helm hands `global` to every subchart, so this chart reads it without any
plumbing. Three keys here carry the hostname — `gatewayListener.hostname`,
`edgeTLS.commonName` and `edgeTLS.dnsNames` — and each resolves in this order:

  1. the key itself, when it is set: an explicit per-chart value still wins;
  2. `global.hostname`, when the key is empty;
  3. `gateway.yadgar.internal`, when neither is set. That is the value
     `values.yaml` shipped before ADR-0808, so a render with no hostname
     anywhere is byte-identical to the render before it.

The keys default to empty in `values.yaml` because a non-empty default cannot be
told apart from a value somebody set, and step 1 would then always win.

`global` MAY BE ABSENT OR NULL. This chart rendered on its own has no `global`
unless the caller passes one, and `global: null` in an overlay removes it; both
fall through to step 3.

CALL IT WITH A DICT, and the name carries the chart's prefix because helm template
names are global across the parent's whole tree:

  {{ include "platform.hostname" (dict "local" .Values.gatewayListener.hostname "context" $) }}
*/}}
{{- define "platform.hostname" -}}
{{- $global := .context.Values.global | default dict -}}
{{- .local | default (get $global "hostname") | default "gateway.yadgar.internal" -}}
{{- end -}}
