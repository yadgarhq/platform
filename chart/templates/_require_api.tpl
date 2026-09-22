{{/*
THE RENDER CHECK: an apply-time `no matches for kind` turned into a render-time
refusal that names the prerequisite.

A TOGGLE GATES A RESOURCE; IT DOES NOT DIAGNOSE A MISSING PREREQUISITE. A toggle
set true on a cluster with no cert-manager renders cleanly and then fails at apply
with `no matches for kind Certificate`, half-way through an install, naming a kind
rather than an operator somebody has to go and install. This partial is what makes
the refusal happen before anything is applied, with the operator's name in it.

WHAT IT PROVES, AND WHAT IT DOES NOT. `.Capabilities.APIVersions.Has` answers "is
this API registered on the target". It NEVER answers "is a controller running". A
cluster carrying cert-manager's CRDs with no cert-manager pod renders, installs,
and then hangs forever on Certificates that never go Ready. The controller half is
a preflight Job and this chart does not carry one yet.

IT MAY ONLY EVER BE CALLED FROM BEHIND A DEFAULT-FALSE TOGGLE. `Has` is false for
every API group outside helm's built-in list whenever there is no cluster and no
`--api-versions`, so a check reachable at a chart's defaults refuses every offline
render — `helm lint --strict`, the shared `helm lint and render` hook, and every
bare `helm template` in the estate's suites. Every `create` toggle in this chart
defaults false, which is what makes this legal here.

CALL IT WITH A DICT:

  {{- include "platform.require-api" (dict
        "context"    $
        "apiVersion" "cert-manager.io/v1"
        "operator"   "cert-manager"
        "toggle"     "certificates.create") }}
*/}}
{{- define "platform.require-api" -}}
{{- $context := .context -}}
{{- if not ($context.Capabilities.APIVersions.Has .apiVersion) -}}
{{- fail (printf (join "" (list
      "platform: this render needs the API %s, which %s provides, and the target does not have it. "
      "%s is true, and that is what asked for it. Install %s in the target cluster, or set %s false. "
      "If you are rendering offline: helm does not populate .Capabilities.APIVersions with "
      "CRD-backed groups from anywhere but a live cluster, so pass --api-versions %s to render this."))
      .apiVersion .operator .toggle .operator .toggle .apiVersion) -}}
{{- end -}}
{{- end -}}
