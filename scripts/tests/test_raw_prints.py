"""NO VALUE IS PRINTED RAW INTO YAML STRUCTURE (yaadgaar 534, 537, 541).

THE CLASS. A Helm print `{{ .Values.x }}` drops the value's characters straight
into the manifest. A newline in it ends the scalar; the next line becomes a key
of its own, and a line starting `---` a whole new document. The review of
platform#75 measured an `isCA` Certificate signed by the internal CA injected
this way at rc=0 through `gatewayListener.controllerName`,
`gatewayListener.envoyProxy.serviceType`, `gatewayListener.envoyProxy.replicas`
and `valkey.port`, long after the Certificate templates were closed.

TWO WALLS, AND THIS FILE HOLDS BOTH.

  * THE LINT GATE. Every print in `chart/templates/` must end in an encoder that
    keeps the value one scalar — `toYaml` (and `nindent`/`indent` after it),
    `toJson`, `quote`, `int`, `int64` or `b64enc` — or be on `ALLOWLIST` below
    with its reason. A print added raw tomorrow reddens this file before any
    review has to find it. `chart/charts/` (vendored subcharts) is not this
    chart's source and is not scanned.
  * THE REFUSAL. Every values string that still reaches a raw print — inside a
    shell script, a JSON body or a quoted string, where `toYaml` cannot go — is on
    the one-line values arm in `templates/render-checks.yaml`, which refuses a
    control character in it. The probes below are the measured shapes.

WHAT THE GATE READS. Template SOURCE, with `{{/* */}}` comments stripped. A print
is any action that is not control flow (`if`, `else`, `end`, `range`, `with`,
`define`, `block`, `break`, `continue`), not `fail`, and not a variable
assignment. Its LAST pipeline stage decides: a stage nested in parentheses or a
string literal does not count, so `{{ $x | int | printf "%s" .Values.y }}` is raw.

Tests: `python3 -m pytest scripts/tests/test_raw_prints.py -q`.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
CHART = REPO / "chart"
TEMPLATES = CHART / "templates"
ESTATE_VALUES = CHART / "ci" / "estate-values.yaml"
API_VERSIONS = ("--api-versions", "cert-manager.io/v1", "--api-versions", "gateway.envoyproxy.io/v1alpha1")

CONTROL = re.compile(r"^(if|else|end|range|with|define|block|break|continue|fail)\b|^\$\w+\s*:?=")
ENCODERS = {"toYaml", "toJson", "quote", "int", "int64", "b64enc"}
INDENTERS = {"nindent", "indent"}

# EVERY RAW PRINT LEFT IN THE TREE, BY FILE AND EXPRESSION, WITH THE REASON IT IS
# SAFE. An entry that matches nothing is stale and reddens
# `test_every_allowlist_entry_still_matches_a_print`, so this list cannot outlive
# the print it excuses.
ONE_LINE = "a values string the one-line values arm in `render-checks.yaml` refuses a control character in"
ALLOWLIST: dict[tuple[str, str], str] = {
    # HELPER OUTPUTS. A `define` returns text; what matters is where it is printed.
    ("_hostname.tpl", '.local | default (get $global "hostname") | default "gateway.yadgar.internal"'):
        "returns the hostname; every call site encodes it with `dict | toYaml`, and the one-line arm refuses a control character in every source of it",
    ("_operators.tpl", ".operator"): "returns a dependency path; `.operator` is one of the chart's own literal operator names",
    ("_preflight.tpl", 'join " " $probes'): "returns probe names, every one a literal this file appends",
    # THE NAMED CERTIFICATE TEMPLATES, each encoded line by line and parsed back by the rendered certificates arm.
    ("certificates.yaml", 'include "platform.certificates.leaves" .'): "every line of the define is encoded",
    ("edge-certificate.yaml", 'include "platform.certificates.edge" .'): "every line of the define is encoded",
    ("internal-ca.yaml", 'include "platform.certificates.internal-ca" .'): "every line of the define is encoded",
    # THE CAPABILITY CHECKS render nothing or `fail`.
    ("render-checks.yaml", 'include "platform.require-api" (dict "context" $ "apiVersion" "cert-manager.io/v1" "operator" "cert-manager" "toggle" "internalCA.create, certificates.create or edgeTLS.create")'):
        "renders nothing or fails",
    ("render-checks.yaml", 'include "platform.require-api" (dict "context" $ "apiVersion" "gateway.envoyproxy.io/v1alpha1" "operator" "Envoy Gateway" "toggle" "gatewayListener.create")'):
        "renders nothing or fails",
    # INSIDE SHELL SCRIPTS AND JSON BODIES, where `toYaml` cannot go.
    ("admin-bootstrap-token.yaml", "$bootstrap.adminToken.secretName"): ONE_LINE,
    ("envoy-gateway-probe.yaml", 'join " " $probes'): "probe names, every one a literal `_preflight.tpl` appends",
    ("envoy-gateway-probe.yaml", "$probe.probeName"): ONE_LINE,
    ("envoy-gateway-probe.yaml", "$probe.programmedMessage | squote"): ONE_LINE,
    ("envoy-gateway-probe.yaml", "$probe.apiVersion"): ONE_LINE,
    ("envoy-gateway-probe.yaml", "$listener.className"): ONE_LINE,
    ("preflight.yaml", 'join " " $probes'): "probe names, every one a literal `_preflight.tpl` appends",
    ("preflight.yaml", "$preflight.probeName"): ONE_LINE,
    ("preflight.yaml", "$preflight.certManager.apiVersion"): ONE_LINE,
    ("preflight.yaml", "$preflight.image | squote"): ONE_LINE,
    ("preflight.yaml", "$preflight.keda.apiVersion"): ONE_LINE,
    ("preflight.yaml", "$preflight.mariadb.unreachableWebhook | squote"): ONE_LINE,
    ("preflight.yaml", "$preflight.mariadb.deniedBy | squote"): ONE_LINE,
    ("preflight.yaml", "$preflight.mariadb.validationMessage | squote"): ONE_LINE,
    ("preflight.yaml", "$preflight.mariadb.apiVersion"): ONE_LINE,
    ("preflight.yaml", "$preflight.prometheus.address | squote"): ONE_LINE,
    ("preflight.yaml", "$preflight.prometheus.readyMessage | squote"): ONE_LINE,
    ("valkey.yaml", 'join " \\\\\\n " $args'):
        "`valkey.maxmemory` and `valkey.maxmemoryPolicy` are on the one-line arm; `valkey.port` is converted with `int`; every other token is a literal",
}


def stages(expression: str) -> list[str]:
    """The pipeline's stages, split on every `|` not inside parentheses or a string."""
    found, depth, quote, start, index = [], 0, "", 0, 0
    while index < len(expression):
        character = expression[index]
        if quote:
            if character == "\\" and quote == '"':
                index += 1
            elif character == quote:
                quote = ""
        elif character in "\"`":
            quote = character
        elif character == "(":
            depth += 1
        elif character == ")":
            depth -= 1
        elif character == "|" and depth == 0:
            found.append(expression[start:index].strip())
            start = index + 1
        index += 1
    found.append(expression[start:].strip())
    return found


def is_encoded(expression: str, alone: bool) -> bool:
    """`alone`: the action is the only thing on its line.

    `nindent` starts the value on a fresh line at a stated depth, so it is safe
    anywhere. `indent` indents EVERY line by N, the first included, so it is safe
    only when the action begins its own line: inline after a key it leaves the
    first line where the key put it and the rest at N, and a key deeper than N
    takes those lines as siblings.
    """
    parts = stages(expression)
    word = lambda stage: stage.split()[0] if stage.split() else ""
    last = word(parts[-1])
    if last == "nindent" or (last == "indent" and alone):
        return len(parts) > 1 and word(parts[-2]) == "toYaml"
    if last == "indent":
        return False
    # `toYaml` AS THE LAST STAGE IS RAW. Printed inline after a key, a block scalar
    # it emits for a multi-line string lands at the key's own indent, and its lines
    # become keys of their own; only `nindent`/`indent` after it places it.
    return last in ENCODERS - {"toYaml"}


def normalise(expression: str) -> str:
    return " ".join(expression.split())


def actions(source: str):
    """Yield (start, end, body, is_comment) for every `{{ }}` action, tokenised.

    A REAL TOKENISER, NOT A REGEX: an action ends at the first `}}` outside a string
    literal, and a comment is only an action that OPENS with `/*` (`{{/*` or
    `{{- /*`). A regex that stripped `{{/* ... */}}` anywhere also matched the
    `"{{/*"` inside `{{ quote "{{/*" }}` and hid every print up to the next `*/}}`.
    """
    index = 0
    while True:
        start = source.find("{{", index)
        if start < 0:
            return
        cursor = start + 2
        if source.startswith("-", cursor) and source[cursor + 1 : cursor + 2].isspace():
            cursor += 1
        head = cursor
        while head < len(source) and source[head] in " \t\n":
            head += 1
        if source.startswith("/*", head):
            close = source.find("*/", head + 2)
            assert close >= 0, f"an unclosed comment at offset {start}"
            end = source.find("}}", close + 2)
            assert end >= 0 and source[close + 2 : end].strip() in ("", "-"), f"a comment not closed by `*/}}` at offset {start}"
            yield start, end + 2, "", True
            index = end + 2
            continue
        quote, position = "", cursor
        while position < len(source):
            character = source[position]
            if quote:
                if character == "\\" and quote in "\"'":
                    position += 1
                elif character == quote:
                    quote = ""
            elif character in "\"`'":
                quote = character
            elif source.startswith("}}", position):
                break
            position += 1
        assert position < len(source), f"an unclosed action at offset {start}"
        body = source[cursor:position]
        if body.rstrip().endswith(" -") or body.rstrip() == "-":
            body = body.rstrip()[:-1]
        yield start, position + 2, body, False
        index = position + 2


def prints(templates: Path):
    """Yield (relative file, line, expression, alone) for every print in the tree."""
    for path in sorted(templates.rglob("*")):
        if path.suffix not in (".yaml", ".tpl") or not path.is_file():
            continue
        source = path.read_text()
        for start, end, body, is_comment in actions(source):
            expression = body.strip()
            if is_comment or not expression or CONTROL.match(expression):
                continue
            line_start = source.rfind("\n", 0, start) + 1
            line_end = source.find("\n", end)
            line_end = len(source) if line_end < 0 else line_end
            alone = not source[line_start:start].strip() and not source[end:line_end].strip()
            yield str(path.relative_to(templates)), source.count("\n", 0, start) + 1, normalise(expression), alone


def raw_prints(templates: Path, allowlist: dict[tuple[str, str], str]) -> list[str]:
    return [
        f"{file}:{line}: {{{{ {expression} }}}}"
        for file, line, expression, alone in prints(templates)
        if not is_encoded(expression, alone) and (Path(file).name, expression) not in allowlist
    ]


# ── THE GATE ─────────────────────────────────────────────────────────────────────


def test_no_template_prints_a_value_raw():
    found = raw_prints(TEMPLATES, ALLOWLIST)
    assert found == [], (
        "these prints drop a value's characters straight into YAML; encode each "
        "with `dict \"k\" X | toYaml | nindent N` (or `| int` for a number), or, "
        "where `toYaml` cannot go, refuse its control characters in the one-line "
        "values arm and allowlist it here with that reason:\n" + "\n".join(found)
    )


def test_every_allowlist_entry_still_matches_a_print():
    seen = {(Path(file).name, expression) for file, _, expression, _ in prints(TEMPLATES)}
    stale = sorted(set(ALLOWLIST) - seen)
    assert stale == [], f"allowlist entries that match no print any more: {stale}"


def test_the_gate_sees_a_print_at_all():
    """A scanner that found nothing would pass having examined nothing."""
    assert sum(1 for _ in prints(TEMPLATES)) >= 150


@pytest.mark.parametrize(
    ("source", "named"),
    [
        ("metadata:\n  name: {{ .Values.name }}\n", ".Values.name"),
        ("  type: {{ $listener.envoyProxy.serviceType }}\n", "$listener.envoyProxy.serviceType"),
        ("  name: {{ printf \"%s-x\" .Values.name }}\n", 'printf "%s-x" .Values.name'),
        ("  name: {{ .Values.name | squote }}\n", ".Values.name | squote"),
        ("  name: {{ .Values.name | int | printf \"%s\" }}\n", '.Values.name | int | printf "%s"'),
        ("  {{- .Values.name | toYaml | printf \"%s\" | nindent 2 }}\n", '.Values.name | toYaml | printf "%s" | nindent 2'),
        ("  port: {{ include \"x\" (dict \"v\" (.Values.port | int)) }}\n", 'include "x" (dict "v" (.Values.port | int))'),
        ("# {{ .Values.name }}\n", ".Values.name"),
        ("  name: {{ .Values.name | toYaml }}\n", ".Values.name | toYaml"),
    ],
    ids=["values", "local", "printf", "squote", "encoder-not-last", "printf-between", "encoder-in-parens", "in-a-comment", "inline-toYaml"],
)
def test_a_raw_print_reddens_the_gate(tmp_path, source, named):
    (tmp_path / "fixture.yaml").write_text("{{/* a comment {{ .Values.ignored }} */}}\n" + source)
    found = raw_prints(tmp_path, ALLOWLIST)
    assert len(found) == 1 and named in found[0], found


@pytest.mark.parametrize(
    "source",
    [
        '  {{- dict "name" .Values.name | toYaml | nindent 2 }}\n',
        "  port: {{ .Values.port | int }}\n",
        "  name: {{ .Values.name | quote }}\n",
        '  "spec":{{ toJson .Values.spec }}\n',
        "{{- if .Values.x }}{{ $y := .Values.y }}{{ $y = 1 }}{{- end }}\n",
        '{{- fail (printf "%s" .Values.x) }}\n',
    ],
    ids=["dict-toYaml", "int", "quote", "toJson", "control-and-assignment", "fail"],
)
def test_an_encoded_print_passes_the_gate(tmp_path, source):
    (tmp_path / "fixture.yaml").write_text(source)
    assert raw_prints(tmp_path, ALLOWLIST) == []


def test_an_allowlist_entry_excuses_only_its_own_file(tmp_path):
    (tmp_path / "other.yaml").write_text("  x: {{ $probe.probeName }}\n")
    assert len(raw_prints(tmp_path, ALLOWLIST)) == 1


# ── THE MEASURED SHAPES, REFUSED ─────────────────────────────────────────────────

PROBES = Path(__file__).resolve().parent / "fixtures" / "raw-print-probes"


def helm(*arguments: str) -> subprocess.CompletedProcess[str]:
    binary = shutil.which("helm")
    assert binary, "helm is not on PATH; this suite renders the chart"
    return subprocess.run([binary, *arguments], capture_output=True, text=True)


ONE_LINE_REFUSAL = "platform: a value this chart prints is not one line of text"
PAYLOAD = (
    "\\n---\\napiVersion: cert-manager.io/v1\\nkind: Certificate\\nmetadata:\\n  name: evil-subca\\n"
    "spec:\\n  isCA: true\\n  secretName: evil-subca\\n  commonName: evil\\n  usages: [cert sign, crl sign]\\n"
    "  issuerRef:\\n    name: yadgar-internal-ca\\n    kind: Issuer"
)
SHAPES = [
    ("gatewayListener: {controllerName: \"gateway.envoyproxy.io/gatewayclass-controller" + PAYLOAD + "\"}", "`gatewayListener.controllerName`"),
    ("gatewayListener: {envoyProxy: {serviceType: \"NodePort" + PAYLOAD + "\"}}", "`gatewayListener.envoyProxy.serviceType`"),
    ("gatewayListener: {envoyProxy: {replicas: \"1" + PAYLOAD + "\"}}", "`gatewayListener.envoyProxy.replicas`"),
    ("valkey: {port: \"6379" + PAYLOAD + "\"}", "`valkey.port`"),
    ("gatewayListener: {className: \"eg" + PAYLOAD + "\"}", "`gatewayListener.className`"),
    ("gatewayListener: {gatewayName: \"edge" + PAYLOAD + "\"}", "`gatewayListener.gatewayName`"),
    ("gatewayListener: {certificateSecretName: \"gateway-tls" + PAYLOAD + "\"}", "`gatewayListener.certificateSecretName`"),
    ("gatewayListener: {envoyProxy: {name: \"edge" + PAYLOAD + "\"}}", "`gatewayListener.envoyProxy.name`"),
    ("gatewayListener: {envoyProxy: {serviceType: NodePort, httpsNodePort: \"30443" + PAYLOAD + "\"}}", "`gatewayListener.envoyProxy.httpsNodePort`"),
    ("valkey: {name: \"valkey" + PAYLOAD + "\"}", "`valkey.name`"),
    ("valkey: {image: \"valkey/valkey:9.1.1" + PAYLOAD + "\"}", "`valkey.image`"),
    ("valkey: {maxmemory: \"512mb" + PAYLOAD + "\"}", "`valkey.maxmemory`"),
    ("valkey: {maxmemoryPolicy: \"allkeys-lru" + PAYLOAD + "\"}", "`valkey.maxmemoryPolicy`"),
    ("valkey: {passwordSecret: {name: \"valkey-password" + PAYLOAD + "\"}}", "`valkey.passwordSecret.name`"),
    ("valkey: {passwordSecret: {key: \"password" + PAYLOAD + "\"}}", "`valkey.passwordSecret.key`"),
    ("bootstrap: {serviceAccountName: \"bootstrap-secrets" + PAYLOAD + "\"}", "`bootstrap.serviceAccountName`"),
    ("bootstrap: {image: \"curlimages/curl" + PAYLOAD + "\"}", "`bootstrap.image`"),
    ("bootstrap: {backoffLimit: \"4" + PAYLOAD + "\"}", "`bootstrap.backoffLimit`"),
    ("bootstrap: {adminToken: {secretName: \"admin-bootstrap-token" + PAYLOAD + "\"}}", "`bootstrap.adminToken.secretName`"),
    ("preflight: {serviceAccountName: \"preflight" + PAYLOAD + "\"}", "`preflight.serviceAccountName`"),
    ("preflight: {image: \"curlimages/curl" + PAYLOAD + "\"}", "`preflight.image`"),
    ("preflight: {probeName: \"preflight-probe" + PAYLOAD + "\"}", "`preflight.probeName`"),
    ("preflight: {backoffLimit: \"0" + PAYLOAD + "\"}", "`preflight.backoffLimit`"),
    ("preflight: {timeoutSeconds: \"120" + PAYLOAD + "\"}", "`preflight.timeoutSeconds`"),
    ("preflight: {pollSeconds: \"3" + PAYLOAD + "\"}", "`preflight.pollSeconds`"),
    ("preflight: {certManager: {apiVersion: \"cert-manager.io/v1" + PAYLOAD + "\"}}", "`preflight.certManager.apiVersion`"),
    ("preflight: {keda: {apiVersion: \"keda.sh/v1alpha1" + PAYLOAD + "\"}}", "`preflight.keda.apiVersion`"),
    ("preflight: {mariadb: {apiVersion: \"k8s.mariadb.com/v1alpha1" + PAYLOAD + "\"}}", "`preflight.mariadb.apiVersion`"),
    ("preflight: {mariadb: {deniedBy: \"denied" + PAYLOAD + "\"}}", "`preflight.mariadb.deniedBy`"),
    ("preflight: {mariadb: {validationMessage: \"either" + PAYLOAD + "\"}}", "`preflight.mariadb.validationMessage`"),
    ("preflight: {mariadb: {unreachableWebhook: \"failed" + PAYLOAD + "\"}}", "`preflight.mariadb.unreachableWebhook`"),
    ("preflight: {prometheus: {address: \"http://p" + PAYLOAD + "\"}}", "`preflight.prometheus.address`"),
    ("preflight: {prometheus: {readyMessage: \"Ready" + PAYLOAD + "\"}}", "`preflight.prometheus.readyMessage`"),
    ("preflight: {envoyGateway: {apiVersion: \"gateway.networking.k8s.io/v1" + PAYLOAD + "\"}}", "`preflight.envoyGateway.apiVersion`"),
    ("preflight: {envoyGateway: {programmedMessage: \"Address" + PAYLOAD + "\"}}", "`preflight.envoyGateway.programmedMessage`"),
    ("preflight: {envoyGateway: {serviceAccountName: \"envoy-gateway-probe" + PAYLOAD + "\"}}", "`preflight.envoyGateway.serviceAccountName`"),
    ("preflight: {envoyGateway: {probeName: \"envoy-gateway-probe" + PAYLOAD + "\"}}", "`preflight.envoyGateway.probeName`"),
    ("preflight: {envoyGateway: {timeoutSeconds: \"300" + PAYLOAD + "\"}}", "`preflight.envoyGateway.timeoutSeconds`"),
    ("prometheus: {forceNamespace: \"observability" + PAYLOAD + "\"}", "`prometheus.forceNamespace`"),
]


@pytest.mark.parametrize(("body", "named"), SHAPES, ids=[named.strip("`") for _, named in SHAPES])
def test_a_value_carrying_a_document_is_refused(tmp_path, body, named):
    override = tmp_path / "override.yaml"
    override.write_text(body + "\n")
    result = helm("template", "platform", str(CHART), *API_VERSIONS, "-f", str(ESTATE_VALUES), "-f", str(override))
    assert result.returncode != 0, f"rendered instead of refusing: {result.stdout[:400]}"
    assert ONE_LINE_REFUSAL in result.stderr and named in result.stderr, result.stderr


@pytest.mark.parametrize("probe", ["g1", "g2", "g3", "v1"])
def test_the_measured_probes_are_refused(probe):
    """The review's own values files, verbatim (`fixtures/raw-print-probes/`)."""
    result = helm("template", "platform", str(CHART), *API_VERSIONS, "-f", str(ESTATE_VALUES), "-f", str(PROBES / f"{probe}.yaml"))
    assert result.returncode != 0, f"rendered instead of refusing: {result.stdout[:400]}"
    assert ONE_LINE_REFUSAL in result.stderr, result.stderr


# ── EVERY NUMBER A TEMPLATE PRINTS THROUGH `int` IS A WHOLE NUMBER IN ITS RANGE ──
#
# `| int` keeps a value one scalar, and it also turns a value that is not a number
# into 0 at rc=0: `replicas: "abc"` rendered `replicas: 0`, `httpsNodePort: "x"`
# nodePort 0, `valkey.port: "x"` port 0 and `--port 0`, where the API server used
# to refuse the raw string loudly. The whole-number arm in `render-checks.yaml`
# refuses each of these eight values unless it is an integer (or a whole float, or
# a string of digits) inside its range. Every other `| int` print in the tree is a
# literal or arithmetic on these eight.
NUMBER_REFUSAL = "platform: a number this chart prints is not a whole number in its range"
NUMBERS = [
    ("gatewayListener: {envoyProxy: {replicas: %s}}", "gatewayListener.envoyProxy.replicas", ["0", "-1"], False, ["1", "'3'"]),
    ("gatewayListener: {envoyProxy: {serviceType: NodePort, httpsNodePort: %s}}", "gatewayListener.envoyProxy.httpsNodePort", ["29999", "32768", "80"], True, ["30443", "'30443'", "null"]),
    ("valkey: {port: %s}", "valkey.port", ["0", "65536"], False, ["6379", "'6380'"]),
    ("bootstrap: {backoffLimit: %s}", "bootstrap.backoffLimit", ["-1"], False, ["0", "4"]),
    ("preflight: {backoffLimit: %s}", "preflight.backoffLimit", ["-1"], False, ["0", "2"]),
    ("preflight: {timeoutSeconds: %s}", "preflight.timeoutSeconds", ["0"], False, ["1", "120"]),
    ("preflight: {pollSeconds: %s}", "preflight.pollSeconds", ["0"], False, ["1", "3"]),
    ("preflight: {envoyGateway: {timeoutSeconds: %s}}", "preflight.envoyGateway.timeoutSeconds", ["0"], False, ["1", "300"]),
]
NOT_WHOLE = ["abc", "'abc'", "true", "1.5", "'1.5'", "'01'", "'-1'", "[1]", "{a: 1}"]


def number_render(tmp_path: Path, body: str) -> subprocess.CompletedProcess[str]:
    override = tmp_path / "number.yaml"
    override.write_text(body + "\n")
    return helm("template", "platform", str(CHART), *API_VERSIONS, "-f", str(ESTATE_VALUES), "-f", str(override))


RED_NUMBERS = [
    (template % value, path)
    for template, path, out_of_range, nullable, _ in NUMBERS
    for value in [*NOT_WHOLE, *out_of_range, *([] if nullable else ["null"])]
]
GREEN_NUMBERS = [(template % value, path) for template, path, _, _, good in NUMBERS for value in good]


@pytest.mark.parametrize(("body", "path"), RED_NUMBERS, ids=[f"{p}={b.split(': ')[-1].rstrip('}')}" for b, p in RED_NUMBERS])
def test_a_number_that_is_not_whole_or_out_of_range_is_refused(tmp_path, body, path):
    result = number_render(tmp_path, body)
    assert result.returncode != 0, f"rendered instead of refusing: {result.stdout[:400]}"
    assert NUMBER_REFUSAL in result.stderr and f"`{path}`" in result.stderr, result.stderr


@pytest.mark.parametrize(("body", "path"), GREEN_NUMBERS, ids=[f"{p}={b.split(': ')[-1].rstrip('}')}" for b, p in GREEN_NUMBERS])
def test_a_whole_number_in_range_renders(tmp_path, body, path):
    result = number_render(tmp_path, body)
    assert result.returncode == 0, result.stderr


# ── THE GATE'S OWN EDGES (the round-3 review) ────────────────────────────────────


def test_inline_toyaml_indent_reddens_the_gate(tmp_path):
    """`a: {{ X | toYaml | indent 2 }}` indents only from the second line, so a key
    deeper than 2 takes the continuation lines as siblings. `indent` is accepted only
    when the action is alone on its line."""
    (tmp_path / "x.yaml").write_text("metadata:\n  annotations:\n    a: {{ .Values.x | toYaml | indent 2 }}\n")
    found = raw_prints(tmp_path, ALLOWLIST)
    assert len(found) == 1 and "indent 2" in found[0], found


def test_indent_alone_on_its_line_passes_the_gate(tmp_path):
    (tmp_path / "x.yaml").write_text("data:\n{{ .Values.x | toYaml | indent 2 }}\n  {{- .Values.y | toYaml | nindent 2 }}\n")
    assert raw_prints(tmp_path, ALLOWLIST) == []


def test_a_comment_marker_inside_a_string_literal_hides_nothing(tmp_path):
    """`{{ quote "{{/*" }}` is a print, not a comment: stripping from it to the next
    `*/}}` hid the raw print between, measured as an injected Secret."""
    (tmp_path / "x.yaml").write_text('# {{ quote "{{/*" }}\n  name: {{ .Values.y }}\n# {{ quote "*/}}" }}\n')
    found = raw_prints(tmp_path, ALLOWLIST)
    assert any(".Values.y" in entry for entry in found), found


def test_a_real_comment_still_hides_its_contents(tmp_path):
    (tmp_path / "x.yaml").write_text("{{/* {{ .Values.a }} */}}\n{{- /* {{ .Values.b }} */ -}}\n")
    assert raw_prints(tmp_path, ALLOWLIST) == []


def test_the_reviewer_fixture_reddens_the_gate():
    """`scripts/tests/fixtures/raw-print-gate/x.tpl`, the round-3 review's own file (`.tpl` so prettier leaves it byte for byte)."""
    found = raw_prints(Path(__file__).resolve().parent / "fixtures" / "raw-print-gate", ALLOWLIST)
    assert any("indent 2" in entry for entry in found) and any(".Values.y" in entry for entry in found), found
