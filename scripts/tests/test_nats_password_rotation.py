"""LEDGER 1425 — ROTATING `nats-auth` / `nats-auth-gateway` DOES NOT ROLL THE BROKER.

WHAT WAS MEASURED, 2026-10-11, AGAINST THIS CHART'S OWN RENDER. `nats-auth` and
`nats-auth-gateway` are minted by the bootstrap Job's `curl` POST
(`templates/bootstrap-secrets.yaml`) — never by a Helm-rendered Secret object — so
there is nothing in the render whose content a checksum could carry. The broker's
password reaches it as `container.env.NATS_PASSWORD{,_GATEWAY}.valueFrom.secretKeyRef`
— this container's OWN ENVIRONMENT, fixed once at process start.
`nats.podTemplate.configChecksumAnnotation: true` already rolls the broker, but
only on a CONFIG change: the ConfigMap it hashes carries the literal text
`$NATS_PASSWORD` (the `<< >>` escape keeps it unquoted so nats-server expands it
as a variable), never the password's bytes, so rotating the Secret moves nothing
that checksum sees. A reload would not help either — SIGHUP re-expands that same
variable against the same already-fixed environment. Only a new pod picks up a
new value.

TWO GATES, BOTH SMALL ON PURPOSE. The fix this ledger entry asks for is a runbook
step, not a template: neither option ADR-0750 would otherwise prefer survives
contact with this chart. A render-time checksum needs rendered content to hash,
which `bootstrap-secrets.yaml`'s `curl` body never gives Helm (option (a)). A
file-plus-reload needs the Secret's own bytes to parse as nats-server config —
`$include` substitutes a whole statement, not a bare scalar, so the included file
would have to read `password: "..."` rather than the raw value `iam` and `gateway`
already read as a plaintext credential — and the Job's Role grants `create`
alone, so a reshaped Secret cannot land on a cluster that already bootstrapped
(option (b)). So this chart documents the manual remedy in README.md instead, and
these two gates are what keep that documentation honest:

  1. THE README SAYS THE RIGHT COMMAND. `broker_restart_runbook_failures` reads
     the section ADR-0750's own `test_bootstrap.py` already owns — the one
     carrying "Rotation is not provided." — and asserts it also carries the
     broker's own remedy: `kubectl ... delete pod nats-0`, naming both Secrets,
     and a warning against `kubectl rollout restart`, because this organisation's
     Argo Application runs `syncPolicy.automated.selfHeal: true`
     (`yadgarhq/argocd`'s `applications/yadgar.yaml`) and would revert the
     `restartedAt` annotation that command writes, restarting the broker a
     second, unplanned time.

  2. THE PREMISE THE RUNBOOK DEPENDS ON STILL HOLDS. `env_secretkeyref_failures`
     renders the chart and asserts the password is still read from
     `secretKeyRef` on the container's environment, naming the Secret and key.
     This is a PREMISE LOCK rather than a red-first behaviour test — the render
     this asserts against is unchanged by this ledger entry, so it already
     passed before this file existed. Its job is to go red the day somebody
     moves either password to a file: that is the day `delete pod` stops being
     the right remedy and README.md's note needs to move with it.

NO SKIPS (ADR-0650), same as every other render suite here: helm absent is a
failure, not a skip.

Run: python3 -m pytest scripts/tests/test_nats_password_rotation.py -q
"""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parents[2]
CHART = REPO / "chart"
ADOPTER_VALUES = REPO / "example" / "values.yaml"
README = REPO / "README.md"

RELEASE_NAMESPACE = "yadgar"

# Same two groups `test_bootstrap.py` and `test_render_checks.py` pass, for the
# same reason: the adopter values this suite renders with turn on the
# certificate and Gateway-listener halves too, and `templates/render-checks.yaml`
# refuses a bare render of either before a single object exists to inspect.
DECLARED_API_VERSIONS = ("cert-manager.io/v1", "gateway.envoyproxy.io/v1alpha1")
API_VERSIONS = tuple(
    part for group in DECLARED_API_VERSIONS for part in ("--api-versions", group)
)


def helm(*arguments: str) -> subprocess.CompletedProcess[str]:
    binary = shutil.which("helm")
    assert binary, (
        "helm is not on PATH. This suite renders the chart, and so does the "
        "`helm lint and render` pre-commit hook — install helm rather than "
        "letting either report a pass it did not earn."
    )
    return subprocess.run([binary, *arguments], capture_output=True, text=True)


def documents_of(stdout: str) -> list[dict]:
    return [
        document
        for document in yaml.safe_load_all(stdout)
        if isinstance(document, dict) and document.get("apiVersion")
    ]


def render_text(chart: Path, *arguments: str) -> str:
    result = helm(
        "template",
        "platform",
        str(chart),
        "--namespace",
        RELEASE_NAMESPACE,
        *API_VERSIONS,
        *arguments,
    )
    assert result.returncode == 0, result.stderr
    return result.stdout


def render(chart: Path, *arguments: str) -> list[dict]:
    return documents_of(render_text(chart, *arguments))


def adopter_render(chart: Path = CHART, *arguments: str) -> list[dict]:
    return render(chart, "-f", str(ADOPTER_VALUES), *arguments)


def of_kind(documents: list[dict], kind: str) -> list[dict]:
    return [document for document in documents if document.get("kind") == kind]


def name_of(document: dict) -> str:
    return str((document.get("metadata") or {}).get("name"))


# ── GATE 2 FIRST — THE RENDER PREMISE THE RUNBOOK NOTE DEPENDS ON ───────────

# `fullnameOverride: nats` (ADR-0805) is what makes the StatefulSet's name, and
# so the runbook's pod name `nats-0`, the literal below rather than something
# derived — a release named anything else still names this object `nats`.
BROKER_STATEFULSET_NAME = "nats"
BROKER_CONTAINER_NAME = "nats"

# The two env vars the broker reads its accounts' passwords from, and the Secret
# each one must still name. `bootstrap-secrets.yaml` mints both under the key
# `password`, and `container.env` in `chart/values.yaml` is where the broker's
# own values point back at them.
PASSWORD_ENV_SECRETS = {
    "NATS_PASSWORD": "nats-auth",
    "NATS_PASSWORD_GATEWAY": "nats-auth-gateway",
}
SECRET_KEY = "password"


def nats_statefulset(documents: list[dict]) -> dict:
    statefulsets = [
        document
        for document in of_kind(documents, "StatefulSet")
        if name_of(document) == BROKER_STATEFULSET_NAME
    ]
    assert len(statefulsets) == 1, (
        f"expected exactly 1 StatefulSet named {BROKER_STATEFULSET_NAME!r} "
        f"(ADR-0805's fullnameOverride, and the runbook's `nats-0`), found "
        f"{len(statefulsets)}"
    )
    return statefulsets[0]


def nats_container_env(statefulset: dict) -> dict[str, dict]:
    containers = statefulset["spec"]["template"]["spec"]["containers"]
    matches = [c for c in containers if c.get("name") == BROKER_CONTAINER_NAME]
    assert len(matches) == 1, (
        f"expected exactly 1 container named {BROKER_CONTAINER_NAME!r} on the "
        f"broker StatefulSet, found {len(matches)}"
    )
    return {entry["name"]: entry for entry in matches[0].get("env", [])}


def env_secretkeyref_failures(documents: list[dict]) -> list[str]:
    """PURE. The runbook's premise: both passwords still env, still secretKeyRef."""
    failures = []
    env = nats_container_env(nats_statefulset(documents))
    for variable, secret in PASSWORD_ENV_SECRETS.items():
        entry = env.get(variable)
        if entry is None:
            failures.append(
                f"expected env var {variable} on the {BROKER_CONTAINER_NAME!r} "
                f"container, found none"
            )
            continue
        ref = (entry.get("valueFrom") or {}).get("secretKeyRef") or {}
        if ref.get("name") != secret or ref.get("key") != SECRET_KEY:
            failures.append(
                f"expected {variable} to read secretKeyRef "
                f"{{name: {secret}, key: {SECRET_KEY}}}, found {ref!r}. A password "
                f"that no longer reads from this container's environment makes "
                f"README.md's `delete pod` remedy the wrong one — see the comment "
                f"beside `nats.podTemplate.configChecksumAnnotation` in "
                f"chart/values.yaml"
            )
    return failures


def test_the_broker_password_still_comes_from_env_secretkeyref():
    failures = env_secretkeyref_failures(adopter_render())
    assert failures == [], "\n".join(failures)


def test_pointing_nats_password_at_a_different_secret_reddens_the_gate():
    """Mutation check: the assertion is tied to the rendered container, not a string."""
    failures = env_secretkeyref_failures(
        adopter_render(
            CHART,
            "--set",
            "nats.container.env.NATS_PASSWORD.valueFrom.secretKeyRef.name=wrong-secret",
        )
    )
    message = "\n".join(failures)
    assert failures, "NATS_PASSWORD was pointed at a different Secret and the gate passed"
    assert "expected NATS_PASSWORD to read secretKeyRef" in message, message
    assert "wrong-secret" in message, message


# ── GATE 1 — THE README NAMES THE BROKER'S OWN REMEDY ───────────────────────

# The sentence `test_bootstrap.py` already anchors its "rotation" gate on — the
# one section this suite's command has to sit beside, same reasoning as that
# file's `export_command_failures`: a remedy an operator meets three sections
# away from the hazard it answers is the paragraph asking for care the hazard's
# own consequences say is worth less than a gate.
ROTATION_MARKER = "Rotation is not provided."

# The exact remedy README.md states. `-n yadgar` rather than a placeholder,
# because this chart's own `## Adopting this in your own installation` section
# installs into that exact namespace and every export command beside it is
# already namespace-qualified the same way.
RESTART_COMMAND = "kubectl -n yadgar delete pod nats-0"

# What the command must NOT be, and why: ADR-0805 names the StatefulSet `nats`,
# so `rollout restart statefulset/nats` is the command an operator reaches for
# first, and it is the wrong one while this Application's selfHeal is on.
ROLLOUT_RESTART_WARNING = "kubectl rollout restart statefulset/nats"


def broker_restart_runbook_failures(readme: str) -> list[str]:
    """Ledger 1425. PURE. Scoped to the section `ROTATION_MARKER` already owns."""
    sections = re.split(r"^## ", readme, flags=re.MULTILINE)
    holding = [section for section in sections if ROTATION_MARKER in section]
    if len(holding) != 1:
        return [
            f"expected exactly 1 section of README.md to carry `{ROTATION_MARKER}`, "
            f"found {len(holding)}"
        ]
    section = holding[0]
    failures = []
    if RESTART_COMMAND not in section:
        failures.append(
            f"missing the broker restart command `{RESTART_COMMAND}` beside "
            f"`{ROTATION_MARKER}`"
        )
    if ROLLOUT_RESTART_WARNING not in section:
        failures.append(
            f"missing the warning against `{ROLLOUT_RESTART_WARNING}` (Argo's "
            f"selfHeal reverts the `restartedAt` annotation it writes)"
        )
    for secret in PASSWORD_ENV_SECRETS.values():
        if secret not in section:
            failures.append(f"missing `{secret}` beside the restart command")
    return failures


def test_the_readme_documents_the_broker_restart_after_a_nats_password_rotation():
    failures = broker_restart_runbook_failures(README.read_text())
    assert failures == [], "\n".join(failures)


def test_dropping_the_restart_command_reddens_the_runbook_gate():
    without = README.read_text().replace(RESTART_COMMAND, "kubectl get pods")
    failures = broker_restart_runbook_failures(without)
    message = "\n".join(failures)
    assert failures, "the broker restart command was dropped and the gate passed"
    assert f"missing the broker restart command `{RESTART_COMMAND}`" in message, message


def test_dropping_the_rollout_restart_warning_reddens_the_runbook_gate():
    without = README.read_text().replace(ROLLOUT_RESTART_WARNING, "kubectl get pods")
    failures = broker_restart_runbook_failures(without)
    message = "\n".join(failures)
    assert failures, "the rollout-restart warning was dropped and the gate passed"
    assert "missing the warning against" in message, message
