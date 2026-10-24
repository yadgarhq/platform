"""THE BROKER PERMISSIONS THE TEAM-MEMBERSHIP EVICTION RIDES ON (team access stage 7).

`plans/team-access.md` (yadgarhq/docs), stage 7, red 3. iam publishes
`yadgar.iam.user.teams-changed` when a user's team set changes, and the gateway
subscribes to it to evict that user's cached `team_ids` and `is_admin`. Both
directions are already permitted in `chart/values.yaml` (`nats.config.merge.
authorization`). Nothing in this chart changes; this suite PINS the two entries,
and pins each account's permissions whole, so neither can widen unseen.

WHY A PIN AND NOT TRUST. A broker that does not permit a subject refuses the
publish asynchronously, while `async_nats::Client::publish` has already returned
`Ok(())` (iam `src/invalidate.rs`, module comment). So a dropped entry evicts
nothing and returns no error to iam: membership changes would stay cached until
the gateway's TTL, with only iam's event-callback log to say so. The render is
the one place the omission can be caught before deploy.

THE RENDER IS R2, `example/values.yaml` with every `create` true, the render that
emits the broker's `nats-config` ConfigMap. The red case deletes each entry from a
copy of `chart/values.yaml` and renders again.

Run: python3 -m pytest scripts/tests/ -q
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

REPO = Path(__file__).resolve().parents[2]
CHART = REPO / "chart"
ADOPTER_VALUES = REPO / "example" / "values.yaml"
DECLARED_API_VERSIONS = ("cert-manager.io/v1", "gateway.envoyproxy.io/v1alpha1")

TEAMS_CHANGED = "yadgar.iam.user.teams-changed"
# (user, direction): iam publishes, the gateway subscribes.
PINNED = (("iam", "publish"), ("gateway", "subscribe"))

# `$NATS_PASSWORD` and its siblings render as bare NATS variables, which JSON
# does not allow; quoted before parsing. Nothing else in the file is non-JSON.
NATS_VARIABLE = re.compile(r'(?<!")\$([A-Z_][A-Z0-9_]*)')


def render(chart: Path) -> list[dict]:
    binary = shutil.which("helm")
    assert binary, "helm is not on PATH; install it rather than let this suite pass unrun"
    arguments = [part for group in DECLARED_API_VERSIONS for part in ("--api-versions", group)]
    result = subprocess.run(
        [binary, "template", "platform", str(chart), *arguments, "-f", str(ADOPTER_VALUES)],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
    return [d for d in yaml.safe_load_all(result.stdout) if isinstance(d, dict) and d.get("apiVersion")]


def broker_users(documents: list[dict]) -> dict[str, dict]:
    """The broker's authorization users, by name, from the rendered `nats-config`."""
    configs = [
        d for d in documents
        if d.get("kind") == "ConfigMap" and d["metadata"]["name"] == "nats-config"
    ]
    assert len(configs) == 1, f"{len(configs)} nats-config ConfigMaps in the render"
    conf = json.loads(NATS_VARIABLE.sub(r'"$\1"', configs[0]["data"]["nats.conf"]))
    return {user["user"]: user for user in conf["authorization"]["users"]}


def missing_teams_changed(users: dict[str, dict]) -> list[str]:
    """Every pinned (user, direction) whose allow list lacks the subject. PURE."""
    failures = []
    for user, direction in PINNED:
        allow = ((users.get(user) or {}).get("permissions") or {}).get(direction, {}).get("allow") or []
        if TEAMS_CHANGED not in allow:
            failures.append(f"user `{user}` {direction}.allow lacks {TEAMS_CHANGED}: {allow}")
    return failures


def test_red_03_teams_changed_is_in_iams_publish_and_the_gateways_subscribe_allow() -> None:
    assert missing_teams_changed(broker_users(render(CHART))) == []


def chart_without_entry(destination: Path, occurrence: int) -> Path:
    """A copy of the chart with the `occurrence`-th (0-based) subject line deleted."""
    copy = destination / "chart"
    shutil.copytree(CHART, copy, symlinks=True)
    values = copy / "values.yaml"
    lines = values.read_text().splitlines(keepends=True)
    hits = [i for i, line in enumerate(lines) if line.strip() == f'- "{TEAMS_CHANGED}"']
    assert len(hits) == 2, f"expected the subject twice in chart/values.yaml, found {len(hits)}"
    del lines[hits[occurrence]]
    values.write_text("".join(lines))
    return copy


@pytest.mark.parametrize(
    ("occurrence", "user", "direction"),
    [(0, "iam", "publish"), (1, "gateway", "subscribe")],
    ids=["iam_publish_deleted", "gateway_subscribe_deleted"],
)
def test_red_03_deleting_either_entry_reddens_the_pin(
    tmp_path: Path, occurrence: int, user: str, direction: str
) -> None:
    failures = missing_teams_changed(broker_users(render(chart_without_entry(tmp_path, occurrence))))
    assert len(failures) == 1 and failures[0].startswith(f"user `{user}` {direction}.allow"), failures


# LEAST PRIVILEGE, PINNED WHOLE. The presence pin above passes a broker that also
# lets the gateway publish the subject, or that widens either allow list to a
# wildcard: a compromised gateway could then forge the evictions and revocations
# it is meant only to receive (`chart/values.yaml`, "GATEWAY IS SUBSCRIBE-ONLY").
# So each account's permissions must equal exactly its one direction on the two
# subjects, with the other direction closed by `deny: ">"`.
SUBJECTS = ["yadgar.iam.credential.revoked", TEAMS_CHANGED]
EXACT_PERMISSIONS = {
    "iam": {"publish": {"allow": SUBJECTS}, "subscribe": {"deny": ">"}},
    "gateway": {"publish": {"deny": ">"}, "subscribe": {"allow": SUBJECTS}},
}


def permission_drift(users: dict[str, dict]) -> list[str]:
    """Every pinned account whose rendered permissions differ from EXACT_PERMISSIONS. PURE."""
    return [
        f"user `{user}` permissions {(users.get(user) or {}).get('permissions')} != {expected}"
        for user, expected in EXACT_PERMISSIONS.items()
        if (users.get(user) or {}).get("permissions") != expected
    ]


def test_each_account_holds_exactly_its_one_direction_on_the_two_subjects() -> None:
    assert permission_drift(broker_users(render(CHART))) == []


def chart_with_values(destination: Path, old: str, new: str) -> Path:
    """A copy of the chart with one exact text replacement in `values.yaml`."""
    copy = destination / "chart"
    shutil.copytree(CHART, copy, symlinks=True)
    values = copy / "values.yaml"
    text = values.read_text()
    assert text.count(old) == 1, f"expected {old!r} once in chart/values.yaml"
    values.write_text(text.replace(old, new))
    return copy


GATEWAY_PUBLISH_DENY = '              publish:\n                deny: ">"\n'
IAM_SUBSCRIBE_DENY = '              subscribe:\n                deny: ">"\n'
TEAMS_CHANGED_LINE = f'                  - "{TEAMS_CHANGED}"\n'


@pytest.mark.parametrize(
    ("old", "new", "user"),
    [
        (
            GATEWAY_PUBLISH_DENY,
            f'              publish:\n                allow:\n{TEAMS_CHANGED_LINE}',
            "gateway",
        ),
        (IAM_SUBSCRIBE_DENY, f'              subscribe:\n                allow:\n{TEAMS_CHANGED_LINE}', "iam"),
        (
            f'                  - "yadgar.iam.credential.revoked"\n{TEAMS_CHANGED_LINE}              subscribe:',
            '                  - "yadgar.iam.>"\n              subscribe:',
            "iam",
        ),
        (
            f'                  - "yadgar.iam.credential.revoked"\n{TEAMS_CHANGED_LINE}\n',
            '                  - "yadgar.>"\n\n',
            "gateway",
        ),
    ],
    ids=["gateway_may_publish", "iam_may_subscribe", "iam_publish_wildcard", "gateway_subscribe_wildcard"],
)
def test_a_widened_permission_reddens_the_pin(tmp_path: Path, old: str, new: str, user: str) -> None:
    drift = permission_drift(broker_users(render(chart_with_values(tmp_path, old, new))))
    assert len(drift) == 1 and drift[0].startswith(f"user `{user}` permissions"), drift
