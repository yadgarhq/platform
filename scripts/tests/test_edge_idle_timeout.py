"""THE EDGE'S DOWNSTREAM IDLE TIMEOUT (yaadgaar #218 follow-up, ADR-1022).

WHAT THE GAP IS. The ClientTrafficPolicy `edge-request-headers` bounds the
request HEADERS from their first byte to their last
(`requestHeadersReceivedTimeout`). A client that completes TLS and then sends no
byte at all never starts that timer. Envoy's `timeout.http.idleTimeout` holds
it, and Envoy's default is 1 h. The gateway's own header-read timer starts at
accept, so behind Envoy that gap is the edge's alone.

WHAT THIS CHART OWNS. The same ClientTrafficPolicy also sets
`spec.timeout.http.idleTimeout` from `gatewayListener.idleTimeoutSeconds`
(default 60, Max 2026-10-27: "Set 60s idleTimeout", which replaces the
30 s of 2026-10-25). It is not a new
object: the parent's object census does not move.

WHAT IS REFUSED, BY NAME. A value that is not a whole number in 1..3600 (3600 is
Envoy's own default, so the value can never be looser than what it replaces),
and a value below `gatewayListener.requestHeadersTimeoutSeconds`. The second is
a policy choice, not an Envoy constraint: the idle timer stops at the first
byte of a request and the headers timer starts there, so they never run
together. The rule keeps the edge from being stricter with a client that has
sent nothing than with one that has started a request head.

Run: python3 -m pytest scripts/tests/ -q
"""

from __future__ import annotations

import re

import pytest

from test_render_checks import ADOPTER_VALUES
from test_request_headers_timeout import (
    FIELD as HEADERS_FIELD,
    KIND,
    adopter,
    api_version_arguments,
    documents,
    http_timeouts,
    one_policy,
    policies,
    template,
    vendored_crd,
)

# ── WRITTEN DOWN ─────────────────────────────────────────────────────────────
FIELD = "idleTimeout"
DEFAULT_SECONDS = 60
VALUE_KEY = "gatewayListener.idleTimeoutSeconds"
HEADERS_KEY = "gatewayListener.requestHeadersTimeoutSeconds"


# ── THE FIELD IS THE ONE THE VENDORED OPERATOR READS ─────────────────────────


def test_the_vendored_crd_declares_the_idle_field():
    """The field is read off the CRD the estate installs, not off documentation."""
    field = http_timeouts(vendored_crd())[FIELD]
    assert field["type"] == "string"
    assert "no active requests" in field["description"], (
        "the field's description no longer defines idle as no active requests: "
        "re-read the operator before trusting this policy"
    )


def test_the_rendered_idle_duration_matches_the_crd_pattern(tmp_path):
    policy, _ = one_policy(tmp_path)
    value = policy["spec"]["timeout"]["http"][FIELD]
    pattern = http_timeouts(vendored_crd())[FIELD]["pattern"]
    assert re.fullmatch(pattern, value), f"{value!r} does not match {pattern!r}"


# ── THE SAME POLICY, NOT A NEW OBJECT ────────────────────────────────────────


def test_the_default_is_sixty_seconds_on_the_one_policy(tmp_path):
    """One ClientTrafficPolicy still renders; it now carries both bounds."""
    policy, rendered = one_policy(tmp_path)
    assert len(policies(rendered)) == 1
    assert policy["spec"]["timeout"] == {
        "http": {HEADERS_FIELD: "10s", FIELD: f"{DEFAULT_SECONDS}s"}
    }


def test_a_stated_value_renders(tmp_path):
    policy, _ = one_policy(tmp_path, "gatewayListener:\n  idleTimeoutSeconds: 20\n")
    assert policy["spec"]["timeout"]["http"][FIELD] == "20s"


def test_a_set_flag_integer_renders(tmp_path):
    """`--set` hands helm an int64, not the float64 a values file does."""
    result = template(
        *api_version_arguments(),
        "-f",
        str(ADOPTER_VALUES),
        "--set",
        "gatewayListener.idleTimeoutSeconds=25",
    )
    assert result.returncode == 0, result.stderr
    (policy,) = policies(documents(result.stdout))
    assert policy["spec"]["timeout"]["http"][FIELD] == "25s"


def test_the_listener_toggle_removes_the_policy(tmp_path):
    result = adopter(tmp_path, "gatewayListener:\n  create: false\n")
    assert result.returncode == 0, result.stderr
    assert policies(documents(result.stdout)) == []


# ── THE RANGE ────────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "written",
    ["0", "3601", "-1", "29.5", '"30"', '"30s"', "null", "true", "[30]"],
)
def test_a_value_outside_the_range_is_refused(tmp_path, written):
    result = adopter(tmp_path, f"gatewayListener:\n  idleTimeoutSeconds: {written}\n")
    assert result.returncode != 0, f"{written} rendered, and it must be refused"
    assert VALUE_KEY in result.stderr, result.stderr


@pytest.mark.parametrize("written", ["3600"])
def test_the_top_of_the_range_renders(tmp_path, written):
    policy, _ = one_policy(
        tmp_path, f"gatewayListener:\n  idleTimeoutSeconds: {written}\n"
    )
    assert policy["spec"]["timeout"]["http"][FIELD] == f"{written}s"


def test_a_misspelt_key_is_refused_by_the_schema(tmp_path):
    """The closed schema (ADR-0850) refuses a key the chart does not read."""
    result = adopter(tmp_path, "gatewayListener:\n  idleTimeoutSecond: 30\n")
    assert result.returncode != 0, "a misspelt key rendered, and it must be refused"
    assert "idleTimeoutSecond" in result.stderr, result.stderr


# ── NOT BELOW THE HEADERS BOUND ──────────────────────────────────────────────


def test_idle_below_the_headers_bound_is_refused(tmp_path):
    result = adopter(
        tmp_path,
        "gatewayListener:\n  idleTimeoutSeconds: 9\n  requestHeadersTimeoutSeconds: 10\n",
    )
    assert result.returncode != 0, "idle 9 s under headers 10 s rendered"
    assert VALUE_KEY in result.stderr, result.stderr
    assert HEADERS_KEY in result.stderr, result.stderr


def test_idle_below_the_headers_bound_is_refused_from_set_flags(tmp_path):
    result = template(
        *api_version_arguments(),
        "-f",
        str(ADOPTER_VALUES),
        "--set",
        "gatewayListener.idleTimeoutSeconds=5",
        "--set",
        "gatewayListener.requestHeadersTimeoutSeconds=6",
    )
    assert result.returncode != 0, "idle 5 s under headers 6 s rendered"
    assert VALUE_KEY in result.stderr, result.stderr


def test_idle_equal_to_the_headers_bound_renders(tmp_path):
    policy, _ = one_policy(
        tmp_path,
        "gatewayListener:\n  idleTimeoutSeconds: 10\n  requestHeadersTimeoutSeconds: 10\n",
    )
    assert policy["spec"]["timeout"]["http"] == {HEADERS_FIELD: "10s", FIELD: "10s"}
