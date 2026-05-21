"""Tests for the benchmark evaluation harness.

These run the real benchmark through the portable-signal pipeline. The headline
invariant is the one the project cares most about: no genuine report is buried.
"""

from __future__ import annotations

from benchmark.evaluate import _flagged, run

VALID_ACTIONS = {
    "fast_track",
    "standard_review",
    "request_clarification",
    "likely_slop",
}


def test_eval_runs_over_full_benchmark():
    rows = run()
    assert len(rows) == 15  # 8 slop + 7 genuine
    for r in rows:
        assert 0 <= r.score <= 100
        assert r.action in VALID_ACTIONS


def test_eval_no_false_positives_on_genuine():
    """Portable signals must never bury a genuine report."""
    genuine = [r for r in run() if r.label == "genuine"]
    assert genuine
    assert [r.id for r in genuine if _flagged(r.action)] == []


def test_eval_catches_recycled_cve():
    """The one slop report that recycles a known CVE is caught by dedup."""
    by_id = {r.id: r for r in run()}
    assert _flagged(by_id["slop-002"].action)
