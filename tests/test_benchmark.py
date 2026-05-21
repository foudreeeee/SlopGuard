"""The benchmark dataset must stay loadable as real Report objects.

If the schema changes in a way that breaks the curated reports, this fails
loudly instead of letting the dataset rot.
"""

import json
from pathlib import Path

import pytest

from slopguard.schema import Report

BENCHMARK = Path(__file__).resolve().parent.parent / "benchmark"
REPORT_FILES = sorted(BENCHMARK.glob("*/*.json"))


def test_benchmark_layout():
    assert (BENCHMARK / "slop").is_dir()
    assert (BENCHMARK / "genuine").is_dir()


def test_benchmark_counts():
    slop = list((BENCHMARK / "slop").glob("*.json"))
    genuine = list((BENCHMARK / "genuine").glob("*.json"))
    assert len(slop) >= 8
    assert len(genuine) >= 8
    assert 20 <= len(slop) + len(genuine) <= 30  # hard cap at 30


@pytest.mark.parametrize(
    "path", REPORT_FILES, ids=[f"{p.parent.name}/{p.name}" for p in REPORT_FILES]
)
def test_benchmark_file_validates_as_report(path: Path):
    data = json.loads(path.read_text(encoding="utf-8"))
    report = Report(**data)
    # The on-disk id should match the file stem prefix, so the label is traceable.
    assert report.id == path.stem.split("-")[0] + "-" + path.stem.split("-")[1]
