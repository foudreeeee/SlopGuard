"""
SlopGuard: triage layer for vulnerability disclosures.

This is the package skeleton. Implementation is in progress.
See docs/architecture.md for the design.
"""

__version__ = "0.1.0-dev"

from slopguard.schema import Report, CodeReference, ReporterInfo

__all__ = ["Report", "CodeReference", "ReporterInfo"]
