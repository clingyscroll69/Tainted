"""Assembles the report: findings, their proof, and why each decision was made.

The data model here is shared. Each surface (the website, a PR comment, the CLI) renders
it its own way.
"""

from tainted.report.model import CoverageNote, Report, ReportSummary, build_report

__all__ = ["Report", "ReportSummary", "CoverageNote", "build_report"]
