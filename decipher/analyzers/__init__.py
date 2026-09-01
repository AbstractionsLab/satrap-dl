"""
Alert Analyzers Package

Each analyzer module registers itself with the AnalyzerRegistry on import.
Import all analyzer modules here to ensure registration.
"""

from .base import BaseAnalyzer, AnalysisResult
from .registry import AnalyzerRegistry

# Import analyzers to trigger registration
from . import suspicious_login  # noqa: F401
from . import network_scanning  # noqa: F401

__all__ = ["BaseAnalyzer", "AnalysisResult", "AnalyzerRegistry"]
