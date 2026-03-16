"""
Case management integrations for incident response platforms.

Provides handlers for creating and managing cases in external
case management tools like Flowintel, TheHive, etc.
"""

from .flowintel_connector import create_case_for_scenario

__all__ = [
    "create_case_for_scenario",
]