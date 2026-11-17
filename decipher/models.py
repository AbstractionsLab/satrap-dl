"""
DECIPHER API models.

Pydantic request and response models shared across the project.
"""

from enum import Enum
from typing import Annotated

from pydantic import AfterValidator, BaseModel, Field, StringConstraints, field_validator


MISP_PRIORITY_LEVELS = frozenset({
    "priority-level:baseline-negligible",
    "priority-level:baseline-minor",
    "priority-level:low",
    "priority-level:medium",
    "priority-level:high",
    "priority-level:severe",
    "priority-level:emergency",
    "baseline-negligible",
    "baseline-minor",
    "low",
    "medium",
    "high",
    "severe",
    "emergency"
})


def has_non_empty_str(v: list[str]) -> list[str]:
    """
    Check that a list contains at least one non-empty string.

    Args:
        v: List of strings to check.

    Returns:
        The list, unchanged.

    Raises:
        ValueError: If the list is empty or contains only empty or whitespace-only strings.
    """
    if not any(s.strip() for s in v):
        raise ValueError("The list must contain at least one non-empty string")
    return v


NonEmptyStr = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1)]
NonEmptyBlankList = Annotated[list[str], AfterValidator(has_non_empty_str)]


class IncidentRequest(BaseModel):
    """Request model for incident case creation."""

    priority_level: str = Field(..., description="MISP priority-level taxonomy tag (e.g. priority-level:high)")
    title: str | None = None
    template_id: int | None = None
    description: dict | None = Field(
        default_factory=dict,
        description="Optional additional key-value pairs to include in the case description",
        examples=[{"system_affected": "My database server", "detected_by": "SIEM"}],
    )

    @field_validator("priority_level")
    @classmethod
    def validate_priority_level(cls, v: str) -> str:
        if v not in MISP_PRIORITY_LEVELS:
            valid = ", ".join(sorted(MISP_PRIORITY_LEVELS))
            raise ValueError(f"Invalid MISP priority level '{v}'. Valid values: [{valid}]")
        return v

    @field_validator("template_id")
    @classmethod
    def validate_template_id(cls, v: int | None) -> int | None:
        if v is not None and v <= 0:
            raise ValueError("template_id must be greater than 0")
        return v


class IncidentResponse(BaseModel):
    """Response model for incident case creation."""

    id: int = Field(..., description="Case ID in Flowintel")
    link: str = Field(..., description="Direct URL to access the case")


class CTILookupResult(str, Enum):
    """
    Outcome of the CTI enrichment of an analysis (ARC-017).
    """

    CTI_FOUND = "cti_found"
    NO_CTI_FOUND = "no_cti_found"
    MISP_LOOKUP_ERROR = "misp_lookup_error"
    MISP_DISABLED = "misp_disabled"
    MISP_UNAVAILABLE = "misp_unavailable"


class AnalysisResult(BaseModel):
    """
    Standard response for all analyzers.

    Attributes:
        analyzed_scenario: The alert type/scenario that was analyzed
        cti_lookup_result: Status of the CTI enrichment phase outcome
        severity: Severity score for the alert data in [0,1]
        report: Dictionary containing analyzer-specific analysis details
        created_case: dictionary containing:
            - id: the ID of the created case, 0 if no case was created.
            - link: URL to the created case, empty string if no case was created.
    """

    analyzed_scenario: str
    cti_lookup_result: CTILookupResult = Field(..., description="Outcome status of the CTI enrichment phase")
    severity: float = Field(..., ge=0, le=1, description="Severity score for the alert data in [0,1]")
    report: dict = Field(
        ...,
        description=(
            "Analyzer-specific analysis details. The `misp_available` entry is deprecated and "
            "will be removed in future versions; use "
            "`cti_lookup_result` instead."
        ),
        # declare the deprecated entry in the OpenAPI schema; the report stays open to any other entry
        json_schema_extra={
            "properties": {
                "misp_available": {
                    "deprecated": True,
                    "description": "Deprecated: use `cti_lookup_result` instead.",
                }
            }
        },
    )
    # Pydantic creates a copy of defaults of mutable type per instance
    created_case: dict = {"id": 0, "link": ""}

    def __str__(self):
        return self.model_dump_json(indent=2)
