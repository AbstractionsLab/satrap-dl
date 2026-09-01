"""
DECIPHER API models.

Pydantic request and response models shared across the project.
"""

from pydantic import BaseModel, Field, field_validator


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


class AnalysisResult(BaseModel):
    """
    Standard response for all analyzers.

    Attributes:
        analyzed_scenario: The alert type/scenario that was analyzed
        severity: Severity score for the alert data in [0,1]
        report: Dictionary containing analyzer-specific analysis details
        created_case: dictionary containing:
            - id: the ID of the created case, 0 if no case was created.
            - link: URL to the created case, empty string if no case was created.
    """

    analyzed_scenario: str
    severity: float = Field(..., ge=0, le=1, description="Severity score for the alert data in [0,1]")
    report: dict
    # Pydantic creates a copy of defaults of mutable type per instance
    created_case: dict = {"id": 0, "link": ""}

    def __str__(self):
        return self.model_dump_json(indent=2)
