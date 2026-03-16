"""
DECIPHER API models.

Pydantic request and response models shared across the project.
"""

from pydantic import BaseModel, ConfigDict, Field


class IncidentRequest(BaseModel):
    """Request model for incident case creation.

    Allows flexible incident data with required score for priority assignment.
    """

    score: float = Field(..., ge=0.0, le=1.0, description="Severity score (0.0 to 1.0)")
    title: str | None = None

    model_config = ConfigDict(extra="allow")  # Allow additional fields, var name must be 'model_config' for Pydantic v2


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
    severity: float
    report: dict
    created_case: dict = {"id": 0, "link": ""}

    def __str__(self):
        return self.model_dump_json(indent=2)
