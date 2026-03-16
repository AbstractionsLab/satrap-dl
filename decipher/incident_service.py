"""
Incident case creation service.

Business logic for creating Flowintel incident cases from alert type and request data.
This module is free of FastAPI dependencies and can be used and tested independently.
"""

from decipher.casemanagement.flowintel_connector import (
    CaseCreationError,
    create_case_from_bundle,
)
from decipher.commons.log_utils import get_logger
from decipher.models import IncidentRequest, IncidentResponse
from decipher.settings import AnalysisScenario, FLOWINTEL_CASE_URL

logger = get_logger(__name__)


def create_incident_case(
    alert_type: str, incident: IncidentRequest
) -> IncidentResponse:
    """Create a Flowintel incident case for the given alert type and request data.

    Args:
        alert_type: Threat scenario identifier (must match a registered AnalysisScenario value).
        incident: Incident request data including mandatory score and optional metadata.

    Returns:
        IncidentResponse with the created case ID and Flowintel link.

    Raises:
        ValueError: If alert_type does not match any known AnalysisScenario.
        CaseCreationError: If Flowintel returns no case ID or the API call fails.
        UnavailablePyFlowintelError: If the Flowintel client cannot be initialised.
    """
    scenario_map = {s.value: s for s in AnalysisScenario}

    if alert_type not in scenario_map:
        available = ", ".join(scenario_map) or "(none)"
        raise ValueError(
            f"Unknown alert type: '{alert_type}'. Available scenarios: [{available}]"
        )

    scenario = scenario_map[alert_type]
    case_id = create_case_from_bundle(scenario=scenario, case_bundle=incident)

    if case_id == 0:
        raise CaseCreationError("No case ID returned from Flowintel")

    link = f"{FLOWINTEL_CASE_URL}/{case_id}"
    return IncidentResponse(id=case_id, link=link)
