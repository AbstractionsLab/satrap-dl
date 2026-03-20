"""
Incident case creation service.

Business logic for creating Flowintel incident cases from request data.
"""

from decipher.casemanagement.flowintel_connector import (
    CaseCreationError,
    create_case_from_bundle,
)
from decipher.commons.log_utils import get_logger
from decipher.models import IncidentRequest, IncidentResponse
from decipher.settings import FLOWINTEL_CASE_URL

logger = get_logger(__name__)


def create_incident_case(incident: IncidentRequest) -> IncidentResponse:
    """Create a Flowintel incident case from the given request data.

    Args:
        incident: Incident request data including mandatory priority_level and optional metadata.

    Returns:
        IncidentResponse with the created case ID and Flowintel link.

    Raises:
        CaseCreationError: If Flowintel returns no case ID or the API call fails.
        UnavailablePyFlowintelError: If the Flowintel client cannot be initialised.
    """
    case_id = create_case_from_bundle(incident)

    if case_id == 0:
        raise CaseCreationError("No case ID returned from Flowintel")

    link = f"{FLOWINTEL_CASE_URL}/{case_id}"
    return IncidentResponse(id=case_id, link=link)
