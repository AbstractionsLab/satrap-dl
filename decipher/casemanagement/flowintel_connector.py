"""
Flowintel Case Management Handler

Functions for creating incident cases in Flowintel.
Supports template-based case creation with customizable fields.
"""

from datetime import datetime
from typing import Any
from pyflowintel import FlowintelConnectionError, PyFlowintel, PyflowintelException
from pyflowintel.commons.exceptions import PyflowintelConfigurationError

from decipher.runtime_settings import load_decipher_runtime_cfg
from decipher.models import IncidentRequest
from decipher.casemanagement.template_catalog import CASE_TEMPLATES
from decipher.commons.log_utils import get_logger
from decipher.settings import AnalysisScenario, DECIPHER_CONFIG_PATH

logger = get_logger(__name__)


def create_case_from_bundle(case_bundle: IncidentRequest) -> int:
    """
    Create a new incident case in Flowintel based on the provided case bundle.

    Args:
        case_bundle: Incident request data including priority_level, optional title,
            template_id, and description fields.

    Returns:
        ID of the created case
    Raises:
        UnavailablePyFlowintelError: If the PyFlowintel client cannot be initialized.
        CaseCreationError: If case creation fails due to Flowintel API errors or configuration issues.
    """
    client = _get_flowintel_client()

    priority_tag = _normalize_priority_level(case_bundle.priority_level)

    title = case_bundle.title or "Incident"
    title = f"[DECIPHER] {title} - {datetime.now().strftime('%Y%m%d-%H%M%S')}"

    description = _format_incident_body(case_bundle.description or {})
    payload = {
        "description": description,
        "tags": [priority_tag],
    }

    try:
        if case_bundle.template_id:
            case_id = _create_case_with_template(client, case_bundle.template_id, title, payload)
        else:
            case_id = _create_case_without_template(client, title, payload)
    except PyflowintelException as e:
        raise CaseCreationError(f"Case creation failed: {e}") from e

    return case_id


def create_case_for_scenario(
    scenario: AnalysisScenario,
    description: str,
    score: float
) -> int:
    """
    Create a new incident case from a Flowintel template.

    Args:
        scenario: High-level analysis scenario (e.g., AnalysisScenario.SUSPICIOUS_LOGIN)
        description: Description of the case to be created.
        score: Severity score to determine priority tag.
        
    Returns:
        ID of the created case

    Raises:
        UnavailablePyFlowintelError: If the PyFlowintel client cannot be initialized.
        CaseCreationError: If case creation fails due to Flowintel API errors.
    """
    client = _get_flowintel_client()

    logger.info(f"Creating case for scenario '{scenario.name}'")
    priority_tag = _assign_priority_tag(score)
    case_payload = {"description": description, "tags": [priority_tag]}

    try:
        # @TODO: Temporarily creating case without template since the Flowintel API does not support
        # editing tags in a case created from a template. To be uncommented in future releases if Flowintel is fixed.
        # template_id = _get_template_id_for_scenario(client, scenario)
        # if template_id == 0:
        # logger.warning(f"No template for '{scenario}'. Creating case without template.")
        #     case_id = create_case_without_template(client, scenario, case_payload)
        # else:
        #     case_id = _create_case_with_template(client, template_id, case_payload)
        title = _default_case_title(scenario)
        case_id = _create_case_without_template(client, title, case_payload)
    except PyflowintelException as e:
        raise CaseCreationError(f"Case creation failed: {e}") from e

    logger.info(f"Flowintel case created: {case_id}")
    return case_id


def _get_flowintel_client() -> PyFlowintel:
    """Initialize and return a PyFlowintel client from the DECIPHER config file.

    Raises:
        UnavailablePyFlowintelError: If the client cannot be initialized.
    """
    try:
        return PyFlowintel.from_config(str(DECIPHER_CONFIG_PATH))
    except PyflowintelConfigurationError as e:
        raise UnavailablePyFlowintelError(f"Case creation skipped. {e}")


def _normalize_priority_level(level: str) -> str:
    prefix = "priority-level:"
    if level.startswith(prefix):
        return level
    return f"{prefix}{level}"


def _format_incident_body(data: dict[str, Any]) -> str:
    """Format a dictionary into a readable incident case report body with 2-level nested dicts supported."""
    lines = []
    sections = []

    format_label = lambda s: s.replace("_", " ").capitalize()

    for key, value in data.items():
        label = format_label(key)

        if isinstance(value, dict):
            sections.append(f"\n[ {label} ]")
            for sub_key, sub_value in value.items():
                sub_label = format_label(sub_key)
                if isinstance(sub_value, dict):
                    sections.append(f"{sub_label}:")
                    for k, v in sub_value.items():
                        sections.append(f"─ {format_label(k)} = {v}")
                else:
                    sections.append(f"  {sub_label}: {sub_value}")
        else:
            lines.append(f"{label}: {value}")

    return "\n".join([*lines, *sections])


def _default_case_title(scenario: AnalysisScenario) -> str:
    """Build a default timestamped case title for the given scenario."""
    template = CASE_TEMPLATES.get(scenario.value)
    base = template.title if template and template.title else f"[DECIPHER] {scenario.value.replace('_', ' ').capitalize()}"
    return f"{base} - {datetime.now().strftime('%Y%m%d-%H%M%S')}"


def _create_case_with_template(client: PyFlowintel, template_id: int, title: str, payload: dict) -> int:
    """
    Create a Flowintel case using a template from the Flowintel repository.

    Note: Due to current Flowintel API limitations (tags are ignored when creating a case from a template), 
    for now this function verifies the template exists but always creates a case without a template.
    This is expected to be updated once Flowintel supports tags in template-based case creation.

    Args:
        client: PyFlowintel client instance.
        template_id: Template identifier.
        title: Case title.
        payload: Additional case data (description, tags).

    Returns:
        ID of the created case, or 0 if creation failed.
    """
    try:
        response = client.templates.find_case_temp_by_id(template_id)
        flowintel_id = response.get("id", 0)
        if flowintel_id == 0:
            logger.warning(f"No Flowintel template found with ID {template_id}. Creating case without template.")
        else:
            logger.info("Case from template currently unsupported. Creating case without template...")
    except FlowintelConnectionError:
        logger.error(f"Connection failed finding template with id '{template_id}'.")
        raise
    return _create_case_without_template(client, title, payload)


def _create_case_without_template(client: PyFlowintel, title: str, payload: dict) -> int:
    """
    Create a Flowintel case without using a template.

    Args:
        client: PyFlowintel client instance.
        title: Case title.
        payload: Case data (description, tags).

    Returns:
        ID of the created case, or 0 if creation failed.
    """
    response = client.cases.create(title, **payload)
    return response.get("case_id", 0)


def _get_template_id_for_scenario(client: PyFlowintel, scenario: AnalysisScenario) -> int:
    """
    Map a catalog template_id to a Flowintel template ID.

    Args:
        template_id: Catalog template identifier (key in CASE_TEMPLATES).

    Returns:
        Corresponding Flowintel case template ID. If no match found, a new template is created.
        If template creation fails, returns 0.
    """
    catalog_template = CASE_TEMPLATES.get(scenario.value)
    title = catalog_template.title if catalog_template else " "

    try:
        response = client.templates.find_case_temp_by_title(title)
        flowintel_id = response.get("id", 0)
        if flowintel_id == 0:
            logger.warning(f"No Flowintel template found with title: {title}.")
    except FlowintelConnectionError:
        logger.error(f"Connection failed getting template for '{scenario}'.")
        raise

    return flowintel_id


def _assign_priority_tag(analysis_score: float) -> str:
    """
    Assign a priority tag based on the severity score.

    Args:
        analysis_score: Severity score used to determine priority level.

    Returns:
        Priority tag string following the format "priority-level:<level>"
        (e.g., "priority-level:high"). Falls back to "priority-level:baseline-minor"
        if the score is below all configured thresholds.
    """
    priority_thresholds = load_decipher_runtime_cfg().priority_thresholds

    # Evaluate the score against thresholds ordered from highest to lowest, returning the first match
    for level, threshold in sorted(priority_thresholds.items(), key=lambda item: item[1], reverse=True):
        if analysis_score >= threshold:
            return f"priority-level:{level}"
    return "priority-level:baseline-minor"


class CaseCreationError(Exception):
    """Custom exception for case creation errors."""

    pass


class UnavailablePyFlowintelError(CaseCreationError):
    """Raised when the PyFlowintel client is unavailable."""

    def __init__(self, message: str | None = None):
        super().__init__(message)
