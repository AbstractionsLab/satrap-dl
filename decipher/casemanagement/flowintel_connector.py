"""
Flowintel Case Management Handler

Functions for creating incident cases in Flowintel.
Supports template-based case creation with customizable fields.
"""

from datetime import datetime
from typing import Any
from pyflowintel import FlowintelConnectionError, PyFlowintel, PyflowintelException
from pyflowintel.commons.utils import read_json
from pyflowintel.commons.exceptions import PyflowintelConfigurationError

from decipher.runtime_settings import load_decipher_runtime_cfg
from decipher.models import IncidentRequest
from decipher.casemanagement.template_catalog import CASE_TEMPLATES, AnalysisScenario
from decipher.commons.log_utils import get_logger
from decipher.settings import DECIPHER_CONFIG_PATH, FLOWINTEL_TEMPLATES_DIR

logger = get_logger(__name__)


def create_case_from_bundle(
    scenario: AnalysisScenario, case_bundle: IncidentRequest
) -> int:
    """
    Create a new incident case in Flowintel based on the provided scenario and case bundle.

    Args:
        scenario: High-level analysis scenario (e.g., AnalysisScenario.SUSPICIOUS_LOGIN)
        case_bundle: An object containing all relevant data for the case, including title, score, and additional details.

    Returns:
        ID of the created case
    Raises:
        UnavailablePyFlowintelError: If the PyFlowintel client cannot be initialized.
        CaseCreationError: If case creation fails due to Flowintel API errors or configuration issues.
    """
    logger.info(f"Creating case for scenario '{scenario.name}'")
    try:
        client = PyFlowintel.from_config(str(DECIPHER_CONFIG_PATH))
    except PyflowintelConfigurationError as e:
        raise UnavailablePyFlowintelError(f"Case creation skipped. {e}")

    title = case_bundle.title or scenario.value.replace('_', ' ').capitalize()
    title = f"[DECIPHER] {title} - {datetime.now().strftime('%Y%m%d-%H%M%S')}"

    description = _format_incident_body(case_bundle.model_extra)
    if case_bundle.model_extra.get("risk") and case_bundle.model_extra["risk"].get("tier"):
        priority_tag = _map_tier_to_tag(case_bundle.model_extra["risk"]["tier"])
        logger.debug(f"Assigned priority tag based on risk tier: {priority_tag}")
    else:
        priority_tag = _assign_priority_tag(case_bundle.score)
        logger.debug(f"Assigned priority tag based on score: {priority_tag}")

    case_payload = {
        "description": description,
        "tags": [priority_tag],
    }

    try:
        response = client.cases.create(title, **case_payload)
    except PyflowintelException as e:
        raise CaseCreationError(f"Case creation failed: {e}") from e

    return response.get("case_id", 0)


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
    try:
        client = PyFlowintel.from_config(str(DECIPHER_CONFIG_PATH))
    except PyflowintelConfigurationError as e:
        raise UnavailablePyFlowintelError(f"Case creation skipped. {e}")

    logger.info(f"Creating case for scenario '{scenario.name}'")
    priority_tag = _assign_priority_tag(score)
    case_payload = {"description": description, "tags": [priority_tag]}

    try:
        # @TODO: Temporarily creating case without template since tags are currently not supported
        # when editing a case through the Flowintel API. To be changed in future releases.
        # template_id = _get_template_id_for_scenario(client, scenario)
        # if template_id == 0:
        # logger.warning(f"No template for '{scenario}'. Creating case without template.")
        #     case_id = create_case_without_template(client, scenario, case_payload)
        # else:
        #     case_id = _create_case_with_template(client, template_id, case_payload)
        case_id = _create_case_without_template(client, scenario, case_payload)
    except PyflowintelException as e:
        raise CaseCreationError(f"Case creation failed: {e}") from e

    logger.info(f"Flowintel case created: {case_id}")
    return case_id


def _create_case_with_template(client: PyFlowintel, template_id: int, case_payload: dict) -> int:
    """
    Create a Flowintel case using a template.
    Args:
        client: PyFlowintel client instance.
        template_id: ID of the template to use.
        case_payload: Data for case update.
    Returns:
        ID of the created case, or 0 if creation failed.
    """
    response = client.templates.create_case_from_template(template_id)
    case_id = response.get("case_id", 0)
    if case_id:
        client.cases.update(case_id, case_payload)
    return case_id


def _create_case_without_template(client: PyFlowintel, scenario: AnalysisScenario, case_payload: dict) -> int:
    """
    Create a Flowintel case without using a template.
    Args:
        client: PyFlowintel client instance.
        scenario: AnalysisScenario enum value.
        case_payload: Data for case creation.
    Returns:
        ID of the created case, or 0 if creation failed.
    """
    template = CASE_TEMPLATES.get(scenario)
    if template and template.title:
        title = template.title
    else:
        title = f"[DECIPHER] {scenario.value.replace('_', ' ').capitalize()}"
    title = f"{title} - {datetime.now().strftime('%Y%m%d-%H%M%S')}"
    response = client.cases.create(title, **case_payload)
    return response.get("case_id", 0)


def _get_template_id_for_scenario(client: PyFlowintel, scenario: AnalysisScenario) -> int:
    """
    Map a given scenario to a Flowintel template ID.

    Args:
        scenario: High-level analysis scenario (e.g., AnalysisScenario.SUSPICIOUS_LOGIN)

    Returns:
        Corresponding Flowintel case template ID. If no match found, a new template is created.
        If template creation fails, returns 0.
    """
    title = CASE_TEMPLATES.get(scenario).title if CASE_TEMPLATES.get(scenario) else " "

    try:
        response = client.templates.find_case_temp_by_title(title)
        template_id = response.get("id", 0)
        if template_id == 0:
            logger.warning(f"No Flowintel template found with title: {title}. " "Creating template...")
            return _create_template_for_scenario(client, scenario)
    except FlowintelConnectionError:
        logger.error(f"Connection failed getting template for '{scenario}'.")
        raise

    return template_id


def _create_template_for_scenario(client: PyFlowintel, scenario: AnalysisScenario) -> int:
    """
    Create a new case template in Flowintel from the template in the catalog.
    """
    template = CASE_TEMPLATES.get(scenario)

    if template is None:
        logger.warning(f"No template data available for '{scenario}'")
        return 0

    try:
        template_data = read_json(str(FLOWINTEL_TEMPLATES_DIR / template.filename))
        response = client.templates.create_case_template(template_data)
        template_id = response.get("template_id", 0)
        logger.info(f"Flowintel template created for '{scenario}': {template_id}")
        return template_id
    except ValueError as e:
        logger.error(f"Fail to read template file for '{scenario}': {e}")
        return 0
    except PyflowintelException as e:
        logger.error(f"Flowintel case template creation failed for '{scenario}': {e}")
        return 0


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


def _map_tier_to_tag(tier: int) -> str:
    """
    Map a given tier (1,2,...) to a corresponding priority tag.
    """
    tier_mapping = {
        1: "priority-level:low",
        2: "priority-level:medium",
        3: "priority-level:high",
        4: "priority-level:severe"
    }
    return tier_mapping.get(tier, "priority-level:baseline-minor")


class CaseCreationError(Exception):
    """Custom exception for case creation errors."""

    pass


class UnavailablePyFlowintelError(CaseCreationError):
    """Raised when the PyFlowintel client is unavailable."""

    def __init__(self, message: str | None = None):
        super().__init__(message)
