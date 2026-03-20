"""
DECIPHER Analysis Service

FastAPI application providing extensible alert analysis endpoints.
"""

from contextlib import asynccontextmanager
from logging import getLevelName
from fastapi import FastAPI, HTTPException, Path, Body
from pydantic import ValidationError

from .analyzers import AnalyzerRegistry
from .settings import API_VERSION, BASE_URL
from .commons.log_utils import setup_logging, get_logger
from .models import AnalysisResult, IncidentRequest, IncidentResponse
from .casemanagement.flowintel_connector import CaseCreationError
from .incident_service import create_incident_case


logger = get_logger(__name__)

# Endpoint URL constants
LIST_ANALYZERS_URL = f"{BASE_URL}/analyzers"
GET_ANALYZER_URL = f"{BASE_URL}/analyzers/{{alert_type}}"
ANALYZE_URL = f"{BASE_URL}/analyze/{{alert_type}}"
INCIDENT_URL = f"{BASE_URL}/incident"
HEALTH_URL = "/health"


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Application lifespan manager for startup/shutdown events.
    """
    # Startup: Initialize logging and implicitly load settings
    setup_logging()
    logger = get_logger(__name__)
    logger.info("DECIPHER API server starting up")
    logger.info(f"Registered analyzers: {AnalyzerRegistry.list_types()}")

    yield

    # Shutdown
    logger.info("DECIPHER API server shutting down")


app = FastAPI(
    title="DECIPHER - Analysis API",
    version=API_VERSION,
    description=(
        "DECIPHER is a SATRAP-DL service for analyzing alert's data based on specific threat scenarios, \n"
        "guided by cyber threat intelligence"
    ),
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan,
)


@app.post(
    ANALYZE_URL,
    response_model=AnalysisResult,
    summary="Run CTI analysis on the information from an alert",
    responses={
        200: {"description": "Analysis completed successfully"},
        404: {"description": "Unknown alert type"},
        422: {"description": "Invalid alert data for the specified type"},
        500: {"description": "Internal analysis error"},
    },
    tags=["Analysis"],
)
def analyze_alert(
    alert_type: str = Path(
        ...,  # mark the parameter as required
        description=f"Type of alert to analyze (options: {LIST_ANALYZERS_URL})",
        examples=["suspicious_login"],
    ),
    data: dict = Body(
        ...,
        description="Alert data matching the schema for the specified analysis type",
        examples=[
            {
                "username": "admin",
                "target_host": "10.0.0.1",
                "src_ips": ["185.220.100.1", "45.155.204.30"],
                "timestamp": "2026-01-31T10:00:00Z",
            }
        ],
    ),
):
    """
    Analyze a threat scenario based on the alert data provided in the request body.

    The `alert_type` parameter determines which analyzer and validation schema to use.

    Returns an AnalysisResult containing:
        `analyzed_scenario`: The alert type/scenario that was analyzed
        `severity`: Severity score for the alert data in [0,1]
        `report`: Dictionary containing analyzer-specific analysis details
        `created_case`: ID of the created case, 0 if no case was created.
    """
    try:
        return AnalyzerRegistry.analyze(alert_type, data)
    except ValidationError as e:
        raise HTTPException(
            status_code=422,
            detail={
                "message": f"Invalid data for alert type '{alert_type}'",
                "errors": e.errors(),
            },
        )
    except ValueError as e:
        logger.warning(str(e))
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Analysis failed: {str(e)}",
        )


@app.post(
    INCIDENT_URL,
    response_model=IncidentResponse,
    summary="Create incident case from priority level and optional metadata",
    responses={
        200: {"description": "Incident case created successfully"},
        422: {"description": "Invalid or missing priority_level (must be a valid MISP priority-level taxonomy tag)"},
        500: {"description": "Flowintel case creation failed"},
    },
    tags=["Incident creation"],
)
def create_incident(
    incident: IncidentRequest = Body(
        ...,
        description="Case creation data with MISP priority level, optional title, template ID and additional fields",
        examples=[
            {
                "priority_level": "priority-level:high",
                "title": "Multiple suspicious login attempts from external IP",
                "template_id": "suspicious_login",
                "description": {"system_affected": "My database server", "detected_by": "SIEM"},
            }
        ],
    ),
):
    """
    Create an incident case in Flowintel from an IncidentRequest (see schema for details).

    Request body:
        `priority_level`: Required MISP priority-level taxonomy tag (e.g. priority-level:high or high)
        `title`: Optional case title; a default is assigned if absent
        `template_id`: Optional case template identifier
        `description`: Optional additional key-value pairs included in the case description

    Returns IncidentResponse containing:
        `id`: Case ID in Flowintel
        `link`: Direct URL to access the case
    """
    try:
        return create_incident_case(incident)
    except CaseCreationError as e:
        logger.error(f"Case creation error: {e}")
        raise HTTPException(status_code=500, detail=f"Case creation failed: {str(e)}")
    except Exception as e:
        logger.error(f"Unexpected error at incident endpoint: {e}", exc_info=True)
        raise HTTPException(
            status_code=500, detail=f"Incident endpoint error: {str(e)}"
        )


@app.get(
    LIST_ANALYZERS_URL,
    summary="List available analyzers",
    response_description="Supported threat scenarios (alert types) with their descriptions",
    tags=["Information"],
)
def list_analyzers():
    """
    List all registered alert types and their descriptions.

    Use this endpoint to discover available alert types for the `/analyze/{alert_type}` endpoint
    """
    result = {}

    for alert_type, analyzer_cls in AnalyzerRegistry.get_registered_classes().items():
        result[alert_type] = {
            "description": analyzer_cls.__doc__.strip(),
            "schema": analyzer_cls.schema.model_json_schema(),
        }

    return result


# @app.get(
#     GET_ANALYZER_URL,
#     summary="Get analyzer details",
#     responses={
#         200: {"description": "Analyzer details"},
#         404: {"description": "Unknown alert type"},
#     },
#     tags=["Information"]
# )
# def get_analyzer(
#     alert_type: str = Path(..., description=f"Alert type identifier (see options: {LIST_ANALYZERS_URL})"),
# ):
#     """
#     Get detailed information about a specific analyzer.

#     Returns the analyzer's description and full JSON schema for input validation.
#     """
#     analyzer_cls = AnalyzerRegistry.get_registered_classes().get(alert_type)

#     if not analyzer_cls:
#         registered = ", ".join(AnalyzerRegistry.list_types()) or "(none)"
#         raise HTTPException(
#             status_code=404,
#             detail=f"Unknown alert type: '{alert_type}'. Available: [{registered}]",
#         )

#     return {
#         "alert_type": alert_type,
#         "description": analyzer_cls.__doc__.strip(),
#         "schema": analyzer_cls.schema.model_json_schema(),
#     }


@app.get(
    HEALTH_URL,
    summary="DECIPHER service health check",
    tags=["System"],
)
def health_check():
    """
    Returns service status and count of loaded analyzers.
    """
    return {
        "status": "ok",
        "service": "decipher-api",
        "analyzers_loaded": len(AnalyzerRegistry.list_types()),
        "available_types": AnalyzerRegistry.list_types(),
        "logging_level": getLevelName(get_logger(__name__).getEffectiveLevel()),
    }


@app.get(
    "/",
    summary="API root",
    include_in_schema=False,
)
def root():
    """Redirect to API documentation."""
    return {
        "service": "DECIPHER Analysis API",
        "version": f"{API_VERSION}",
        "docs": "/docs",
        "redoc": "/redoc",
        "health": "/health",
        "analyzers": f'"/api/{API_VERSION}/analyzers"',
    }
