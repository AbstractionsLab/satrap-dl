# Creating a custom analyzer

A new threat scenario scored against MISP threat intelligence is added by subclassing `MISPCTIAnalyzer`, which implements the whole analysis pipeline: IOC search, scoring, case creation and report assembly. 

To support a new threat scenario analyzer in the API:

1. Add the scenario identifier to the `AnalysisScenario` enumeration in `decipher/settings.py`. This is the value used in the endpoint path, `/api/v1/analyze/<identifier>`:

    ```python
    class AnalysisScenario(Enum):
        SUSPICIOUS_LOGIN = "suspicious_login"
        NETWORK_SCANNING = "suspicious_nt_scanning"
        NEW_SCENARIO = "new_scenario"
    ```

2. Create a new module in `decipher/analyzers/` with the alert schema and the analyzer:

    ```python
    from pydantic import BaseModel

    from .registry import AnalyzerRegistry
    from .scenario_analyzer import MISPCTIAnalyzer
    from ..settings import AnalysisScenario


    class NewScenarioAlert(BaseModel):
        """Define your alert schema here"""


    @AnalyzerRegistry.register
    class NewScenarioAnalyzer(MISPCTIAnalyzer):
        """Brief description of what this analyzer does."""

        alert_type = AnalysisScenario.NEW_SCENARIO.value
        schema = NewScenarioAlert
        case_headline = "Sentence describing the scenario in the case description"

        def build_ioc_mapping(self, alert: NewScenarioAlert) -> dict[str, list[str]]:
            """Map the alert fields to the MISP attribute types to search for."""
            return {
                "ip-src": alert.src_ips,
                ...
            }
    ```

    The docstring of the analyzer class is returned by the `/analyzers` endpoint, so keep it meaningful for the users of the API.

3. Import the new module in `decipher/analyzers/__init__.py` so that the registration decorator runs at startup:

    ```python
    from . import new_scenario
    ```

4. Rebuild the image of the DECIPHER API before starting the service, so that the new analyzer is loaded.

### Customizing the analysis pipeline

Besides the two mandatory members `case_headline` and `build_ioc_mapping()`, a subclass can override the following methods. Each one is optional and the base implementation is used when it is not overridden.

| Member | Purpose |
|---|---|
| `misp_search_params(config)` | Adjust the MISP search parameters for this scenario. E.g., the network scanning analyzer uses it to force `enforce_warninglist` to `false` |
| `extend_analysis(alert, report)` | Run additional analysis steps and add their output to the report, as the network scanning analyzer does for `identified-scanners` |
| `retrieve_misp_cti(alert, config, report)` | Replace the CTI retrieval logic altogether. An override is responsible for setting `misp_available` and `misp_events_found` in the report and for recording lookup errors in `log_summary` |
| `case_suppression_reason(severity, report)` | Return a message to skip case creation for this analysis, or `None` to create the case |
| `case_notes` | Extra sentences appended to the scoring note in the case description, for scenario-specific caveats |

A scenario that does not rely on MISP at all can instead implement the minimal `BaseAnalyzer` interface directly, defining `alert_type`, `schema` and `analyze()`, and returning an `AnalysisResult` from `decipher/models.py`.

For further reference, see `decipher/analyzers/scenario_analyzer.py`, along with its subclasses `SuspiciousLoginAnalyzer` and `NetworkScanningAnalyzer`.

<br/>

[Back](/docs/manual/decipher/analyzers.md)
