# Analyzers

Analyzers are pluggable threat scenario handlers that implement the logic for detecting and analyzing specific types of security incidents. Each analyzer performs enrichment, scoring, and generates analysis reports tailored to its threat scenario.

## Available analyzers

### Suspicious login analyzer

Detects and analyzes potentially malicious login attempts.

**Threat scenario:** A user account is accessed from an unusual location, multiple failed attempts, or known malicious source IP.

**Endpoint:** `POST /api/v1/analyze/suspicious_login`

**Required fields:**

- `username` (string): Username attempting login
- `target_host` (string): Target host IP or hostname
- `src_ips` (array of strings): Source IP address(es)
- `timestamp` (string): ISO 8601 formatted timestamp


**Analysis process:**

1. **IOC search in MISP** — Queries MISP for threat intelligence on source IPs, target host, and username
2. **Event discovery** — Retrieves MISP events containing matching indicators of compromise
3. **Severity scoring** — Calculates threat severity based on:
   - Event threat level classification
   - Presence of MITRE ATT&CK tags (technique mapping)
   - Analysis completion stage
   - Sightings and admiralty tags
4. **Case creation** — Creates security case in Flowintel if enabled in the configuration

**Example request:**

```bash
curl -X POST http://localhost:8000/api/v1/analyze/suspicious_login \
  -H "Content-Type: application/json" \
  -d '{
    "username": "admin",
    "target_host": "100.43.11.26",
    "src_ips": ["203.0.113.1"],
    "timestamp": "2026-01-31T10:00:00Z"
  }'
```

**Example response:**

```json
{
  "analyzed_scenario": "suspicious_login",
  "severity": 0.0,
  "report": {
    "log_summary": [
      "Case creation for analysis disabled in configuration."
    ],
    "misp_available": "True",
	"misp_events_found":[],
    "score_breakdown": []
  },
  "created_case": {
    "id": 0,
    "link": ""
  }
}
```

## Creating a custom analyzer

The analyzer framework is extensible. New analyzers can be added by implementing the `BaseAnalyzer` interface.


1. Create a new file in `decipher/analyzers/` with the following structure:

```python
from decipher.analyzers.base import BaseAnalyzer, AnalysisResult
from decipher.analyzers.registry import AnalyzerRegistry
from pydantic import BaseModel

class NewScenarioAlert(BaseModel):
    """Define your alert schema here"""
    pass

@AnalyzerRegistry.register
class NewScenarioAnalyzer(BaseAnalyzer):
    """Brief description of what this analyzer does"""
    alert_type = "alert_type_name"
    schema = NewScenarioAlert
    
    def analyze(self, alert: BaseModel) -> AnalysisResult:
        """Analyze the alert and return a result"""

        # Your implementation here

        return AnalysisResult(
            analyzed_scenario=self.alert_type,
            severity=0, # example severity score
            report="...",
            created_case=None
        )
```

2. Import your new analyzer in `decipher/analyzers/__init__.py` for automatic registration:

```python
from . import new_scenario_analyzer # module name
```

3. Inherit from `MISPEnrichmentMixin` for MISP enrichment functionality:

```python
from decipher.analyzers.mixins.misp_enrichment import MISPEnrichmentMixin

@AnalyzerRegistry.register
class NewScenarioAnalyzer(BaseAnalyzer, MISPEnrichmentMixin):
    # ... rest of implementation
    
    def analyze(self, alert):
		...
        # Enrich with MISP
        ioc_mapping = {...}  # Map alert fields to MISP IOC types
        enrichment = self.enrich_iocs_with_misp(ioc_mapping)

		...
        
```

4. To load the new analyzer, make sure to rebuild the image of the DECIPHER API before starting the service.

For further reference, see the existing `SuspiciousLoginAnalyzer` implementation in `decipher/analyzers/suspicious_login.py` for a complete example of an analyzer with MISP enrichment and scoring logic.


## Testing analyzers

DECIPHER includes unit tests and test runners for validating analyzers. See the `tests/decipher/` folder for example unit tests, test scripts and test data.

<br/>

[Back to home](/docs/manual/decipher/README.md)
