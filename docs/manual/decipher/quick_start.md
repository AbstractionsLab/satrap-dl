# Getting Started

This guide will help you perform your first analysis and incident creation using the DECIPHER's REST API after the service is deployed and running.

## Prerequisites

- DECIPHER API service running on `http://localhost:8000` (see [Installation](/docs/manual/decipher/installation.md))
- `curl` command-line tool or a REST client

## DECIPHER REST API operations

### Retrieve service version and identification details

Check identification details of the DECIPHER REST service at the root endpoint:

```bash
curl http://localhost:8000
```

The response lists the API version and the paths of the documentation, health and analyzer endpoints:

```json
{
  "service": "DECIPHER Analysis API",
  "version": "v1",
  "docs": "/docs",
  "redoc": "/redoc",
  "health": "/health",
  "analyzers": "/api/v1/analyzers"
}
```

### Verify service health

Check that the DECIPHER service is running and healthy:

```bash
curl http://localhost:8000/health
```

Expected response:

```json
{
  "version": "v1",
  "status": "ok",
  "service": "decipher-api",
  "analyzers_loaded": 2,
  "available_types": ["suspicious_login", "suspicious_nt_scanning"],
  "logging_level": "INFO"
}
```

`available_types` lists the threat scenarios that the running service can analyze, and `logging_level` reflects the level currently in force.

### List available analyzers

Get the list of threat scenarios that DECIPHER can analyze:

```bash
curl http://localhost:8000/api/v1/analyzers
```

This returns all available analyzers with their descriptions and required fields.

### Analyze an alert

This is the main service of the DECIPHER REST API; it computes a severity-confidence score in [0,1] of a threat alert, relying on CTI. For instance,

```bash
curl -X POST http://localhost:8000/api/v1/analyze/suspicious_login \
  -H "Content-Type: application/json" \
  -d '{
    "username": "admin",
    "target_host": "10.0.0.1",
    "src_ips": ["185.220.100.1"],
    "timestamp": "2026-01-31T10:00:00Z"
  }'
```

The response includes detailed analysis findings and errors. Optionally (configured in the runtime settings), a case containing the analysis report and a priority tag can be automatically created in Flowintel.

Two errors are worth recognizing when integrating the endpoint:

- **404** — the alert type in the path is not registered. The message lists the registered types.
- **422** — the request body does not match the schema of that alert type. The message lists the offending fields.

See the [Analyzers](/docs/manual/decipher/analyzers.md) page for details on the response, supported threat scenarios, and how to create custom analyzers for additional scenarios.

### Create an incident case

Use the incident endpoint to create a prioritized incident case in Flowintel:

```bash
curl -X POST http://localhost:8000/api/v1/incident \
  -H "Content-Type: application/json" \
  -d '{
    "priority_level": "high",
    "title": "Suspicious login from external IP",
    "description": {
      "system_affected": "Production database server",
      "detected_by": "Wazuh SIEM",
      "threat_actor": "APT28",
      "iocs": ["185.220.100.1"]
    }
  }'
```

A prioritized case is created in Flowintel with the the given priority tag and the description. This endpoint is intended to be used for automating case creation as part of tool processes (e.g. as part of an automated response workflow in a SIEM).

Request fields:

- `priority_level` (required): a grade of the MISP `priority-level` taxonomy, given with or without the taxonomy prefix. Accepted grades are `baseline-negligible`, `baseline-minor`, `low`, `medium`, `high`, `severe` and `emergency`. Any other value is rejected with a 422 response listing the valid ones.
- `title` (optional): case title. The service prefixes it with `[DECIPHER]` and appends a timestamp; a default title is used when the field is absent.
- `template_id` (optional): identifier of a Flowintel case template, which must be a positive integer.
- `description` (optional): key-value pairs rendered into the case description. Values that are themselves objects are rendered as nested sections, up to two levels.

**Note:** A `template_id` is currently only verified to exist in Flowintel; the case is always created without a template because the Flowintel API ignores tags when creating a case from one, which would drop the priority tag.

### View the API documentation

DECIPHER provides interactive API documentation. Open your browser and navigate to:

```
http://localhost:8000/docs
```

This is a Swagger UI interface where you can:

- Browse all available endpoints
- View request/response schemas
- Try endpoints directly from the browser
- See example requests and responses


## Troubleshooting

**Service not responding**

```bash
curl -v http://localhost:8000/health
```

Check service logs:

```bash
docker logs decipher-api-<x> -f
```

**MISP enrichment not working**

Ensure MISP is correctly configured in `decipher-settings.yaml` and the service is running. Then, in`decipher-runtime-cfg.yaml` ensure that MISP enrichment is enabled:

```yaml
analysis:
  enable_misp_search: true
```

**Configuration changes not taking effect**

Verify that the correct configuration file at `/config` is being edited and that the files are correctly named (see [Configuration](/docs/manual/decipher/configuration.md) for details).

Changing the MISP credentials or logging settings require a container restart to take effect:

```bash
docker restart decipher-api-<x>
```

<br/>

[Back to home](/docs/manual/decipher/README.md)
