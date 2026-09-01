# Suspicious login analyzer

Analyzes potentially malicious login attempts to a system.

**Threat scenario:** A user account is accessed from an unusual location, multiple failed attempts, or known malicious source IP.

**Endpoint:** `POST /api/v1/analyze/suspicious_login`

**Required fields:**

- `username` (string): Username attempting login
- `target_host` (string): Target host IP or hostname
- `src_ips` (array of strings): Source IP address(es)
- `timestamp` (string): ISO 8601 formatted timestamp

**Searched IOCs:**

All four fields are searched in MISP, mapped to the following attribute types:

| Alert field | MISP attribute type |
|---|---|
| `src_ips` | `ip-src` |
| `target_host` | `ip-dst` |
| `username` | `target-user` |

The search uses the MISP parameters set in the [runtime configuration](./configuration.md#decipher-runtime-cfgyaml) as they are, so attributes hitting an enabled warninglist are excluded from the results when `enforce_warninglist` is on.

**Case creation:** This analyzer creates a case for every analyzed alert when `enable_case_creation` is set in the configuration, including alerts scored 0. The score only determines the priority tag.

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

<br/>

[Back](/docs/manual/decipher/analyzers.md)