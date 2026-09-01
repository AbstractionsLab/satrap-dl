# Suspicious web scanning analyzer

Analyzes suspicious network and web scanning activity against exposed services.

**Threat scenario:** A source probes a host for exploitable endpoints, for example with a scanning tool, an unusual sequence of requested URLs, or uncommon HTTP methods.

**Endpoint:** `POST /api/v1/analyze/suspicious_nt_scanning`

**Required fields:**

- `src_ip` (array of strings): Source IP address(es) of the scanning activity
- `uri` (array of strings): Requested (probed) URI/path(s) at the target host
- `user_agents` (array of strings): Observed `User-Agent` string(s)

**Optional fields:**

- `http_method` (array of strings): Requested HTTP method(s)
- `target_host` (string): Name or IP address (with optional port) of the scanned endpoint. Context only, never searched as an IOC
- `timestamp` (string): ISO 8601 formatted timestamp of the detected activity
- `detection_chain` (array of pairs): Chronologically ordered `[rule_id, rule_name]` pairs that triggered the alert

**Searched IOCs:**

The alert fields are mapped to MISP attribute types as follows. Fields absent from the mapping are not searched.

| Alert field | MISP attribute type |
|---|---|
| `src_ip` | `ip-src` |
| `uri` | `uri` |
| `user_agents` | `user-agent` |
| `http_method` | `http-method`, only when the field is present |

Unlike the other analyzers, this scenario searches MISP with `enforce_warninglist` forced to `false`, regardless of the value set in the [runtime configuration](./configuration.md#decipher-runtime-cfgyaml). See [Identified scanners](#identified-scanners) for the rationale.

**Example request:**

```bash
curl -X POST http://localhost:8000/api/v1/analyze/suspicious_nt_scanning \
  -H "Content-Type: application/json" \
  -d '{
    "src_ip": ["66.240.192.138"],
    "uri": ["/cgi-bin/.%2e/%2e%2e/bin/sh", "/actuator/env"],
    "user_agents": ["Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)"],
    "http_method": ["GET"],
    "target_host": "10.20.30.40:8080",
    "timestamp": "2026-08-25T03:02:11Z",
    "detection_chain": [[3001, "path traversal pattern"], [3002, "actuator endpoint probing"]]
  }'
```

**Example response:**

```json
{
  "analyzed_scenario": "suspicious_nt_scanning",
  "severity": 0.666595,
  "report": {
    "log_summary": [
      "Case creation for analysis disabled in configuration."
    ],
    "identified-scanners": [
      "66.240.192.138: ['List of known Shodan scanning IPs'];"
    ],
    "misp_available": "True",
    "misp_events_found": [
      412
    ],
    "score_breakdown": [
      {
        "event_id": 412,
        "score": 0.666595,
        "severity": 1.0,
        "confidence": 0.666595,
        "threat_level_value": 1.0,
        "tags_multiplier": 1.3,
        "c_analysis": 0.5,
        "c_evidence": 0.833189,
        "attribute_breakdowns": [
          {
            "c_sightings": 0,
            "c_admiralty": 0.6,
            "c_attr": 0.24
          },
          {
            "c_sightings": 0.5,
            "c_admiralty": 0.8,
            "c_attr": 0.62
          },
          {
            "c_sightings": 0,
            "c_admiralty": 0.6,
            "c_attr": 0.24
          },
          {
            "c_sightings": 0,
            "c_admiralty": 0.6,
            "c_attr": 0.24
          }
        ]
      }
    ]
  },
  "created_case": {
    "id": 0,
    "link": ""
  }
}
```

## Identified scanners

The `identified-scanners` field reports known and likely-legitimate scanning sources, identified by matching the alert source IP addresses with IPs in enabled MISP warninglists (see below) and the `scanning_ip` attribute of `research-scanner` objects.

The field appears empty when no source matches, and it is absent from the report in two cases: when the MISP IOC search is disabled in the configuration, and when the scanner lookup itself fails. In the latter case the reason is appended to `log_summary` and the rest of the analysis proceeds normally.

This field is intended as contextual information for the analyst and does not affect the severity-confidence score.

## Case creation

This analyzer suppresses case creation when the analysis found no evidence at all, that is, when the severity score is zero **and** `identified-scanners` is empty. The reason is recorded in `log_summary` and no case is created even if `enable_case_creation` is set in the configuration.

A zero score accompanied by a non-empty `identified-scanners` still produces a case, so that scanning activity from a source known to MISP reaches the analyst.

## MISP warninglists

[MISP warninglists](https://www.circl.lu/doc/misp/warninglists/) are lists of well-known indicators prone to be false positives, such as public DNS resolvers, CDN ranges or the address ranges of public scanning services.
Warninglists are disabled in a fresh MISP instance.

DECIPHER ships a convenient setup tool that enables a MISP administrator to enable/disable warninglists with a single command. A default set of warninglists used by the scanning analyzer (decipher/tools/wrnlst_defaults.py) is included along with the runner; we recommend modifying this list according to your needs.

From the SATRAP-DL dev environment:

```sh
python decipher/tools/warninglists_mgr.py enable
```

Alternatively, with the DECIPHER API service running:

```sh
docker exec decipher-api-1 \
  python -m decipher.tools.warninglists_mgr enable
```

### Admin requirements
The warninglists tool reads the MISP URL and API key from `config/decipher-settings.yaml`. Toggling a warninglist requires administrative privileges in MISP. If the key configured for the service belongs to a regular user, pass an administrator key for this command only:

```sh
docker exec decipher-api-1 \
  python -m decipher.tools.warninglists_mgr enable --api-key <admin-key>
```

### Examples

```sh
python -m decipher.tools.warninglists_mgr list
python -m decipher.tools.warninglists_mgr enable --names "Shodan IP Ranges Used for Scanning"
python -m decipher.tools.warninglists_mgr disable --ids 98 99
```

Warninglists are selected by name because IDs are assigned by each MISP instance and differ across installations. Use the `list` command to obtain the names and IDs of your instance.

<br/>

[Back](/docs/manual/decipher/analyzers.md)