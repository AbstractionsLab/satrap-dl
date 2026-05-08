# Configuration

The DECIPHER REST service uses three YAML configuration files located in the `/config/` folder at the project root. Each file serves a specific purpose and has different reload requirements.

## Configuration files overview

| File | Purpose | Reload | 
|------|---------|--------|
| `decipher-settings.yaml` | Service settings (logging, MISP, Flowintel) | Requires restart |
| `decipher-runtime-cfg.yaml` | Runtime options (MISP search flags, service toggles) | No restart |
| `decipher-scoring-cfg.yaml` | Scoring configuration (threat scoring weights and factors) | No restart |

This allows operators to:

- Deploy once and adjust behavior without restart
- Run several analysis tests by changing scoring weights and features on the fly
- Quickly disable failing integrations (MISP, Flowintel)
- Experiment with different analyzer configurations

## Setup

1. Create a copy of the template files n the `/config` folder, removing the `.template` suffix:

    ```sh
    cp config/decipher-settings.template.yaml config/decipher-settings.yaml
    cp config/decipher-runtime-cfg.template.yaml config/decipher-runtime-cfg.yaml
    cp config/decipher-scoring-cfg.template.yaml config/decipher-scoring-cfg.yaml
    ```

2. Update each file with your environment settings.

## decipher-settings.yaml

Service-level configuration for logging and integrations. Changes to this file require service restart.

### Logging

```yaml
logging:
  level: INFO          # DEBUG, INFO, WARNING, ERROR
```

- **level**: Logging verbosity (case-insensitive). Use `DEBUG` for troubleshooting, `INFO` for production.

### MISP integration

```yaml
misp:
  url: "http://localhost:80"
  api_key: "your-misp-api-key"
  verify_ssl: true
```

- **url**: MISP instance URL.
- **api_key**: MISP API key for authentication.
- **verify_ssl**: SSL certificates verification. By default this parameter is set to `false` for convenience in development or testing environments. For production environments, it is recommended to set this parameter to `true` and ensure that the MISP instance has valid SSL certificates.

### Flowintel integration

```yaml
flowintel:
  base_url: "http://localhost:7006/api"
  api_key: "your-flowintel-api-key"
  case_url: "http://alt_host:7006/"
```

- **base_url**: Flowintel instance URL.
- **api_key**: Flowintel API key for authentication.
- **case_url**: If set, this URL is used for creating links of the form `<case_url>/case/<case_id>` to access the created cases. If not set, the `base_url` (without '/api') is used to create links of the form `<base_url>/cases/<case_id>`. This parameter is useful for instance when using forwarding ports to access a remote Flowintel instance.

## decipher-runtime-cfg.yaml

Runtime options that control settings for the analysis endpoint. Changes to these settings take effect without restarting the service.

### Analysis options

* **enable_misp_search**: Whether to enable the use of a MISP instance for searching IOCs (default: `true`). This parameter is intended for testing purposes, allowing to disable MISP search when a MISP instance is not available.
* **enable_case_creation**: Whether to enable Flowintel case creation in the `/analyze` endpoint (default: `false`). Note that this setting is independent from the `/incident` endpoint, which always creates a case in Flowintel if the Flowintel integration is configured in `decipher-settings.yaml`.

### MISP search options
* **limit**: Maximum number of attributes retrieved in a MISP search(default: `1000`)
* **event_timestamp**: Filter for events modified/created after a timestamp, e.g. `7d`, `5h`, `15m` (default: `10d`). This parameter is used to limit the scope of MISP searches to recent events, which are more likely to be relevant for active threats.

### Priority thresholds 

Score thresholds for assigning priority levels to cases created in Flowintel as part of the `/analyze` endpoint. Cases created via the `/incident` endpoint are assigned the priority tag specified in the request body.

* **severe**: Score threshold for severe priority; score >= 0.85 (default: `0.85`)
* **high**: Score threshold for high priority; score >= 0.6 (default: `0.6`)
* **medium**: Score threshold for medium priority; score >= 0.4 (default: `0.4`)
* **low**: Score threshold for low priority; score >= 0.2 (default: `0.2`)

### Common use cases

**Disable MISP search for testing**

```yaml
analysis:
  enable_misp_search: false
```

**Enable automatic case creation in Flowintel**

```yaml
analysis:
  enable_case_creation: true
priority_thresholds:
  severe: 0.85
  high: 0.6
```

**Adjust MISP search to retrieve fewer attributes**

```yaml
misp_search:
  limit: 500
  event_timestamp: 30d
```

## decipher-scoring-cfg.yaml

Threat scoring parameters that control how severity and confidence scores are computed. Changes to this file take effect immediately without restarting the service.

The scoring engine computes two independent values: **severity** (how dangerous the threat is) and **confidence** (how much to trust the assessment) that are aggregated into a final score in the range [0, 1].

Details about the scoring computation can be found in the [technical specifications](https://abstractionslab.github.io/satrap-dl/traceability/SRS.html#SRS-053) on the traceability website.

### Severity computation

Severity is derived from the MISP event threat level and threat-indicating tags (e.g. `mitre-attack-pattern`).

**Threat level mapping**

```yaml
threat_level:
  high: 1.00
  medium: 0.50
  low: 0.25
  undefined: 0.00
```

Map MISP event threat levels to severity scores. Undefined threat levels map to 0 (zero-by-default).

**Tags multiplier**

```yaml
tags_multiplier: 1.3
```

Applied when threat-indicating tags are present in the event or any attribute. The final severity is computed as:

```
Severity = min(1.0, threat_level × tags_multiplier)
```

Example: A `medium` threat with threat tags yields `0.50 × 1.3 = 0.65` severity.

### Confidence computation

Confidence is assembled from analyst judgment (analysis stage) and empirical evidence (sightings and Admiralty scale).

**Confidence weights**

Determine the impact of each aspect on the final confidence score. The sum of the weights must be 1.

```yaml
confidence_weights:
  analysis: 0.5      # Analyst assessment of investigation completeness
  empirical: 0.5     # Evidence-based signals (sightings + Admiralty)
```

**Analysis stage mapping (MISP event "analysis" field)**

```yaml
analysis_stage:
  initial: 0.2       # Early triage
  ongoing: 0.5       # Investigation in progress
  completed: 1.0     # Fully analyzed
```

**Attribute-level evidence weights**

```yaml
attribute_weights:
  sightings: 0.6     # Weight for sighting-based confidence
  admiralty: 0.4     # Weight for Admiralty scale assessment
```


### Customizing the scoring model

The default values are assigned as a model. After initial deployment of DECIPHER, **analysts are expected to** observe a meaningful sample of scored events and **adjust the weights** used throughout the computation as per these observations and their own use of MISP tags and features.

For instance:

1. **Increase `tags_multiplier`** to make threat-indicating tags more impactful.
2. **Adjust `threat_level` values** to match your environment's risk tolerance.
3. **Rebalance confidence weights** (e.g., increase `empirical` if you trust sightings more than analyst assessment).
4. **Modify Admiralty mappings** to reflect your source reliability standards.

Example: To trust sightings and admiralty more heavily than analyst judgment:

```yaml
confidence_weights:
  analysis: 0.4      # Decreased from 0.5
  empirical: 0.6     # Increased from 0.5
```

## Additional configuration
See the [deployment README](/deployment/README.md) for infrastructure-level configuration.

<br/>

[Back to home](/docs/manual/decipher/README.md)
