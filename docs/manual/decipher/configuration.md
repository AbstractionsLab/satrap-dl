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

The two reloadable files are re-read whenever their modification time changes, so saving an edit is enough for it to apply to the next analysis request.

## REST service setup

1. Create a copy of the template files in the `/config` folder, removing the `.template` suffix:

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
  level: "info"               # debug, info, warning, error
  enable_file_logging: false
```

- **level**: Logging verbosity (case-insensitive). Use `debug` for troubleshooting, `info` for production.
- **enable_file_logging**: Whether to write the logs to a file under `logs/decipher/` in addition to standard output (default: `false`). In the containerized deployment, the log directory needs a writable bind mount for this option to work; see the [deployment reference](./deployment.md#security-of-the-decipher-api-container).

### MISP integration

```yaml
misp:
  url: "https://localhost"
  api_key: "your-misp-api-key"
  verify_ssl: false
  timeout: 5
```

- **url**: MISP instance URL.
- **api_key**: MISP API key for authentication.
- **verify_ssl**: SSL certificates verification. By default this parameter is set to `false` for convenience in development or testing environments. For production environments, it is recommended to set this parameter to `true` and ensure that the MISP instance has valid SSL certificates.
- **timeout**: Connection timeout in seconds for the requests sent to MISP (default: `5`).

The four MISP settings can also be provided through the environment variables `MISP_URL`, `MISP_API_KEY`, `MISP_VERIFY_SSL` and `MISP_TIMEOUT`, which take precedence over the values in the file. If the URL or the API key resolves to an empty value, the service starts with a warning and every analysis returns a severity of `0`.

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

* **enable_misp_search**: Whether to enable the use of a MISP instance for searching IOCs (`true` in the shipped template). This parameter is intended for testing purposes, allowing to disable MISP search when a MISP instance is not available. When it is off, the analysis returns a severity of `0` with a report stating that the search is disabled, without contacting MISP.
* **enable_case_creation**: Whether to enable Flowintel case creation in the `/analyze` endpoint (`false` in the shipped template). Note that this setting is independent from the `/incident` endpoint, which always creates a case in Flowintel if the Flowintel integration is configured in `decipher-settings.yaml`.

Both options fall back to `false` when the key, or the whole file, is missing. The file is read again at every analysis request, so edits take effect on the next call.

### MISP search options
* **limit**: Maximum number of attributes retrieved in a MISP search(default: `1000`)
* **event_timestamp**: Filter for events modified/created after a timestamp, e.g. `7d`, `5h`, `15m` (default: `7d`). This parameter is used to limit the scope of MISP searches to recent events, which are more likely to be relevant for active threats.
* **enforce_warninglist**: Whether to exclude attributes found in an enabled MISP warninglist from the search results (default: `true`). Excluded attributes contribute no evidence to the severity score. The [suspicious web scanning analyzer](./web_scn_analyzer.md#identified-scanners) overrides this to `false` by design, since it reports warninglist matches as analyst context without altering the score.
* **max_values_per_type**: Maximum number of IOC values searched per attribute type (default: `50`). All the values of an attribute type are searched in a single request, so this setting bounds the size of each request when an alert reports a large number of indicators, for example a long list of probed paths. Values beyond the limit are reported in the logs and left out of the search.

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

Severity is derived from the MISP event threat level and threat-indicating tags.

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

Applied when the matched MISP event carries a tag identifying a threat, that is, a tag whose name contains `mitre-attack-pattern` or `mitre-intrusion-set`. Only tags at the event level are considered. The final severity is computed as:

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

The sightings contribution is computed from the true and false positive sightings recorded on the attribute and needs no configuration.

**Admiralty scale mappings**

Grades of the [Admiralty scale](https://www.misp-project.org/taxonomies.html) taxonomy, mapped to confidence factors. Source reliability runs from `a` to `g`, information credibility from `1` to `6`.

```yaml
admiralty_source_reliability:
  a: 1.00  # Completely reliable
  b: 0.80  # Usually reliable
  c: 0.60  # Fairly reliable
  d: 0.40  # Not usually reliable
  e: 0.20  # Unreliable
  f: 0.10  # Cannot be judged / reliability unknown
  g: 0.00  # Deliberately misleading

admiralty_info_credibility:
  "1": 1.00  # Confirmed by other sources
  "2": 0.80  # Probably true
  "3": 0.60  # Possibly true
  "4": 0.40  # Doubtful
  "5": 0.20  # Improbable
  "6": 0.00  # Truth cannot be judged
```

The two grades are combined with a geometric mean, so a weak grade on either axis suppresses the result and cannot be compensated by the other. Admiralty tags set on an attribute take precedence over the ones set on its event; an absent tag counts as `0.0`, not as a neutral value.

**Unused parameters**

The `impacted_sector` block present in the template is not read by the scoring engine. It is kept as a placeholder for a future refinement of the model.

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

## MISP instance setup

DECIPHER relies on specific MISP tags to determine the confidence in the score and to create simulation events for testing.

We recommend to enable the following set of taxonomies in MISP and make use of them in your events to benefit from the DECIPHER features.

 | Taxonomy | Used by |
 |---|---|
 | admiralty-scale | scoring engine, confidence computation |
 | priority-level | case management, priority tags of the created cases |
 | tlp | tests |
 | type | tests |

 Login with an Admin user into MISP and go to the "Event actions" → "List taxonomies" menu.

The severity multiplier is driven by the MITRE ATT&CK galaxies instead of a taxonomy: an event tagged with `misp-galaxy:mitre-attack-pattern` or `misp-galaxy:mitre-intrusion-set` receives the `tags_multiplier`.

The analyzers also make use of MISP warninglists, which are disabled in a fresh instance. See [MISP warninglists](./web_scn_analyzer.md#misp-warninglists) for the setup tool that enables the ones used by DECIPHER.


## Additional configuration
See the [deployment README](/deployment/README.md) for infrastructure-level configuration.

<br/>

[Back to home](/docs/manual/decipher/README.md)
