# Analyzers

Analyzers are threat scenario handlers that implement the logic for analyzing and scoring specific types of security incidents relying on existing CTI. Each analyzer performs enrichment, scoring, and generates analysis reports tailored to its threat scenario.

The overall analysis process consists of:

1. **IOC search in MISP** — Queries MISP for threat intelligence on the scenario IOCs
2. **Scenario-specific analysis** — Optional extra steps whose output is added to the report, such as the lookup for known scanning sources reported by the suspicious web scanning analyzer
3. **Severity scoring** — Calculates threat severity based on:
   - Event threat level classification
   - Presence of tags identifying threats (e.g., MITRE ATT&CK techniques)
   - Analysis completion stage
   - Sightings and admiralty tags
4. **Case creation** — Creates security case in Flowintel if enabled in the configuration

The runtime configuration is reloaded at every call, so a change to `enable_misp_search`, `enable_case_creation`, the MISP search parameters or the priority thresholds applies to the next analysis without restarting the service.

## Analysis result

Every call to an `/analyze` endpoint returns the same structure, regardless of the threat scenario. The four top-level fields answer: what was analyzed, how severe it is, why, and where to follow up.

| Field | Type | How to read it |
|---|---|---|
| `analyzed_scenario` | string | The alert type that was analyzed, echoed back from the request |
| `severity` | number in [0, 1] | The CTI severity score of the alert. `0` means no supporting threat intelligence was found, not that the alert is harmless |
| `report` | dict | The evidence behind the score, plus notes on the analysis run |
| `created_case` | dict | The `id` and `link` of the Flowintel case (optionally) opened after the analysis. An `id` of `0` and an empty `link` mean no case was created |

### Reading the report

The `report` object carries the following keys. Analyzers may add their own, for example `identified-scanners` in the [suspicious web scanning analyzer](./web_scn_analyzer.md).

| Key | How to read it |
|---|---|
| `misp_available` | `"True"` or `"False"` as a string. `"False"` means the score was computed without any MISP intelligence, either because the search is disabled in the configuration or because MISP could not be reached |
| `misp_events_found` | IDs of the MISP events that matched at least one of the alert IOCs. Use them to open the events in MISP and read the full intelligence. The key is absent when the IOC search did not run |
| `score_breakdown` | One entry per matched MISP event, showing how each contributed to the score. Empty when nothing matched |
| `log_summary` | Notes about the analysis execution, including any failure that was handled gracefully, for example an unreachable MISP or a failed case creation. Worth checking whenever a score looks lower than expected |

When `enable_misp_search` is off in the runtime configuration, the analysis stops before any lookup and the report reduces to `misp_available` set to `"False"` and a `log_summary` stating that the search is disabled. Neither `misp_events_found` nor `score_breakdown` is present, and the severity is `0`.

### Reading the score breakdown

Each entry in `score_breakdown` explains one MISP event. Its score is the product of **severity**, how dangerous the intelligence says the threat is, and **confidence**, how much the intelligence can be trusted.

| Field | How to read it |
|---|---|
| `event_id` | The MISP event this entry refers to |
| `score` | This event's contribution, `severity * confidence` |
| `severity` | Threat severity, `threat_level_value * tags_multiplier`, capped at 1.0. Note that this is the severity of a single event, not the `severity` reported at the top level of the response |
| `threat_level_value` | Derived from the threat level assigned to the event in MISP |
| `tags_multiplier` | Raised above 1.0 when the event carries tags that identify a threat, such as a MITRE ATT&CK attack pattern or intrusion set |
| `confidence` | Weighted combination of `c_analysis` and `c_evidence` |
| `c_analysis` | Analyst judgment: how far the MISP event's investigation has progressed |
| `c_evidence` | Empirical evidence: the combined confidence of all matched attributes |
| `attribute_breakdowns` | Per attribute, `c_sightings` from the true and false positive sightings, `c_admiralty` from the Admiralty scale tags, and `c_attr` combining the two |

An absent signal counts as zero rather than neutral: an event with no Admiralty tags, no sightings, or an undefined threat level lowers the score instead of leaving it unchanged. Conversely, evidence accumulates, so several matched events or attributes push the score higher than any of them would alone.

### From score to priority

The score determines the priority tag of the created case, following the configured priority thresholds. A score below every threshold still produces a case, tagged as `priority-level:baseline-minor`, when case creation is enabled. Both the thresholds and the weights of the scoring model are documented in the [configuration reference](./configuration.md).

An analyzer may additionally suppress case creation for a given analysis, in which case the reason is appended to `log_summary` and `created_case` keeps its zero id. The [suspicious web scanning analyzer](./web_scn_analyzer.md#case-creation) uses this to avoid opening cases with no supporting evidence.

See the pages of the built-in analyzers below for a complete example response.

## Built-in analyzers
DECIPHER ships with the following built-in analyzers:

- [Suspicious login](./susp_login_analyzer.md)
- [Suspicious web scanning](./web_scn_analyzer.md)

## Custom analyzers

The design of the analyzer package is extensible and flexible to support new analyzers. Follow this guide to [add your own analyzers](./custom_analyzer.md).

## Testing analyzers

DECIPHER includes unit tests and test runners for validating analyzers. See the `tests/decipher/` folder for example unit tests, test scripts and test data.

<br/>

[Back to home](/docs/manual/decipher/README.md)
