"""
CTI Severity Scoring System
============================
Computes a severity score [0, 1] for MISP threat intelligence events and attributes.

Score = Severity * Confidence

Where:
    Severity   = min(1.0, threat_level * tags_multiplier)
    Confidence = 0.5 × C_analysis + 0.5 × c_evidence

C_attr = w * C_sightings + w * C_admiralty

Aggregation across attributes and events uses Noisy-OR:
    c_evidence = 1 - ∏(1 - C_attr_i)
    Score_aggregate = 1 - ∏(1 - score_i)

Three entry points mirror the MISP data hierarchy:

    score_attribute(attr, event): scores a single attribute within an event context
    score_event(event): aggregates attribute scores into an event score
    score_events(events): aggregates event scores into a final score
"""

import math
from functools import reduce

from decipher.scoringengine.datamodels import (
	AdmiraltyTags, AnalysisStage, AttributeBreakdown, AttributeData, EventData, EventScoreResult, FinalScoreResult, Sightings
)
import decipher.scoringengine.factors as config


def score_attribute(
    attr: AttributeData,
    cfg: config.ScoringConfig,
    event_admiralty: AdmiraltyTags | None = None,
) -> AttributeBreakdown:
    """
    Compute the empirical attribute confidence for a single MISP attribute.

    Args:
        attr:            The attribute to score.
        event_admiralty: Event-level Admiralty tags used as a fallback when
                         the attribute carries no Admiralty tags of its own.

    Returns:
        AttributeBreakdown — the attribute-tier confidence breakdown 
        including the final value for inspection.
    """
    resolved = resolve_admiralty(attr.admiralty, event_admiralty or AdmiraltyTags())
    breakdown = attribute_confidence(attr.sightings, resolved, cfg)
    return breakdown


def score_event(event: EventData, cfg: config.ScoringConfig) -> EventScoreResult:
    """
    Compute the aggregated score for a MISP event.

    Severity and analysis confidence are computed once from event-level fields
    (copied onto each attribute by the ingestion layer). Per-attribute empirical
    confidences are aggregated via Noisy-OR, then combined with the analysis
    confidence at event level.

    Args:
        event: The event to score. Must contain at least one attribute.

    Returns:
        An EventScoreResult with the final score and all intermediate components.
    """
    # Attribute tier — empirical confidence per attribute
    breakdowns = [
        score_attribute(attr, cfg, event_admiralty=event.admiralty)
        for attr in event.attributes
    ]
    c_evidence  = noisy_or([a.c_attr for a in breakdowns])

    # Event tier — use event-level fields
    sev, tl, mm  = _compute_severity(event.threat_level, event.has_mitre_tags, cfg)
    ca           = _compute_c_analysis(event.analysis, cfg)
    confidence   = _compute_event_confidence(ca, c_evidence, cfg)

    return EventScoreResult(
        event_id=event.id,
        score=sev * confidence,
        severity=sev,
        threat_level_value=tl,
        tags_multiplier=mm,
        c_analysis=ca,
        c_evidence=c_evidence,
        confidence=confidence,
        attribute_breakdowns=breakdowns,
    )


def score_events(events: list[EventData]) -> FinalScoreResult:
    """
    Compute the final aggregated score across multiple MISP events.

    Event scores are aggregated via Noisy-OR.

    Args:
        events: The list of events to score. Each must contain at least one
                attribute.

    Returns:
        A FinalScoreResult with the final score and per-event results.
    """
    if not events:
        return FinalScoreResult(score=0.0, event_results=())
    
    cfg = config.load_scoring_config()
    event_results = tuple(score_event(e, cfg) for e in events)
    return FinalScoreResult(
        score=noisy_or([r.score for r in event_results]),
        event_results=event_results,
    )


# Partial scoring functions

def _compute_severity(threat_level: config.ThreatLevel, has_mitre_tags: bool, cfg: config.ScoringConfig) -> tuple[float, float, float]:
    """
    Compute severity from threat level and MITRE tag presence.

    Returns (severity, threat_level_value, tags_multiplier).
    min(1.0, ...) keeps the result bounded when the multiplier is applied.
    """
    tl_value   = cfg.threat_level_values[threat_level]
    tags_mult = cfg.tags_multiplier if has_mitre_tags else 1.0
    return min(1.0, tl_value * tags_mult), tl_value, tags_mult

def _compute_c_analysis(stage: AnalysisStage, cfg: config.ScoringConfig) -> float:
    """Confidence contribution from the event analysis stage."""
    return cfg.analysis_stage_values[stage]

def _compute_c_sightings(sightings: Sightings) -> float:
    """
    Confidence contribution from sightings via a rescaled Beta posterior.

    Raw posterior mean:  P = (TP + 1) / (TP + FP + 2)
    Rescaled to [0, 1]:  C = max(0, 2P - 1)

    Zero sightings → 0.0; strong true positives → approaches 1.0.
    """
    p = (sightings.true_positives + 1) / (sightings.true_positives + sightings.false_positives + 2)
    return max(0, 2 * p - 1)

def _compute_c_admiralty(tags: AdmiraltyTags, cfg: config.ScoringConfig) -> float:
    """
    Confidence contribution from Admiralty scale tags.

    Absent tags map to 0.0. Geometric mean ensures that weakness in either
    dimension (source reliability or information credibility) suppresses the
    combined result — neither axis can compensate for the other.
    """
    sr = cfg.source_reliability_values[tags.source_reliability] if tags.source_reliability is not None else 0.0
    ic = cfg.info_credibility_values[tags.info_credibility]     if tags.info_credibility   is not None else 0.0
    return math.sqrt(sr * ic)

def resolve_admiralty(attr: AdmiraltyTags, event: AdmiraltyTags) -> AdmiraltyTags:
    """
    Merge Admiralty tags with attribute-level taking precedence.

    Falls back to event-level only when the attribute tag is absent (None).
    """
    return AdmiraltyTags(
        source_reliability=attr.source_reliability or event.source_reliability,
        info_credibility=attr.info_credibility     or event.info_credibility,
    )

def attribute_confidence(sightings: Sightings, admiralty: AdmiraltyTags, cfg: config.ScoringConfig) -> AttributeBreakdown:
    """
    Compute the attribute-tier confidence from sightings and Admiralty tags.

    Returns an AttributeBreakdown with all intermediate values.
    """
    cs = _compute_c_sightings(sightings)
    ca = _compute_c_admiralty(admiralty, cfg)
    return AttributeBreakdown(
        c_sightings=cs,
        c_admiralty=ca,
        c_attr=cfg.w_sightings * cs + cfg.w_admiralty * ca,
    )

def _compute_event_confidence(c_analysis_value: float, c_evidence_value: float, cfg: config.ScoringConfig) -> float:
    """
    Combine event-level analyst judgment with aggregated empirical confidence.

    Weighted sum rather than product ensures graceful degradation when one
    stream is absent.
    """
    return cfg.w_analysis * c_analysis_value + cfg.w_empirical * c_evidence_value


def noisy_or(values: list[float]) -> float:
    """
    Noisy-OR aggregation: 1 - ∏(1 - v_i)

    Compounds independent evidence streams: each additional confirmed signal
    pushes the aggregate upward. A single high-confidence signal can drive
    the aggregate near 1. Empty input returns 0.0.
    """
    if not values:
        return 0.0
    return 1.0 - reduce(lambda acc, v: acc * (1.0 - v), values, 1.0)