from dataclasses import dataclass, field

from decipher.scoringengine.factors import AnalysisStage, InfoCredibility, SourceReliability, ThreatLevel


@dataclass(slots=True)
class Sightings:
    """True positive and false positive sighting counts from MISP."""
    true_positives: int = 0
    false_positives: int = 0

    def __post_init__(self) -> None:
        if self.true_positives < 0:
            raise ValueError(f"true_positives must be >= 0, got {self.true_positives}")
        if self.false_positives < 0:
            raise ValueError(f"false_positives must be >= 0, got {self.false_positives}")


@dataclass(slots=True)
class AdmiraltyTags:
    """
    Admiralty scale tags for an event or attribute.

    None indicates the tag is absent, which maps to a confidence
    contribution of 0.0 — absence is not treated as neutral.
    Attribute-level tags take precedence over event-level tags.
    """
    source_reliability: SourceReliability | None = None
    info_credibility: InfoCredibility | None = None


@dataclass(slots=True)
class AttributeData:
    """
    A single MISP attribute with all scoring-relevant fields.
    """
    value: str = ""
    type: str = ""
    sightings: Sightings = field(default_factory=Sightings)
    admiralty: AdmiraltyTags = field(default_factory=AdmiraltyTags)


@dataclass(slots=True)
class EventData:
    """
    A MISP event containing one or more attributes.
    """
    id: int
    threat_level: ThreatLevel = ThreatLevel.UNDEFINED
    analysis: AnalysisStage = AnalysisStage.INITIAL
    admiralty: AdmiraltyTags = field(default_factory=AdmiraltyTags)
    attributes: list[AttributeData] = field(default_factory=list)
    has_mitre_tags: bool = False

    def __post_init__(self) -> None:
        if not self.attributes:
            raise ValueError(
                "EventData must contain at least one attribute. "
                "The scoring workflow guarantees events are retrieved via "
                "attribute search results, so an empty attribute list is unexpected."
            )
        
    def __str__(self) -> str:
        sr    = self.admiralty.source_reliability.value if self.admiralty.source_reliability else "absent"
        ic    = self.admiralty.info_credibility.value   if self.admiralty.info_credibility   else "absent"
        return (
            f"EventData("
            f"id={self.id}, "
            f"threat={self.threat_level.value}, "
            f"analysis={self.analysis.value}, "
            f"has_mitre_threat_tags={self.has_mitre_tags}, "
            f"admiralty=({sr}/{ic}), "
            f"num_attributes={len(self.attributes)}"
            f")"
        )
    


# ---------------------------------------------------------------------------
# Score breakdown — for transparency, logging, and analyst inspection
# ---------------------------------------------------------------------------

@dataclass(frozen=True, slots=True)
class AttributeBreakdown:
    """
    Evidence-based confidence breakdown for a single attribute.

    Captures the attribute-tier signals only (sightings, Admiralty).
    Frozen to prevent mutation after computation.
    """
    c_sightings: float
    c_admiralty: float
    c_attr:      float   # weighted combination of the two above

    def __str__(self) -> str:
        return (
            f"c_attr={self.c_attr:.2f}"
            f" (sightings={self.c_sightings:.2f},"
            f" admiralty={self.c_admiralty:.2f})"
        )


@dataclass(frozen=True, slots=True)
class EventScoreResult:
    """
    Full score breakdown for a single MISP event.

    Frozen to prevent mutation after computation.
    """
    event_id:int
    score:                float
    severity:             float
    confidence:           float
    threat_level_value:   float
    tags_multiplier:     float
    c_analysis:           float
    c_evidence:          float   # Noisy-OR of per-attribute c_attr values
    attribute_breakdowns: list[AttributeBreakdown]

    def __str__(self) -> str:
        lines = [
            f"Event ID: {self.event_id}",
            f"Score:    {self.score:.3f}",
            f"├─ Severity:   {self.severity:.3f}"
            f"  (threat={self.threat_level_value:.2f},"
            f" tags_mult={self.tags_multiplier:.2f})",
            f"├─ Confidence: {self.confidence:.3f}",
            f"├─– Assessment:  {self.c_analysis:.3f}",
            f"└─– Evidence: {self.c_evidence:.3f}"
            f"  (From {len(self.attribute_breakdowns)} attribute(s))",
        ]
        for i, ab in enumerate(self.attribute_breakdowns, start=1):
            lines.append(f"...... Attr {i}: {ab}")
        return "\n".join(lines)


@dataclass(frozen=True, slots=True)
class FinalScoreResult:
    """Aggregated score across multiple MISP events."""
    score:         float
    event_results: tuple[EventScoreResult, ...]

    def __str__(self) -> str:
        lines = [f"FINAL SCORE of {len(self.event_results)} event(s): {self.score:.4f}"]
        for er in self.event_results:
            lines.append("  " + str(er).replace("\n", "\n  "))
        return "\n".join(lines)


def inspect_event(event: EventData) -> str:
    """
    Detailed description of an EventData instance, including all nested attribute elements.
    For a compact single-line summary use str(event) instead.

    Args:
        event: The EventData instance to inspect.

    Returns:
        A formatted multi-line string describing all fields at every level.
    """
    def _fmt_admiralty(admiralty: AdmiraltyTags, label: str) -> list[str]:
        sr = admiralty.source_reliability.value if admiralty.source_reliability else "absent"
        ic = admiralty.info_credibility.value   if admiralty.info_credibility   else "absent"
        return [f"{label}source_reliability = {sr}", f"{label}info_credibility   = {ic}"]

    lines: list[str] = [event.__str__()]

    for attr in event.attributes:
        tp = attr.sightings.true_positives
        fp = attr.sightings.false_positives
        lines += [
            f"  ├─ Attribute {attr.type}:{attr.value}",
            f"  │    sightings: TP={tp}, FP={fp}",
            "  │    admiralty:",
            *[f"  │      {l}" for l in _fmt_admiralty(attr.admiralty, "")],
        ]

    return "\n".join(lines)
