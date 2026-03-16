from dataclasses import dataclass
from enum import Enum

from decipher.commons.config_loader import load_yaml_file
from decipher.commons.log_utils import get_logger
from decipher.settings import SCORING_CONFIG_PATH

logger = get_logger(__name__)

class ThreatLevel(str, Enum):
    """MISP threat level values."""
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNDEFINED = "undefined"


class AnalysisStage(str, Enum):
    """MISP analysis stage values."""
    COMPLETED = "completed"
    ONGOING = "ongoing"
    INITIAL = "initial"


class SourceReliability(str, Enum):
    """Admiralty scale source reliability grades"""
    A = "a"
    B = "b"
    C = "c"
    D = "d"
    E = "e"
    F = "f"
    G = "g"


class InfoCredibility(str, Enum):
    """Admiralty scale information credibility grades"""
    ONE = "1"
    TWO = "2"
    THREE = "3"
    FOUR = "4"
    FIVE = "5"
    SIX = "6"


@dataclass
class ScoringConfig:
    tags_multiplier: float

    threat_level_values: dict[ThreatLevel, float]
    analysis_stage_values: dict[AnalysisStage, float]

    w_analysis: float
    w_empirical: float

    source_reliability_values: dict[SourceReliability, float]
    info_credibility_values: dict[InfoCredibility, float]

    w_sightings: float
    w_admiralty: float


def load_scoring_config() -> ScoringConfig:
    """Load scoring model configuration from YAML.
    
    Raises parse errors thrown by load_yaml_file.
    A missing file is the only condition that falls back to an empty dict,
    since it is a legitimate "use all defaults" state.

    Raises:
        ValueError:      If weight validation checks fail (e.g. weights not summing to 1.0).
        yaml.YAMLError:  If the file exists but cannot be parsed.
    """
    try:
        config = load_yaml_file(SCORING_CONFIG_PATH)
    except FileNotFoundError as e:
        logger.warning(f"Scoring config not found at {SCORING_CONFIG_PATH}, using defaults")
        config = {}

    g = lambda path, default: _get(config, path, default)  # noqa: E731

    w_analysis  = g("confidence_weights.analysis",  0.5)
    w_empirical = g("confidence_weights.empirical", 0.5)
    _validate_weights("confidence_weights", [w_analysis, w_empirical])

    w_sightings = g("attribute_weights.sightings", 0.6)
    w_admiralty = g("attribute_weights.admiralty", 0.4)
    _validate_weights("attribute_weights", [w_sightings, w_admiralty])

    return ScoringConfig(
        tags_multiplier=g("tags_multiplier", 1.5),
        threat_level_values={
            ThreatLevel.HIGH:      g("threat_level.high",      1.00),
            ThreatLevel.MEDIUM:    g("threat_level.medium",    0.50),
            ThreatLevel.LOW:       g("threat_level.low",       0.25),
            ThreatLevel.UNDEFINED: g("threat_level.undefined", 0.00),
        },
        analysis_stage_values={
            AnalysisStage.COMPLETED: g("analysis_stage.completed", 1.00),
            AnalysisStage.ONGOING:   g("analysis_stage.ongoing",   0.50),
            AnalysisStage.INITIAL:   g("analysis_stage.initial",   0.00),
        },
        w_analysis=w_analysis,
        w_empirical=w_empirical,
        source_reliability_values={
            SourceReliability.A: g("admiralty_source_reliability.a", 1.00),
            SourceReliability.B: g("admiralty_source_reliability.b", 0.80),
            SourceReliability.C: g("admiralty_source_reliability.c", 0.60),
            SourceReliability.D: g("admiralty_source_reliability.d", 0.40),
            SourceReliability.E: g("admiralty_source_reliability.e", 0.20),
            SourceReliability.F: g("admiralty_source_reliability.f", 0.00),
            SourceReliability.G: g("admiralty_source_reliability.g", 0.00),
        },
        info_credibility_values={
            InfoCredibility.ONE:   g("admiralty_info_credibility.1", 1.00),
            InfoCredibility.TWO:   g("admiralty_info_credibility.2", 0.80),
            InfoCredibility.THREE: g("admiralty_info_credibility.3", 0.60),
            InfoCredibility.FOUR:  g("admiralty_info_credibility.4", 0.40),
            InfoCredibility.FIVE:  g("admiralty_info_credibility.5", 0.20),
            InfoCredibility.SIX:   g("admiralty_info_credibility.6", 0.00),
        },
        w_sightings=w_sightings,
        w_admiralty=w_admiralty,
    )


def _get(config: dict, key_path: str, default: float) -> float:
    """
    Retrieve a float from the loaded config using a dot-separated key path.

    Args:
        key_path: Dot-separated path (e.g. "confidence_weights.analysis").
        default:  Value to use when the key is absent from the config.

    Returns:
        The config value cast to float, or default if the key is absent.

    Raises:
        TypeError:  If the value found at key_path cannot be used as a float.
        ValueError: If the value found at key_path cannot be converted to float.
    """
    keys  = key_path.split(".")
    node  = config
    for key in keys:
        if not isinstance(node, dict) or key not in node:
            logger.debug(f"Config key '{key_path}' not found, using default: {default}")
            return default
        node = node[key]
    return float(node)


def _validate_weights(name: str, weights: list[float]) -> None:
    """
    Assert that each named weight pair sums to 1.0 within floating-point tolerance.

    Args:
        name:  Human-readable name of the weight group, used in the error message.
        weights: List of weight values.

    Raises:
        ValueError: If the weights do not sum to 1.0 within tolerance.
    """
    total = sum(weights)
    if abs(total - 1.0) > 1e-8:
        raise ValueError(
            f"The sum of the weights for '{name}' must be 1.0; currently = {total:.9f}. "
            f"Check {SCORING_CONFIG_PATH}"
        )
