"""
Analyzer Registry for alert analysis.

Provides automatic discovery and dispatch of analyzers based on alert type.
"""

from typing import Type
from .base import BaseAnalyzer, AnalysisResult


class AnalyzerRegistry:
    """
    Registry for alert analyzers with decorator-based registration.

    This registry stores analyzer classes at import/registration time and
    instantiates analyzer objects lazily on first use.
    """

    # Mapping of alert_type -> analyzer class name
    _analyzers: dict[str, Type[BaseAnalyzer]] = {}
    # Analyzer instances per alert_type
    _instances: dict[str, BaseAnalyzer] = {}

    @classmethod
    def register(cls, analyzer_cls: Type[BaseAnalyzer]) -> Type[BaseAnalyzer]:
        """
        Decorator to register an analyzer class.
        
        Args:
            analyzer_cls: BaseAnalyzer subclass to register

        Returns:
            The same class passed in, allowing @AnalyzerRegistry.register to be used as a decorator.

        Raises:
            ValueError: If alert_type is already registered or not defined in the class
        """
        alert_type = getattr(analyzer_cls, "alert_type", None)
        if not alert_type:
            raise ValueError("Analyzer class must define 'alert_type' attribute")

        if alert_type in cls._analyzers:
            raise ValueError(f"Analyzer for '{alert_type}' already registered")

        cls._analyzers[alert_type] = analyzer_cls
        return analyzer_cls

    @classmethod
    def get(cls, alert_type: str) -> BaseAnalyzer | None:
        """Retrieve analyzer instance by alert type, instantiating if not already created."""
        if alert_type in cls._instances:
            return cls._instances[alert_type]

        analyzer_cls = cls._analyzers.get(alert_type)
        if not analyzer_cls:
            return None

        instance = analyzer_cls()
        cls._instances[alert_type] = instance
        return instance

    @classmethod
    def list_types(cls) -> list[str]:
        """List all registered alert types (class registrations)."""
        return list(cls._analyzers.keys())

    @classmethod
    def get_registered_classes(cls) -> dict[str, Type[BaseAnalyzer]]:
        """Return a shallow copy of the registered analyzer classes mapping."""
        return dict(cls._analyzers)

    @classmethod
    def analyze(cls, alert_type: str, data: dict) -> AnalysisResult:
        """
        Route analysis to appropriate analyzer.
        
        Args:
            alert_type: Type of alert (must be registered)
            data: Raw alert data dictionary
            
        Returns:
            AnalysisResult from the matched analyzer
            
        Raises:
            ValueError: If alert_type is not registered
        """
        analyzer = cls.get(alert_type)

        if not analyzer:
            registered = ", ".join(cls.list_types()) or "(none)"
            raise ValueError(
                f"Unknown alert type: '{alert_type}'. "
                f"Registered types: [{registered}]"
            )

        validated_alert = analyzer.validate(data)
        return analyzer.analyze(validated_alert)

    @classmethod
    def clear(cls) -> None:
        """Clear all registered analyzer classes and instances (useful for tests)."""
        cls._analyzers.clear()
        cls._instances.clear()
