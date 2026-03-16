"""
Base classes for alert analyzers.

All analyzers must inherit from BaseAnalyzer and implement the analyze() method.
"""

from abc import ABC, abstractmethod
from typing import Type
from pydantic import BaseModel

from decipher.models import AnalysisResult


class BaseAnalyzer(ABC):
    """
    Abstract base class for all alert analyzers.
    
    Subclasses must define:
        - alert_type: Unique string identifier for this analyzer
        - schema: Pydantic model class for input validation
        - analyze(): Implementation of analysis logic
    
    Example:
        @AnalyzerRegistry.register
        class MyAnalyzer(BaseAnalyzer):
            alert_type = "my_alert"
            schema = MyAlertSchema
            
            def analyze(self, alert: MyAlertSchema) -> AnalysisResult:
                # analysis logic
                return AnalysisResult(...)
    """
    alert_type: str
    schema: Type[BaseModel]
    
    @abstractmethod
    def analyze(self, alert: BaseModel) -> AnalysisResult:
        """
        Perform analysis on the validated alert.
        
        Args:
            alert: Validated alert data matching self.schema
            
        Returns:
            AnalysisResult with case creation recommendation and details
        """
        pass
    
    def validate(self, data: dict) -> BaseModel:
        """
        Validate input data against this analyzer's schema.
        
        Args:
            data: Raw dictionary from API request
            
        Returns:
            Validated Pydantic model instance
            
        Raises:
            ValidationError: If data doesn't match schema
        """
        return self.schema(**data)
