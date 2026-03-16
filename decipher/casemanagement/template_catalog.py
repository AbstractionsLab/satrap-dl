from dataclasses import dataclass

from decipher.settings import AnalysisScenario


@dataclass(frozen=True)
class CaseTemplate:
    title: str
    filename: str


CASE_TEMPLATES: dict[AnalysisScenario, CaseTemplate] = {
    AnalysisScenario.SUSPICIOUS_LOGIN: 
        CaseTemplate(
            title="[DECIPHER] Suspicious Login Activity",
            filename="suspicious_login.json",
        )
}
