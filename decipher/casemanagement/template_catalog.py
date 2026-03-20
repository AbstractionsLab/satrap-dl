from dataclasses import dataclass


@dataclass(frozen=True)
class CaseTemplate:
    title: str
    filename: str


CASE_TEMPLATES: dict[str, CaseTemplate] = {
    "suspicious_login": CaseTemplate(
        title="[DECIPHER] Suspicious Login Activity",
        filename="suspicious_login.json",
    )
}
