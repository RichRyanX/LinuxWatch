# rules/base_rule.py
# Abstract base class for all detection rules. Defines the shared interface
# (name, severity, detect(), make_alert()) that every rule subclass must follow.

from abc import ABC, abstractmethod


class BaseRule(ABC):
    """
    Abstract base class for all LinuxWatch detection rules.
    Every rule must implement a name, severity, and detect() method.
    """

    # Override these in each subclass
    name: str = "unnamed_rule"
    severity: str = "INFO"  # INFO | WARNING | CRITICAL

    @abstractmethod
    def detect(self, entries: list[dict]) -> list[dict]:
        """
        Analyze a list of parsed log entry dicts.
        Returns a list of alert dicts for any suspicious activity found.
        Each alert dict must contain at minimum:
            - rule:      str   (rule name)
            - severity:  str   (INFO / WARNING / CRITICAL)
            - message:   str   (human-readable description)
            - timestamp: datetime
            - evidence:  list  (raw log lines that triggered the alert)
        """
        pass

    def make_alert(self, message: str, timestamp, evidence: list[str]) -> dict:
        """
        Helper to build a consistently structured alert dict.
        """
        return {
            "rule":      self.name,
            "severity":  self.severity,
            "message":   message,
            "timestamp": timestamp,
            "evidence":  evidence,
        }