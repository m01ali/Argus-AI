"""
Argus-AI — a privacy-first continuous vulnerability-assessment and
patch-recommendation agent.

Built on the PLPF framework. Implements the four-stage closed loop:
Discovery → Validation → Patch Proposal → Re-scan, modelled on the
Aardvark scan–validate–patch–rescan pattern but running entirely on
local LLMs so engagement data never leaves the host.
"""

from .config import (
    ArgusConfig, ModelConfig, SandboxConfig, ScopeConfig, ReportConfig,
)
from .orchestrator import Argus, deny_all
from .models import Finding, LoopResult, Severity, ValidationVerdict, PatchStatus
from .report import write_reports

__version__ = "0.1.0"
__all__ = [
    "Argus", "ArgusConfig", "ModelConfig", "SandboxConfig", "ScopeConfig",
    "ReportConfig", "Finding", "LoopResult", "Severity", "ValidationVerdict",
    "PatchStatus", "write_reports", "deny_all",
]
