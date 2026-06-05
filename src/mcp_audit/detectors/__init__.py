"""Detector registry."""
from .base import Confidence, Detector, Finding, ScanContext, Severity, ToolInfo
from .command_injection import CommandInjectionDetector
from .secrets import SecretsDetector
from .shadow_mcp import ShadowMcpDetector
from .supply_chain import SupplyChainDetector
from .tool_poisoning import ToolPoisoningDetector

ALL_DETECTORS: list[Detector] = [
    ToolPoisoningDetector(),
    SecretsDetector(),
    CommandInjectionDetector(),
    SupplyChainDetector(),
    ShadowMcpDetector(),
]

__all__ = [
    "ALL_DETECTORS", "Detector", "Finding", "ScanContext", "Severity",
    "Confidence", "ToolInfo",
]
