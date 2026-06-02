from __future__ import annotations

import abc
from dataclasses import dataclass

from php_vuln_scanner.file_parser import ParsingService, ParsedFile
from php_vuln_scanner.taint_engine import TaintEngine, TaintModel
from php_vuln_scanner.findings import Finding, Rule


@dataclass(frozen=True)
class ModuleContext:
    module_id: str
    owasp_category: str
    config: dict
    parsing: ParsingService

    def create_taint_engine(self, taint_model: dict) -> TaintEngine:
        """Build a taint engine from the modules config data"""
        return TaintEngine(TaintModel.from_dict(taint_model))


class ScannerModule(abc.ABC):
    """Base class for every module"""

    @abc.abstractmethod
    def rules(self) -> list[Rule]:
        """All rules this module can report"""

    @abc.abstractmethod
    def analyze(self, parsed_files: list[ParsedFile], context: ModuleContext) -> list[Finding]:
        """Analyze the parsed files and return findings"""
