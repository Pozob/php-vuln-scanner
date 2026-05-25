from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from tree_sitter import Node
from php_vuln_scanner.file_parser import ParsedFile

logger = logging.getLogger(__name__)

_CALLABLE_REGEX = re.compile(r"^\w+(::\w+)?$")

class TaintEngine:
    def __init__(self, model: TaintModel) -> None:
        self._model = model

    def analyze_file(self, parsed_file: ParsedFile) -> list[TaintFlow]:
        # pass for now
        pass

@dataclass(frozen=True)
class TaintModel:
    sources: frozenset[str]
    sinks: dict[str, str]  # name of the function -> sink type
    method_sinks: dict[str, str]  # method name (coomming from "Class::method") -> sink type
    sanitizers: dict[str, frozenset[str]]  # function name -> sink types it clears

    @classmethod
    def from_dict(cls, data: dict) -> TaintModel:
        # sources
        sources = data.get("sources")
        if not isinstance(sources, list) or not all(
            isinstance(s, str) and s.startswith("$") for s in sources
        ):
            raise ValueError("taint model: 'sources' must be a list of PHP variable names ('$_GET', ...)")

        # sinks
        sinks: dict[str, str] = {}
        method_sinks: dict[str, str] = {}
        for sink_type, names in _check_for_string_list(data, "sinks").items():
            for name in names:
                if not _CALLABLE_REGEX.match(name):
                    raise ValueError(f"taint model: sink entry {name!r} is not a callable name")
                if "::" in name:
                    method_sinks[name.split("::")[1]] = sink_type
                else:
                    sinks[name] = sink_type

        # sanitizers
        sanitizers: dict[str, set[str]] = {}
        for sink_type, names in _check_for_string_list(data, "sanitizers").items():
            for name in names:
                if not _CALLABLE_REGEX.match(name):
                    logger.debug("taint model: ignoring descriptive sanitizer entry %r", name)
                    continue
                callable_name = name.split("::")[-1]
                sanitizers.setdefault(callable_name, set()).add(sink_type)

        return cls(
            sources=frozenset(sources),
            sinks=sinks,
            method_sinks=method_sinks,
            sanitizers={name: frozenset(types) for name, types in sanitizers.items()},
        )


def _check_for_string_list(data: dict, key: str) -> dict[str, list[str]]:
    value = data.get(key, {})

    if not isinstance(value, dict) or not all(
        isinstance(names, list) and all(isinstance(n, str) for n in names)
        for names in value.values()
    ):
        raise ValueError(f"taint model: '{key}' must map sink types to a lists of names")
    return value


@dataclass(frozen=True)
class TaintStep:
    line: int
    description: str


@dataclass(frozen=True)
class Taint:
    source: str  # the source like "$_GET"
    steps: tuple[TaintStep, ...]
    sanitized_for: frozenset[str] = frozenset()


@dataclass(frozen=True)
class TaintFlow:
    source: str
    sink_type: str
    sink_name: str
    sink_node: Node
    steps: tuple[TaintStep, ...]