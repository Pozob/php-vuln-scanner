from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from tree_sitter import Node
from php_vuln_scanner.file_parser import ParsedFile

logger = logging.getLogger(__name__)

_CALLABLE_REGEX = re.compile(r"^\w+(::\w+)?$")

# These nodes open a new analysis scope
_SCOPE_TYPES = {
    "function_definition",
    "method_declaration",
    "anonymous_function_creation_expression",
    "arrow_function",
}

_INCLUDE_TYPES = {
    "include_expression": "include",
    "include_once_expression": "include_once",
    "require_expression": "require",
    "require_once_expression": "require_once",
}

_NUMERIC_CASTS = {"int", "integer", "float", "double", "real", "bool", "boolean"}

class TaintEngine:
    """Analyzes parsed files for taint flows according to the TaintModel"""

    def __init__(self, model: TaintModel) -> None:
        self._model = model

    def analyze_file(self, parsed_file: ParsedFile) -> list[TaintFlow]:
        """Return all unsanitized source->sink flows in the file."""
        analysis = _ScopeAnalyzer(self._model, parsed_file)
        analysis.visit_scope(parsed_file.root)
        return analysis.flows

@dataclass(frozen=True)
class TaintModel:
    sources: frozenset[str]
    sinks: dict[str, str]  # name of the function -> sink type
    method_sinks: dict[str, str]  # method name (coomming from "Class::method") -> sink type
    sanitizers: dict[str, frozenset[str]]  # function name -> sink types it clears

    @classmethod
    def from_dict(cls, data: dict) -> TaintModel:
        """Build a model from a YAML config

        The config should the following shape:
            sources: ["$_GET", ...]
            sinks: {sql: [mysql_query, "PDO::query"], xss: [echo], ...}
            sanitizers: {sql: [mysqli_real_escape_string], xss: [htmlspecialchars]}
        """

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
                    # We do not resolve the class of an object at runtime, so a "Class::method" will be matched
                    # just on the function name. So "PDO::query" would matches $foo->query()
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
                # Same as for sinks: only the bare callable name is matched.
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
    """One single step in a taint. What happend where?"""

    line: int
    description: str


@dataclass(frozen=True)
class Taint:
    """Taint carried by a value and how it ended up here

    ``sanitized_for`` holds the sink types this value is already safe for
    """

    source: str  # the source like "$_GET"
    steps: tuple[TaintStep, ...]
    sanitized_for: frozenset[str] = frozenset()


@dataclass(frozen=True)
class TaintFlow:
    """A completed source->sink flow that no matching sanitizer interrupted"""

    sink_type: str
    sink_name: str
    source: str
    sink_node: Node
    steps: tuple[TaintStep, ...]

    @property
    def line(self) -> int:
        return self.sink_node.start_point[0] + 1


class _ScopeAnalyzer:
    def __init__(self, model: TaintModel, parsed_file: ParsedFile) -> None:
        self._model = model
        self._parsed_file = parsed_file
        self.flows: list[TaintFlow] = []
        # Taint state of the scope currently being analyzed with: variable name -> taint.
        # If a varibale is not set, it is considered clean
        self._track: dict[str, Taint] = {}

    def visit_scope(self, scope_root: Node) -> None:
        """Analyze one scope.

        Each scope gets a fresh taint state. Nested scopes are collected during the
        walk and analyzed afterwards.
        """
        nested: list[Node] = []
        self._track = {}
        self._visit(scope_root, nested, is_scope_root=True)
        for scope in nested:
            self.visit_scope(scope)

    def _visit(self, node: Node, nested: list[Node], is_scope_root: bool = False) -> None:
        """Walk statements in order and update the taint state.

        Every branch below returns instead of falling through to the generic
        child walk, because the respective handler already consumed the whole
        subtree
        """
        if node.type in _SCOPE_TYPES and not is_scope_root:
            nested.append(node)
            return
        if node.type == "if_statement":
            self._handle_if(node, nested)
            return
        if node.type in ("assignment_expression", "augmented_assignment_expression"):
            self._handle_assignment(node)
            return
        if node.type == "echo_statement":
            for child in node.named_children:
                self._check_sink_args("echo", [child])
            return
        if self._is_evaluable(node):
            # Expression in statement position like a bare call, echo-like output, a include
            self._eval(node)
            return
        for child in node.children:
            self._visit(child, nested)

    @staticmethod
    def _is_evaluable(node: Node) -> bool:
        return node.type in (
            "function_call_expression",
            "member_call_expression",
            "print_intrinsic",
            "shell_command_expression",
            "encapsed_string",
        ) or node.type in _INCLUDE_TYPES

    # region if
    def _handle_if(self, node: Node, nested: list[Node]) -> None:
        """Analyze every branch from the same entry state and join the results.

        Without this every branch would write into one shared state and the last
        one in source order would win, wiping out the taint of earlier branches
        """
        condition = node.child_by_field_name("condition")
        if condition is not None:
            self._visit(condition, nested)  # the condition itself may hold a sink

        branches = [node.child_by_field_name("body")]
        branches += list(node.children_by_field_name("alternative"))  # elseif / else

        entry = dict(self._track)
        outcomes: list[dict[str, Taint]] = []
        for branch in branches:
            if branch is None:
                continue
            self._track = dict(entry)
            self._visit(branch, nested)
            outcomes.append(self._track)
        if not any(branch is not None and branch.type == "else_clause" for branch in branches):
            outcomes.append(entry)  # without an else the whole statement may be skipped

        self._track = _join(outcomes)

    # endregion
    # region assignment handling
    def _handle_assignment(self, node: Node) -> None:
        """Propagate the taint of the right-hand side onto the assigned variable."""
        left = node.child_by_field_name("left")
        right = node.child_by_field_name("right")

        if right is None:
            return

        taint = self._eval(right)

        # Only plain variables are tracked. For anything else like array, object or
        # variable variables drop the write. the right-hand side was still evaluated
        # above, so sinks in it are reported
        if left is None or left.type != "variable_name":
            return
        var = self._parsed_file.text(left)

        if node.type == "augmented_assignment_expression":
            # "$a .= $b" keeps whatever $a already carried, so the old state of the variable is part of the result.
            taint = _merge(self._track.get(var), taint)

        if taint is None:
            self._track.pop(var, None)  # overwritten with clean data: taint is killed
        else:
            step = TaintStep(self._parsed_file.line(node), f"tainted value assigned to {var}")
            self._track[var] = Taint(taint.source, taint.steps + (step,), taint.sanitized_for)
    # endregion
    # region expression evaluation
    def _eval(self, node: Node) -> Taint | None:
        """Return the taint an expression evaluates to or none if clean

        Handlers are looked up by node type ("_eval_<type>"). Node types  without a handler fall back to
        the merge of their children, which is the safe default for the many wrapper nodes taht tree-sitter produces
        """
        handler = getattr(self, f"_eval_{node.type}", None)
        if handler is not None:
            return handler(node)
        if node.type in _INCLUDE_TYPES:
            args = node.named_children
            return self._check_sink_args(_INCLUDE_TYPES[node.type], args)
        return _merge(*(self._eval(child) for child in node.named_children))

    def _eval_variable_name(self, node: Node) -> Taint | None:
        name = self._parsed_file.text(node)
        if name in self._model.sources:
            return self._new_source_taint(name, node)
        return self._track.get(name)

    def _eval_subscript_expression(self, node: Node) -> Taint | None:
        """Taint of "$arr[...]" is the taint of the array itself.

        Indices are deliberately not distinguished: "$_GET['id']" is tainted because "$_GET"
        is a source, and a tainted "$data" makes every "$data[...]" tainted
        """
        base = node.named_children[0] if node.named_children else None
        if base is not None and base.type == "variable_name":
            name = self._parsed_file.text(base)
            if name in self._model.sources:
                return self._new_source_taint(name, node)
            return self._track.get(name)
        return _merge(*(self._eval(child) for child in node.named_children))

    def _eval_binary_expression(self, node: Node) -> Taint | None:
        left = node.child_by_field_name("left")
        right = node.child_by_field_name("right")
        operator = node.child_by_field_name("operator")

        left_taint = self._eval(left) if left is not None else None
        right_taint = self._eval(right) if right is not None else None
        # Only string concatenation carries a payload through. Math operations and comparisons produce
        # numbers/booleans, which cannot transport an injection, so their result is treated as clean.
        if operator is not None and operator.type == ".":
            return _merge(left_taint, right_taint)
        return None

    def _eval_encapsed_string(self, node: Node) -> Taint | None:
        return _merge(*(self._eval(c) for c in node.named_children))

    def _eval_conditional_expression(self, node: Node) -> Taint | None:
        # "$a ? $b : $c" can yield either branch, so the result is tainted if either one is.
        branches = [node.child_by_field_name("body"), node.child_by_field_name("alternative")]
        return _merge(*(self._eval(branch) for branch in branches if branch is not None))

    def _eval_cast_expression(self, node: Node) -> Taint | None:
        cast_type = node.child_by_field_name("type")
        value = node.child_by_field_name("value")
        taint = self._eval(value) if value is not None else None
        if cast_type is not None and self._parsed_file.text(cast_type).lower() in _NUMERIC_CASTS:
            return None  # numeric cast destroys any payload
        return taint

    def _eval_print_intrinsic(self, node: Node) -> Taint | None:
        self._check_sink_args("print", node.named_children)
        return None

    def _eval_shell_command_expression(self, node: Node) -> Taint | None:
        # Backticks are a sink, but unlike echo/print they also have a value (the command output),
        # which stays tainted, so ->taint_through.
        return self._check_sink_args("shell_exec", node.named_children, taint_through=True)

    def _eval_function_call_expression(self, node: Node) -> Taint | None:
        return self._eval_call(node, self._model.sinks)

    def _eval_member_call_expression(self, node: Node) -> Taint | None:
        return self._eval_call(node, self._model.method_sinks)

    def _eval_call(self, node: Node, sink_map: dict[str, str]) -> Taint | None:
        """Evaluate a call: sanitizer, sink, or plain taint propagation.

        The arguments are evaluated first so that sinks nested inside them are reported regardless
        """
        name_node = node.child_by_field_name("function") or node.child_by_field_name("name")
        arguments = node.child_by_field_name("arguments")

        name = self._parsed_file.text(name_node) if name_node is not None else ""
        args = arguments.named_children if arguments is not None else []
        args_taint = _merge(*(self._eval(argument) for argument in args))
        cleared_types = self._model.sanitizers.get(name)

        if cleared_types is not None:
            if args_taint is None:
                return None  # nothing tainted went in, so nothing to mark as cleared
            step = TaintStep(self._parsed_file.line(node), f"sanitized for {'/'.join(sorted(cleared_types))} by {name}()")
            return Taint(args_taint.source, args_taint.steps + (step,), args_taint.sanitized_for | cleared_types)

        sink_type = sink_map.get(name)
        if sink_type is not None:
            self._report(sink_type, name, args_taint, node)
            return None  # we dont track the returnvalue of a sink

        # Unknown function: pass the argument taint through. This keeps flows through wrappers and unmodelled
        # helpers visible at the cost of false positives for functions that actually neutralize their input.
        return args_taint

    # endregion
    # region sinks

    def _check_sink_args(
        self, sink_name: str, args: list[Node], taint_through: bool = False
    ) -> Taint | None:
        """Report a sink that is a language construct

        echo, print, backticks and include/require have no call node, so the sink name is passed
        in by the caller and looked up in the normal sink map
        """
        taint = _merge(*(self._eval(argument) for argument in args))
        sink_type = self._model.sinks.get(sink_name)
        if sink_type is not None and args:
            self._report(sink_type, sink_name, taint, args[0].parent or args[0])
        return taint if taint_through else None

    # endregion

    def _report(self, sink_type: str, sink_name: str, taint: Taint | None, node: Node) -> None:
        """Record a finding unless the value is clean or already sanitized here.

        Sanitization is checked per sink type. example: htmlspecialchars() clears "xss" but the same
        value reaching an "sql" sink is still reported
        """
        if taint is None or sink_type in taint.sanitized_for:
            return
        step = TaintStep(self._parsed_file.line(node), f"reaches {sink_type} sink {sink_name}")
        self.flows.append(
            TaintFlow(sink_type, sink_name, taint.source, node, taint.steps + (step,))
        )

    def _new_source_taint(self, source: str, node: Node) -> Taint:
        step = TaintStep(self._parsed_file.line(node), f"user input from {source}")
        return Taint(source=source, steps=(step,))

def _join(states: list[dict[str, Taint]]) -> dict[str, Taint]:
    """Joins the states of alternative control-flow paths at their merge point
    A variable stays tainted if any of the incoming paths taints it"""
    joined: dict[str, Taint] = {}
    for name in {name for state in states for name in state}:
        taint = _merge(*(state.get(name) for state in states))
        if taint is not None:
            joined[name] = taint
    return joined

def _merge(*taints: Taint | None) -> Taint | None:
    """Combines expression taints and stays tainted if any part of the expression is tainted
    A sink is only sanitized if every tainted part of it was sanitized"""
    present = [taint for taint in taints if taint is not None]
    if not present:
        return None
    # Using intersection and not union: "htmlspecialchars($a) . $b" because is only safe for the sink
    # types that *both* parts are safe for, since $b reaches the sink raw.
    sanitized = frozenset.intersection(*(t.sanitized_for for t in present))
    # Only one representative trace is kept.
    first = present[0]
    return Taint(first.source, first.steps, sanitized)
