from __future__ import annotations

import html
import json
from dataclasses import asdict
from datetime import datetime, timezone
from importlib import metadata
from pathlib import Path

from php_vuln_scanner.findings import Severity
from php_vuln_scanner.scanner import ScanResult

_SEVERITY_DISPLAY_ORDER = list(Severity)


def scanner_version() -> str:
    try:
        return metadata.version("php-vuln-scanner")
    except metadata.PackageNotFoundError:
        return "unknown"


# region JSON
def build_report(result: ScanResult) -> dict:
    by_severity = {
        str(sev): sum(1 for f in result.findings if f.severity == sev) for sev in _SEVERITY_DISPLAY_ORDER
    }
    by_category = {}
    for finding in result.findings:
        by_category[finding.owasp_category] = by_category.get(finding.owasp_category, 0) + 1

    return {
        "scanner": {"name": "phpscan", "version": scanner_version()},
        "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "target": str(result.target),
        "modules": [
            {
                "id": module.manifest.id,
                "version": module.manifest.version,
                "owasp_category": module.manifest.owasp_category,
                "requires_taint_engine": module.manifest.requires_taint_engine,
            }
            for module in result.modules
        ],
        "effective_config": {
            "core": asdict(result.core_config),
            "modules": {module.manifest.id: module.config for module in result.modules},
        },
        "files": {
            "found": len(result.files),
            "parsed": len(result.parsed_files),
            "with_parse_errors": [
                parsed_file.rel_path for parsed_file in result.parsed_files if parsed_file.has_parse_errors
            ],
        },
        "summary": {
            "total_findings": len(result.findings),
            "by_severity": by_severity,
            "by_category": dict(sorted(by_category.items())),
        },
        "findings": [finding.to_dict() for finding in result.findings],
    }


def write_json_report(report: dict, path: Path) -> None:
    path.write_text(json.dumps(report, indent=2), encoding="utf-8")

# endregion

#region terminal
def render_terminal(result: ScanResult, verbose: bool = False) -> str:
    with_errors = [pf.rel_path for pf in result.parsed_files if pf.has_parse_errors]
    lines = [
        f"phpscan {scanner_version()} scanned '{result.target}'",
        f"PHP files found:  {len(result.files)}",
        f"parsed:           {len(result.parsed_files)}"
        + (f" ({len(with_errors)} with syntax errors)" if with_errors else ""),
        f"modules run:      {', '.join(m.manifest.id for m in result.modules) or 'none'}",
    ]

    if not result.findings:
        lines.append("No findings. Clean scan")
        return "\n".join(lines)

    counts = {sev: sum(1 for f in result.findings if f.severity == sev) for sev in _SEVERITY_DISPLAY_ORDER}
    severity_summary = ", ".join(f"{sev}: {n}" for sev, n in counts.items() if n)
    by_category: dict[str, int] = {}
    for finding in result.findings:
        by_category[finding.owasp_category] = by_category.get(finding.owasp_category, 0) + 1
    category_summary = ", ".join(f"{cat}: {n}" for cat, n in sorted(by_category.items()))
    lines.append(f"findings:         {len(result.findings)} ({severity_summary})")
    lines.append(f"by category:      {category_summary}")

    for severity in _SEVERITY_DISPLAY_ORDER:
        group = [f for f in result.findings if f.severity == severity]
        if not group:
            continue
        lines.append(f"\n{severity} severity:")
        for f in group:
            lines.append(f"  {f.file}:{f.line} - {f.rule_id}  [{f.cwe or 'no CWE'}]  {f.message}")
            if verbose:
                lines.append(f"      snippet:     {f.snippet}")
                lines.append(f"      remediation: {f.remediation}")
                for step in f.taint_trace or ():
                    lines.append(f"      trace: line {step.line}: {step.description}")
    return "\n".join(lines)

# endregion

#region html
_HTML_PAGE_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>PHP-Vuln-Scanner Report</title>
<style>
  body {{ font-family: system-ui, -apple-system, sans-serif; margin: 2rem auto;
         max-width: 60rem; padding: 0 1rem; color: #1f2430; background: #f7f8fa; }}
  h1 {{ font-size: 1.4rem; }}
  .box {{ background: #fff; border: 1px solid #d0d3dd; border-radius: 6px;
                     padding: 0.8rem 1rem; margin-bottom: 0.8rem; }}
  .box td {{ padding: 0.1rem 0.8rem 0.1rem 0; color: #444; }}
  .box h2 {{ font-size: 1rem; margin: 0 0 0.3rem; }}
  .severity {{ display: inline-block; border-radius: 4px; padding: 0.05rem 0.5rem;
          font-size: 0.8rem; color: #fff; margin-right: 0.5rem; }}
  .sev-high {{ background: #d52714; }}
  .sev-medium {{ background: #cd8409; }}
  .sev-low {{ background: #2e7cbd; }}
  pre {{ background: #f0f2f5; border-radius: 4px; padding: 0.5rem; overflow-x: auto;
        font-size: 0.85rem; }}
  .remediation {{ border-left: 3px solid #2e86c1; padding-left: 0.6rem; color: #333; }}
  .trace {{ color: #666; font-size: 0.85rem; margin: 0.3rem 0 0; }}
</style>
</head>
<body>
<h1>PHP-Vuln-Scanner Report</h1>
<div class="box"><table>
<tr><td>Target</td><td>{target}</td></tr>
<tr><td>Scanned at</td><td>{timestamp}</td></tr>
<tr><td>Scanner</td><td>PHP-Vuln-Scanner (phpscan) {version}</td></tr>
<tr><td>Modules</td><td>{modules}</td></tr>
<tr><td>Files</td><td>{files_found} found, {files_parsed} parsed</td></tr>
<tr><td>Findings</td><td>{summary}</td></tr>
</table></div>
{findings}
</body>
</html>
"""

_HTML_FINDINGS_TEMPLATE = """<div class="box">
<h2><span class="severity sev-{severity}">{severity}</span>{rule_id}: {message}</h2>
<p class="loc">{file}:{line} - {owasp_category} - {cwe} - module: {module_id}</p>
<pre>{snippet}</pre>
<p class="remediation"><strong>Remediation:</strong> {remediation}</p>
{trace}
</div>
"""


def render_html(report: dict) -> str:
    """Render the report dict as one self-contained HTML page."""
    findings_html = []
    for finding in report["findings"]:
        trace = ""
        if finding["taint_trace"]:
            steps = " -> ".join(
                f"line {s['line']}: {html.escape(s['description'])}" for s in finding["taint_trace"]
            )
            trace = f'<p class="trace">Taint trace: {steps}</p>'
        findings_html.append(
            _HTML_FINDINGS_TEMPLATE.format(
                severity=html.escape(finding["severity"]),
                rule_id=html.escape(finding["rule_id"]),
                message=html.escape(finding["message"]),
                file=html.escape(finding["file"]),
                line=finding["line"],
                owasp_category=html.escape(finding["owasp_category"]),
                cwe=html.escape(finding["cwe"] or "no CWE"),
                module_id=html.escape(finding["module_id"]),
                snippet=html.escape(finding["snippet"]),
                remediation=html.escape(finding["remediation"]),
                trace=trace,
            )
        )
    if not findings_html:
        findings_html.append('<div class="finding"><h2>No findings. Clean scan.</h2></div>')

    by_severity = report["summary"]["by_severity"]
    summary = f"{report['summary']['total_findings']} total (" + ", ".join(
        f"{sev}: {n}" for sev, n in by_severity.items() if n
    ).rstrip(", ") + ")" if report["summary"]["total_findings"] else "No findings. Clean scan"

    return _HTML_PAGE_TEMPLATE.format(
        target=html.escape(report["target"]),
        timestamp=html.escape(report["timestamp"]),
        version=html.escape(report["scanner"]["version"]),
        modules=html.escape(
            ", ".join(f"{m['id']} v{m['version']}" for m in report["modules"]) or "none"
        ),
        files_found=report["files"]["found"],
        files_parsed=report["files"]["parsed"],
        summary=html.escape(summary),
        findings="\n".join(findings_html),
    )

# endregion