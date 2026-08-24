import argparse
import sys
from pathlib import Path

# Säkerställ att projektets rotmapp alltid finns i Python-sökvägen
project_root = Path(__file__).resolve().parent.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from src.auditor import ConfigAuditor

console = Console()

def generate_markdown_report(report_data: dict, output_path: str):
    target = report_data["target_file"]
    score = report_data["score"]
    
    md_content = f"# Network Hardening Audit Report: {target}\n\n"
    md_content += f"**Compliance Score:** {score}% ({report_data['passed']}/{report_data['total_rules']} checks passed)\n\n"
    md_content += "| Rule ID | Severity | Status | Title | Remediation |\n"
    md_content += "| :--- | :--- | :--- | :--- | :--- |\n"

    for f in report_data["findings"]:
        status = "✅ PASS" if f["passed"] else "❌ FAIL"
        remediation = f["remediation"].replace("\n", " <br> ") if not f["passed"] else "N/A"
        md_content += f"| {f['id']} | {f['severity']} | {status} | {f['title']} | `{remediation}` |\n"

    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(md_content)

def main():
    parser = argparse.ArgumentParser(description="Network Configuration & Security Compliance Auditor")
    parser.add_argument("config_file", help="Path to network configuration file (e.g., sample_configs/cisco_switch_insecure.cfg)")
    parser.add_argument("--rules", default="rules/compliance_rules.json", help="Path to JSON compliance rules")
    parser.add_argument("--output", help="Save markdown report to specified path (e.g., reports/audit_result.md)")
    
    args = parser.parse_args()

    try:
        auditor = ConfigAuditor(rules_path=args.rules)
        report = auditor.audit_file(args.config_file)
    except Exception as e:
        console.print(f"[bold red]Error:[/] {e}")
        sys.exit(1)

    # Print Header Panel
    score_color = "green" if report["score"] >= 80 else ("yellow" if report["score"] >= 50 else "red")
    console.print(Panel(
        f"[bold white]Target Config:[/] {report['target_file']}\n"
        f"[bold white]Compliance Score:[/] [{score_color}]{report['score']}%[/{score_color}] "
        f"({report['passed']}/{report['total_rules']} checks passed)",
        title="[bold cyan]Network Security Compliance Auditor[/]",
        border_style="cyan"
    ))

    # Findings Table
    table = Table(title="Audit Findings Summary", show_header=True, header_style="bold magenta")
    table.add_column("ID", width=10)
    table.add_column("Severity", width=10)
    table.add_column("Status", width=10)
    table.add_column("Check / Title", width=35)
    table.add_column("Remediation / Details", width=35)

    for finding in report["findings"]:
        status_text = "[bold green]PASS[/]" if finding["passed"] else "[bold red]FAIL[/]"
        
        sev_color = "red" if finding["severity"] in ["CRITICAL", "HIGH"] else "yellow" if finding["severity"] == "MEDIUM" else "blue"
        severity_text = f"[{sev_color}]{finding['severity']}[/{sev_color}]"

        details = finding["details"] if finding["passed"] else f"[italic]{finding['remediation']}[/italic]"

        table.add_row(
            finding["id"],
            severity_text,
            status_text,
            finding["title"],
            details
        )

    console.print(table)

    if args.output:
        generate_markdown_report(report, args.output)
        console.print(f"\n[bold green]✓[/] Markdown report saved to: [cyan]{args.output}[/cyan]")

if __name__ == "__main__":
    main()