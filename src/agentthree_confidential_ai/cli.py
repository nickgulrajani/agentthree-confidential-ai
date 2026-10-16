"""CLI: demonstrate attested allow vs untrusted deny — zero cloud cost."""

from __future__ import annotations

import json
from pathlib import Path

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from agentthree_confidential_ai.attestation.quote import (
    forge_untrusted_claim,
    issue_quote,
)
from agentthree_confidential_ai.control_plane import ConfidentialControlPlane

console = Console()

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_POLICY = ROOT / "configs" / "policy.yaml"
DEFAULT_AUDIT = ROOT / "audit" / "logs" / "access.jsonl"

# Synthetic regulated payload (not real PHI)
SAMPLE_PHI = (
    b"Patient MRN-DEMO-4421 | Dx: Type 2 Diabetes | Meds: metformin 500mg | "
    b"DOB: 1978-04-12 | Facility: Riverside Clinic (SYNTHETIC DATA)"
)


def _plane(policy: Path, audit: Path) -> ConfidentialControlPlane:
    return ConfidentialControlPlane.from_paths(policy, audit)


@click.group()
@click.version_option(package_name="agentthree-confidential-ai")
def main() -> None:
    """AgentThree Confidential AI — attestation-gated protected data access."""


@main.command("demo")
@click.option("--policy", type=click.Path(path_type=Path), default=DEFAULT_POLICY)
@click.option("--audit", type=click.Path(path_type=Path), default=DEFAULT_AUDIT)
def demo(policy: Path, audit: Path) -> None:
    """Run the signature demo: attested ALLOW, untrusted DENY."""
    console.print(
        Panel.fit(
            "[bold]AgentThree Confidential AI[/bold]\n"
            "Local simulation of GCP Confidential Space + KMS + IAM + audit\n"
            "[dim]No cloud billing — portfolio / interview demo[/dim]",
            border_style="cyan",
        )
    )

    plane = _plane(policy, audit)
    blob = plane.seal_sample(SAMPLE_PHI, data_class="PHI")
    console.print(f"[dim]Sealed PHI under[/dim] {blob.kms_key}")

    # --- Attested path (TEE) ---
    attested_quote = issue_quote(
        workload_id="llm-inference-vllm",
        image_digest="sha256:demo-attested-vllm-0001",
        tee_type="simulated-sev-snp",
    )
    ok = plane.request_decrypt(
        blob, quote=attested_quote, purpose="inference"
    )

    # --- Untrusted path ---
    untrusted_quote = forge_untrusted_claim(workload_id="rogue-notebook")
    denied = plane.request_decrypt(
        blob, quote=untrusted_quote, purpose="inference"
    )

    table = Table(title="Protected data access decisions", show_lines=True)
    table.add_column("Workload", style="bold")
    table.add_column("TEE / Attestation")
    table.add_column("Outcome")
    table.add_column("Reason")

    table.add_row(
        "llm-inference-vllm",
        f"✓ {attested_quote.tee_type}",
        "[green]ALLOW[/green]",
        ok.reason,
    )
    table.add_row(
        "rogue-notebook",
        "✗ forged / no TEE",
        "[red]DENY[/red]",
        denied.reason,
    )
    console.print(table)

    if ok.allowed and ok.plaintext:
        console.print(
            Panel(
                ok.plaintext.decode(),
                title="[green]Decrypted inside attested workload[/green]",
                border_style="green",
            )
        )
    else:
        console.print("[red]Unexpected: attested path failed[/red]")
        raise SystemExit(1)

    if denied.allowed:
        console.print("[red]Unexpected: untrusted path was allowed[/red]")
        raise SystemExit(1)

    console.print(
        f"\n[dim]Audit trail written to[/dim] {audit}\n"
        "[bold]Demo complete:[/bold] attested decrypt succeeded; "
        "untrusted decrypt denied."
    )


@main.command("audit-show")
@click.option("--audit", type=click.Path(path_type=Path), default=DEFAULT_AUDIT)
@click.option("--limit", default=20, show_default=True)
def audit_show(audit: Path, limit: int) -> None:
    """Print recent audit events (JSONL)."""
    plane = _plane(DEFAULT_POLICY, audit)
    events = plane.audit.read_all()[-limit:]
    for event in events:
        console.print_json(json.dumps(event))


@main.command("compare")
def compare() -> None:
    """Print where to find multi-cloud comparison docs."""
    docs = ROOT / "docs"
    console.print(
        Panel(
            "\n".join(
                [
                    f"• GCP (primary): {docs / 'gcp-confidential-space.md'}",
                    f"• GCP GKE:       {docs / 'gcp-confidential-gke.md'}",
                    f"• AWS Nitro:     {docs / 'aws-nitro-enclaves.md'}",
                    f"• Azure CC:      {docs / 'azure-confidential-computing.md'}",
                    f"• Overview:      {docs / 'architecture-overview.md'}",
                ]
            ),
            title="Comparison architectures",
            border_style="blue",
        )
    )


if __name__ == "__main__":
    main()
