#!/usr/bin/env python3
"""
Trailmark PoC: Java 3rd-Party Library Vulnerability Finder & Remediator
========================================================================

Demonstrates how to use Trailmark to:

1. Parse a Java project into a queryable call graph.
2. Cross-reference imported packages against a static CVE database.
3. Trace call paths from HTTP entrypoints to vulnerable library call sites.
4. Annotate findings on the graph and run preanalysis (blast radius, taint).
5. Diff the vulnerable graph against a remediated version.
6. Emit a human-readable remediation report.

Usage
-----
From the repository root (after `uv sync --all-groups`):

    uv run python examples/java-vuln-poc/analysis/analyze.py

Or, to target arbitrary directories:

    uv run python examples/java-vuln-poc/analysis/analyze.py \\
        --vulnerable  path/to/vulnerable-app/src \\
        --remediated  path/to/remediated-app/src
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from trailmark.models.annotations import AnnotationKind
from trailmark.models.graph import CodeGraph
from trailmark.query.api import QueryEngine

# ---------------------------------------------------------------------------
# Paths (relative to this script)
# ---------------------------------------------------------------------------
_SCRIPT_DIR = Path(__file__).parent
_POC_ROOT = _SCRIPT_DIR.parent
_CVE_DB_PATH = _SCRIPT_DIR / "cve_database.json"

_DEFAULT_VULNERABLE = _POC_ROOT / "vulnerable-app" / "src" / "main" / "java"
_DEFAULT_REMEDIATED = _POC_ROOT / "remediated-app" / "src" / "main" / "java"

# ---------------------------------------------------------------------------
# CVE database helpers
# ---------------------------------------------------------------------------


def load_cve_db(path: Path) -> dict[str, list[dict[str, Any]]]:
    with open(path) as f:
        return json.load(f)


def scan_imports(src_dir: Path) -> set[str]:
    """Scan Java source files for full import paths.

    Returns the set of fully-qualified import prefixes found, e.g.
    ``{"org.apache.logging.log4j", "com.fasterxml.jackson", ...}``.
    Trailmark's graph.dependencies only stores the top-level package name
    (e.g. ``"org"``); this function provides finer-grained resolution needed
    for accurate CVE matching.
    """
    imports: set[str] = set()
    for java_file in src_dir.rglob("*.java"):
        for line in java_file.read_text(errors="replace").splitlines():
            stripped = line.strip()
            if stripped.startswith("import ") and stripped.endswith(";"):
                fqn = stripped[len("import ") : -1].strip()
                # Remove trailing class name (last component) so we keep the
                # package path, e.g. org.apache.logging.log4j.LogManager
                # → org.apache.logging.log4j
                parts = fqn.rsplit(".", 1)
                if len(parts) == 2:
                    imports.add(parts[0])
                else:
                    imports.add(fqn)
    return imports


def match_cves(
    imports: set[str],
    cve_db: dict[str, list[dict[str, Any]]],
) -> list[dict[str, Any]]:
    """Return CVE records for every import whose package prefix is in the DB."""
    hits: list[dict[str, Any]] = []
    seen_cves: set[str] = set()
    for import_path in imports:
        for prefix, cves in cve_db.items():
            if prefix == "_comment":
                continue
            if import_path.startswith(prefix):
                for cve in cves:
                    if cve["cve"] in seen_cves:
                        continue
                    seen_cves.add(cve["cve"])
                    entry = dict(cve)
                    entry["matched_import"] = import_path
                    hits.append(entry)
    return hits


# ---------------------------------------------------------------------------
# Graph building
# ---------------------------------------------------------------------------


def build_engine(src_dir: Path) -> QueryEngine:
    """Parse a Java source directory into a Trailmark QueryEngine."""
    print(f"  Parsing: {src_dir}")
    engine = QueryEngine.from_directory(str(src_dir), language="java")
    summary = engine.summary()
    print(
        f"  Graph: {summary['total_nodes']} nodes, "
        f"{summary['call_edges']} call edges, "
        f"{summary['entrypoints']} entrypoints detected"
    )
    return engine


# ---------------------------------------------------------------------------
# Vulnerability detection
# ---------------------------------------------------------------------------


def _method_name(node_id: str) -> str:
    """Extract the bare method name from a node ID.

    E.g. ``com.example.util.LoggingUtil:LoggingUtil.logAccess`` → ``logAccess``
    """
    # Format: module:ClassName.method  or  module:function
    after_colon = node_id.split(":")[-1]
    return after_colon.rsplit(".", 1)[-1]


def _build_call_index(
    graph: CodeGraph,
) -> dict[str, list[str]]:
    """Build a reverse index: method_name → [caller_node_ids].

    For Java's inferred cross-file calls the edge target is a raw expression
    like ``loggingUtil.logAccess``.  This index maps the method-name suffix
    (e.g. ``logAccess``) to every node whose edge target ends with ``.logAccess``
    or equals ``logAccess``, enabling name-based path resolution without
    requiring full type inference.
    """
    from trailmark.models.edges import EdgeKind

    index: dict[str, list[str]] = {}
    for edge in graph.edges:
        if edge.kind != EdgeKind.CALLS:
            continue
        target = edge.target_id
        # Strip object prefix for dotted calls like "loggingUtil.logAccess"
        method = target.rsplit(".", 1)[-1] if "." in target else target
        index.setdefault(method, []).append(edge.source_id)
    return index


def find_vulnerable_callers(
    engine: QueryEngine,
    cve_record: dict[str, Any],
) -> dict[str, list[list[str]]]:
    """Find attack paths from HTTP entrypoints to vulnerable library sinks.

    Strategy
    --------
    The Java parser models external library calls as edge *targets* — strings
    like ``objectMapper.readValue`` — that are not themselves graph nodes.
    Inferred cross-file calls (e.g. ``loggingUtil.logAccess``) also use
    variable names rather than class names, so Trailmark's graph-traversal
    primitives cannot resolve them automatically.

    This function bridges the gap with a two-step name-based search:

    1. Scan all CALLS edges whose target contains a vulnerable pattern to
       identify the project's own functions that invoke the vulnerable sink
       (e.g. ``LoggingUtil.logAccess`` → ``logger.info``).

    2. Scan all CALLS edges whose target *ends with* the same method name
       (e.g. ``.logAccess``) to find which other nodes call those functions.
       Intersect with the detected HTTP entrypoints to build attack paths.

    Returns a dict mapping the call pattern string to a list of call paths,
    where each path is ``[entrypoint_id, ..., vulnerable_caller_id]``.
    """
    from trailmark.models.edges import EdgeKind

    graph = engine._store._graph  # noqa: SLF001

    entrypoint_ids = {ep["node_id"] for ep in engine.attack_surface()}

    # Pre-build a method-name → [caller] index (all CALLS edges in the graph).
    call_index = _build_call_index(graph)

    results: dict[str, list[list[str]]] = {}

    for call_pattern in cve_record.get("vulnerable_calls", []):
        # Step 1 — find project nodes that directly invoke the vulnerable sink.
        direct_callers: set[str] = set()
        for edge in graph.edges:
            if edge.kind == EdgeKind.CALLS and call_pattern in edge.target_id:
                direct_callers.add(edge.source_id)

        if not direct_callers:
            continue

        # Step 2 — for each direct caller, find HTTP entrypoints that can reach
        # it.  We do a BFS backwards through the call-index up to 5 hops.
        all_paths: list[list[str]] = []

        for caller_id in sorted(direct_callers):
            caller_method = _method_name(caller_id)
            # Find nodes that call caller_id (by method name).
            immediate_parents = set(call_index.get(caller_method, []))
            # Filter to only nodes that exist in the graph.
            immediate_parents = {p for p in immediate_parents if p in graph.nodes}

            for parent_id in sorted(immediate_parents):
                if parent_id in entrypoint_ids:
                    all_paths.append([parent_id, caller_id])
                else:
                    # One more hop — check if *this* parent is called by an entrypoint.
                    parent_method = _method_name(parent_id)
                    grandparents = {
                        gp
                        for gp in call_index.get(parent_method, [])
                        if gp in graph.nodes and gp in entrypoint_ids
                    }
                    for gp_id in sorted(grandparents):
                        all_paths.append([gp_id, parent_id, caller_id])

            # Also include direct entrypoint → caller paths when a single-hop
            # edge exists (e.g. an entrypoint itself calls the vulnerable method).
            for ep_id in entrypoint_ids:
                ep_method_targets = {
                    edge.target_id
                    for edge in graph.edges
                    if edge.kind == EdgeKind.CALLS and edge.source_id == ep_id
                }
                if caller_id in ep_method_targets:
                    path = [ep_id, caller_id]
                    if path not in all_paths:
                        all_paths.append(path)

        if all_paths:
            results[call_pattern] = all_paths

    return results


def annotate_findings(
    engine: QueryEngine,
    cve_record: dict[str, Any],
    callers_map: dict[str, list[list[str]]],
) -> int:
    """Add FINDING annotations to each node that is on a vulnerable path.

    Every node in every path (entrypoint → ... → vulnerable caller) is
    annotated so that ``engine.findings()`` surfaces the full blast of
    affected code, not just the direct caller.
    """
    annotated = 0
    cve_id = cve_record["cve"]
    name = cve_record["name"]
    severity = cve_record["severity"]

    seen: set[str] = set()
    for call_pattern, paths in callers_map.items():
        for path in paths:
            for node_id in path:
                if node_id in seen:
                    continue
                seen.add(node_id)
                desc = (
                    f"{cve_id} ({name}) [{severity}]: "
                    f"node is on a call path to vulnerable sink '{call_pattern}'. "
                    f"Remediation: {cve_record['remediation']}"
                )
                added = engine.annotate(
                    node_id,
                    AnnotationKind.FINDING,
                    desc,
                    source="trailmark-vuln-poc",
                )
                if added:
                    annotated += 1
    return annotated


# ---------------------------------------------------------------------------
# Reporting helpers
# ---------------------------------------------------------------------------

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
SEVERITY_EMOJI = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢", "INFO": "⚪"}


def _sep(char: str = "─", width: int = 72) -> str:
    return char * width


def print_header(title: str) -> None:
    print(f"\n{'═' * 72}")
    print(f"  {title}")
    print(f"{'═' * 72}")


def print_section(title: str) -> None:
    print(f"\n{_sep()}")
    print(f"  {title}")
    print(_sep())


def format_path(path: list[str]) -> str:
    return " → ".join(path)


# ---------------------------------------------------------------------------
# Main analysis workflow
# ---------------------------------------------------------------------------


def run_analysis(
    vulnerable_dir: Path,
    remediated_dir: Path,
) -> None:
    cve_db = load_cve_db(_CVE_DB_PATH)

    # ------------------------------------------------------------------
    # Phase 1: Parse vulnerable app
    # ------------------------------------------------------------------
    print_header("Phase 1 — Parse vulnerable Java project")
    vuln_engine = build_engine(vulnerable_dir)

    # ------------------------------------------------------------------
    # Phase 2: CVE matching
    # ------------------------------------------------------------------
    print_section("Phase 2 — Match imported packages against CVE database")

    imports = scan_imports(vulnerable_dir)
    print(f"  Detected Java imports ({len(imports)}):")
    for imp in sorted(imports):
        print(f"    {imp}")

    matched_cves = match_cves(imports, cve_db)
    matched_cves.sort(key=lambda c: SEVERITY_ORDER.get(c.get("severity", "INFO"), 99))

    if not matched_cves:
        print("  ✅  No known vulnerable packages detected.")
    else:
        print(f"\n  ⚠️  {len(matched_cves)} CVE(s) matched:\n")
        for cve in matched_cves:
            emoji = SEVERITY_EMOJI.get(cve["severity"], "⚪")
            print(
                f"  {emoji} [{cve['severity']}] {cve['cve']} — {cve['name']}\n"
                f"       Matched import             : {cve['matched_import']}\n"
                f"       Affects                    : {cve['affects_versions']}\n"
                f"       Fixed in                   : {cve['fixed_version']}\n"
                f"       CVSS score                 : {cve['cvss']}\n"
            )

    # ------------------------------------------------------------------
    # Phase 3: Call-graph tracing & annotation
    # ------------------------------------------------------------------
    print_section("Phase 3 — Trace call paths from HTTP entrypoints to vulnerable sinks")

    all_findings: list[dict[str, Any]] = []
    for cve in matched_cves:
        callers_map = find_vulnerable_callers(vuln_engine, cve)
        if not callers_map:
            print(
                f"  [{cve['cve']}] No reachable call paths found for "
                f"vulnerable calls: {cve.get('vulnerable_calls', [])}"
            )
            continue

        annotated = annotate_findings(vuln_engine, cve, callers_map)

        emoji = SEVERITY_EMOJI.get(cve["severity"], "⚪")
        print(f"\n  {emoji} {cve['cve']} — {cve['name']} [{cve['severity']}]")
        for call_pattern, paths in callers_map.items():
            print(f"\n    Vulnerable sink  : {call_pattern}")
            print(f"    Entrypoint paths : {len(paths)} path(s) found\n")
            for i, path in enumerate(paths[:5], 1):
                print(f"      Path {i}: {format_path(path)}")
            if len(paths) > 5:
                print(f"      ... and {len(paths) - 5} more path(s)")

        print(f"\n    Annotated {annotated} node(s) with FINDING on the graph.")
        all_findings.append(
            {
                "cve": cve,
                "callers": callers_map,
                "annotated_nodes": annotated,
            }
        )

    # ------------------------------------------------------------------
    # Phase 4: Preanalysis (blast radius, taint propagation)
    # ------------------------------------------------------------------
    print_section("Phase 4 — Preanalysis: blast radius & taint propagation")

    preanalysis_result = vuln_engine.preanalysis()
    br = preanalysis_result["blast_radius"]
    tp = preanalysis_result["taint_propagation"]
    ep = preanalysis_result["entrypoints"]

    print(
        f"  Blast radius  : {br['annotated_nodes']} nodes annotated, "
        f"max radius = {br['max_radius']}, "
        f"high-blast nodes = {br['high_blast_count']} (threshold ≥ {br['threshold']})"
    )
    print(
        f"  Taint spread  : {tp['tainted_nodes']} nodes reachable from "
        f"{tp['taint_sources']} untrusted entrypoint(s)"
    )
    print(
        f"  Entrypoints   : {ep['total_entrypoints']} total, "
        f"{ep['reachable_nodes']} reachable nodes"
    )
    print(f"  Trust breakdown: {ep['by_trust_level']}")

    # Show high-blast-radius nodes that are also findings
    high_blast = vuln_engine.subgraph("high_blast_radius")
    finding_nodes = vuln_engine.findings(kind=AnnotationKind.FINDING)
    finding_ids = {n["id"] for n in finding_nodes}
    high_blast_findings = [n for n in high_blast if n["id"] in finding_ids]
    if high_blast_findings:
        print("\n  ⚠️  High-blast-radius nodes that are ALSO on a vulnerable path:")
        for node in high_blast_findings:
            print(f"      {node['id']}  (kind={node['kind']}, cc={node['cyclomatic_complexity']})")

    # ------------------------------------------------------------------
    # Phase 5: Attack surface
    # ------------------------------------------------------------------
    print_section("Phase 5 — Attack surface")

    attack_surface = vuln_engine.attack_surface()
    if not attack_surface:
        print(
            "  No entrypoints detected (add Spring MVC annotations or .trailmark/entrypoints.toml)."
        )
    else:
        print(f"  {len(attack_surface)} detected entrypoint(s):\n")
        for ep in sorted(attack_surface, key=lambda e: e["node_id"]):
            print(
                f"    • {ep['node_id']}\n"
                f"      kind={ep['kind']}, trust={ep['trust_level']}, "
                f"asset_value={ep['asset_value']}"
            )

    # ------------------------------------------------------------------
    # Phase 6: Diff vulnerable vs remediated
    # ------------------------------------------------------------------
    print_section("Phase 6 — Diff: vulnerable vs. remediated")

    print(f"  Parsing remediated app: {remediated_dir}")
    rem_engine = build_engine(remediated_dir)

    diff = rem_engine.diff_against(vuln_engine)
    delta = diff.get("summary_delta", {})
    nodes_diff = diff.get("nodes", {})
    edges_diff = diff.get("edges", {})
    ep_diff = diff.get("entrypoints", {})

    print(f"\n  Node delta      : {delta}")
    print(f"  Nodes added     : {len(nodes_diff.get('added', []))}")
    print(f"  Nodes removed   : {len(nodes_diff.get('removed', []))}")
    print(f"  Nodes modified  : {len(nodes_diff.get('modified', []))}")
    print(f"  Edges added     : {len(edges_diff.get('added', []))}")
    print(f"  Edges removed   : {len(edges_diff.get('removed', []))}")
    print(
        f"  Entrypoints added/removed/modified: "
        f"{len(ep_diff.get('added', []))} / "
        f"{len(ep_diff.get('removed', []))} / "
        f"{len(ep_diff.get('modified', []))}"
    )

    # ------------------------------------------------------------------
    # Phase 7: Remediation report
    # ------------------------------------------------------------------
    print_header("Phase 7 — Remediation Report")

    if not all_findings:
        print("  ✅  No call-graph-reachable vulnerabilities found. Nothing to remediate.")
        return

    total_cves = len(all_findings)
    total_paths = sum(sum(len(paths) for paths in f["callers"].values()) for f in all_findings)
    print(
        f"  Summary: {total_cves} CVE(s) with reachable call paths "
        f"({total_paths} total path(s) from HTTP entrypoints)\n"
    )

    for finding in all_findings:
        cve = finding["cve"]
        emoji = SEVERITY_EMOJI.get(cve["severity"], "⚪")
        print(f"{emoji} {cve['cve']} — {cve['name']}  [{cve['severity']}  CVSS {cve['cvss']}]")
        print(f"   Import    : {cve['matched_import']}")
        print(f"   Affects   : {cve['affects_versions']}")
        print(f"   Fixed in  : {cve['fixed_version']}")
        print(f"   Fix       : {cve['remediation']}")
        print()

    print(_sep())
    print("  Next steps:")
    print("  1. Update pom.xml / build.gradle with the patched versions above.")
    print("  2. Re-run this script against the patched source tree to confirm")
    print("     call-graph paths to vulnerable sinks are gone.")
    print("  3. Review annotated findings in the graph (engine.findings()) for")
    print("     any business-logic paths that still flow through the affected API.")
    print(_sep())


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Trailmark PoC: Java 3rd-party library vulnerability finder"
    )
    parser.add_argument(
        "--vulnerable",
        type=Path,
        default=_DEFAULT_VULNERABLE,
        help="Path to the vulnerable Java source directory",
    )
    parser.add_argument(
        "--remediated",
        type=Path,
        default=_DEFAULT_REMEDIATED,
        help="Path to the remediated Java source directory",
    )
    return parser.parse_args()


def main() -> None:
    args = _parse_args()

    if not args.vulnerable.exists():
        print(f"ERROR: vulnerable directory not found: {args.vulnerable}", file=sys.stderr)
        sys.exit(1)
    if not args.remediated.exists():
        print(f"ERROR: remediated directory not found: {args.remediated}", file=sys.stderr)
        sys.exit(1)

    print("╔══════════════════════════════════════════════════════════════════════╗")
    print("║   Trailmark PoC — Java 3rd-Party Library Vulnerability Analysis      ║")
    print("╚══════════════════════════════════════════════════════════════════════╝")

    run_analysis(args.vulnerable, args.remediated)

    print("\n✅  Analysis complete.\n")


if __name__ == "__main__":
    main()
