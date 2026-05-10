# Java 3rd-Party Library Vulnerability PoC

This example demonstrates how to use **Trailmark** to find and remediate
third-party library vulnerabilities in a Java Spring Boot application by
building a call graph, tracing attack paths from HTTP entrypoints to
vulnerable library sinks, and diffing a patched version against the original.

## Vulnerabilities demonstrated

| CVE | Name | Library | CVSS |
|-----|------|---------|------|
| CVE-2021-44228 | Log4Shell | log4j-core 2.14.1 | 10.0 |
| CVE-2021-45046 | Log4Shell bypass | log4j-core 2.15.0 | 9.0 |
| CVE-2022-42889 | Text4Shell | commons-text 1.9 | 9.8 |
| CVE-2022-42003 | Jackson resource exhaustion | jackson-databind 2.13.3 | 7.5 |
| CVE-2022-42004 | Jackson resource exhaustion (2) | jackson-databind 2.13.3 | 7.5 |
| CVE-2022-22965 | Spring4Shell | Spring Boot 2.6.3 | 9.8 |

## Project layout

```
java-vuln-poc/
  vulnerable-app/       # Spring Boot app with intentionally vulnerable dependencies
    pom.xml             # Maven config with vulnerable library versions
    src/main/java/
      VulnApp.java      # Application entry point
      controller/
        UserController.java   # Spring MVC REST endpoints (HTTP entrypoints)
      service/
        UserService.java      # Jackson deserialization (CVE-2022-42003/42004)
        ReportService.java    # Commons-Text StringSubstitutor (Text4Shell)
      util/
        LoggingUtil.java      # Log4j logger calls (Log4Shell)

  remediated-app/       # Same app with all dependencies patched
    pom.xml             # Patched library versions
    src/main/java/      # Same structure; code-level fixes where applicable

  analysis/
    analyze.py          # Trailmark analysis script (the main PoC driver)
    cve_database.json   # Static CVE records keyed by import prefix
```

## How it works

The analysis script (`analysis/analyze.py`) runs seven phases:

```
Phase 1 — Parse          Parse Java source → Trailmark CodeGraph
Phase 2 — CVE match      Cross-reference graph.dependencies against CVE DB
Phase 3 — Path tracing   entrypoint_paths_to(vulnerable_sink) for each CVE
Phase 4 — Preanalysis    blast_radius, taint_propagation, privilege_boundary
Phase 5 — Attack surface Enumerate Spring MVC endpoints as untrusted entrypoints
Phase 6 — Diff           diff_against() to compare vulnerable vs. remediated
Phase 7 — Report         Human-readable remediation summary
```

### Key Trailmark APIs used

| API | Purpose |
|-----|---------|
| `QueryEngine.from_directory(path, language="java")` | Parse Java source into a call graph |
| `engine.summary()` | Get node counts, call edges, imported packages |
| `engine.attack_surface()` | List Spring MVC endpoints tagged as HTTP entrypoints |
| `engine.entrypoint_paths_to(sink)` | Trace call paths from HTTP endpoints to a vulnerable method |
| `engine.annotate(node, FINDING, description)` | Mark a node as a finding on the graph |
| `engine.findings()` | Retrieve all annotated findings |
| `engine.preanalysis()` | Run blast-radius, taint, and privilege-boundary passes |
| `engine.subgraph("high_blast_radius")` | Nodes with the most downstream impact |
| `rem_engine.diff_against(vuln_engine)` | Structural diff: nodes/edges/entrypoints added or removed |

## Running the PoC

**Prerequisites:** Python ≥ 3.12, [uv](https://docs.astral.sh/uv/).

```bash
# From the repository root — install Trailmark and its dependencies
uv sync --all-groups

# Run the full analysis (defaults to the bundled vulnerable/remediated apps)
uv run python examples/java-vuln-poc/analysis/analyze.py
```

To point the script at different directories:

```bash
uv run python examples/java-vuln-poc/analysis/analyze.py \
    --vulnerable path/to/your/project/src \
    --remediated path/to/your/patched/project/src
```

## Expected output (abbreviated)

```
╔══════════════════════════════════════════════════════════════════════╗
║   Trailmark PoC — Java 3rd-Party Library Vulnerability Analysis      ║
╚══════════════════════════════════════════════════════════════════════╝

════════════════════════════════════════════════════════════════════════
  Phase 1 — Parse vulnerable Java project
════════════════════════════════════════════════════════════════════════
  Parsing: .../vulnerable-app/src/main/java
  Graph: 14 nodes, 12 call edges, 3 entrypoints detected

────────────────────────────────────────────────────────────────────────
  Phase 2 — Match imported packages against CVE database
────────────────────────────────────────────────────────────────────────
  Detected import prefixes: ['java', 'org', 'com', 'springframework']

  ⚠️  6 CVE(s) matched:

  🔴 [CRITICAL] CVE-2021-44228 — Log4Shell
       Matched package prefix : org
       Affects                : 2.0-beta9 to 2.14.1
       Fixed in               : 2.17.1
       CVSS score             : 10.0
  ...

────────────────────────────────────────────────────────────────────────
  Phase 3 — Trace call paths from HTTP entrypoints to vulnerable sinks
────────────────────────────────────────────────────────────────────────

  🔴 CVE-2021-44228 — Log4Shell [CRITICAL]

    Vulnerable sink  : logger.info
    Entrypoint paths : 2 path(s) found

      Path 1: controller/UserController:getUser → util/LoggingUtil:logAccess → logger.info
      Path 2: controller/UserController:importUser → util/LoggingUtil:logError → logger.error

    Annotated 6 node(s) with FINDING on the graph.
  ...

════════════════════════════════════════════════════════════════════════
  Phase 7 — Remediation Report
════════════════════════════════════════════════════════════════════════

  Summary: 3 CVE(s) with reachable call paths (7 total path(s) from HTTP entrypoints)

🔴 CVE-2021-44228 — Log4Shell  [CRITICAL  CVSS 10.0]
   Package   : org
   Affects   : 2.0-beta9 to 2.14.1
   Fixed in  : 2.17.1
   Fix       : Upgrade log4j-core to 2.17.1 or later. ...
  ...
```

## Remediation guidance

Each vulnerability has a specific fix reflected in `remediated-app/pom.xml`:

| Library | Vulnerable | Patched |
|---------|-----------|---------|
| `log4j-core` | 2.14.1 | **2.17.2** |
| `commons-text` | 1.9 | **1.10.0** |
| `jackson-databind` | 2.13.3 | **2.13.4.2** |
| `spring-boot-starter-parent` | 2.6.3 | **2.6.6** |

Code-level changes in the remediated app:

- `UserService.deserializeUser`: return type narrowed from `Object` to `Map<String, Object>`;
  `enableDefaultTyping` removed.
- `UserController.importUser`: error log no longer passes raw user payload to the logger.

## Extending the PoC

- **Add more CVEs**: extend `analysis/cve_database.json` with additional import
  prefixes and vulnerable call patterns.
- **Integrate SARIF**: run a static analyser (e.g. SpotBugs, Semgrep) and pass
  the output to `engine.augment_sarif("results.sarif")` to merge external
  findings into the Trailmark graph.
- **Custom entrypoints**: if your framework is not auto-detected, add
  `.trailmark/entrypoints.toml` to the project root (see the main README for
  syntax).
- **Automate in CI**: wrap `analyze.py` in a GitHub Actions step; fail the
  build when `all_findings` is non-empty.
