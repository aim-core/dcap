"""
******************************************************************************
 * FILE:        /src/infrastructure/catalog/entries/python/constructs_extended.py
 * LAYER:       Infrastructure Layer
 * MODULE:      Extended Python Constructs
 * PURPOSE:     Additional security constructs (os.system, yaml.load, debug=True)
 * DOMAIN:      Catalog
 * AUTHOR:      DCAVP Engineering System
 * CREATED:     2026-05-23
 * UPDATED:     2026-05-23
 * VERSION:     v0.2.0
 *
 * LICENSE: Apache-2.0 / Enterprise Extension
 ******************************************************************************
"""
# -*- coding: utf-8 -*-
"""
Extended Python constructs for DCAVP.
OS System, YAML Load, Debug=True, and more.
"""

from src.domain.constructs.construct_model import (
    ConstructDefinition, DangerCondition, FixedWeight,
    KnowledgeCitation, RiskMapping, RiskType,
    Severity, Confidence, Tier, TierPermission, TierPermissionLevel,
    AnalysisBounds,
)

# Import shared utilities from parent
import src.infrastructure.catalog.entries.python.python_constructs as _pc

# ═══════════════════════════════════════════════════════════════════════════════
# CONST-SEC-002 — os.system()
# ═══════════════════════════════════════════════════════════════════════════════

OS_SYSTEM_CONSTRUCT = ConstructDefinition(
    construct_id="CONST-SEC-002",
    construct_name="os.system",
    catalog_version="2026.05.12",
    language="python",
    description="os.system() executes a shell command. CWE-78: OS Command Injection.",
    ast_node_types=("Call",),
    states=("dynamic_cmd", "constant_cmd"),
    danger_conditions=(
        _pc._dc("DC-001", "dynamic_cmd", Severity.CRITICAL.value, Confidence.CERTAIN.value,
            "os.system() with dynamic command enables shell injection (CWE-78).",
            "AST_PATTERN", "CWE-78", cwes=("CWE-78",)),
    ),
    acceptance_conditions=("no_os_system_present",),
    tier_permissions=_pc._all_tiers("Warn", "Error", "Block", "CRITICAL: block", b_esc="ERROR", r_esc="CRITICAL"),
    analysis_bounds=_pc._bounds(3, 0, 10, 10, "Cmd tracing: 3"),
    analysis_constraints=("CANNOT_TRACK_THROUGH_ENV",),
    risk_mappings=(_pc._rm(RiskType.CYBERSECURITY, 950, "Command injection (CWE-78)", "CWE-78"),),
    linked_policies=("POL-SEC-001",),
    linked_standards=("CWE-78",),
    knowledge_citations=(_pc._C_CWE78, _pc._C_OS_SYSTEM),
    human_review_triggers=("OS_SYSTEM_IN_WEB_REQUEST",),
    boundary_conditions=("COMMAND_FROM_ENVIRONMENT",),
)

# ═══════════════════════════════════════════════════════════════════════════════
# CONST-SEC-006 — yaml.load()
# ═══════════════════════════════════════════════════════════════════════════════

YAML_LOAD_CONSTRUCT = ConstructDefinition(
    construct_id="CONST-SEC-006",
    construct_name="yaml.load",
    catalog_version="2026.05.12",
    language="python",
    description="yaml.load() without SafeLoader enables code execution (CWE-502).",
    ast_node_types=("Call",),
    states=("default_loader",),
    danger_conditions=(
        _pc._dc("DC-001", "default_loader", Severity.CRITICAL.value, Confidence.CERTAIN.value,
            "yaml.load() without SafeLoader enables arbitrary code execution (CWE-502).",
            "AST_PATTERN", "CWE-502", cwes=("CWE-502",)),
    ),
    acceptance_conditions=("no_yaml_load",),
    tier_permissions=_pc._all_tiers("Warn", "Error", "Block", "CRITICAL: block", b_esc="ERROR", r_esc="CRITICAL"),
    analysis_bounds=_pc._bounds(2, 0, 10, 5, "Arg tracing: 2"),
    analysis_constraints=("CANNOT_DETECT_CUSTOM_LOADERS",),
    risk_mappings=(_pc._rm(RiskType.CYBERSECURITY, 940, "Deserialization attack (CWE-502)", "CWE-502"),),
    linked_policies=("POL-SEC-001",),
    linked_standards=("CWE-502",),
    knowledge_citations=(_pc._C_CWE502, _pc._C_YAML),
    human_review_triggers=("YAML_LOAD_WITH_USER_DATA",),
    boundary_conditions=("CUSTOM_LOADER_UNKNOWN",),
)

# ═══════════════════════════════════════════════════════════════════════════════
# CONST-SEC-007 — debug=True
# ═══════════════════════════════════════════════════════════════════════════════

DEBUG_TRUE_CONSTRUCT = ConstructDefinition(
    construct_id="CONST-SEC-007",
    construct_name="debug=True",
    catalog_version="2026.05.12",
    language="python",
    description="app.run(debug=True) enables Werkzeug debugger (CWE-489).",
    ast_node_types=("Call",),
    states=("debug_enabled",),
    danger_conditions=(
        _pc._dc("DC-001", "debug_enabled", Severity.CRITICAL.value, Confidence.CERTAIN.value,
            "Flask debug mode in production enables code execution (CWE-489).",
            "AST_PATTERN", "CWE-489", cwes=("CWE-489",)),
    ),
    acceptance_conditions=("no_debug_true",),
    tier_permissions=_pc._all_tiers("Warn", "Error", "Block", "CRITICAL: block", b_esc="ERROR", r_esc="CRITICAL"),
    analysis_bounds=_pc._bounds(1, 0, 10, 5, "Keyword check"),
    analysis_constraints=("CANNOT_DETECT_ENV_DEBUG",),
    risk_mappings=(_pc._rm(RiskType.CYBERSECURITY, 910, "Debug mode in production (CWE-489)", "CWE-489"),),
    linked_policies=("POL-SEC-001",),
    linked_standards=("CWE-489",),
    knowledge_citations=(_pc._C_CWE489, _pc._C_FLASK),
    human_review_triggers=("DEBUG_TRUE_IN_PRODUCTION",),
    boundary_conditions=("DEBUG_FROM_ENV",),
)

# ═══════════════════════════════════════════════════════════════════════════════
# ALL EXTENDED CONSTRUCTS
# ═══════════════════════════════════════════════════════════════════════════════

SSRF_CONSTRUCT = ConstructDefinition(
    construct_id="CONST-SEC-008",
    construct_name="requests.get",
    catalog_version="2026.05.12",
    language="python",
    description="requests.get() with user-controlled URL enables SSRF (CWE-918).",
    ast_node_types=("Call",),
    states=("user_controlled_url", "static_url"),
    danger_conditions=(
        _pc._dc("DC-001", "user_controlled_url", Severity.CRITICAL.value, Confidence.CERTAIN.value,
            "requests.get() with dynamic URL may enable SSRF attacks (CWE-918). Validate URLs against allowlist.",
            "AST_PATTERN", "CWE-918", cwes=("CWE-918",)),
    ),
    acceptance_conditions=("no_user_controlled_urls",),
    tier_permissions=_pc._all_tiers("Warn", "Error", "Block", "CRITICAL: block", b_esc="ERROR", r_esc="CRITICAL"),
    analysis_bounds=_pc._bounds(2, 0, 10, 5, "URL tracing: 2"),
    analysis_constraints=("CANNOT_VALIDATE_URL_AGAINST_ALLOWLIST",),
    risk_mappings=(_pc._rm(RiskType.CYBERSECURITY, 890, "SSRF via user-controlled URL (CWE-918)", "CWE-918"),),
    linked_policies=("POL-SEC-001",),
    linked_standards=("CWE-918",),
    knowledge_citations=(_pc._C_CWE918, _pc._C_REQUESTS),
    human_review_triggers=("SSRF_USER_URL",),
    boundary_conditions=("URL_FROM_EXTERNAL_SOURCE",),
)



SQL_INJECTION_CONSTRUCT = ConstructDefinition(
    construct_id="CONST-SEC-011",
    construct_name="sql_injection",
    catalog_version="2026.05.12",
    language="python",
    description="SQL execute() with dynamic query enables SQL injection (CWE-89).",
    ast_node_types=("Call",),
    states=("dynamic_query", "static_query"),
    danger_conditions=(
        _pc._dc("DC-001", "dynamic_query", Severity.CRITICAL.value, Confidence.CERTAIN.value,
            "SQL query built with string formatting enables SQL injection (CWE-89). Use parameterized queries.",
            "AST_PATTERN", "CWE-89", cwes=("CWE-89",)),
    ),
    acceptance_conditions=("parameterized_queries_only",),
    tier_permissions=_pc._all_tiers("Warn", "Error", "Block", "CRITICAL: block", b_esc="ERROR", r_esc="CRITICAL"),
    analysis_bounds=_pc._bounds(2, 0, 10, 5, "Query tracing: 2"),
    analysis_constraints=("CANNOT_DETECT_ORM_BASED_INJECTION",),
    risk_mappings=(_pc._rm(RiskType.CYBERSECURITY, 960, "SQL injection (CWE-89)", "CWE-89"),),
    linked_policies=("POL-SEC-001",),
    linked_standards=("CWE-89",),
    knowledge_citations=(_pc._cite("CWE-89","SQL Injection","2024-02-29","https://cwe.mitre.org/data/definitions/89.html"),),
    human_review_triggers=("SQL_INJECTION_DYNAMIC_QUERY",),
    boundary_conditions=(),
)


OS_REMOVE_CONSTRUCT = ConstructDefinition(
    construct_id="CONST-SEC-010",
    construct_name="os.remove",
    catalog_version="2026.05.12",
    language="python",
    description="os.remove() with dynamic path enables file deletion attacks.",
    ast_node_types=("Call",),
    states=("dynamic_path", "static_path"),
    danger_conditions=(
        _pc._dc("DC-001", "dynamic_path", Severity.CRITICAL.value, Confidence.CERTAIN.value,
            "os.remove() with dynamic path may delete arbitrary files. Validate paths.",
            "AST_PATTERN", "CWE-22", cwes=("CWE-22",)),
    ),
    acceptance_conditions=("no_dynamic_remove",),
    tier_permissions=_pc._all_tiers("Warn", "Error", "Block", "CRITICAL: block", b_esc="ERROR", r_esc="CRITICAL"),
    analysis_bounds=_pc._bounds(2, 0, 10, 5, "Path tracing: 2"),
    analysis_constraints=("CANNOT_VALIDATE_PATH",),
    risk_mappings=(_pc._rm(RiskType.CYBERSECURITY, 880, "File deletion via user path", "CWE-22"),),
    linked_policies=("POL-SEC-001",),
    linked_standards=("CWE-22",),
    knowledge_citations=(_pc._C_CWE78,),
    human_review_triggers=("DYNAMIC_FILE_DELETE",),
    boundary_conditions=(),
)


EXTENDED_CONSTRUCTS = (
    OS_SYSTEM_CONSTRUCT,
    YAML_LOAD_CONSTRUCT,
    DEBUG_TRUE_CONSTRUCT,
    SSRF_CONSTRUCT,
    OS_REMOVE_CONSTRUCT,
    SQL_INJECTION_CONSTRUCT,
)