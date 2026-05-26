"""
******************************************************************************
 * FILE:        /src/infrastructure/catalog/entries/python/constructs_extended.py
 * LAYER:       Infrastructure Layer
 * MODULE:      Extended Python Security Constructs
 * PURPOSE:     11 extended security constructs for DCAVP v0.4.0
 * DOMAIN:      Catalog
 * AUTHOR:      DCAVP Engineering System
 * CREATED:     2026-05-25
 * UPDATED:     2026-05-25
 * VERSION:     v0.4.0
 *
 * LICENSE: Apache-2.0 / Enterprise Extension
 ******************************************************************************
"""

import sys
import pathlib as _pl
sys.path.insert(0, str(_pl.Path(__file__).parent.parent.parent.parent.parent))

from src.infrastructure.catalog.entries.python.python_constructs import (
    _cite, _dc, _rm, _bounds, _all_tiers,
    _C_CWE78, _C_OS_SYSTEM, _C_CWE502, _C_YAML,
    _C_CWE489, _C_FLASK, _C_CWE918, _C_REQUESTS,
    _C_CWE89, _C_SQLITE,
)
from src.domain.constructs.construct_model import (
    ConstructDefinition, RiskType, Severity, Confidence,
)

# ═══════════════════════════════════════════════════
# 1. OS_SYSTEM — CONST-SEC-002
# ═══════════════════════════════════════════════════
OS_SYSTEM_CONSTRUCT = ConstructDefinition(
    construct_id="CONST-SEC-002", construct_name="os.system",
    catalog_version="2026.05.12", language="python",
    description="os.system() executes shell commands. CWE-78.",
    ast_node_types=("Call",), states=("dynamic_cmd", "constant_cmd"),
    danger_conditions=(
        _dc("DC-001", "dynamic_cmd", Severity.CRITICAL.value, Confidence.CERTAIN.value,
            "os.system() with dynamic command enables shell injection. Use subprocess.run([cmd], shell=False).",
            "AST_PATTERN", "CWE-78", cwes=("CWE-78",)),
        _dc("DC-003", "constant_cmd", Severity.WARNING.value, Confidence.CERTAIN.value,
            "os.system() with constant string — replace with subprocess.run().",
            "AST_PATTERN", "CWE-78", cwes=("CWE-78",)),
    ),
    acceptance_conditions=("no_os_system_present",),
    tier_permissions=_all_tiers("Warn", "Error", "Block", "CRITICAL: block", b_esc="ERROR", r_esc="CRITICAL"),
    analysis_bounds=_bounds(3, 0, 10, 10, "Cmd tracing: 3"),
    analysis_constraints=("CANNOT_TRACK_THROUGH_ENV",),
    risk_mappings=(_rm(RiskType.CYBERSECURITY, 950, "Command injection (CWE-78)", "CWE-78"),),
    linked_policies=("POL-SEC-001",), linked_standards=("CWE-78",),
    knowledge_citations=(_C_CWE78, _C_OS_SYSTEM),
    human_review_triggers=("OS_SYSTEM_IN_WEB_REQUEST",), boundary_conditions=("COMMAND_FROM_ENVIRONMENT",),
)

# ═══════════════════════════════════════════════════
# 2. YAML_LOAD — CONST-SEC-006
# ═══════════════════════════════════════════════════
YAML_LOAD_CONSTRUCT = ConstructDefinition(
    construct_id="CONST-SEC-006", construct_name="yaml.load",
    catalog_version="2026.05.12", language="python",
    description="yaml.load() without SafeLoader. CWE-502.",
    ast_node_types=("Call",), states=("default_loader", "safe_loader"),
    danger_conditions=(
        _dc("DC-001", "default_loader", Severity.ERROR.value, Confidence.CERTAIN.value,
            "yaml.load() without SafeLoader may enable code execution. Use yaml.safe_load().",
            "AST_PATTERN", "CWE-502", cwes=("CWE-502",)),
    ),
    acceptance_conditions=("no_yaml_load_with_default_loader",),
    tier_permissions=_all_tiers("Warn", "Error", "Block", "CRITICAL: block", b_esc="ERROR", r_esc="CRITICAL"),
    analysis_bounds=_bounds(2, 0, 10, 5, "Arg tracing: 2"),
    analysis_constraints=("CANNOT_DETECT_CUSTOM_LOADERS",),
    risk_mappings=(_rm(RiskType.CYBERSECURITY, 940, "Deserialization (CWE-502)", "CWE-502"),),
    linked_policies=("POL-SEC-001",), linked_standards=("CWE-502",),
    knowledge_citations=(_C_CWE502, _C_YAML),
    human_review_triggers=("YAML_LOAD_WITH_USER_DATA",), boundary_conditions=("CUSTOM_LOADER_UNKNOWN",),
)

# ═══════════════════════════════════════════════════
# 3. DEBUG_TRUE — CONST-SEC-007
# ═══════════════════════════════════════════════════
DEBUG_TRUE_CONSTRUCT = ConstructDefinition(
    construct_id="CONST-SEC-007", construct_name="debug=True",
    catalog_version="2026.05.12", language="python",
    description="Flask debug mode in production. CWE-489.",
    ast_node_types=("Call",), states=("debug_enabled",),
    danger_conditions=(
        _dc("DC-001", "debug_enabled", Severity.WARNING.value, Confidence.CERTAIN.value,
            "app.run(debug=True) exposes debug console. Remove before production.",
            "AST_PATTERN", "CWE-489", cwes=("CWE-489",)),
    ),
    acceptance_conditions=("no_debug_true_in_production",),
    tier_permissions=_all_tiers("Warn", "Error", "Block", "CRITICAL: block", b_esc="ERROR", r_esc="CRITICAL"),
    analysis_bounds=_bounds(1, 0, 10, 5, "Keyword check"),
    analysis_constraints=("CANNOT_DETECT_ENV_BASED_DEBUG",),
    risk_mappings=(_rm(RiskType.CYBERSECURITY, 910, "Debug mode (CWE-489)", "CWE-489"),),
    linked_policies=("POL-SEC-001",), linked_standards=("CWE-489",),
    knowledge_citations=(_C_CWE489, _C_FLASK),
    human_review_triggers=("DEBUG_TRUE_IN_PRODUCTION",), boundary_conditions=("DEBUG_FROM_ENV",),
)

# ═══════════════════════════════════════════════════
# 4. SSRF — CONST-SEC-008
# ═══════════════════════════════════════════════════
SSRF_CONSTRUCT = ConstructDefinition(
    construct_id="CONST-SEC-008", construct_name="requests.get",
    catalog_version="2026.05.12", language="python",
    description="requests.get() with user URL. CWE-918.",
    ast_node_types=("Call",), states=("user_controlled_url", "static_url"),
    danger_conditions=(
        _dc("DC-001", "user_controlled_url", Severity.ERROR.value, Confidence.CERTAIN.value,
            "requests.get() with dynamic URL may enable SSRF. Validate URLs against allowlist.",
            "AST_PATTERN", "CWE-918", cwes=("CWE-918",)),
        _dc("DC-004", "static_url", Severity.WARNING.value, Confidence.CERTAIN.value,
            "requests.get() with static URL — verify domain is trusted.",
            "AST_PATTERN", "CWE-918", cwes=("CWE-918",)),
    ),
    acceptance_conditions=("no_user_controlled_urls",),
    tier_permissions=_all_tiers("Warn", "Error", "Block", "CRITICAL: block", b_esc="ERROR", r_esc="CRITICAL"),
    analysis_bounds=_bounds(2, 0, 10, 5, "URL tracing: 2"),
    analysis_constraints=("CANNOT_VALIDATE_URL",),
    risk_mappings=(_rm(RiskType.CYBERSECURITY, 890, "SSRF (CWE-918)", "CWE-918"),),
    linked_policies=("POL-SEC-001",), linked_standards=("CWE-918",),
    knowledge_citations=(_C_CWE918, _C_REQUESTS),
    human_review_triggers=("SSRF_USER_URL",), boundary_conditions=("URL_FROM_EXTERNAL",),
)

# ═══════════════════════════════════════════════════
# 5. OS_REMOVE — CONST-SEC-010
# ═══════════════════════════════════════════════════
OS_REMOVE_CONSTRUCT = ConstructDefinition(
    construct_id="CONST-SEC-010", construct_name="os.remove",
    catalog_version="2026.05.12", language="python",
    description="os.remove() with dynamic path. CWE-22.",
    ast_node_types=("Call",), states=("dynamic_path", "static_path"),
    danger_conditions=(
        _dc("DC-001", "dynamic_path", Severity.ERROR.value, Confidence.CERTAIN.value,
            "os.remove() with dynamic path may delete arbitrary files. Validate paths.",
            "AST_PATTERN", "CWE-22", cwes=("CWE-22",)),
        _dc("DC-005", "static_path", Severity.WARNING.value, Confidence.CERTAIN.value,
            "os.remove() with static path — verify path is intended.",
            "AST_PATTERN", "CWE-22", cwes=("CWE-22",)),
    ),
    acceptance_conditions=("no_dynamic_remove",),
    tier_permissions=_all_tiers("Warn", "Error", "Block", "CRITICAL: block", b_esc="ERROR", r_esc="CRITICAL"),
    analysis_bounds=_bounds(2, 0, 10, 5, "Path tracing: 2"),
    analysis_constraints=("CANNOT_VALIDATE_PATH",),
    risk_mappings=(_rm(RiskType.CYBERSECURITY, 880, "File deletion (CWE-22)", "CWE-22"),),
    linked_policies=("POL-SEC-001",), linked_standards=("CWE-22",),
    knowledge_citations=(_C_CWE78,), human_review_triggers=("DYNAMIC_FILE_DELETE",), boundary_conditions=(),
)

# ═══════════════════════════════════════════════════
# 6. SQL_INJECTION — CONST-SEC-011
# ═══════════════════════════════════════════════════
SQL_INJECTION_CONSTRUCT = ConstructDefinition(
    construct_id="CONST-SEC-011", construct_name="sql_injection",
    catalog_version="2026.05.12", language="python",
    description="SQL execute() with dynamic query. CWE-89.",
    ast_node_types=("Call",), states=("dynamic_query", "static_query"),
    danger_conditions=(
        _dc("DC-001", "dynamic_query", Severity.CRITICAL.value, Confidence.CERTAIN.value,
            "SQL query built with string formatting enables SQL injection. Use parameterized queries.",
            "AST_PATTERN", "CWE-89", cwes=("CWE-89",)),
    ),
    acceptance_conditions=("parameterized_queries_only",),
    tier_permissions=_all_tiers("Warn", "Error", "Block", "CRITICAL: block", b_esc="ERROR", r_esc="CRITICAL"),
    analysis_bounds=_bounds(2, 0, 10, 5, "Query tracing: 2"),
    analysis_constraints=("CANNOT_DETECT_ORM_INJECTION",),
    risk_mappings=(_rm(RiskType.CYBERSECURITY, 960, "SQL injection (CWE-89)", "CWE-89"),),
    linked_policies=("POL-SEC-001",), linked_standards=("CWE-89",),
    knowledge_citations=(_C_CWE89, _C_SQLITE),
    human_review_triggers=("SQL_INJECTION_DYNAMIC_QUERY",), boundary_conditions=(),
)

# ═══════════════════════════════════════════════════
# 7. PACKAGE_HALLUCINATION — CONST-AIHALL-001
# ═══════════════════════════════════════════════════
PACKAGE_HALLUCINATION_CONSTRUCT = ConstructDefinition(
    construct_id="CONST-AIHALL-001", construct_name="ai_hallucinated_package",
    catalog_version="2026.05.12", language="python",
    description="AI-hallucinated package import — not on PyPI.",
    ast_node_types=("Import", "ImportFrom"), states=("package_not_found",),
    danger_conditions=(
        _dc("DC-001", "package_not_found", Severity.CRITICAL.value, Confidence.CERTAIN.value,
            "Package does not exist on PyPI. May be AI hallucination or typosquatting target.",
            "AST_PATTERN", "CWE-1104", cwes=("CWE-1104",)),
    ),
    acceptance_conditions=("all_imports_verified",),
    tier_permissions=_all_tiers("Warn", "Error", "Block", "CRITICAL: block", b_esc="ERROR", r_esc="CRITICAL"),
    analysis_bounds=_bounds(1, 0, 50, 50, "PyPI verification"),
    analysis_constraints=("REQUIRES_NETWORK",),
    risk_mappings=(_rm(RiskType.CYBERSECURITY, 980, "Hallucinated package", "CWE-1104"),),
    linked_policies=("POL-SEC-001",), linked_standards=("CWE-1104",),
    knowledge_citations=(_cite("CWE-1104","Unmaintained Components","2024-02-29","https://cwe.mitre.org"),),
    human_review_triggers=("AI_HALLUCINATED_PACKAGE",), boundary_conditions=("NETWORK_UNAVAILABLE",),
)

# ═══════════════════════════════════════════════════
# 8. SECURITY_THEATER — CONST-AI-001
# ═══════════════════════════════════════════════════
SECURITY_THEATER_CONSTRUCT = ConstructDefinition(
    construct_id="CONST-AI-001", construct_name="security_theater",
    catalog_version="2026.05.12", language="python",
    description="Insecure hash comparison. CWE-916.",
    ast_node_types=("Compare",), states=("insecure_hash_compare",),
    danger_conditions=(
        _dc("DC-001", "insecure_hash_compare", Severity.ERROR.value, Confidence.CERTAIN.value,
            "Password compared using hash function. Use bcrypt.checkpw().",
            "AST_PATTERN", "CWE-916", cwes=("CWE-916",)),
    ),
    acceptance_conditions=("constant_time_comparison_used",),
    tier_permissions=_all_tiers("Warn", "Error", "Block", "CRITICAL: block", b_esc="ERROR", r_esc="CRITICAL"),
    analysis_bounds=_bounds(1, 0, 10, 5, "Pattern match"), analysis_constraints=(),
    risk_mappings=(_rm(RiskType.CYBERSECURITY, 940, "Security theater (CWE-916)", "CWE-916"),),
    linked_policies=("POL-SEC-001",), linked_standards=("CWE-916",),
    knowledge_citations=(_cite("CWE-916","Password Hashing","2024-02-29","https://cwe.mitre.org"),),
    human_review_triggers=("SECURITY_THEATER",), boundary_conditions=(),
)

# ═══════════════════════════════════════════════════
# 9. JWT_NONE — CONST-JWT-001
# ═══════════════════════════════════════════════════
JWT_NONE_ALG_CONSTRUCT = ConstructDefinition(
    construct_id="CONST-JWT-001", construct_name="jwt_algorithm_none",
    catalog_version="2026.05.12", language="python",
    description="JWT decoded with verify_signature=False. CWE-347.",
    ast_node_types=("Call",), states=("signature_bypassed",),
    danger_conditions=(
        _dc("DC-001", "signature_bypassed", Severity.ERROR.value, Confidence.CERTAIN.value,
            "JWT signature verification disabled. Attacker can forge tokens.",
            "AST_PATTERN", "CWE-347", cwes=("CWE-347",)),
    ),
    acceptance_conditions=("jwt_signature_verified",),
    tier_permissions=_all_tiers("Warn", "Error", "Block", "CRITICAL: block", b_esc="ERROR", r_esc="CRITICAL"),
    analysis_bounds=_bounds(1, 0, 10, 5, "Keyword check"), analysis_constraints=(),
    risk_mappings=(_rm(RiskType.CYBERSECURITY, 950, "JWT bypass (CWE-347)", "CWE-347"),),
    linked_policies=("POL-SEC-001",), linked_standards=("CWE-347",),
    knowledge_citations=(_cite("CWE-347","Signature Verification","2024-02-29","https://cwe.mitre.org"),),
    human_review_triggers=("JWT_SIGNATURE_BYPASS",), boundary_conditions=(),
)

# ═══════════════════════════════════════════════════
# 10. CRYPTO_ECB — CONST-CRYPTO-001
# ═══════════════════════════════════════════════════
CRYPTO_ECB_CONSTRUCT = ConstructDefinition(
    construct_id="CONST-CRYPTO-001", construct_name="crypto_ecb_mode",
    catalog_version="2026.05.12", language="python",
    description="AES in ECB mode. CWE-327.",
    ast_node_types=("Call",), states=("ecb_mode_detected",),
    danger_conditions=(
        _dc("DC-001", "ecb_mode_detected", Severity.ERROR.value, Confidence.CERTAIN.value,
            "AES ECB mode reveals data patterns. Use AES.MODE_GCM.",
            "AST_PATTERN", "CWE-327", cwes=("CWE-327",)),
    ),
    acceptance_conditions=("no_ecb_mode",),
    tier_permissions=_all_tiers("Warn", "Error", "Block", "CRITICAL: block", b_esc="ERROR", r_esc="CRITICAL"),
    analysis_bounds=_bounds(1, 0, 10, 5, "Pattern match"), analysis_constraints=(),
    risk_mappings=(_rm(RiskType.CYBERSECURITY, 880, "ECB mode (CWE-327)", "CWE-327"),),
    linked_policies=("POL-SEC-001",), linked_standards=("CWE-327",),
    knowledge_citations=(_cite("CWE-327","Broken Crypto","2024-02-29","https://cwe.mitre.org"),),
    human_review_triggers=("CRYPTO_ECB",), boundary_conditions=(),
)

# ═══════════════════════════════════════════════════
# 11. TEMPLATE_INJECTION — CONST-SSTI-001
# ═══════════════════════════════════════════════════
TEMPLATE_INJECTION_CONSTRUCT = ConstructDefinition(
    construct_id="CONST-SSTI-001", construct_name="template_injection",
    catalog_version="2026.05.12", language="python",
    description="render_template_string with user input. CWE-94.",
    ast_node_types=("Call",), states=("user_controlled_template",),
    danger_conditions=(
        _dc("DC-001", "user_controlled_template", Severity.CRITICAL.value, Confidence.CERTAIN.value,
            "Template injection via render_template_string enables RCE.",
            "AST_PATTERN", "CWE-94", cwes=("CWE-94",)),
    ),
    acceptance_conditions=("no_user_controlled_templates",),
    tier_permissions=_all_tiers("Warn", "Error", "Block", "CRITICAL: block", b_esc="ERROR", r_esc="CRITICAL"),
    analysis_bounds=_bounds(1, 0, 10, 5, "Pattern match"), analysis_constraints=(),
    risk_mappings=(_rm(RiskType.CYBERSECURITY, 960, "SSTI (CWE-94)", "CWE-94"),),
    linked_policies=("POL-SEC-001",), linked_standards=("CWE-94",),
    knowledge_citations=(_cite("CWE-94","Code Injection","2024-02-29","https://cwe.mitre.org"),),
    human_review_triggers=("SSTI_TEMPLATE_INJECTION",), boundary_conditions=(),
)

# ═══════════════════════════════════════════════════
# ALL EXTENDED CONSTRUCTS
# ═══════════════════════════════════════════════════
EXTENDED_CONSTRUCTS = (
    OS_SYSTEM_CONSTRUCT,
    YAML_LOAD_CONSTRUCT,
    DEBUG_TRUE_CONSTRUCT,
    SSRF_CONSTRUCT,
    OS_REMOVE_CONSTRUCT,
    SQL_INJECTION_CONSTRUCT,
    PACKAGE_HALLUCINATION_CONSTRUCT,
    SECURITY_THEATER_CONSTRUCT,
    JWT_NONE_ALG_CONSTRUCT,
    CRYPTO_ECB_CONSTRUCT,
    TEMPLATE_INJECTION_CONSTRUCT,
)