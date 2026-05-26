"""
******************************************************************************
 * FILE:        /src/interfaces/report/fix_data.py
 * LAYER:       Interface Layer
 * MODULE:      Fix Suggestions Data
 * PURPOSE:     Mapping of constructs to fix suggestions and CWE references
 * DOMAIN:      Report
 * AUTHOR:      DCAVP Engineering System
 * CREATED:     2026-05-26
 * UPDATED:     2026-05-26
 * VERSION:     v0.4.0
 *
 * LICENSE: Apache-2.0 / Enterprise Extension
 ******************************************************************************
"""
# Fix data 
FIXES = { 
    "eval": "Replace with json.loads()", 
    "exec": "Remove", 
    "subprocess": "Pass args as list, shell=False", 
    "pickle.loads": "Use json.loads()", 
    "os.system": "Use subprocess.run()", 
    "yaml.load": "Use yaml.safe_load()", 
    "debug=True": "Remove before production", 
    "requests.get": "Restrict to trusted domains", 
    "os.remove": "Restrict to trusted dirs", 
    "random": "Use secrets module", 
    "sql_injection": "Use parameterized queries", 
    "open": "Use pathlib.Path().read_text()", 
    "ai_hallucinated_package": "Verify on PyPI", 
    "security_theater": "Use bcrypt.checkpw()", 
    "jwt_algorithm_none": "Verify JWT signature", 
    "crypto_ecb_mode": "Use AES.MODE_GCM", 
    "template_injection": "Never pass user input to templates", 
} 
CWE_MAP = { 
    "eval": "CWE-94", "exec": "CWE-94", 
    "subprocess": "CWE-78", "pickle.loads": "CWE-502", 
    "os.system": "CWE-78", "yaml.load": "CWE-502", 
    "debug=True": "CWE-489", "requests.get": "CWE-918", 
    "os.remove": "CWE-22", "random": "CWE-338", 
    "sql_injection": "CWE-89", "open": "CWE-22", 
    "ai_hallucinated_package": "CWE-1104", 
    "security_theater": "CWE-916", 
    "jwt_algorithm_none": "CWE-347", 
    "crypto_ecb_mode": "CWE-327", 
    "template_injection": "CWE-94", 
} 
