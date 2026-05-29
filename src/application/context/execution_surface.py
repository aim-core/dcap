"""
******************************************************************************
 * FILE:        /src/application/context/execution_surface.py
 * LAYER:       Application Layer
 * MODULE:      Execution Surface Mapper
 * PURPOSE:     Map execution surfaces by tracking proximity of sources to sinks
 * DOMAIN:      Context
 * AUTHOR:      DCAP Engineering
 * CREATED:     2026-05-29
 * UPDATED:     2026-05-29
 * VERSION:     v0.6.0
 *
 * LICENSE: Apache-2.0 / Enterprise Extension
 ******************************************************************************
"""

SINKS = {"eval", "exec", "subprocess.run", "subprocess.call", "os.system", "pickle.loads", "open"}

def map_execution_surface(findings: list[dict]) -> list[dict]:
    surfaces = []
    tainted = [f for f in findings if "TAINTED" in f.get("state","") or any(s in f.get("state","") for s in ("dynamic_arg", "dynamic_cmd", "external_source_arg"))]
    sinks = [f for f in findings if f.get("construct") in SINKS]
    for t in tainted:
        for s in sinks:
            loc_t = t.get("location","").split(":")[0]
            loc_s = s.get("location","").split(":")[0]
            if loc_t == loc_s:
                surfaces.append({
                    "source": t.get("construct", "unknown"),
                    "sink": s.get("construct", "unknown"),
                    "file": loc_t,
                    "risk_radius": "HIGH" if s.get("severity") == "critical" else "MEDIUM",
                    "chain": f"{t.get('construct','')} -> {s.get('construct','')}"
                })
    return surfaces