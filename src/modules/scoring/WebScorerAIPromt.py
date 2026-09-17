import json
from ai.ai import ia_realizar_consulta

def ia_priorizar_paginas_sqli_batch(pages_list: list, job_context: dict = None):
    """
    AI mode: freely assesses SQLi priority for a batch of pages without prescribed scoring rules.
    pages_list:  list of {id, url, base_url, is_admin_path, ...context fields...}
    job_context: optional {vulnerable: [{url, injection_types}], exploited: [{url, injection_types}]}
                 — pages already found vulnerable/exploited in this job, for richer context.
    Returns: list of {id, priority_score, priority_level, confidence, should_test, reasons}
    """
    json_pages = json.dumps(pages_list, ensure_ascii=False)

    context_section = ""
    if job_context:
        vuln_pages  = job_context.get('vulnerable', [])
        expl_pages  = job_context.get('exploited', [])
        if vuln_pages or expl_pages:
            ctx_lines = ["# KNOWN ATTACK SURFACE (same job, already confirmed)"]
            if expl_pages:
                ctx_lines.append(f"\nExploited pages ({len(expl_pages)} — SQLi fully confirmed and dumped):")
                for p in expl_pages:
                    itypes = ', '.join(p.get('injection_types') or []) or 'unknown'
                    ctx_lines.append(f"  - {p['url']}  [types: {itypes}]")
            if vuln_pages:
                ctx_lines.append(f"\nVulnerable pages ({len(vuln_pages)} — SQLi confirmed, not yet exploited):")
                for p in vuln_pages:
                    itypes = ', '.join(p.get('injection_types') or []) or 'unknown'
                    ctx_lines.append(f"  - {p['url']}  [types: {itypes}]")
            ctx_lines.append(
                "\nUse this context to calibrate scores: pages structurally similar to confirmed "
                "vulnerable/exploited ones (same path pattern, same parameter names, same application "
                "area) deserve higher priority. Pages in unrelated areas of the application may be "
                "deprioritised if the attack surface appears exhausted."
            )
            context_section = "\n".join(ctx_lines) + "\n\n"

    n = len(pages_list)
    prompt = f"""# ROLE
You are a senior web penetration tester with deep expertise in SQL Injection discovery and web application security.

# TASK
Analyze the following {n} web pages and assign each a SQL Injection testing priority based entirely on your security expertise.
You decide the criteria, the weighting, and the score — no fixed rules are imposed.

{context_section}# INPUT DATA ({n} pages to score):
{json_pages}

Each page contains these observable characteristics:
- id: page identifier (keep it in output)
- url: full URL of the page
- base_url: base URL of the application
- is_admin_path: the URL path suggests an administration area
- has_login_form: a login form is present
- has_register_form: a registration form is present
- has_search_form: a search form is present
- has_upload_form: a file upload form is present
- has_form_without_csrf: at least one form lacks CSRF protection
- has_errors: the page exposes error messages (strong SQLi indicator — error-based injection, stack traces, DB errors)
- has_parametres_url: parameters are embedded in the URL path
- is_referred_robots: the URL appears in robots.txt (often hides sensitive endpoints)
- has_get_params: the URL contains GET query parameters
- has_post_params: the page accepts POST parameters

# MANDATORY RESPONSE FORMAT
You MUST return a JSON object with a single key "pages" whose value is a vector (array) of exactly {n} elements — one per input page, in any order.
Do NOT return a bare array. Do NOT return a single page. Return the full object with all {n} pages inside "pages".
No Markdown, no explanation outside the JSON.

Each element of the "pages" vector must have:
- "id" (integer): copied from the input
- "priority_score" (integer 0-100): your overall SQLi risk score
- "priority_level" (string): "low", "medium", or "high"
- "confidence" (integer 0-100): how confident you are in this assessment
- "should_test" (boolean): whether this page warrants active SQLi testing
- "reasons" (array of strings): the main factors that drove your score up or down

# EXPECTED OUTPUT FORMAT (example with 2 pages)
{{
  "pages": [
    {{
      "id": 1,
      "priority_score": 87,
      "priority_level": "high",
      "confidence": 92,
      "should_test": true,
      "reasons": ["error messages exposed", "POST parameters present", "no CSRF on form"]
    }},
    {{
      "id": 2,
      "priority_score": 12,
      "priority_level": "low",
      "confidence": 85,
      "should_test": false,
      "reasons": ["static page", "no user input detected"]
    }}
  ]
}}"""

    accion = f"AI open-ended SQLi priority assessment for {n} pages"
    resultado_ia = ia_realizar_consulta(prompt, accion)

    # Accept both {"pages": [...]} (new format) and a bare list (fallback)
    if resultado_ia == -1:
        print("Error: AI returned an error.")
        return None
    if isinstance(resultado_ia, dict):
        resultado_ia = resultado_ia.get('pages', [])
    if not isinstance(resultado_ia, list) or len(resultado_ia) == 0:
        print("Error: AI response does not contain a valid pages vector.")
        return None

    print(f"\nAI Batch SQLi Priority — {len(resultado_ia)} results")
    for r in resultado_ia:
        print(f"  id={r.get('id')} score={r.get('priority_score')} level={r.get('priority_level')}")

    return resultado_ia