import argparse
import sys
from pathlib import Path
from jinja2 import Environment, FileSystemLoader
from xhtml2pdf import pisa
from markupsafe import Markup, escape


import json
from ai.ai import ia_realizar_consulta
from modules.sqli_ai_attack.DBAdminInyector import ia_generar_sql_insertar_usuario_admin
from modules.sqli_ai_attack.DBCredentialHunter import ia_obtener_credenciales_bases_de_datos

IA_AVAILABLE=True

# Add project root to path to import database.py
sys.path.insert(0, str(Path(__file__).parent.parent))
from db.database import DatabaseManager

BASE_DIR = Path(__file__).parent
TEMPLATES_DIR = BASE_DIR / "templates"
OUTPUT_DIR = BASE_DIR / "output"
OUTPUT_DIR.mkdir(exist_ok=True)


def ia_generar_informe_ejecutivo_sqli(datos_informe: dict):
    json_datos_informe = json.dumps(datos_informe, ensure_ascii=False)

    prompt = f"""# ROLE
You are an expert in offensive cybersecurity and in writing executive reports for technical audits.

# TASK
Write a high-level executive report about a SQL Injection analysis.
The text must sound natural, professional, and specific to the case analysed, avoiding generic repetitive phrases.
ALL text values in the JSON output must be written in English.

# CONTEXT
The report has been generated from an automated analysis performed on a web testing or evaluation environment.
The goal is not to explain theory, but to synthesise the scope, findings and real impact observed.
Prioritise the most relevant information and emphasise what best describes the demonstrated risk.

# INPUT DATA (JSON):
{json_datos_informe}

# STRICT RESPONSE RULES
1. Reply EXCLUSIVELY with a JSON object.
2. Do not include Markdown code blocks (```json).
3. The JSON object must have a single root key called "informe_ejecutivo".
4. "informe_ejecutivo" must contain exactly these keys:
- "resumen_general" (string)
- "alcance" (string)
- "hallazgos_clave" (array of strings)
- "impacto_global" (string)
- "conclusion" (string)
5. Do not invent data.
6. Do not add remediation recommendations.
7. Do not explain technical theory.
8. Do not include payloads or detailed exploitation steps.
9. Do not copy literally any phrase from the output example.
10. Do not use generic formulations when you can use specific information from the case.
11. If there is a lot of data, select only the most representative items.
12. Use an executive, clear, professional and slightly more analytical than descriptive tone.
13. The text must be understandable to a non-technical person.
14. Write ALL string values in English.

# CUSTOMISATION GUIDELINES
- In "resumen_general", summarise the result with a sentence that reflects the magnitude of the case.
- In "alcance", mention the type of environment and the breadth of the analysis.
- In "hallazgos_clave", prioritise the elements that best describe the demonstrated risk.
- In "impacto_global", describe the main consequence observed.
- In "conclusion", close with a specific executive assessment, not a standard phrase.

# EXPECTED OUTPUT FORMAT
{{
  "informe_ejecutivo": {{
    "resumen_general": "The automated analysis validated a web exposure scenario with real SQL Injection exploitation capability, highlighting a broad attack surface and consistent results across multiple endpoints.",
    "alcance": "A web environment with multiple entry points was evaluated, combining reconnaissance, detection and exploitation validation tasks on sensitive forms and parameters.",
    "hallazgos_clave": [
      "Several vulnerable endpoints were identified with different input methods.",
      "Exploitation allowed enumeration of database structures and tables.",
      "Access to relevant schema metadata was observed.",
      "The detected behaviour confirms exposure in both GET and POST methods."
    ],
    "impacto_global": "The impact is high, as the validated vulnerability demonstrates the ability to extract information and perform detailed reconnaissance of the internal architecture.",
    "conclusion": "The analysed case reflects significant SQL Injection exposure and confirms a real risk to the confidentiality of stored information."
  }}
}}"""

    accion = "Generate SQL Injection exploitation executive report"
    resultado_ia = ia_realizar_consulta(prompt, accion)

    if resultado_ia == -1 or not isinstance(resultado_ia, dict) or 'informe_ejecutivo' not in resultado_ia:
        print("Error: The AI response does not have the expected format.")
        return

    informe = resultado_ia['informe_ejecutivo']

    print("\nSQL Injection Exploitation Executive Report")
    print("=============================================")

    print("\nGeneral Summary")
    print("----------------")
    print(informe['resumen_general'])

    print("\nScope")
    print("--------")
    print(informe['alcance'])

    print("\nKey Findings")
    print("----------------")
    for item in informe['hallazgos_clave']:
        print(f"- {item}")

    print("\nGlobal Impact")
    print("--------------")
    print(informe['impacto_global'])

    print("\nConclusion")
    print("----------")
    print(informe['conclusion'])

    return informe


def parse_args():
    parser = argparse.ArgumentParser(description="Generates the PDF report for a job")
    parser.add_argument(
        "--id",
        dest="job_id",
        type=int,
        help="ID of the job for which the report will be generated"
    )
    return parser.parse_args()

def render_template(template_name, context):
    env = Environment(
        loader=FileSystemLoader(TEMPLATES_DIR),
        autoescape=True
    )

    def url_break(url):
        """Splits URL at /, ? and & and force-breaks any remaining long tokens."""
        import re
        text = str(url)
        tokens = re.split(r'([/&?])', text)
        result = []
        for tok in tokens:
            if tok in ('/', '&', '?'):
                result.append(str(escape(tok)) + '<br/>')
            else:
                # break any token longer than 28 chars
                escaped_tok = str(escape(tok))
                if len(tok) > 28:
                    chunks = [escaped_tok[i:i+28] for i in range(0, len(escaped_tok), 28)]
                    result.append('<br/>'.join(chunks))
                else:
                    result.append(escaped_tok)
        return Markup(''.join(result))

    def force_break(text, width=28):
        """Inserts <br/> every `width` characters in tokens that have no natural break point."""
        if not text:
            return Markup('')
        result = []
        for token in str(text).split(' '):
            if len(token) > width:
                chunks = [str(escape(token[i:i+width])) for i in range(0, len(token), width)]
                result.append('<br/>'.join(chunks))
            else:
                result.append(str(escape(token)))
        return Markup(' '.join(result))

    env.filters['url_break']   = url_break
    env.filters['force_break'] = force_break
    template = env.get_template(template_name)
    return template.render(**context)


def generate_pdf_from_html(html_content, output_path):
    with open(output_path, "wb") as pdf_file:
        result = pisa.CreatePDF(src=html_content, dest=pdf_file)
    return result.err


def _normalize_job(job):
    if not job:
        return None

    timestamp = job.get("timestamp")
    if timestamp is not None:
        timestamp = str(timestamp)

    return {
        "id": job.get("id"),
        "type": job.get("type") or "",
        "model": job.get("model") or "",
        "target_url": job.get("target_url") or "",
        "timestamp": timestamp or "",
    }


def _build_bd_structure_from_exploitation(job_id):
    """Builds the {bases_de_datos: [{nombre, tablas:[{nombre,columnas}]}]} dict
    that DBCredentialHunter / DBAdminInyector expect, filtered by job."""
    import json as _json
    import re as _re

    TABLA_PATTERNS = [
        _re.compile(r'.*_users?$',       _re.IGNORECASE),
        _re.compile(r'.*_accounts?$',    _re.IGNORECASE),
        _re.compile(r'.*_members?$',     _re.IGNORECASE),
        _re.compile(r'.*_admins?$',      _re.IGNORECASE),
        _re.compile(r'.*_logins?$',      _re.IGNORECASE),
        _re.compile(r'.*_auth.*',        _re.IGNORECASE),
        _re.compile(r'.*_sessions?$',    _re.IGNORECASE),
        _re.compile(r'.*_tokens?$',      _re.IGNORECASE),
        _re.compile(r'.*_passwords?$',   _re.IGNORECASE),
        _re.compile(r'.*_credentials?$', _re.IGNORECASE),
        _re.compile(r'.*_roles?$',       _re.IGNORECASE),
        _re.compile(r'.*_permissions?$', _re.IGNORECASE),
        _re.compile(r'^users?$',         _re.IGNORECASE),
        _re.compile(r'^accounts?$',      _re.IGNORECASE),
        _re.compile(r'^members?$',       _re.IGNORECASE),
        _re.compile(r'^admins?$',        _re.IGNORECASE),
        _re.compile(r'^sessions?$',      _re.IGNORECASE),
        _re.compile(r'^tokens?$',        _re.IGNORECASE),
        _re.compile(r'^roles?$',         _re.IGNORECASE),
    ]

    def _is_relevant(t):
        return any(p.match(t) for p in TABLA_PATTERNS)

    try:
        tables_rows, cols_rows = DatabaseManager.get_exploit_schema_rows(job_id=job_id)
    except Exception as e:
        print(f"⚠️  Could not fetch DB structure for AI: {e}")
        return None

    # Build columns index
    cols_index = {}
    for row in cols_rows:
        etid  = row['sqli_exploit_tables_id']
        tname = row['table_name'] or ''
        try:
            cols = _json.loads(row['columns_json']) if isinstance(row['columns_json'], str) else (row['columns_json'] or [])
            if not isinstance(cols, list):
                cols = []
        except Exception:
            cols = []
        cols_index.setdefault(etid, {})[tname] = cols

    dbs_dict = {}
    for row in tables_rows:
        db_name = row['db_name'] or 'unknown'
        etid    = row['exploit_tables_id']
        try:
            tables = _json.loads(row['tables_json']) if isinstance(row['tables_json'], str) else (row['tables_json'] or [])
            if not isinstance(tables, list):
                tables = []
        except Exception:
            tables = []
        dbs_dict.setdefault(db_name, {})
        for tname in tables:
            if _is_relevant(tname):
                dbs_dict[db_name][tname] = cols_index.get(etid, {}).get(tname, [])

    databases = [
        {"nombre": db, "tablas": [{"nombre": t, "columnas": c} for t, c in tabs.items()]}
        for db, tabs in dbs_dict.items() if tabs
    ]
    return {"bases_de_datos": databases} if databases else None


def _format_credentials(result):
    """Formats ia_obtener_credenciales_bases_de_datos result as HTML."""
    if not result:
        return '<p style="color:#888">No credential analysis available.</p>'
    parts = []
    for bd in result:
        relevancia = bd.get('relevancia', '').upper()
        color = {'HIGH': '#c0392b', 'MEDIUM': '#d35400', 'LOW': '#27ae60'}.get(relevancia, '#555')
        parts.append(
            f'<p><strong style="color:{color}">[{relevancia}] {bd.get("base_de_datos","")} </strong> '
            f'— {bd.get("motivo_relevancia","")}</p>'
        )
        for entry in bd.get('tablas_credenciales_probables', []):
            users  = ', '.join(entry.get('campo_usuario', []))
            passw  = ', '.join(entry.get('campo_password', []))
            thash  = entry.get('tipo_hash_probable', 'unknown')
            parts.append(
                f'<p style="margin-left:12px">📋 <strong>{entry.get("tabla","")}</strong> '
                f'— user: <em>{users}</em> | password: <em>{passw}</em> [{thash}]</p>'
            )
        tokens = bd.get('tablas_tokens_sesiones', [])
        if tokens:
            parts.append(f'<p style="margin-left:12px">🔑 Tokens/Sessions: {escape(", ".join(tokens))}</p>')
        reuse = bd.get('riesgo_reutilizacion_credenciales', False)
        parts.append(f'<p style="margin-left:12px">Reuse risk: {"⚠️ YES" if reuse else "NO"} — {escape(bd.get("explicacion",""))}</p>')
    return Markup(''.join(parts))


def _format_admin_sql(result):
    """Formats ia_generar_sql_insertar_usuario_admin result as HTML."""
    if not result:
        return '<p style="color:#888">No admin SQL generation available.</p>'
    parts = []
    for bd in result:
        plat = bd.get('plataforma_detectada', 'unknown')
        parts.append(
            f'<p><strong>🎯 {escape(bd.get("base_de_datos",""))} </strong>'
            f'[{escape(plat)}] — table: <em>{escape(bd.get("tabla_objetivo",""))}</em></p>'
        )
        usr = bd.get('usuario_generado', {})
        parts.append(
            f'<p style="margin-left:12px">User: <strong>{escape(str(usr.get("username","")))}</strong> '
            f'/ Pass: <strong>{escape(str(usr.get("password_plain","")))}</strong> '
            f'[{escape(str(usr.get("tipo_hash","")))}]</p>'
        )
        for sql in bd.get('sentencias_sql', []):
            parts.append(f'<pre style="background:#1e1e1e;color:#d4d4d4;padding:6px 10px;border-radius:4px;font-size:7pt;white-space:pre-wrap;word-break:break-all;margin-left:12px">{escape(sql)}</pre>')
        for aux in bd.get('sentencias_sql_auxiliares', []):
            parts.append(f'<p style="margin-left:12px;color:#888">Aux table <em>{escape(aux.get("tabla",""))}</em>: {escape(aux.get("descripcion",""))}</p>')
            for sql in aux.get('sentencias', []):
                parts.append(f'<pre style="background:#1e1e1e;color:#d4d4d4;padding:6px 10px;border-radius:4px;font-size:7pt;white-space:pre-wrap;word-break:break-all;margin-left:24px">{escape(sql)}</pre>')
        if bd.get('notas'):
            parts.append(f'<p style="margin-left:12px;color:#888"><em>{escape(bd["notas"])}</em></p>')
    return Markup(''.join(parts))


def _build_ia_datos(job, metrics, ports, webs, findings, exploitation_results):
    """Builds the dict in the format expected by ia_generar_informe_ejecutivo_sqli."""
    def _to_list(val):
        if isinstance(val, list):
            return val
        if not val:
            return []
        return [x.strip() for x in str(val).split(',') if x.strip()]

    return {
        "job": job,
        "metrics": metrics,
        "ports": [
            {
                "host":    p.get('host', ''),
                "port":    p.get('port', ''),
                "state":   p.get('nmap_state', ''),
                "service": p.get('nmap_service', ''),
                "version": p.get('nmap_version', ''),
            }
            for p in ports
        ],
        "webs": [
            {
                "url":              w.get('url', ''),
                "technologies":     _to_list(w.get('technologies', '')),
                "cookies":          _to_list(w.get('cookies', '')),
                "headers":          _to_list(w.get('headers', '')),
                "uncommon_headers": _to_list(w.get('uncommon_headers', '')),
            }
            for w in webs
        ],
        "findings": [
            {
                "url":              f.get('url', ''),
                "method":           f.get('method', ''),
                "injection_points": _to_list(f.get('injection_points', '')),
                "injection_types":  _to_list(f.get('injection_types', '')),
            }
            for f in findings
        ],
        "exploitation_results": [
            {
                "db_name":      e.get('db_name', ''),
                "tables_count": e.get('tables_count', 0),
                "tables":       e.get('tables', []),
            }
            for e in exploitation_results
        ],
    }


def _format_summary(informe: dict) -> str:
    """Converts the dict returned by the AI into structured HTML for the PDF."""
    if not informe:
        return ''
    parts = []
    summary = informe.get('resumen_general') or informe.get('executive_summary')
    if summary:
        parts.append(f'<p><strong>Executive Summary</strong><br/>{summary}</p>')
    scope = informe.get('alcance') or informe.get('scope')
    if scope:
        parts.append(f'<p><strong>Scope</strong><br/>{scope}</p>')
    hallazgos = informe.get('hallazgos_clave') or informe.get('key_findings', [])
    if hallazgos:
        items = ''.join(f'<li>{h}</li>' for h in hallazgos)
        parts.append(f'<p><strong>Key Findings</strong></p><ul>{items}</ul>')
    impact = informe.get('impacto_global') or informe.get('global_impact')
    if impact:
        parts.append(f'<p><strong>Overall Impact</strong><br/>{impact}</p>')
    conclusion = informe.get('conclusion') or informe.get('conclusion_en')
    if conclusion:
        parts.append(f'<p><strong>Conclusion</strong><br/>{conclusion}</p>')
    return ''.join(parts)


def main():
    args = parse_args()

    raw_job = DatabaseManager.get_job(args.job_id) if args.job_id else DatabaseManager.get_latest_job()
    job = _normalize_job(raw_job)

    if not job:
        if args.job_id:
            print(f"Job with id={args.job_id} not found")
        else:
            print("No jobs available to generate the report")
        return 1

    job_id = job["id"]
    metrics              = DatabaseManager.get_report_metrics(job_id)
    ports                = DatabaseManager.get_report_ports(job_id)
    webs                 = DatabaseManager.get_report_webs(job_id)
    findings             = DatabaseManager.get_report_findings(job_id)
    exploitation_results = DatabaseManager.get_report_exploitation_results(job_id)
    activity_logs        = DatabaseManager.get_report_activity_logs(job_id)

    # Call the AI to generate the executive summary
    is_ia_job = (job.get('type', '') == 'IA')
    summary_ai = ''
    if IA_AVAILABLE and is_ia_job:
        try:
            import json as _json
            from decimal import Decimal

            class _DecimalEncoder(_json.JSONEncoder):
                def default(self, o):
                    if isinstance(o, Decimal):
                        return int(o) if o == o.to_integral_value() else float(o)
                    return super().default(o)

            datos_ia = _build_ia_datos(job, metrics, ports, webs, findings, exploitation_results)
            # Normalize Decimals by round-tripping through JSON
            datos_ia = _json.loads(_json.dumps(datos_ia, cls=_DecimalEncoder))
            informe = ia_generar_informe_ejecutivo_sqli(datos_ia)
            summary_ai = _format_summary(informe)
        except Exception as e:
            print(f"⚠️  Could not generate AI summary: {e}")
    if not summary_ai and is_ia_job:
        summary_ai = "Could not generate executive summary."

    # --- Credential Hunter & Admin Injector IA sections ---
    ia_credentials_html = ''
    ia_admin_sql_html   = ''
    if IA_AVAILABLE and is_ia_job:
        bd_structure = _build_bd_structure_from_exploitation(job_id)
        if bd_structure:
            try:
                cred_result = ia_obtener_credenciales_bases_de_datos(bd_structure)
                ia_credentials_html = _format_credentials(cred_result)
            except Exception as e:
                print(f"⚠️  Credential Hunter AI error: {e}")
                ia_credentials_html = f'<p style="color:#c0392b">Error: {e}</p>'
            try:
                admin_result = ia_generar_sql_insertar_usuario_admin(bd_structure)
                ia_admin_sql_html = _format_admin_sql(admin_result)
            except Exception as e:
                print(f"⚠️  Admin Injector AI error: {e}")
                ia_admin_sql_html = f'<p style="color:#c0392b">Error: {e}</p>'
        else:
            ia_credentials_html = '<p style="color:#888">No exploited DB data found for this job.</p>'
            ia_admin_sql_html   = '<p style="color:#888">No exploited DB data found for this job.</p>'


    data = {
        "titulo": "SQL Injection Exploitation Technical Report",
        "job": job,
        "is_ia_job": is_ia_job,
        "summary_ai": summary_ai,
        "metrics": metrics,
        "ports": ports,
        "webs": webs,
        "findings": findings,
        "exploitation_results": exploitation_results,
        "activity_logs": activity_logs,
        "ia_credentials_html": ia_credentials_html,
        "ia_admin_sql_html": ia_admin_sql_html,
    }

    html = render_template("report.html", data)

    fecha = job["timestamp"].replace(" ", "_").replace(":", "-").replace("/", "-")[:19]
    output_pdf = OUTPUT_DIR / f"report_job{job_id}_{fecha}.pdf"

    error = generate_pdf_from_html(html, output_pdf)

    if error:
        print("Error generating the PDF")
    else:
        print(f"PDF generated successfully: {output_pdf}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
