#!/usr/bin/env python3
"""
DBSchemaAnalyzer.py - AI analysis of the structure of an already-exploited DB.

Pattern: BaseModule (Template Method) over SqliAiAttackModule.
It locates the users / roles / permissions tables of ONE specific database
and passes them to the AI to infer the route toward a privileged user.
The AI logic (previously in ia_funciones_especificas) now lives in this module.
"""

from __future__ import annotations

if __name__ == "__main__":
    import os
    import sys
    sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))

import re

from core import ModuleResult
from modules.sqli_ai_attack.DBSchemaAnalyzerPromt import ia_analizar_estructura_bd_para_usuario_privilegiado
from modules.sqli_ai_attack._base import SqliAiAttackModule


class DBSchemaAnalyzer(SqliAiAttackModule):
    slug = "db_schema_analyzer"
    REQUIRE_DB = True  # schema analysis operates on a specific DB

    TABLA_PATTERNS = [
        re.compile(r'.*_users?$',        re.IGNORECASE),
        re.compile(r'.*_groups?$',       re.IGNORECASE),
        re.compile(r'.*_roles?$',        re.IGNORECASE),
        re.compile(r'.*_permissions?$',  re.IGNORECASE),
        re.compile(r'.*_user_groups?$',  re.IGNORECASE),
        re.compile(r'.*_user_roles?$',   re.IGNORECASE),
        re.compile(r'.*_auth.*',         re.IGNORECASE),
        re.compile(r'.*_rights?$',       re.IGNORECASE),
        re.compile(r'.*_accounts?$',     re.IGNORECASE),
        re.compile(r'.*_members?$',      re.IGNORECASE),
        re.compile(r'.*_admins?$',       re.IGNORECASE),
        re.compile(r'.*_logins?$',       re.IGNORECASE),
        re.compile(r'.*_acl.*',          re.IGNORECASE),
        re.compile(r'.*_privileges?$',   re.IGNORECASE),
        re.compile(r'^users?$',          re.IGNORECASE),
        re.compile(r'^groups?$',         re.IGNORECASE),
        re.compile(r'^roles?$',          re.IGNORECASE),
        re.compile(r'^accounts?$',       re.IGNORECASE),
        re.compile(r'^members?$',        re.IGNORECASE),
        re.compile(r'^admins?$',         re.IGNORECASE),
    ]

    def run(self) -> ModuleResult:
        self.console.banner("🧭 DBSCHEMAANALYZER - Structure analysis")
        self.console.plain(f"📦 DB: {self.db_name}"
                           + (f"  🧾 job {self.job_id}" if self.job_id else ""))

        # The offensive AI prompt for this capability has been removed; the call
        # below only prints a warning and performs no analysis.
        ia_analizar_estructura_bd_para_usuario_privilegiado(self.bd_structure)
        return ModuleResult.empty(
            self.slug,
            f"AI structure analysis disabled (offensive prompt removed) for '{self.db_name}'",
        )


if __name__ == "__main__":
    result = DBSchemaAnalyzer._cli(
        "Uses AI to analyze a DB's structure to locate privileged users"
    ).execute()
    sys.exit(result.exit_code())
