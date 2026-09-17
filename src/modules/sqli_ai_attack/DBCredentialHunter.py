#!/usr/bin/env python3
"""
DBCredentialHunter.py - AI location of credential tables.

Pattern: BaseModule (Template Method) over SqliAiAttackModule.
It filters the tables likely to contain credentials and asks the AI for an open
analysis of where they are and what hash type is likely.
The AI logic (previously in ia_funciones_especificas) now lives in this module.
"""

from __future__ import annotations

if __name__ == "__main__":
    import os
    import sys
    sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))

import re

from core import ModuleResult
from modules.sqli_ai_attack.DBCredentialHunterPromt import ia_obtener_credenciales_bases_de_datos
from modules.sqli_ai_attack._base import SqliAiAttackModule


class DBCredentialHunter(SqliAiAttackModule):
    slug = "db_credential_hunter"
    REQUIRE_DB = False  # if --db is not given, it analyzes all DBs

    TABLA_PATTERNS = [
        re.compile(r'.*_users?$',        re.IGNORECASE),
        re.compile(r'.*_accounts?$',     re.IGNORECASE),
        re.compile(r'.*_members?$',      re.IGNORECASE),
        re.compile(r'.*_admins?$',       re.IGNORECASE),
        re.compile(r'.*_logins?$',       re.IGNORECASE),
        re.compile(r'.*_auth.*',         re.IGNORECASE),
        re.compile(r'.*_sessions?$',     re.IGNORECASE),
        re.compile(r'.*_tokens?$',       re.IGNORECASE),
        re.compile(r'.*_passwords?$',    re.IGNORECASE),
        re.compile(r'.*_credentials?$',  re.IGNORECASE),
        re.compile(r'.*_api_keys?$',     re.IGNORECASE),
        re.compile(r'^users?$',          re.IGNORECASE),
        re.compile(r'^accounts?$',       re.IGNORECASE),
        re.compile(r'^members?$',        re.IGNORECASE),
        re.compile(r'^admins?$',         re.IGNORECASE),
        re.compile(r'^sessions?$',       re.IGNORECASE),
        re.compile(r'^tokens?$',         re.IGNORECASE),
    ]

    def run(self) -> ModuleResult:
        self.console.banner("🔑 DBCREDENTIALHUNTER - Credential search")
        self.console.plain(
            ("📦 DB: " + self.db_name) if self.db_name else "📦 Mode: ALL DBs"
        )

        resultado = ia_obtener_credenciales_bases_de_datos(self.bd_structure)
        if not resultado:
            return ModuleResult.empty(self.slug,
                                      "The AI did not return a credential analysis")
        return ModuleResult.ok(self.slug,
                               f"{len(resultado)} database(s) with probable credentials",
                               findings=len(resultado))


if __name__ == "__main__":
    result = DBCredentialHunter._cli(
        "Uses AI to locate the credential tables of the exploited DBs"
    ).execute()
    sys.exit(result.exit_code())
