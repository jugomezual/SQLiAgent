"""
DBAdminInyector.py - AI generation of admin-user insertion SQL.

Pattern: BaseModule (Template Method) over SqliAiAttackModule.
Over the detected users/roles tables, it asks the AI for the SQL statements
to insert (or promote) an administrator user according to the schema.
The AI logic (previously in ia_funciones_especificas) now lives in this module.
"""

from __future__ import annotations

if __name__ == "__main__":
    import os
    import sys
    sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))

import re

from core import ModuleResult
from modules.sqli_ai_attack.DBAdminInyectorPromt import ia_generar_sql_insertar_usuario_admin
from modules.sqli_ai_attack._base import SqliAiAttackModule


class DBAdminInyector(SqliAiAttackModule):
    slug = "db_admin_inyector"
    REQUIRE_DB = False  # if --db is not given, it operates on all DBs

    TABLA_PATTERNS = [
        re.compile(r'.*_users?$',        re.IGNORECASE),
        re.compile(r'.*_accounts?$',     re.IGNORECASE),
        re.compile(r'.*_members?$',      re.IGNORECASE),
        re.compile(r'.*_admins?$',       re.IGNORECASE),
        re.compile(r'.*_logins?$',       re.IGNORECASE),
        re.compile(r'.*_auth.*',         re.IGNORECASE),
        re.compile(r'.*_roles?$',        re.IGNORECASE),
        re.compile(r'.*_groups?$',       re.IGNORECASE),
        re.compile(r'.*_permissions?$',  re.IGNORECASE),
        re.compile(r'.*_user_roles?$',   re.IGNORECASE),
        re.compile(r'.*_user_groups?$',  re.IGNORECASE),
        re.compile(r'.*_usermeta$',      re.IGNORECASE),
        re.compile(r'^users?$',          re.IGNORECASE),
        re.compile(r'^accounts?$',       re.IGNORECASE),
        re.compile(r'^members?$',        re.IGNORECASE),
        re.compile(r'^admins?$',         re.IGNORECASE),
        re.compile(r'^roles?$',          re.IGNORECASE),
        re.compile(r'^groups?$',         re.IGNORECASE),
    ]

    def run(self) -> ModuleResult:
        self.console.banner("🛠️  DBADMININYECTOR - Admin SQL generation")
        self.console.plain(
            ("📦 DB: " + self.db_name) if self.db_name else "📦 Mode: ALL DBs"
        )

        resultado = ia_generar_sql_insertar_usuario_admin(self.bd_structure)
        if not resultado:
            return ModuleResult.empty(self.slug,
                                      "The AI did not return valid SQL statements")
        return ModuleResult.ok(self.slug,
                               f"SQL generated for {len(resultado)} database(s)",
                               findings=len(resultado))


if __name__ == "__main__":
    result = DBAdminInyector._cli(
        "Uses AI to generate the admin-user insertion SQL statements"
    ).execute()
    sys.exit(result.exit_code())
