"""sqli_ai_attack - AI-assisted DB post-exploitation.

The three modules share the lifecycle of `SqliAiAttackModule` (a subclass of
`BaseModule`):

    - db_schema_analyzer   (DBSchemaAnalyzer)   -> route to a privileged user
    - db_credential_hunter (DBCredentialHunter) -> credential tables
    - db_admin_inyector    (DBAdminInyector)    -> admin-insertion SQL

Importing the classes is done defensively: if the AI layer is not available
(missing config, dependencies not installed...), the package remains
importable instead of blowing up.
"""

try:  # noqa: SIM105
    from modules.sqli_ai_attack._base import SqliAiAttackModule
    from modules.sqli_ai_attack.DBSchemaAnalyzer import DBSchemaAnalyzer
    from modules.sqli_ai_attack.DBCredentialHunter import DBCredentialHunter
    from modules.sqli_ai_attack.DBAdminInyector import DBAdminInyector

    __all__ = [
        "SqliAiAttackModule",
        "DBSchemaAnalyzer",
        "DBCredentialHunter",
        "DBAdminInyector",
    ]
except Exception as _exc:  # noqa: BLE001
    import warnings
    warnings.warn(f"sqli_ai_attack: could not register the AI modules: {_exc}")
    __all__ = []
