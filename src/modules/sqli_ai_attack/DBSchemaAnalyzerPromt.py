"""DBSchemaAnalyzerPromt - offensive AI prompt removed.

This module used to build a language-model prompt that inferred, per database,
the structural path toward a highly privileged user. That offensive prompt has
been removed to prevent the tool from being misused for attacks; the public
entry point below is kept as a stub so importers and callers keep working.
"""

from modules.sqli_ai_attack._base import offensive_prompt_removed_notice


def ia_analizar_estructura_bd_para_usuario_privilegiado(estructura_bd: dict):
    """Disabled stub: the offensive AI prompt for this capability was removed.

    Prints a warning explaining the removal and performs no analysis. The
    ``estructura_bd`` argument is accepted only to preserve the original
    signature. Always returns ``None``.
    """
    offensive_prompt_removed_notice("privileged-user database structure analysis")
    return None
