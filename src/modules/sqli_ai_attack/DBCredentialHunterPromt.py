"""DBCredentialHunterPromt - offensive AI prompt removed.

This module used to build a language-model prompt that analysed a multi-database
structure to locate credential-bearing tables, infer password-hash schemes and
flag session/token hijacking vectors. That offensive prompt has been removed to
prevent the tool from being misused for attacks; the public entry point below is
kept as a stub so importers and callers keep working.
"""

from modules.sqli_ai_attack._base import offensive_prompt_removed_notice


def ia_obtener_credenciales_bases_de_datos(estructura_bd: dict):
    """Disabled stub: the offensive AI prompt for this capability was removed.

    Prints a warning explaining the removal and performs no analysis. The
    ``estructura_bd`` argument is accepted only to preserve the original
    signature. Returns ``None`` so callers report an empty (no-op) result.
    """
    offensive_prompt_removed_notice("database credential discovery")
    return None
