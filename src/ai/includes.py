# *******************************************
# INCLUDES
# *******************************************

# Equivalent to includes.php: imports the AI library and the specific functions.
# In Python this is done through the package; this file exists for parity with the
# PHP structure, but the real import is performed in each usage script.

from ai.ai import ia_realizar_consulta, ia_limpiar_json, ia_guardar_log_fichero  # noqa: F401
