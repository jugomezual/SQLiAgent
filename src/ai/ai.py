# *************************************************
# AI Library v1.1
# (c) Julio Gómez López - UALTECH - UAL
# *************************************************
# Platform-specific functions (previously in ia_funciones_especificas.py)
# now live alongside each module that uses them: modules/scoring/WebScorerAIPromt.py,
# modules/sqli_ai_attack/DB*Promt.py.

import json
import time
import re
import logging
import os
import requests
from datetime import datetime
from urllib.parse import urlparse

from dotenv import load_dotenv

# *************************************************
# AI configuration — read from the repo root's .env:
#   IA_MODELO         model to use (the backend is chosen by prefix/port)
#   IA_API_KEY        Gemini API key (gemini-* models)
#   IA_LLAMA_API_URL  Ollama (:11434) or OpenWebUI (:8080) endpoint
#   IA_LLAMA_API_KEY  OpenWebUI API key
# *************************************************
load_dotenv()


# *************************************************
# GENERAL FUNCTIONS
# *************************************************

def ia_realizar_consulta(prompt: str, accion: str):
    inicio = time.time()
    fecha_hora = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    modelo = os.getenv('IA_MODELO', '')

    servidor = ''
    if modelo.startswith('gemini'):
        servidor = 'gemini'
    else:
        llama_api_url = os.getenv('IA_LLAMA_API_URL', '')
        if llama_api_url:
            parsed = urlparse(llama_api_url)
            servidor = parsed.hostname or 'unknown'

    # PERFORM THE QUERY
    if modelo.startswith('gemini'):
        # If the model starts with "gemini", call the Gemini function
        respuesta_ia = gemini_realizar_consulta(prompt)
    else:
        # Check the apiURL to see which model it is
        api_url = os.getenv('IA_LLAMA_API_URL', '')
        if ':8080' in api_url:
            # OpenWebUI / OpenAI format
            respuesta_ia = llama_realizar_consulta_openwebui(prompt)
        elif ':11434' in api_url:
            # Ollama direct
            respuesta_ia = llama_realizar_consulta_ollama(prompt)
        else:
            respuesta_ia = {'resultado': -1, 'tokens': {}, 'respuesta_cruda': 'URL not recognized'}

    resultado      = respuesta_ia['resultado']
    tokens         = respuesta_ia['tokens']
    respuesta_cruda = respuesta_ia.get('respuesta_cruda', '')

    fin = time.time()
    tiempo_ejecucion = fin - inicio

    resultado_log = "Error" if (resultado == -1 or resultado == "Modelo no soportado") else "Success"

    # For the version with DB:
    # ia_guardar_log_bd(servidor, accion, modelo, fecha_hora, tiempo_ejecucion,
    #                   -1 if resultado_log == "Error" else 1, tokens)

    # Save log to file
    if resultado_log == "Error" and respuesta_cruda:
        resultado_para_log = f"ERROR. Full AI response:\n{respuesta_cruda}"
    else:
        resultado_para_log = (
            json.dumps(resultado, ensure_ascii=False, indent=2)
            if isinstance(resultado, (dict, list))
            else str(resultado)
        )

    ia_guardar_log_fichero(
        servidor, accion, prompt, resultado_para_log,
        modelo, fecha_hora, tiempo_ejecucion, resultado_log, tokens
    )

    return resultado


# *************************************************
# GEMINI
# *************************************************

def gemini_realizar_consulta(prompt: str) -> dict:
    # You can see all available models with:
    # https://generativelanguage.googleapis.com/v1beta/models?key=YOUR_API_KEY
    # the model used is indicated in the URL

    # Initialize the tokens dictionary
    tokens = {
        'tokens_prompt':       0,
        'tokens_razonamiento': 0,
        'tokens_respuesta':    0,
        'tokens_total':        0,
    }

    try:
        # GET THE API KEY
        api_key = os.getenv('IA_API_KEY', '')
        modelo  = os.getenv('IA_MODELO', '')

        # Currently supported models:
        # modelo = "gemini-2.5-pro"
        # modelo = "gemini-2.5-flash"

        url = f"https://generativelanguage.googleapis.com/v1beta/models/{modelo}:generateContent"

        data = {
            'contents': [
                {'parts': [{'text': prompt}]}
            ],
            'generationConfig': {
                'responseMimeType': 'application/json',
                'temperature': 0.1,
            }
        }

        headers = {
            'Content-Type': 'application/json',
            'x-goog-api-key': api_key,
        }

        # Execute
        response = requests.post(url, json=data, headers=headers, timeout=60000, verify=False)
        http_code = response.status_code
        response_text = response.text

        # In response we have:
        #   ['usageMetadata']                                -->  processing statistics
        #   ['candidates'][0]['content']['parts'][0]['text'] --> AI response

        # Get the response
        if http_code != 200:
            logging.error(f"Error calling the Gemini API. Code: {http_code}. Response: {response_text}")
            print(f"Error communicating with the API (Code: {http_code})")
            return {'resultado': -1, 'tokens': tokens, 'respuesta_cruda': response_text}

        try:
            respuesta_api = response.json()
        except Exception:
            logging.error(f"API response is not valid JSON: {response_text}")
            print("The API response is not valid JSON.")
            return {'resultado': -1, 'tokens': tokens, 'respuesta_cruda': response_text}

        if 'error' in respuesta_api:
            error_message = respuesta_api['error'].get('message', 'Unknown error in the API')
            logging.error(f"Error in the Gemini API: {error_message}")
            print(f"Error in the Gemini API: {error_message}")
            return {'resultado': -1, 'tokens': tokens, 'respuesta_cruda': response_text}

        # Extract the tokens
        usage = respuesta_api.get('usageMetadata', {})
        if usage:
            tokens['tokens_prompt']       = usage.get('promptTokenCount', 0)
            tokens['tokens_razonamiento'] = usage.get('thoughtsTokenCount', 0)
            tokens['tokens_respuesta']    = usage.get('candidatesTokenCount', 0)
            tokens['tokens_total']        = usage.get('totalTokenCount', 0)

        contenido_texto = (
            respuesta_api.get('candidates', [{}])[0]
            .get('content', {})
            .get('parts', [{}])[0]
            .get('text', '')
        )

        if not contenido_texto:
            logging.error(f"Gemini response empty or with unexpected format: {response_text}")
            print("The Gemini response is empty or has an unexpected format.")
            return {'resultado': -1, 'tokens': tokens, 'respuesta_cruda': response_text}

        # Clean and extract the JSON robustly
        json_limpio = ia_limpiar_json(contenido_texto)
        try:
            resultado_ia = json.loads(json_limpio)
        except json.JSONDecodeError:
            error_message = "The content of the Gemini response is not valid JSON."
            logging.error(f"{error_message} Response received: {json_limpio}")
            print(f"{error_message}")
            print(f"Response received:\n{json_limpio}")
            return {'resultado': -1, 'tokens': tokens, 'respuesta_cruda': response_text}

        return {'resultado': resultado_ia, 'tokens': tokens, 'respuesta_cruda': response_text}

    except Exception as e:
        logging.error(f"Exception in ia_realizar_consulta: {e}")
        print("An exception occurred on the server during the AI query.")
        return {'resultado': -1, 'tokens': tokens, 'respuesta_cruda': f'Exception: {e}'}


# *************************************************
# LLAMA-SPECIFIC FUNCTIONS
# *************************************************

def llama_realizar_consulta_ollama(prompt: str, options: dict = None) -> dict:
    # Initialize the tokens dictionary
    tokens = {
        'tokens_prompt':       0,
        'tokens_razonamiento': 0,
        'tokens_respuesta':    0,
        'tokens_total':        0,
    }

    try:
        # Configuration of the Llama request
        api_url = os.getenv('IA_LLAMA_API_URL', '')
        modelo  = os.getenv('IA_MODELO', '')

        # stream=True: Ollama sends tokens one by one, preventing the TCP connection
        # from going completely silent during generation (a cause of ETIMEDOUT
        # in slow models like gemma3:12b that can take >30s).
        data = {
            'model':  modelo,
            'prompt': prompt,
            'stream': True,
            'format': 'json',   # <--- So it responds with JSON only
            'options': {
                'temperature': 0.2,
                'num_ctx':     8192,
            }
        }

        headers = {'Content-Type': 'application/json'}

        response = requests.post(api_url, json=data, headers=headers, timeout=300, stream=True)
        http_code = response.status_code

        if http_code != 200:
            response_text = response.text
            logging.error(f"Error calling the Llama API. Code: {http_code}. Response: {response_text}")
            print(f"Error communicating with the Llama API (Code: {http_code})")
            return {'resultado': -1, 'tokens': tokens, 'respuesta_cruda': response_text}

        # Accumulate the stream chunks until done=true is received
        contenido_texto = ''
        ultimo_chunk    = {}
        raw_lines       = []

        for line in response.iter_lines():
            if not line:
                continue
            decoded = line.decode('utf-8') if isinstance(line, bytes) else line
            raw_lines.append(decoded)
            try:
                chunk = json.loads(decoded)
            except json.JSONDecodeError:
                continue
            if chunk.get('error'):
                error_message = chunk['error']
                logging.error(f"Error in the Llama API (stream): {error_message}")
                print(f"Error in the Llama API: {error_message}")
                return {'resultado': -1, 'tokens': tokens, 'respuesta_cruda': decoded}
            contenido_texto += chunk.get('response', '')
            if chunk.get('done'):
                ultimo_chunk = chunk
                break

        response_text = '\n'.join(raw_lines)

        # Extract the tokens from the final chunk
        tokens['tokens_prompt']    = ultimo_chunk.get('prompt_eval_count', 0)
        tokens['tokens_respuesta'] = ultimo_chunk.get('eval_count', 0)
        tokens['tokens_total']     = tokens['tokens_prompt'] + tokens['tokens_respuesta']

        if not contenido_texto:
            logging.error(f"Llama response empty or with unexpected format: {response_text}")
            print("The Llama response is empty or has an unexpected format.")
            return {'resultado': -1, 'tokens': tokens, 'respuesta_cruda': response_text}

        # Clean and extract the JSON robustly
        json_limpio = ia_limpiar_json(contenido_texto)
        try:
            resultado_ia = json.loads(json_limpio)
        except json.JSONDecodeError:
            error_message = "The content of the Llama response is not valid JSON."
            logging.error(f"{error_message} Response received: {json_limpio}")
            print(f"{error_message}")
            print(f"Response received:\n{json_limpio}")
            return {'resultado': -1, 'tokens': tokens, 'respuesta_cruda': response_text}

        return {'resultado': resultado_ia, 'tokens': tokens, 'respuesta_cruda': response_text}

    except Exception as e:
        logging.error(f"Exception in llama_realizar_consulta: {e}")
        print("An exception occurred on the server during the AI query (Llama).")
        return {'resultado': -1, 'tokens': tokens, 'respuesta_cruda': f'Exception: {e}'}


def llama_realizar_consulta_openwebui(prompt: str, options: dict = None) -> dict:
    # Initialize the tokens dictionary
    tokens = {
        'tokens_prompt':       0,
        'tokens_razonamiento': 0,   # Not available in this API
        'tokens_respuesta':    0,
        'tokens_total':        0,
    }

    try:
        # Configuration of the Llama request (OpenAI/Chat Completions format)
        modelo  = os.getenv('IA_MODELO', '')
        api_url = os.getenv('IA_LLAMA_API_URL', '')
        api_key = os.getenv('IA_LLAMA_API_KEY', '')

        headers = {
            'Authorization': f'Bearer {api_key}',
            'Content-Type':  'application/json',
        }

        # stream=True: prevents the TCP connection from going silent during
        # generation of slow models, avoiding ETIMEDOUT at ~30s.
        data = {
            'model': modelo,
            'messages': [
                {'role': 'user', 'content': prompt}
            ],
            'format': 'json',   # <--- So it responds with JSON only
            'stream': True,
        }

        response = requests.post(api_url, json=data, headers=headers, timeout=300, stream=True)
        http_code = response.status_code

        if http_code != 200:
            response_text = response.text
            logging.error(f"Error calling the Llama API. Code: {http_code}. Response: {response_text}")
            print(f"Error communicating with the Llama API (Code: {http_code})")
            return {'resultado': -1, 'tokens': tokens, 'respuesta_cruda': response_text}

        # Accumulate the SSE chunks (OpenAI format: "data: {...}")
        contenido_texto = ''
        raw_lines       = []

        for line in response.iter_lines():
            if not line:
                continue
            decoded = line.decode('utf-8') if isinstance(line, bytes) else line
            raw_lines.append(decoded)
            if not decoded.startswith('data: '):
                continue
            data_str = decoded[6:]
            if data_str == '[DONE]':
                break
            try:
                chunk = json.loads(data_str)
            except json.JSONDecodeError:
                continue
            if 'error' in chunk:
                error_val = chunk['error']
                error_message = (
                    json.dumps(error_val)
                    if isinstance(error_val, (dict, list))
                    else str(error_val or 'Unknown error in the Llama API')
                )
                logging.error(f"Error in the Llama API (stream): {error_message}")
                print(f"Error in the Llama API: {error_message}")
                return {'resultado': -1, 'tokens': tokens, 'respuesta_cruda': decoded}
            delta = chunk.get('choices', [{}])[0].get('delta', {}).get('content', '')
            contenido_texto += delta
            # The usage chunk arrives in the last message before [DONE]
            if chunk.get('usage'):
                usage = chunk['usage']
                tokens['tokens_prompt']    = usage.get('prompt_tokens', 0)
                tokens['tokens_respuesta'] = usage.get('completion_tokens', 0)
                tokens['tokens_total']     = usage.get('total_tokens', 0)

        response_text = '\n'.join(raw_lines)

        if 'error' in response_text[:200]:
            try:
                respuesta_api = json.loads(raw_lines[0]) if raw_lines else {}
                if 'error' in respuesta_api:
                    error_val = respuesta_api['error']
                    error_message = (
                        json.dumps(error_val)
                        if isinstance(error_val, (dict, list))
                        else str(error_val or 'Unknown error in the Llama API')
                    )
                    logging.error(f"Error in the Llama API: {error_message}")
                    print(f"Error in the Llama API: {error_message}")
                    return {'resultado': -1, 'tokens': tokens, 'respuesta_cruda': response_text}
            except Exception:
                pass

        if not contenido_texto:
            logging.error(f"Llama response empty or with unexpected format: {response_text}")
            print("The Llama response is empty or has an unexpected format.")
            return {'resultado': -1, 'tokens': tokens, 'respuesta_cruda': response_text}

        # Clean and extract the JSON robustly
        json_limpio = ia_limpiar_json(contenido_texto)
        try:
            resultado_ia = json.loads(json_limpio)
        except json.JSONDecodeError:
            error_message = "The content of the Llama response is not valid JSON."
            logging.error(f"{error_message} Response received: {json_limpio}")
            print(f"{error_message}")
            print(f"Response received:\n{json_limpio}")
            return {'resultado': -1, 'tokens': tokens, 'respuesta_cruda': response_text}

        return {'resultado': resultado_ia, 'tokens': tokens, 'respuesta_cruda': response_text}

    except Exception as e:
        logging.error(f"Exception in llama_realizar_consulta: {e}")
        print("An exception occurred on the server during the AI query (Llama).")
        return {'resultado': -1, 'tokens': {}, 'respuesta_cruda': f'Exception: {e}'}


# *************************************************
# JSON UTILITIES
# *************************************************

def ia_limpiar_json(json_string: str) -> str:
    if not json_string:
        return ""

    # 1. Remove markdown code blocks if present
    match = re.search(r'```(?:json)?\s*(.*?)\s*```', json_string, re.DOTALL)
    if match:
        json_string = match.group(1)

    # 2. Safely remove the UTF-8 BOM if present
    json_string = json_string.replace('﻿', '')

    # 3. Remove control characters (0-31 and 127) in a UTF-8-safe way
    json_string = re.sub(r'[\x00-\x1F\x7F]', '', json_string)

    # 3. Extract only what is between the first { or [ and the last } or ]
    inicio_json  = json_string.find('{')
    inicio_array = json_string.find('[')

    if inicio_json == -1 and inicio_array == -1:
        # Doesn't look like JSON, return as-is so json.loads fails and it gets logged
        return json_string.strip()

    if inicio_json != -1 and (inicio_array == -1 or inicio_json < inicio_array):
        inicio = inicio_json
        fin    = json_string.rfind('}')
    else:
        inicio = inicio_array
        fin    = json_string.rfind(']')

    if fin == -1 or fin < inicio:
        return json_string[inicio:].strip()

    json_string = json_string[inicio:fin + 1]

    # 4. Fix trailing commas in objects and arrays
    # Removes commas before } or ]
    json_string = re.sub(r',\s*([\]}])', r'\1', json_string)

    # 5. Clean up possible invalid escapes (like \$ or \_)
    json_string = re.sub(r'(?<!\\)\\(?![\\"/bfnrtu])', r'\\\\', json_string)

    return json_string.strip()


# *************************************************
# LOGGING
# *************************************************

def ia_guardar_log_bd(servidor, accion, modelo, fecha_hora, tiempo_ejecucion, resultado, tokens):
    """
    DB version — requires database connection configuration.
    Equivalent to ia_guardar_log_bd in PHP.
    """
    # bd = conectar_BD()
    # if not bd: ...
    # INSERT INTO ia_log (servidor, modelo, accion, fecha_hora, tiempo_ejecucion,
    #   tokens_prompt, tokens_razonamiento, tokens_respuesta, tokens_total, resultado)
    pass


def ia_guardar_log_fichero(servidor, accion, prompt, resultado, modelo_utilizado,
                           fecha_hora, tiempo_ejecucion, resultado_log, tokens):
    log_entry  = "========================================\n"
    log_entry += f"[DATE AND TIME]: {fecha_hora}\n"
    log_entry += f"[SERVER]: {servidor}\n"
    log_entry += f"[ACTION]: {accion}\n"
    log_entry += f"[MODEL]: {modelo_utilizado}\n"
    log_entry += f"[EXECUTION TIME]: {tiempo_ejecucion} seconds\n"

    if isinstance(tokens, dict):
        log_entry += f"[PROMPT TOKENS]: {tokens.get('tokens_prompt', 0)}\n"
        log_entry += f"[REASONING TOKENS]: {tokens.get('tokens_razonamiento', 0)}\n"
        log_entry += f"[RESPONSE TOKENS]: {tokens.get('tokens_respuesta', 0)}\n"
        log_entry += f"[TOTAL TOKENS]: {tokens.get('tokens_total', 0)}\n"

    log_entry += f"[STATE]: {resultado_log}\n"
    log_entry += "--- PROMPT ---\n"
    log_entry += f"{prompt}\n"
    log_entry += "--- RESULT ---\n"
    log_entry += f"{resultado}\n"
    log_entry += "========================================\n\n"

    # Build the file name with the date and time
    fecha_fichero = datetime.now().strftime('%Y_%m_%d_%H_%M')

    # So the file saves correctly: replace invalid characters in the name
    modelo_safe = re.sub(r'[^A-Za-z0-9_\-]', '_', modelo_utilizado)

    log_dir = os.path.join(os.path.dirname(__file__), '..', 'ia_logs')
    os.makedirs(log_dir, exist_ok=True)

    log_file_path = os.path.join(log_dir, f"{fecha_fichero}_{modelo_safe}_IA.log")

    # Safe writing in append mode
    with open(log_file_path, 'a', encoding='utf-8') as f:
        f.write(log_entry)
