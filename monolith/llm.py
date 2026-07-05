import os
import json
from typing import Optional

try:
    import requests
    HAS_REQUESTS = True
except Exception:
    HAS_REQUESTS = False

try:
    import openai
    HAS_OPENAI = True
except Exception:
    HAS_OPENAI = False


OLLAMA_URL = os.getenv('OLLAMA_URL', 'http://127.0.0.1:11434')


def analyze_with_ollama(prompt: str, model: str = 'llama2') -> Optional[str]:
    """Call a local Ollama instance (HTTP) to generate analysis.

    Falls back to None if Ollama isn't reachable.
    """
    if not HAS_REQUESTS:
        return None

    url = f"{OLLAMA_URL}/api/generate"
    payload = {
        'model': model,
        'prompt': prompt,
        'max_tokens': 512,
    }
    try:
        r = requests.post(url, json=payload, timeout=30)
        r.raise_for_status()
        data = r.json()
        # Ollama returns `completion`/`result` depending on version — be flexible
        if isinstance(data, dict):
            if 'result' in data:
                return data['result']
            if 'completion' in data:
                return data['completion']
            # Try first text field
            for v in data.values():
                if isinstance(v, str) and len(v) > 0:
                    return v
        return None
    except Exception:
        return None


def analyze_vuln(prompt: str, prefer_local: bool = True) -> str:
    """Analyze text with local Ollama if available, otherwise fallback to OpenAI if key provided.

    Returns string analysis (may be a simulated answer if no provider available).
    """
    # Try local Ollama
    if prefer_local:
        res = analyze_with_ollama(prompt)
        if res:
            return res

    # Fallback to OpenAI if configured
    if HAS_OPENAI and os.getenv('OPENAI_API_KEY'):
        openai.api_key = os.getenv('OPENAI_API_KEY')
        try:
            resp = openai.Completion.create(engine='text-davinci-003', prompt=prompt, max_tokens=512)
            return resp.choices[0].text.strip()
        except Exception:
            pass

    # Last-resort simulated answer
    return "[SIMULATION] No LLM provider available — enable local Ollama or set OPENAI_API_KEY"
