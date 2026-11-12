"""
Compiled Regex Attack Patterns for AI Threat Detection
Inspired by OWASP & ModSecurity Core Rule Set (CRS)
"""

import re

ENCODED_CHARS = re.compile(r"%[0-9a-fA-F]{2}")
DOUBLE_ENCODED = re.compile(r"%25[0-9a-fA-F]{2}")

_SQLI = (
    r"(?:union\s+(?:all\s+)?select|"
    r"'\s*or\s+.+=|"
    r"'\s*and\s+.+=|"
    r"1\s*=\s*1|"
    r"sleep\s*\(|"
    r"benchmark\s*\(|"
    r"waitfor\s+delay|"
    r"extractvalue\s*\(|"
    r"updatexml\s*\(|"
    r"load_file\s*\(|"
    r"into\s+(?:out|dump)file|"
    r"group\s+by\s+.+having|"
    r"order\s+by\s+\d+|"
    r"(?:drop|alter|create)\s+table|"
    r"information_schema|"
    r"(?:char|concat|hex|unhex)\s*\(|"
    r"0x[0-9a-f]{6,}|"
    r"--\s*$|"
    r"/\*.*?\*/)"
)

_XSS = (
    r"(?:<script[^>]*>|"
    r"javascript\s*:|"
    r"vbscript\s*:|"
    r"onload\s*=|"
    r"onerror\s*=|"
    r"onclick\s*=|"
    r"onmouseover\s*=|"
    r"onfocus\s*=|"
    r"eval\s*\(|"
    r"expression\s*\(|"
    r"document\.(?:cookie|location|write)|"
    r"window\.(?:location|navigate)|"
    r"(?:alert|prompt|confirm)\s*\()"
)

_PATH_TRAVERSAL = (
    r"(?:\.\./|\.\.\\|"
    r"%2e%2e(?:/|\\|%2f|%5c)|"
    r"(?:etc/passwd|windows/win\.ini|boot\.ini)|"
    r"(?:\.git/config|\.env|web\.config))"
)

_COMMAND_INJECTION = (
    r"(?:;\s*(?:cat|ls|id|whoami|uname|curl|wget|bash|sh|cmd|powershell)|"
    r"\|\s*(?:cat|ls|id|whoami|uname|curl|wget|bash|sh|cmd|powershell)|"
    r"`[^`]*`|"
    r"\$\([^)]*\)|"
    r"\$\{[^}]*\})"
)

_FILE_INCLUSION = (
    r"(?:php://(?:filter|input|data)|"
    r"file://|"
    r"data://[^,]*;base64|"
    r"phar://)"
)

_XXE_INJECTION = (
    r"(?:<!entity\s+\w+\s+system|"
    r"<!doctype\s+\w+\s+\[|"
    r"xmlns:xi\s*=|"
    r"xi:include)"
)

_SSRF = (
    r"(?:169\.254\.169\.254|"
    r"metadata\.google\.internal|"
    r"localhost(?::\d+)?(?:/|\?)|"
    r"127\.0\.0\.1(?::\d+)?(?:/|\?)|"
    r"(?:gopher|dict)://)"
)

_LOG4SHELL = (
    r"\$\{(?:\$|\w+)*jndi:"
)

_CRLF_INJECTION = (
    r"(?:%0d%0a|\r\n|%0d|%0a)"
)

_OPEN_REDIRECT = (
    r"(?:(?:redirect|url|next|return|dest|target)=(?:https?:|//)[^&]+)"
)

SQLI = re.compile(_SQLI, re.IGNORECASE)
XSS = re.compile(_XSS, re.IGNORECASE)
PATH_TRAVERSAL = re.compile(_PATH_TRAVERSAL, re.IGNORECASE)
COMMAND_INJECTION = re.compile(_COMMAND_INJECTION, re.IGNORECASE)
FILE_INCLUSION = re.compile(_FILE_INCLUSION, re.IGNORECASE)
XXE_INJECTION = re.compile(_XXE_INJECTION, re.IGNORECASE)
SSRF = re.compile(_SSRF, re.IGNORECASE)
LOG4SHELL = re.compile(_LOG4SHELL, re.IGNORECASE)
CRLF_INJECTION = re.compile(_CRLF_INJECTION, re.IGNORECASE)
OPEN_REDIRECT = re.compile(_OPEN_REDIRECT, re.IGNORECASE)

