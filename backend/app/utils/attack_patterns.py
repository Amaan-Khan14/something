"""
Comprehensive attack pattern signatures for URL-based attack detection.
Covers 11+ attack types with multiple variants each.
"""
import re
from typing import List, Dict, Tuple

# Attack type constants
ATTACK_TYPES = {
    "SQL_INJECTION": "SQL Injection",
    "XSS": "Cross-Site Scripting",
    "DIRECTORY_TRAVERSAL": "Directory Traversal",
    "COMMAND_INJECTION": "Command Injection",
    "SSRF": "Server-Side Request Forgery",
    "LFI_RFI": "Local/Remote File Inclusion",
    "CREDENTIAL_STUFFING": "Credential Stuffing/Brute Force",
    "HTTP_PARAM_POLLUTION": "HTTP Parameter Pollution",
    "XXE_INJECTION": "XML External Entity Injection",
    "WEB_SHELL": "Web Shell Upload",
    "TYPOSQUATTING": "Typosquatting/URL Spoofing",
    "OPEN_REDIRECT": "Open Redirect",
    "LDAP_INJECTION": "LDAP Injection",
    "TEMPLATE_INJECTION": "Template Injection",
    "HTTP_SMUGGLING": "HTTP Request Smuggling",
    "PATH_CONFUSION": "Path Confusion",
}

# Severity levels
SEVERITY = {
    "CRITICAL": "Critical",
    "HIGH": "High",
    "MEDIUM": "Medium",
    "LOW": "Low",
}


class AttackPatterns:
    """Comprehensive attack pattern database"""

    # SQL Injection Patterns
    SQL_INJECTION_PATTERNS = [
        # Union-based
        (r"union\s+(all\s+)?select", "union-based", SEVERITY["CRITICAL"]),
        (r"union.*select.*from", "union-based", SEVERITY["CRITICAL"]),

        # Boolean-based blind
        (r"(\s|%20)(and|or)(\s|%20)+\d+\s*=\s*\d+", "boolean-blind", SEVERITY["HIGH"]),
        (r"'(\s|%20)+(and|or)(\s|%20)+'[^']*'(\s|%20)*=(\s|%20)*'", "boolean-blind", SEVERITY["HIGH"]),

        # Error-based
        (r"(convert|cast)\(.*\)", "error-based", SEVERITY["HIGH"]),
        (r"extractvalue\(", "error-based", SEVERITY["HIGH"]),
        (r"updatexml\(", "error-based", SEVERITY["HIGH"]),

        # Time-based blind
        (r"(sleep|benchmark|waitfor)\s*\(", "time-based", SEVERITY["HIGH"]),
        (r"pg_sleep\(", "time-based", SEVERITY["HIGH"]),

        # Stacked queries
        (r";\s*(drop|delete|insert|update|create)\s+", "stacked-queries", SEVERITY["CRITICAL"]),

        # Classic patterns
        (r"'(\s|%20)*(or|and)(\s|%20)*'1'(\s|%20)*=(\s|%20)*'1", "classic", SEVERITY["CRITICAL"]),
        (r"'(\s|%20)*(or|and)(\s|%20)*1(\s|%20)*=(\s|%20)*1", "classic", SEVERITY["CRITICAL"]),
        (r"admin'(\s|%20)*--", "classic", SEVERITY["CRITICAL"]),
        (r"'(\s|%20)*or(\s|%20)*'.*'(\s|%20)*=(\s|%20)*'", "classic", SEVERITY["CRITICAL"]),

        # Comment injection
        (r"(/\*|\*/|--|#|;%00)", "comment-injection", SEVERITY["MEDIUM"]),

        # Database fingerprinting
        (r"@@version|version\(\)", "fingerprinting", SEVERITY["MEDIUM"]),
        (r"user\(\)|database\(\)|schema\(\)", "fingerprinting", SEVERITY["MEDIUM"]),
    ]

    # XSS Patterns
    XSS_PATTERNS = [
        # Script tags
        (r"<script[^>]*>.*?</script>", "reflected", SEVERITY["HIGH"]),
        (r"<script[^>]*>", "reflected", SEVERITY["HIGH"]),
        (r"javascript:", "reflected", SEVERITY["HIGH"]),

        # Event handlers
        (r"on(load|error|click|mouse|focus|blur|change|submit)\s*=", "reflected", SEVERITY["HIGH"]),
        (r"onerror\s*=.*alert", "reflected", SEVERITY["HIGH"]),

        # Image-based XSS
        (r"<img[^>]*src[^>]*>", "reflected", SEVERITY["MEDIUM"]),
        (r"<img[^>]*onerror", "reflected", SEVERITY["HIGH"]),

        # Iframe injection
        (r"<iframe[^>]*>", "reflected", SEVERITY["HIGH"]),

        # Data URIs
        (r"data:text/html", "dom-based", SEVERITY["HIGH"]),

        # SVG-based XSS
        (r"<svg[^>]*onload", "reflected", SEVERITY["HIGH"]),

        # Encoded attacks
        (r"&#x?[0-9a-f]+;", "encoded", SEVERITY["MEDIUM"]),
        (r"%3Cscript", "encoded", SEVERITY["HIGH"]),

        # DOM-based
        (r"document\.(write|cookie|location)", "dom-based", SEVERITY["HIGH"]),
        (r"window\.(location|name)", "dom-based", SEVERITY["MEDIUM"]),

        # Template injection patterns
        (r"\{\{.*\}\}", "template-xss", SEVERITY["MEDIUM"]),
    ]

    # Directory Traversal Patterns
    DIRECTORY_TRAVERSAL_PATTERNS = [
        (r"\.\./\.\./", "path-traversal", SEVERITY["HIGH"]),
        (r"\.\./.*etc/passwd", "path-traversal", SEVERITY["CRITICAL"]),
        (r"\.\./.*boot\.ini", "path-traversal", SEVERITY["CRITICAL"]),
        (r"\.\.\\\.\.\\", "windows-traversal", SEVERITY["HIGH"]),
        (r"\.\.%2f", "encoded-traversal", SEVERITY["HIGH"]),
        (r"%2e%2e%2f", "encoded-traversal", SEVERITY["HIGH"]),
        (r"\.\.%5c", "windows-encoded", SEVERITY["HIGH"]),
        (r"\.\.%255c", "double-encoded", SEVERITY["HIGH"]),
        (r"\.\./.*windows/system32", "windows-traversal", SEVERITY["CRITICAL"]),
        (r"/etc/(passwd|shadow|hosts|issue)", "unix-files", SEVERITY["CRITICAL"]),
        (r"c:\\(windows|winnt)", "windows-files", SEVERITY["HIGH"]),
        (r"\.\.;/", "semicolon-bypass", SEVERITY["HIGH"]),
    ]

    # Command Injection Patterns
    COMMAND_INJECTION_PATTERNS = [
        (r";\s*(ls|cat|wget|curl|nc|netcat|bash|sh)\s", "shell-command", SEVERITY["CRITICAL"]),
        (r"\|\s*(whoami|id|uname|hostname)", "pipe-command", SEVERITY["CRITICAL"]),
        (r"`.*`", "backtick-execution", SEVERITY["CRITICAL"]),
        (r"\$\(.*\)", "command-substitution", SEVERITY["CRITICAL"]),
        (r"&&\s*(rm|mv|cp|kill)", "chain-command", SEVERITY["CRITICAL"]),
        (r"\|\|\s*(echo|printf)", "or-command", SEVERITY["MEDIUM"]),
        (r">\s*/dev/null", "redirect", SEVERITY["MEDIUM"]),
        (r"&\s*[a-z]+", "background-exec", SEVERITY["HIGH"]),
        (r"chmod\s+[0-7]{3}", "permission-change", SEVERITY["HIGH"]),
        (r"(wget|curl).*http", "download-command", SEVERITY["HIGH"]),
    ]

    # SSRF Patterns
    SSRF_PATTERNS = [
        (r"(https?://)?localhost", "localhost-access", SEVERITY["HIGH"]),
        (r"(https?://)?127\.0\.0\.", "loopback", SEVERITY["HIGH"]),
        (r"(https?://)?169\.254\.169\.254", "metadata-service", SEVERITY["CRITICAL"]),
        (r"(https?://)?10\.\d+\.\d+\.\d+", "private-ip-10", SEVERITY["HIGH"]),
        (r"(https?://)?192\.168\.\d+\.\d+", "private-ip-192", SEVERITY["HIGH"]),
        (r"(https?://)?172\.(1[6-9]|2[0-9]|3[01])\.\d+\.\d+", "private-ip-172", SEVERITY["HIGH"]),
        (r"@[0-9a-f:]+", "ipv6-ssrf", SEVERITY["MEDIUM"]),
        (r"file:///", "file-protocol", SEVERITY["CRITICAL"]),
        (r"dict://", "dict-protocol", SEVERITY["HIGH"]),
        (r"gopher://", "gopher-protocol", SEVERITY["HIGH"]),
    ]

    # LFI/RFI Patterns
    LFI_RFI_PATTERNS = [
        (r"(file|page|include|path)=.*\.\./", "lfi", SEVERITY["HIGH"]),
        (r"(file|page)=.*etc/passwd", "lfi-passwd", SEVERITY["CRITICAL"]),
        (r"(file|page|include)=https?://", "rfi", SEVERITY["CRITICAL"]),
        (r"php://filter", "php-filter", SEVERITY["HIGH"]),
        (r"php://input", "php-input", SEVERITY["CRITICAL"]),
        (r"data://text/plain", "data-wrapper", SEVERITY["HIGH"]),
        (r"expect://", "expect-wrapper", SEVERITY["CRITICAL"]),
        (r"zip://", "zip-wrapper", SEVERITY["MEDIUM"]),
        (r"\x00", "null-byte-injection", SEVERITY["HIGH"]),
    ]

    # Credential Stuffing / Brute Force Patterns
    CREDENTIAL_STUFFING_PATTERNS = [
        (r"(username|user|login)=admin&(password|pass|pwd)=", "credential-attempt", SEVERITY["MEDIUM"]),
        (r"(password|pass|pwd)=(admin|password|123456|root)", "common-password", SEVERITY["MEDIUM"]),
        (r"login.*attempts?=\d+", "multiple-attempts", SEVERITY["LOW"]),
    ]

    # HTTP Parameter Pollution Patterns
    HTTP_PARAM_POLLUTION_PATTERNS = [
        (r"([?&][a-zA-Z_][a-zA-Z0-9_]*=).*\1", "duplicate-param", SEVERITY["MEDIUM"]),
        (r"([?&]id=\d+).*\1", "id-pollution", SEVERITY["MEDIUM"]),
    ]

    # XXE Injection Patterns
    XXE_PATTERNS = [
        (r"<!DOCTYPE[^>]*<!ENTITY", "xxe-entity", SEVERITY["CRITICAL"]),
        (r"<!ENTITY.*SYSTEM", "xxe-system", SEVERITY["CRITICAL"]),
        (r"<!ENTITY.*file://", "xxe-file", SEVERITY["CRITICAL"]),
        (r"SYSTEM\s+['\"]file://", "xxe-file-ref", SEVERITY["CRITICAL"]),
        (r"<!ENTITY.*PUBLIC", "xxe-public", SEVERITY["HIGH"]),
    ]

    # Web Shell Patterns
    WEB_SHELL_PATTERNS = [
        (r"(cmd|shell|backdoor|c99|r57|b374k)\.(php|asp|aspx|jsp)", "shell-filename", SEVERITY["CRITICAL"]),
        (r"\.php\?cmd=", "php-shell", SEVERITY["CRITICAL"]),
        (r"eval\(.*\$_(GET|POST|REQUEST)", "eval-shell", SEVERITY["CRITICAL"]),
        (r"system\(\$_(GET|POST)", "system-shell", SEVERITY["CRITICAL"]),
        (r"passthru|shell_exec|exec|popen", "php-exec-func", SEVERITY["HIGH"]),
        (r"Runtime\.getRuntime\(\)\.exec", "java-runtime-exec", SEVERITY["CRITICAL"]),
    ]

    # Typosquatting/URL Spoofing Patterns
    TYPOSQUATTING_PATTERNS = [
        (r"[a-z0-9]+(l|i|1)(l|i|1)[a-z0-9]+\.(com|net|org)", "char-substitution", SEVERITY["MEDIUM"]),
        (r"[a-z]+-(login|signin|account|verify)\.", "phishing-subdomain", SEVERITY["HIGH"]),
        (r"[a-z]+\.tk|\.ml|\.ga|\.cf|\.gq", "suspicious-tld", SEVERITY["MEDIUM"]),
    ]

    # Open Redirect Patterns
    OPEN_REDIRECT_PATTERNS = [
        (r"(redirect|redir|url|next|continue|return)=https?://", "url-redirect", SEVERITY["MEDIUM"]),
        (r"(redirect|url)=//", "protocol-relative", SEVERITY["MEDIUM"]),
        (r"(redirect|url)=%2f%2f", "encoded-redirect", SEVERITY["MEDIUM"]),
    ]

    # LDAP Injection Patterns
    LDAP_INJECTION_PATTERNS = [
        (r"\*\)(\(|%28)", "ldap-wildcard", SEVERITY["HIGH"]),
        (r"(\(|\)).*(\||&)", "ldap-operator", SEVERITY["HIGH"]),
        (r"%28.*%29.*%7c", "encoded-ldap", SEVERITY["HIGH"]),
    ]

    # Template Injection Patterns
    TEMPLATE_INJECTION_PATTERNS = [
        (r"\{\{.*config.*\}\}", "flask-jinja", SEVERITY["CRITICAL"]),
        (r"\$\{.*\}", "el-injection", SEVERITY["HIGH"]),
        (r"<%.*%>", "erb-injection", SEVERITY["HIGH"]),
        (r"\{\%.*\%\}", "template-tag", SEVERITY["MEDIUM"]),
    ]

    # HTTP Request Smuggling Patterns
    HTTP_SMUGGLING_PATTERNS = [
        (r"Transfer-Encoding:.*chunked.*Content-Length:", "te-cl", SEVERITY["CRITICAL"]),
        (r"Content-Length:.*Transfer-Encoding:", "cl-te", SEVERITY["CRITICAL"]),
    ]

    # Path Confusion Patterns
    PATH_CONFUSION_PATTERNS = [
        (r"/\.\.;/", "path-param-confusion", SEVERITY["MEDIUM"]),
        (r"/%2e/", "encoded-dot-confusion", SEVERITY["MEDIUM"]),
        (r"/\.;/", "semicolon-confusion", SEVERITY["MEDIUM"]),
    ]

    @classmethod
    def get_all_patterns(cls) -> List[Tuple[str, str, str, str, float]]:
        """
        Get all attack patterns with metadata.
        Returns: List of (pattern, attack_type, subtype, severity, confidence_weight)
        """
        patterns = []

        for pattern, subtype, severity in cls.SQL_INJECTION_PATTERNS:
            patterns.append((pattern, ATTACK_TYPES["SQL_INJECTION"], subtype, severity, 0.95))

        for pattern, subtype, severity in cls.XSS_PATTERNS:
            patterns.append((pattern, ATTACK_TYPES["XSS"], subtype, severity, 0.90))

        for pattern, subtype, severity in cls.DIRECTORY_TRAVERSAL_PATTERNS:
            patterns.append((pattern, ATTACK_TYPES["DIRECTORY_TRAVERSAL"], subtype, severity, 0.92))

        for pattern, subtype, severity in cls.COMMAND_INJECTION_PATTERNS:
            patterns.append((pattern, ATTACK_TYPES["COMMAND_INJECTION"], subtype, severity, 0.93))

        for pattern, subtype, severity in cls.SSRF_PATTERNS:
            patterns.append((pattern, ATTACK_TYPES["SSRF"], subtype, severity, 0.88))

        for pattern, subtype, severity in cls.LFI_RFI_PATTERNS:
            patterns.append((pattern, ATTACK_TYPES["LFI_RFI"], subtype, severity, 0.91))

        for pattern, subtype, severity in cls.CREDENTIAL_STUFFING_PATTERNS:
            patterns.append((pattern, ATTACK_TYPES["CREDENTIAL_STUFFING"], subtype, severity, 0.70))

        for pattern, subtype, severity in cls.HTTP_PARAM_POLLUTION_PATTERNS:
            patterns.append((pattern, ATTACK_TYPES["HTTP_PARAM_POLLUTION"], subtype, severity, 0.75))

        for pattern, subtype, severity in cls.XXE_PATTERNS:
            patterns.append((pattern, ATTACK_TYPES["XXE_INJECTION"], subtype, severity, 0.94))

        for pattern, subtype, severity in cls.WEB_SHELL_PATTERNS:
            patterns.append((pattern, ATTACK_TYPES["WEB_SHELL"], subtype, severity, 0.96))

        for pattern, subtype, severity in cls.TYPOSQUATTING_PATTERNS:
            patterns.append((pattern, ATTACK_TYPES["TYPOSQUATTING"], subtype, severity, 0.65))

        for pattern, subtype, severity in cls.OPEN_REDIRECT_PATTERNS:
            patterns.append((pattern, ATTACK_TYPES["OPEN_REDIRECT"], subtype, severity, 0.78))

        for pattern, subtype, severity in cls.LDAP_INJECTION_PATTERNS:
            patterns.append((pattern, ATTACK_TYPES["LDAP_INJECTION"], subtype, severity, 0.85))

        for pattern, subtype, severity in cls.TEMPLATE_INJECTION_PATTERNS:
            patterns.append((pattern, ATTACK_TYPES["TEMPLATE_INJECTION"], subtype, severity, 0.89))

        for pattern, subtype, severity in cls.HTTP_SMUGGLING_PATTERNS:
            patterns.append((pattern, ATTACK_TYPES["HTTP_SMUGGLING"], subtype, severity, 0.92))

        for pattern, subtype, severity in cls.PATH_CONFUSION_PATTERNS:
            patterns.append((pattern, ATTACK_TYPES["PATH_CONFUSION"], subtype, severity, 0.80))

        return patterns

    @classmethod
    def compile_patterns(cls) -> Dict[str, List[Tuple[re.Pattern, str, str, float]]]:
        """
        Compile all regex patterns for efficient matching.
        Returns: Dict mapping attack_type to list of (compiled_pattern, subtype, severity, confidence)
        """
        compiled = {}
        all_patterns = cls.get_all_patterns()

        for pattern_str, attack_type, subtype, severity, confidence in all_patterns:
            try:
                compiled_pattern = re.compile(pattern_str, re.IGNORECASE)
                if attack_type not in compiled:
                    compiled[attack_type] = []
                compiled[attack_type].append((compiled_pattern, subtype, severity, confidence))
            except re.error as e:
                print(f"Error compiling pattern '{pattern_str}': {e}")

        return compiled
