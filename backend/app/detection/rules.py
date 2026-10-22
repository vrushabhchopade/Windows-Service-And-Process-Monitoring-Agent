"""
WAF and IDS Rule Definitions for SentinelShield
Each rule contains regex patterns, attack classification, severity, explanation, and remediation.
"""

from typing import List, Dict, Any
import re

RULES: List[Dict[str, Any]] = [
    # ------------------ SQL INJECTION (SQLi) ------------------
    {
        "rule_id": "WAF-SQLI-001",
        "name": "SQL Injection - UNION Operator",
        "category": "SQL Injection",
        "severity": "CRITICAL",
        "pattern": r"(?i)\bUNION\b\s+(?:ALL\s+)?\bSELECT\b",
        "confidence": 0.99,
        "default_action": "BLOCK",
        "description": "Detects UNION-based SQL Injection aimed at extracting data from other tables.",
        "explanation": "The payload uses the UNION SELECT syntax to combine query results with unauthorized database tables.",
        "recommendation": "Use parameterized queries or prepared statements (e.g., PDO, SQLAlchemy) to ensure user input is never executed as SQL code."
    },
    {
        "rule_id": "WAF-SQLI-002",
        "name": "SQL Injection - Tautology / Boolean Bypass",
        "category": "SQL Injection",
        "severity": "HIGH",
        "pattern": r"(?i)(?:'|\"|\b)\s*(?:OR|AND)\s+['\"0-9a-z_]+\s*=\s*['\"0-9a-z_]+|(?:\bor\b|\band\b)\s+(?:1=1|true=true|0=0)",
        "confidence": 0.95,
        "default_action": "BLOCK",
        "description": "Detects logical tautology patterns (such as OR 1=1) used to bypass authentication or filter clauses.",
        "explanation": "The input injects a condition that always evaluates to TRUE (e.g., ' OR 1=1), causing the query to return all records or bypass password checks.",
        "recommendation": "Enforce strict ORM data validation and use strongly typed parameterized variables."
    },
    {
        "rule_id": "WAF-SQLI-003",
        "name": "SQL Injection - Stacked Query / DDL Statement",
        "category": "SQL Injection",
        "severity": "CRITICAL",
        "pattern": r"(?i);\s*(?:DROP|INSERT|UPDATE|DELETE|ALTER|EXEC|EXECUTE)\b",
        "confidence": 0.98,
        "default_action": "BLOCK",
        "description": "Detects stacked SQL queries attempting database alteration or table dropping.",
        "explanation": "A semicolon terminates the original query followed by an unauthorized destructive SQL command like DROP or DELETE.",
        "recommendation": "Disable stacked queries in the database driver and use the principle of least privilege for database service accounts."
    },
    {
        "rule_id": "WAF-SQLI-004",
        "name": "SQL Injection - Information Schema / System Metadata",
        "category": "SQL Injection",
        "severity": "CRITICAL",
        "pattern": r"(?i)\b(?:information_schema|sysdatabases|sysobjects|pg_catalog|sqlite_master)\b",
        "confidence": 0.97,
        "default_action": "BLOCK",
        "description": "Detects reconnaissance targeting system metadata catalogs to discover schema and table names.",
        "explanation": "Targeting database internal schemas is a hallmark of automated SQL extraction tools like sqlmap.",
        "recommendation": "Restrict application database users from querying system metadata tables."
    },
    {
        "rule_id": "WAF-SQLI-005",
        "name": "SQL Injection - Time-based / Blind Delay Functions",
        "category": "SQL Injection",
        "severity": "HIGH",
        "pattern": r"(?i)\b(?:sleep\s*\(\s*\d+\s*\)|waitfor\s+delay|benchmark\s*\(\s*\d+\s*,|pg_sleep\s*\(\s*\d+\s*\))",
        "confidence": 0.96,
        "default_action": "BLOCK",
        "description": "Detects blind time-based SQL injection probes that force artificial server sleep delays.",
        "explanation": "Attacker forces the database to sleep to infer information one character at a time based on response latency.",
        "recommendation": "Audit endpoints with abnormal latency and wrap all dynamic queries into parameterized calls."
    },

    # ------------------ CROSS-SITE SCRIPTING (XSS) ------------------
    {
        "rule_id": "WAF-XSS-001",
        "name": "Cross-Site Scripting - Script Tag Injection",
        "category": "Cross-Site Scripting",
        "severity": "CRITICAL",
        "pattern": r"(?i)<\s*script[^>]*>.*?<\s*/\s*script\s*>|<\s*script[^>]*>",
        "confidence": 0.99,
        "default_action": "BLOCK",
        "description": "Detects explicit HTML <script> tags submitted in query parameters, headers, or body.",
        "explanation": "An attacker is attempting to inject executable JavaScript directly into the page DOM to hijack user sessions or credentials.",
        "recommendation": "Encode all user-supplied data using HTML entity encoding before rendering, and implement a strict Content Security Policy (CSP)."
    },
    {
        "rule_id": "WAF-XSS-002",
        "name": "Cross-Site Scripting - Inline Event Handler",
        "category": "Cross-Site Scripting",
        "severity": "HIGH",
        "pattern": r"(?i)\bon(?:load|error|click|mouseover|focus|blur|mouseenter|submit)\s*=\s*(?:\"[^\"]*\"|'[^']*'|[^\s>]+)",
        "confidence": 0.96,
        "default_action": "BLOCK",
        "description": "Detects JavaScript inline DOM event handlers (e.g., onload=, onerror=) attached to HTML elements.",
        "explanation": "Inline event attributes trigger script execution whenever the element loads or the user interacts with it.",
        "recommendation": "Use DOMPurify or equivalent HTML sanitization libraries and disallow 'unsafe-inline' scripts in HTTP Content-Security-Policy headers."
    },
    {
        "rule_id": "WAF-XSS-003",
        "name": "Cross-Site Scripting - Pseudo-Protocol Injection",
        "category": "Cross-Site Scripting",
        "severity": "HIGH",
        "pattern": r"(?i)(?:javascript|vbscript|data):[\s\S]*?(?:alert|eval|prompt|confirm|document\.cookie)",
        "confidence": 0.95,
        "default_action": "BLOCK",
        "description": "Detects javascript: URI schemes commonly used in href or src attributes.",
        "explanation": "Supplying a javascript: URI causes browsers to execute malicious payload code when the link or source is processed.",
        "recommendation": "Validate that all URLs strictly conform to 'http://' or 'https://' schemes before rendering."
    },
    {
        "rule_id": "WAF-XSS-004",
        "name": "Cross-Site Scripting - SVG / Image Vector",
        "category": "Cross-Site Scripting",
        "severity": "HIGH",
        "pattern": r"(?i)<\s*(?:svg|img|iframe|body|input)[^>]*(?:onload|onerror|src\s*=\s*javascript:)",
        "confidence": 0.97,
        "default_action": "BLOCK",
        "description": "Detects SVG or IMG tag payloads that fire JavaScript upon loading.",
        "explanation": "Tags like <svg/onload=...> or <img src=x onerror=...> bypass naive script tag filters and execute automatically.",
        "recommendation": "Strictly validate file uploads and sanitize all rich-text input with allowlist-based HTML cleaners."
    },

    # ------------------ DIRECTORY TRAVERSAL & LFI ------------------
    {
        "rule_id": "WAF-LFI-001",
        "name": "Directory Traversal - Path Step Sequences",
        "category": "Directory Traversal",
        "severity": "HIGH",
        "pattern": r"(?:\.\./|\.\.\\|\.%2e/|\.%2e\\|%2e%2e/|%2e%2e\\)",
        "confidence": 0.96,
        "default_action": "BLOCK",
        "description": "Detects relative directory traversal sequences (../ or ..\\) designed to break out of the web root.",
        "explanation": "The path contains relative directory navigation steps targeting parent folders and filesystem boundaries.",
        "recommendation": "Avoid using client-supplied file paths; use an indirect index or map paths through os.path.abspath() verification."
    },
    {
        "rule_id": "WAF-LFI-002",
        "name": "Local File Inclusion - Sensitive System Files",
        "category": "Local File Inclusion",
        "severity": "CRITICAL",
        "pattern": r"(?i)(?:/etc/(?:passwd|shadow|hosts|issue)|(?:windows|winnt)/system32|boot\.ini|win\.ini|proc/self/environ)",
        "confidence": 0.98,
        "default_action": "BLOCK",
        "description": "Detects attempts to access core operating system configuration files.",
        "explanation": "Targeting /etc/passwd or win.ini attempts to read system credentials, users, or kernel parameters.",
        "recommendation": "Hardcode allowed file mappings and enforce chroot or container isolation for the web process."
    },
    {
        "rule_id": "WAF-LFI-003",
        "name": "Local File Inclusion - Protocol Wrappers / Null Byte",
        "category": "Local File Inclusion",
        "severity": "HIGH",
        "pattern": r"(?i)(?:php://filter|php://input|file://|phar://|expect://|%00)",
        "confidence": 0.94,
        "default_action": "BLOCK",
        "description": "Detects PHP stream wrappers and null byte injection used to bypass file extensions.",
        "explanation": "Stream wrappers can trick applications into decoding arbitrary files or executing base64 payloads.",
        "recommendation": "Disable allow_url_include in runtime configuration and reject any requests containing null bytes (%00)."
    },

    # ------------------ COMMAND INJECTION (RCE) ------------------
    {
        "rule_id": "WAF-CMDI-001",
        "name": "Command Injection - Shell Metacharacter Chaining",
        "category": "Command Injection",
        "severity": "CRITICAL",
        "pattern": r"(?:;|\||&&|\|\||`|\$\()\s*(?:cat|ls|dir|whoami|id|uname|netstat|curl|wget|bash|sh|powershell|cmd)\b",
        "confidence": 0.98,
        "default_action": "BLOCK",
        "description": "Detects shell command chaining characters combined with standard administrative commands.",
        "explanation": "Shell operators like ; or && are chained with commands like whoami or curl to execute arbitrary code on the underlying host.",
        "recommendation": "Never pass user input to system shell execution functions (e.g. os.system, subprocess with shell=True)."
    },
    {
        "rule_id": "WAF-CMDI-002",
        "name": "Command Injection - Reverse Shell / Network Utility",
        "category": "Command Injection",
        "severity": "CRITICAL",
        "pattern": r"(?i)(?:nc\s+-[ecl]|bash\s+-i|/dev/tcp/|powershell\s+-enc|cmd\.exe\s+/c)",
        "confidence": 0.99,
        "default_action": "BLOCK",
        "description": "Detects signature payloads used to initiate interactive reverse shells or encoded PowerShell executions.",
        "explanation": "Reverse shell strings attempt to open an outbound TCP socket back to the attacker's listening command-and-control server.",
        "recommendation": "Lock down outbound egress firewall traffic and audit process creation telemetry."
    },

    # ------------------ SUSPICIOUS HEADERS & SCANNER BOTS ------------------
    {
        "rule_id": "WAF-SCAN-001",
        "name": "Security Scanner - Automated Reconnaissance Tool",
        "category": "Scanner Detection",
        "severity": "MEDIUM",
        "pattern": r"(?i)\b(?:sqlmap|nikto|masscan|nmap|dirbuster|gobuster|wpscan|acunetix|havij|nessus)\b",
        "confidence": 0.99,
        "default_action": "BLOCK",
        "description": "Detects automated vulnerability scanners and security auditing tools via User-Agent or headers.",
        "explanation": "The client User-Agent matches a known offensive security scanner actively probing for vulnerabilities.",
        "recommendation": "Deploy edge rate limiting, challenge unknown automated user agents with CAPTCHA or immediate edge drops."
    },
    {
        "rule_id": "WAF-HEADER-002",
        "name": "HTTP Header Injection - CRLF Injection",
        "category": "Header Injection",
        "severity": "HIGH",
        "pattern": r"(?:\r\n|\r|\n)(?:Set-Cookie|Location|Content-Type|X-Forwarded):",
        "confidence": 0.95,
        "default_action": "BLOCK",
        "description": "Detects Carriage Return Line Feed (CRLF) characters designed to split HTTP headers.",
        "explanation": "Injecting newline characters can cause HTTP response splitting, leading to cache poisoning or session fixation.",
        "recommendation": "Strip all carriage return (\\r) and line feed (\\n) characters from values passed to HTTP response headers."
    }
]
