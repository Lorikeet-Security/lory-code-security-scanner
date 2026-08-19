"""Extension-to-language mapping, and what counts as scannable text.

Language gating is what keeps a PHP rule off a Python file, so the map is
part of the engine's correctness, not a display detail.
"""

from __future__ import annotations

from pathlib import Path

#: Suffix → language name used in rule `languages:` lists.
EXTENSIONS: dict[str, str] = {
    ".py": "python", ".pyi": "python", ".pyw": "python",
    ".js": "javascript", ".jsx": "javascript", ".mjs": "javascript", ".cjs": "javascript",
    ".ts": "typescript", ".tsx": "typescript", ".mts": "typescript", ".cts": "typescript",
    ".php": "php", ".phtml": "php", ".php5": "php", ".php7": "php", ".inc": "php",
    ".rb": "ruby", ".erb": "ruby", ".rake": "ruby",
    ".go": "go",
    ".java": "java", ".jsp": "java",
    ".kt": "kotlin", ".kts": "kotlin",
    ".cs": "csharp", ".cshtml": "csharp", ".razor": "csharp",
    ".rs": "rust",
    ".c": "c", ".h": "c",
    ".cpp": "cpp", ".cc": "cpp", ".cxx": "cpp", ".hpp": "cpp", ".hh": "cpp",
    ".swift": "swift",
    ".scala": "scala",
    ".ex": "elixir", ".exs": "elixir",
    ".pl": "perl", ".pm": "perl",
    ".sh": "shell", ".bash": "shell", ".zsh": "shell", ".ksh": "shell",
    ".ps1": "powershell", ".psm1": "powershell",
    ".sql": "sql",
    ".html": "html", ".htm": "html", ".vue": "html", ".svelte": "html",
    ".twig": "html", ".blade": "html", ".jinja": "html", ".j2": "html", ".hbs": "html",
    ".css": "css", ".scss": "css", ".sass": "css", ".less": "css",
    ".yml": "yaml", ".yaml": "yaml",
    ".json": "json",
    ".toml": "toml",
    ".xml": "xml", ".plist": "xml",
    ".tf": "terraform", ".tfvars": "terraform",
    ".hcl": "hcl",
    ".env": "env", ".ini": "ini", ".cfg": "ini", ".conf": "ini", ".properties": "ini",
    ".gradle": "gradle",
    ".md": "markdown", ".mdx": "markdown", ".rst": "markdown", ".txt": "text",
    ".pem": "pem", ".key": "pem", ".crt": "pem", ".p12": "pem", ".pfx": "pem",
    ".tpl": "text", ".tmpl": "text",
}

#: Filenames whose language is not carried by an extension.
FILENAMES: dict[str, str] = {
    "dockerfile": "dockerfile",
    "containerfile": "dockerfile",
    "makefile": "make",
    "jenkinsfile": "groovy",
    "gemfile": "ruby",
    "rakefile": "ruby",
    "procfile": "text",
    ".env": "env",
    ".npmrc": "ini",
    ".netrc": "ini",
    ".htaccess": "apache",
    "nginx.conf": "nginx",
    "id_rsa": "pem",
    "id_dsa": "pem",
    "id_ecdsa": "pem",
    "id_ed25519": "pem",
}


def detect(path: Path) -> str:
    """The language of a file, or ``""`` when it is not one we scan.

    Compound suffixes are checked first so ``.env.production`` and
    ``Dockerfile.web`` are recognised rather than silently skipped — a
    production env file is exactly where a leaked secret lives.
    """
    name = path.name.lower()

    if name in FILENAMES:
        return FILENAMES[name]

    for stem, language in FILENAMES.items():
        if stem.startswith(".") and name.startswith(stem + "."):
            return language
        if not stem.startswith(".") and name.startswith(stem + "."):
            return language

    suffix = path.suffix.lower()
    if suffix in EXTENSIONS:
        return EXTENSIONS[suffix]

    # `.env.local` and friends: the meaningful part is not the last suffix.
    for part in reversed(path.suffixes):
        if part.lower() in EXTENSIONS:
            return EXTENSIONS[part.lower()]

    return ""
