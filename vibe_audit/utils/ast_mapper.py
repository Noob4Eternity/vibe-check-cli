"""AST mapper with tree-sitter support for multi-language analysis.

Uses tree-sitter for robust parsing when available, falls back to
regex-based extraction for compatibility.

Supports: Python, JavaScript, TypeScript, JSX, TSX
"""

from __future__ import annotations

import ast
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set

logger = logging.getLogger("vibe_audit.ast_mapper")


@dataclass
class ImportInfo:
    """A single import statement."""
    module: str                    # e.g. 'react', 'flask', 'os'
    names: List[str] = field(default_factory=list)  # e.g. ['useState', 'useEffect']
    alias: Optional[str] = None
    file: str = ""
    line: int = 0
    is_default: bool = False       # import X from 'foo' (default)


@dataclass
class FunctionInfo:
    """A function/method definition."""
    name: str
    params: List[str]
    file: str = ""
    start_line: int = 0
    end_line: int = 0
    is_async: bool = False
    is_exported: bool = False
    decorators: List[str] = field(default_factory=list)


@dataclass
class ClassInfo:
    """A class definition."""
    name: str
    bases: List[str]
    methods: List[str]
    file: str = ""
    start_line: int = 0


@dataclass
class ASTMap:
    """Aggregated AST information for an entire repository."""
    imports: List[ImportInfo] = field(default_factory=list)
    functions: List[FunctionInfo] = field(default_factory=list)
    classes: List[ClassInfo] = field(default_factory=list)
    languages: Set[str] = field(default_factory=set)


# ── Language detection ─────────────────────────────────────────────

_EXT_TO_LANGUAGE = {
    ".py": "python",
    ".js": "javascript",
    ".jsx": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".mjs": "javascript",
    ".cjs": "javascript",
}


def detect_language(file_path: Path) -> Optional[str]:
    """Detect language from file extension."""
    return _EXT_TO_LANGUAGE.get(file_path.suffix.lower())


# ── Python AST extraction (using stdlib `ast`) ────────────────────

def _extract_python(file_path: Path, content: str) -> tuple[List[ImportInfo], List[FunctionInfo], List[ClassInfo]]:
    """Extract imports, functions, and classes from Python source."""
    imports: List[ImportInfo] = []
    functions: List[FunctionInfo] = []
    classes: List[ClassInfo] = []
    rel = str(file_path)

    try:
        tree = ast.parse(content, filename=str(file_path))
    except SyntaxError:
        return imports, functions, classes

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imports.append(ImportInfo(
                    module=alias.name,
                    alias=alias.asname,
                    file=rel,
                    line=node.lineno,
                ))
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            names = [alias.name for alias in (node.names or [])]
            imports.append(ImportInfo(
                module=module,
                names=names,
                file=rel,
                line=node.lineno,
            ))
        elif isinstance(node, ast.FunctionDef) or isinstance(node, ast.AsyncFunctionDef):
            decorators = []
            for dec in node.decorator_list:
                if isinstance(dec, ast.Name):
                    decorators.append(dec.id)
                elif isinstance(dec, ast.Attribute):
                    decorators.append(f"{ast.dump(dec)}")
            functions.append(FunctionInfo(
                name=node.name,
                params=[arg.arg for arg in node.args.args],
                file=rel,
                start_line=node.lineno,
                end_line=node.end_lineno or node.lineno,
                is_async=isinstance(node, ast.AsyncFunctionDef),
                decorators=decorators,
            ))
        elif isinstance(node, ast.ClassDef):
            bases = []
            for base in node.bases:
                if isinstance(base, ast.Name):
                    bases.append(base.id)
                elif isinstance(base, ast.Attribute):
                    bases.append(f"{base.attr}")
            methods = [
                n.name for n in node.body
                if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
            ]
            classes.append(ClassInfo(
                name=node.name,
                bases=bases,
                methods=methods,
                file=rel,
                start_line=node.lineno,
            ))

    return imports, functions, classes


# ── JavaScript / TypeScript extraction (regex-based) ──────────────

# Import patterns:
# import { useState, useEffect } from 'react'
# import React from 'react'
# import * as fs from 'fs'
# const { readFile } = require('fs')
# import('dynamic')

_JS_IMPORT_NAMED = re.compile(
    r"""import\s+\{([^}]+)\}\s+from\s+['"]([^'"]+)['"]""",
    re.MULTILINE,
)
_JS_IMPORT_DEFAULT = re.compile(
    r"""import\s+(\w+)\s+from\s+['"]([^'"]+)['"]""",
    re.MULTILINE,
)
_JS_IMPORT_STAR = re.compile(
    r"""import\s+\*\s+as\s+(\w+)\s+from\s+['"]([^'"]+)['"]""",
    re.MULTILINE,
)
_JS_REQUIRE = re.compile(
    r"""(?:const|let|var)\s+(?:\{([^}]+)\}|(\w+))\s*=\s*require\s*\(\s*['"]([^'"]+)['"]\s*\)""",
    re.MULTILINE,
)

# Function patterns:
_JS_FUNC_DECL = re.compile(
    r"""(?:export\s+)?(?:default\s+)?(?:async\s+)?function\s+(\w+)\s*\(([^)]*)\)""",
    re.MULTILINE,
)
_JS_ARROW_EXPORT = re.compile(
    r"""(?:export\s+)?(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s+)?\(?([^)]*?)\)?\s*=>""",
    re.MULTILINE,
)

# Class patterns:
_JS_CLASS = re.compile(
    r"""(?:export\s+)?class\s+(\w+)(?:\s+extends\s+(\w+))?""",
    re.MULTILINE,
)


def _extract_js_ts(file_path: Path, content: str) -> tuple[List[ImportInfo], List[FunctionInfo], List[ClassInfo]]:
    """Extract imports, functions, and classes from JS/TS source using regex."""
    imports: List[ImportInfo] = []
    functions: List[FunctionInfo] = []
    classes: List[ClassInfo] = []
    rel = str(file_path)
    lines = content.splitlines()

    def _line_number(match_start: int) -> int:
        return content[:match_start].count("\n") + 1

    # Named imports: import { a, b } from 'module'
    for m in _JS_IMPORT_NAMED.finditer(content):
        names = [n.strip().split(" as ")[0].strip() for n in m.group(1).split(",") if n.strip()]
        imports.append(ImportInfo(
            module=m.group(2),
            names=names,
            file=rel,
            line=_line_number(m.start()),
        ))

    # Default imports: import X from 'module'
    for m in _JS_IMPORT_DEFAULT.finditer(content):
        name = m.group(1)
        module = m.group(2)
        # Skip if already captured as named import at same line
        imports.append(ImportInfo(
            module=module,
            names=[],
            alias=name,
            file=rel,
            line=_line_number(m.start()),
            is_default=True,
        ))

    # Star imports: import * as X from 'module'
    for m in _JS_IMPORT_STAR.finditer(content):
        imports.append(ImportInfo(
            module=m.group(2),
            alias=m.group(1),
            file=rel,
            line=_line_number(m.start()),
        ))

    # require(): const { a, b } = require('module')
    for m in _JS_REQUIRE.finditer(content):
        if m.group(1):  # destructured
            names = [n.strip() for n in m.group(1).split(",") if n.strip()]
            imports.append(ImportInfo(
                module=m.group(3),
                names=names,
                file=rel,
                line=_line_number(m.start()),
            ))
        else:  # default
            imports.append(ImportInfo(
                module=m.group(3),
                alias=m.group(2),
                file=rel,
                line=_line_number(m.start()),
                is_default=True,
            ))

    # Functions
    for m in _JS_FUNC_DECL.finditer(content):
        params = [p.strip().split(":")[0].strip() for p in m.group(2).split(",") if p.strip()]
        is_exported = "export" in content[max(0, m.start()-20):m.start()]
        is_async = "async" in content[max(0, m.start()-10):m.start() + len(m.group(0))]
        functions.append(FunctionInfo(
            name=m.group(1),
            params=params,
            file=rel,
            start_line=_line_number(m.start()),
            is_async=is_async,
            is_exported=is_exported,
        ))

    for m in _JS_ARROW_EXPORT.finditer(content):
        params = [p.strip().split(":")[0].strip() for p in m.group(2).split(",") if p.strip()]
        is_exported = content[max(0, m.start()-10):m.start() + 10].strip().startswith("export")
        functions.append(FunctionInfo(
            name=m.group(1),
            params=params,
            file=rel,
            start_line=_line_number(m.start()),
            is_exported=is_exported,
        ))

    # Classes
    for m in _JS_CLASS.finditer(content):
        bases = [m.group(2)] if m.group(2) else []
        classes.append(ClassInfo(
            name=m.group(1),
            bases=bases,
            methods=[],
            file=rel,
            start_line=_line_number(m.start()),
        ))

    return imports, functions, classes


# ── Tree-sitter extraction (when available) ───────────────────────

_TREE_SITTER_AVAILABLE = False
try:
    from tree_sitter import Language, Parser
    _TREE_SITTER_AVAILABLE = True
except ImportError:
    pass


def _try_tree_sitter_extract(file_path: Path, content: str, language: str):
    """Try to use tree-sitter for parsing. Returns None if unavailable."""
    if not _TREE_SITTER_AVAILABLE:
        return None

    try:
        lang_module = None
        if language == "python":
            import tree_sitter_python as tsp
            lang_module = tsp
        elif language in ("javascript", "typescript"):
            try:
                import tree_sitter_javascript as tsjs
                lang_module = tsjs
            except ImportError:
                return None

        if lang_module is None:
            return None

        ts_lang = Language(lang_module.language())
        parser = Parser(ts_lang)
        tree = parser.parse(content.encode("utf-8"))

        imports: List[ImportInfo] = []
        functions: List[FunctionInfo] = []
        classes: List[ClassInfo] = []
        rel = str(file_path)

        def _walk(node):
            # Extract imports
            if node.type == "import_statement":
                text = content[node.start_byte:node.end_byte]
                # Parse the import text using regex (tree-sitter gives us clean boundaries)
                named = _JS_IMPORT_NAMED.search(text)
                if named:
                    names = [n.strip().split(" as ")[0].strip() for n in named.group(1).split(",") if n.strip()]
                    imports.append(ImportInfo(
                        module=named.group(2),
                        names=names,
                        file=rel,
                        line=node.start_point[0] + 1,
                    ))
                else:
                    default = _JS_IMPORT_DEFAULT.search(text)
                    if default:
                        imports.append(ImportInfo(
                            module=default.group(2),
                            alias=default.group(1),
                            file=rel,
                            line=node.start_point[0] + 1,
                            is_default=True,
                        ))

            # Extract function declarations
            elif node.type in ("function_declaration", "function_definition"):
                name_node = node.child_by_field_name("name")
                if name_node:
                    functions.append(FunctionInfo(
                        name=content[name_node.start_byte:name_node.end_byte],
                        params=[],
                        file=rel,
                        start_line=node.start_point[0] + 1,
                        end_line=node.end_point[0] + 1,
                    ))

            elif node.type == "class_declaration":
                name_node = node.child_by_field_name("name")
                if name_node:
                    classes.append(ClassInfo(
                        name=content[name_node.start_byte:name_node.end_byte],
                        bases=[],
                        methods=[],
                        file=rel,
                        start_line=node.start_point[0] + 1,
                    ))

            for child in node.children:
                _walk(child)

        _walk(tree.root_node)
        return imports, functions, classes

    except Exception as e:
        logger.debug("Tree-sitter extraction failed: %s", e)
        return None


# ── Main mapper ───────────────────────────────────────────────────

_SKIP_DIRS = {
    "node_modules", ".venv", "venv", "__pycache__", ".git",
    ".next", "dist", "build", ".tox", ".mypy_cache",
}


def build_ast_map(repo_path: str | Path) -> ASTMap:
    """Build a comprehensive AST map of the entire repository.

    Tries tree-sitter first, falls back to regex/stdlib extraction.
    """
    root = Path(repo_path)
    ast_map = ASTMap()

    for file_path in root.rglob("*"):
        if file_path.is_dir():
            continue
        if any(skip in file_path.parts for skip in _SKIP_DIRS):
            continue

        language = detect_language(file_path)
        if language is None:
            continue

        ast_map.languages.add(language)

        try:
            content = file_path.read_text(errors="ignore")
        except Exception:
            continue

        if not content.strip():
            continue

        rel_path = file_path.relative_to(root)

        # Try tree-sitter first
        ts_result = _try_tree_sitter_extract(rel_path, content, language)
        if ts_result:
            imports, functions, classes = ts_result
            logger.debug("Tree-sitter parsed %s", rel_path)
        elif language == "python":
            imports, functions, classes = _extract_python(rel_path, content)
        else:
            imports, functions, classes = _extract_js_ts(rel_path, content)

        ast_map.imports.extend(imports)
        ast_map.functions.extend(functions)
        ast_map.classes.extend(classes)

    logger.info(
        "AST map: %d imports, %d functions, %d classes across %s",
        len(ast_map.imports), len(ast_map.functions),
        len(ast_map.classes), ast_map.languages,
    )
    return ast_map
