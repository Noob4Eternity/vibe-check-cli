"""Export-level hallucination detection.

Goes beyond checking if a *package* exists — checks if specific
*named imports* from popular packages actually exist.

Example: `from flask import nonexistent_function` or
         `import { useServerAction } from 'react'`

LLMs frequently hallucinate plausible-sounding but non-existent APIs.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Dict, FrozenSet, List, Optional, Set

from vibe_audit.analyzers.base import BaseAnalyzer
from vibe_audit.models.finding import Category, Finding, Severity
from vibe_audit.utils.ast_mapper import ImportInfo, build_ast_map

logger = logging.getLogger("vibe_audit.hallucination")


# ── Known exports of popular packages ──────────────────────────────
# We maintain curated lists of real exports for the most commonly
# hallucinated packages. This is deterministic — no API calls needed.

_KNOWN_EXPORTS: Dict[str, FrozenSet[str]] = {
    # React
    "react": frozenset({
        "useState", "useEffect", "useContext", "useReducer", "useCallback",
        "useMemo", "useRef", "useImperativeHandle", "useLayoutEffect",
        "useDebugValue", "useDeferredValue", "useTransition", "useId",
        "useSyncExternalStore", "useInsertionEffect", "useOptimistic",
        "useActionState", "use", "useFormStatus",
        "Component", "PureComponent", "Fragment", "StrictMode", "Suspense",
        "lazy", "memo", "forwardRef", "createContext", "createElement",
        "cloneElement", "createRef", "isValidElement", "Children",
        "startTransition", "cache",
    }),

    # React DOM
    "react-dom": frozenset({
        "createRoot", "hydrateRoot", "render", "hydrate", "unmountComponentAtNode",
        "findDOMNode", "createPortal", "flushSync", "preload", "preinit",
    }),
    "react-dom/client": frozenset({
        "createRoot", "hydrateRoot",
    }),
    "react-dom/server": frozenset({
        "renderToString", "renderToStaticMarkup", "renderToPipeableStream",
        "renderToReadableStream",
    }),

    # Next.js
    "next/navigation": frozenset({
        "useRouter", "usePathname", "useSearchParams", "useParams",
        "useSelectedLayoutSegment", "useSelectedLayoutSegments",
        "redirect", "permanentRedirect", "notFound",
    }),
    "next/router": frozenset({
        "useRouter", "withRouter",
    }),
    "next/link": frozenset({"default"}),  # default export
    "next/image": frozenset({"default"}),
    "next/head": frozenset({"default"}),
    "next/script": frozenset({"default"}),
    "next/font/google": frozenset({
        "Inter", "Roboto", "Open_Sans", "Lato", "Montserrat", "Poppins",
        "Raleway", "Oswald", "Outfit", "Playfair_Display", "Nunito",
    }),
    "next/headers": frozenset({
        "cookies", "headers",
    }),
    "next/cache": frozenset({
        "revalidatePath", "revalidateTag", "unstable_cache",
    }),
    "next/server": frozenset({
        "NextRequest", "NextResponse", "NextMiddleware",
    }),

    # Flask
    "flask": frozenset({
        "Flask", "Blueprint", "request", "Response", "make_response",
        "jsonify", "redirect", "url_for", "render_template",
        "render_template_string", "flash", "get_flashed_messages",
        "session", "g", "current_app", "abort", "send_file",
        "send_from_directory", "after_this_request", "has_request_context",
        "has_app_context", "stream_with_context",
    }),

    # FastAPI
    "fastapi": frozenset({
        "FastAPI", "APIRouter", "Request", "Response", "WebSocket",
        "Depends", "Query", "Path", "Body", "Header", "Cookie", "Form",
        "File", "UploadFile", "HTTPException", "status", "BackgroundTasks",
        "Security",
    }),
    "fastapi.responses": frozenset({
        "JSONResponse", "HTMLResponse", "PlainTextResponse",
        "RedirectResponse", "StreamingResponse", "FileResponse",
    }),
    "fastapi.middleware.cors": frozenset({"CORSMiddleware"}),

    # Django
    "django.shortcuts": frozenset({
        "render", "redirect", "get_object_or_404", "get_list_or_404",
    }),
    "django.http": frozenset({
        "HttpResponse", "HttpResponseRedirect", "JsonResponse",
        "HttpResponseNotFound", "HttpResponseForbidden",
        "HttpResponseBadRequest", "HttpRequest", "FileResponse",
        "StreamingHttpResponse",
    }),
    "django.db": frozenset({"models", "connection", "connections"}),
    "django.urls": frozenset({"path", "re_path", "include", "reverse"}),

    # Express
    "express": frozenset({"default"}),  # default export

    # Pandas
    "pandas": frozenset({
        "DataFrame", "Series", "read_csv", "read_json", "read_excel",
        "read_sql", "read_parquet", "concat", "merge", "pivot_table",
        "crosstab", "cut", "qcut", "date_range", "to_datetime",
        "get_dummies", "isna", "isnull", "notna", "notnull",
    }),

    # Standard library (Python — commonly hallucinated)
    "os": frozenset({
        "path", "getcwd", "listdir", "makedirs", "mkdir", "remove",
        "rmdir", "rename", "stat", "walk", "environ", "getenv",
        "system", "popen", "sep", "linesep", "curdir", "pardir",
    }),
    "os.path": frozenset({
        "join", "exists", "isfile", "isdir", "basename", "dirname",
        "splitext", "abspath", "relpath", "expanduser", "getsize",
    }),
    "json": frozenset({
        "dumps", "loads", "dump", "load", "JSONDecodeError",
        "JSONEncoder", "JSONDecoder",
    }),
    "typing": frozenset({
        "Any", "Dict", "List", "Optional", "Set", "Tuple", "Union",
        "Callable", "Iterable", "Iterator", "Generator", "Sequence",
        "Mapping", "TypeVar", "Generic", "Protocol", "Literal",
        "ClassVar", "Final", "Annotated", "TypeAlias", "TypeGuard",
        "ParamSpec", "Concatenate", "Unpack", "TypeVarTuple",
        "NamedTuple", "TypedDict", "overload",
    }),
}


class HallucinationDetector(BaseAnalyzer):
    """Detects hallucinated named imports from popular packages."""

    @property
    def name(self) -> str:
        return "hallucination"

    @property
    def tier(self) -> int:
        return 1  # Deterministic

    async def analyze(
        self, repo_path: str, config: dict | None = None
    ) -> List[Finding]:
        ast_map = build_ast_map(repo_path)
        findings: List[Finding] = []

        for imp in ast_map.imports:
            if not imp.names:
                continue  # default / star import — can't check

            known = _KNOWN_EXPORTS.get(imp.module)
            if known is None:
                continue  # not a tracked package

            for name in imp.names:
                if name == "*":
                    continue
                if name not in known:
                    findings.append(Finding(
                        title=f"Hallucinated Import: {name} from '{imp.module}'",
                        severity=Severity.HIGH,
                        category=Category.HALLUCINATED_IMPORT,
                        file=imp.file,
                        line=imp.line,
                        description=(
                            f"'{name}' is not a known export of '{imp.module}'. "
                            f"This is likely hallucinated by an LLM. "
                            f"Known exports include: {', '.join(sorted(list(known)[:8]))}..."
                        ),
                        remediation=(
                            f"Remove or replace '{name}'. Check the '{imp.module}' "
                            f"documentation for the correct API."
                        ),
                        ai_prompt=(
                            f"The import '{{{{ {name} }}}}' from '{imp.module}' in {imp.file} "
                            f"does not exist. Find the correct API and fix the import."
                        ),
                        evidence=f"'{name}' not in known exports of '{imp.module}'",
                        tool="hallucination-detector",
                    ))

        logger.info("Hallucination scan: %d finding(s) from %d imports",
                     len(findings), len(ast_map.imports))
        return findings
