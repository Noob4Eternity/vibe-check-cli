from __future__ import annotations
import os
import re
import json
import math
import sys
import time
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional, Tuple

try:
    import tomllib  # Python 3.11+
except ImportError:
    try:
        import tomli as tomllib  # type: ignore[no-redef]
    except ImportError:
        tomllib = None  # type: ignore[assignment]

# filepath: /Users/kron/Coding/Projects/hackx4.0/vibe_audit/analyzers/dependencies.py
"""
Module: dependencies
Purpose: scan a git repository for package config files (requirements.txt, package.json),
         extract packages and check their registry metadata on PyPI and npm.
"""

import urllib.request
import urllib.parse


def find_config_files(root: str) -> List[str]:
    matches = []
    for dirpath, _, filenames in os.walk(root):
        for fname in filenames:
            if fname in ("requirements.txt", "package.json", "pyproject.toml"):
                matches.append(os.path.join(dirpath, fname))
    return matches


def parse_requirements(path: str) -> List[Dict[str, Optional[str]]]:
    """
    Returns list of dicts: {'name': <pkg-name>, 'requested': <version-spec or None>, 'source': path}
    Very permissive parser: skips VCS/editable installs and comments.
    """
    entries = []
    ver_split = re.compile(r'([<>=!~]{1,2})')
    with open(path, "r", encoding="utf-8") as fh:
        for raw in fh:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("-r") or line.startswith("--requirement"):
                # could include other files; skip handling includes for simplicity
                continue
            if line.startswith("-e") or line.startswith("git+"):
                # editable/vcs installs - skip
                continue
            # cut off inline comments
            line = line.split("#", 1)[0].strip()
            # remove extras like package[extra]
            name_part = line.split(";", 1)[0].strip()
            # split on version specifiers; keep requested specifier if present
            m = ver_split.search(name_part)
            if m:
                idx = m.start()
                pkg = name_part[:idx].strip()
                requested = name_part[idx:].strip()
            else:
                pkg = name_part.strip()
                requested = None
            # strip extras in brackets
            pkg = re.sub(r"\[.*\]", "", pkg)
            if pkg:
                entries.append({"name": pkg, "requested": requested, "source": path})
    return entries


def parse_pyproject_toml(path: str) -> List[Dict[str, Optional[str]]]:
    """
    Extract dependencies from pyproject.toml.
    Supports [project.dependencies], [project.optional-dependencies],
    and [tool.poetry.dependencies] / [tool.poetry.dev-dependencies].
    Returns list of dicts: {'name': name, 'requested': versionSpec or None, 'source': path}
    """
    entries = []
    if tomllib is None:
        return entries
    try:
        with open(path, "rb") as fh:
            data = tomllib.load(fh)
    except Exception:
        return entries

    ver_split = re.compile(r'([<>=!~]{1,2})')

    def _parse_pep508(spec: str) -> tuple[str, Optional[str]]:
        """Split a PEP 508 dependency string into (name, version_spec)."""
        spec = spec.split(";", 1)[0].strip()  # strip env markers
        spec = re.sub(r"\[.*?\]", "", spec)   # strip extras
        m = ver_split.search(spec)
        if m:
            return spec[:m.start()].strip(), spec[m.start():].strip()
        return spec.strip(), None

    # [project.dependencies]  — PEP 517/518 list of PEP 508 strings
    project = data.get("project") or {}
    for dep in project.get("dependencies") or []:
        name, requested = _parse_pep508(dep)
        if name:
            entries.append({"name": name, "requested": requested, "source": path})

    # [project.optional-dependencies]  — dict of group -> list of PEP 508 strings
    for group_deps in (project.get("optional-dependencies") or {}).values():
        for dep in group_deps or []:
            name, requested = _parse_pep508(dep)
            if name:
                entries.append({"name": name, "requested": requested, "source": path})

    # [tool.poetry.dependencies] / [tool.poetry.dev-dependencies]  — dict of name -> version
    poetry = (data.get("tool") or {}).get("poetry") or {}
    for key in ("dependencies", "dev-dependencies", "group"):
        if key == "group":
            # poetry groups: [tool.poetry.group.<name>.dependencies]
            for group in (poetry.get("group") or {}).values():
                for name, spec in (group.get("dependencies") or {}).items():
                    if name.lower() == "python":
                        continue
                    requested = spec if isinstance(spec, str) else None
                    entries.append({"name": name, "requested": requested, "source": path})
        else:
            for name, spec in (poetry.get(key) or {}).items():
                if name.lower() == "python":
                    continue
                requested = spec if isinstance(spec, str) else None
                entries.append({"name": name, "requested": requested, "source": path})

    return entries


def parse_package_json(path: str) -> List[Dict[str, Optional[str]]]:
    """
    Extract package names from dependencies, devDependencies, optionalDependencies, peerDependencies.
    Returns list of dicts: {'name': name, 'requested': versionSpec, 'source': path}
    """
    entries = []
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except Exception:
        return entries
    for key in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
        deps = data.get(key) or {}
        if isinstance(deps, dict):
            for name, spec in deps.items():
                entries.append({"name": name, "requested": spec, "source": path})
    return entries


def _http_get_json(url: str, timeout: int = 10) -> Dict[str, Any]:
    req = urllib.request.Request(url, headers={"Accept": "application/json", "User-Agent": "vibe-audit/1.0"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        raw = resp.read()
        try:
            return json.loads(raw.decode("utf-8", errors="replace"))
        except Exception:
            return {}


def check_pypi(name: str) -> Dict[str, Any]:
    """
    Query PyPI JSON API for package metadata.
    """
    encoded = urllib.parse.quote(name, safe="")
    url = f"https://pypi.org/pypi/{encoded}/json"
    try:
        data = _http_get_json(url)
        if not data:
            return {"found": False, "registry_url": url, "error": "no-data"}
        info = data.get("info", {}) or {}
        releases = data.get("releases", {}) or {}
        latest_version = info.get("version")
        latest_release_date = None
        if latest_version and latest_version in releases:
            files = releases.get(latest_version) or []
            times = [f.get("upload_time_iso_8601") for f in files if f.get("upload_time_iso_8601")]
            if times:
                latest_release_date = max(times)
        return {
            "found": True,
            "registry_url": url,
            "latest_version": latest_version,
            "latest_release_date": latest_release_date,
            "summary": info.get("summary"),
        }
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return {"found": False, "registry_url": url, "status": 404}
        return {"found": False, "registry_url": url, "error": str(e)}
    except Exception as e:
        return {"found": False, "registry_url": url, "error": str(e)}


def check_npm(name: str) -> Dict[str, Any]:
    """
    Query npm registry for package metadata.
    """
    encoded = urllib.parse.quote(name, safe="")
    url = f"https://registry.npmjs.org/{encoded}"
    try:
        data = _http_get_json(url)
        if not data:
            return {"found": False, "registry_url": url, "error": "no-data"}
        dist_tags = data.get("dist-tags") or {}
        latest_version = dist_tags.get("latest")
        time_info = data.get("time") or {}
        latest_release_date = time_info.get(latest_version) if latest_version else time_info.get("modified")
        description = data.get("description")
        return {
            "found": True,
            "registry_url": url,
            "latest_version": latest_version,
            "latest_release_date": latest_release_date,
            "summary": description,
        }
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return {"found": False, "registry_url": url, "status": 404}
        return {"found": False, "registry_url": url, "error": str(e)}
    except Exception as e:
        return {"found": False, "registry_url": url, "error": str(e)}


def determine_registry(name: str, source_path: str) -> str:
    """
    Heuristic: if source file is requirements.txt or pyproject.toml -> pypi,
    if package.json -> npm.
    Fallback: only scoped packages (starting with @) are unambiguously npm;
    everything else defaults to pypi (hyphens are common in Python package names).
    """
    if source_path.endswith("requirements.txt") or source_path.endswith("pyproject.toml"):
        return "pypi"
    if source_path.endswith("package.json"):
        return "npm"
    # fallback: only scoped npm packages (e.g. @scope/pkg) are unambiguously npm
    if name.startswith("@"):
        return "npm"
    return "pypi"


def check_entries(entries: List[Dict[str, Optional[str]]]) -> List[Dict[str, Any]]:
    results = []
    seen = set()
    for e in entries:
        name = e.get("name")
        source = e.get("source", "")
        requested = e.get("requested")
        if not name:
            continue
        key = (name, determine_registry(name, source))
        if key in seen:
            continue
        seen.add(key)
        registry = determine_registry(name, source)
        if registry == "pypi":
            meta = check_pypi(name)
        else:
            meta = check_npm(name)
        out = {
            "package": name,
            "package_type": registry,
            "requested": requested,
            "source_file": source,
        }
        out.update(meta)
        results.append(out)
        # slight pause to be polite to registries
        time.sleep(0.1)
    return results


def scan_repository(root: str) -> List[Dict[str, Any]]:
    files = find_config_files(root)
    all_entries: List[Dict[str, Optional[str]]] = []
    for f in files:
        if f.endswith("requirements.txt"):
            all_entries.extend(parse_requirements(f))
        elif f.endswith("package.json"):
            all_entries.extend(parse_package_json(f))
        elif f.endswith("pyproject.toml"):
            all_entries.extend(parse_pyproject_toml(f))
    return check_entries(all_entries)


# ---------------------------------------------------------------------------
# Health scoring
# ---------------------------------------------------------------------------

# Individual package scores (out of 10)
_SCORE_UP_TO_DATE        = 10
_SCORE_PATCH_BEHIND      =  9
_SCORE_MINOR_BEHIND      =  7   # 1–2 minor versions behind
_SCORE_MANY_MINOR_BEHIND =  5   # 3+ minor versions behind
_SCORE_MAJOR_BEHIND_ONE  =  3   # one major version behind
_SCORE_MAJOR_BEHIND_MANY =  1   # two or more major versions behind
_SCORE_DEPRECATED        =  0   # no release in > 3 years
_SCORE_NOT_FOUND         =  0   # 404 / hallucinated
_SCORE_UNKNOWN_VERSION   =  8   # found but version info unavailable

# A package is considered deprecated when its last release is older than this
_DEPRECATION_YEARS = 3


def _parse_semver(v: str) -> Tuple[int, ...]:
    """Parse a version string into a tuple of ints, e.g. '2.3.1' -> (2, 3, 1)."""
    parts = []
    for segment in re.split(r"[.\-]", v):
        m = re.match(r"(\d+)", segment)
        if m:
            parts.append(int(m.group(1)))
    return tuple(parts) if parts else (0,)


def _extract_base_version(requested: Optional[str]) -> Optional[str]:
    """
    Pull the first concrete version number out of a specifier string.
    e.g.  '>=2.25,<3.0'  -> '2.25'
          '==1.4.2'       -> '1.4.2'
          '^4.17.1'       -> '4.17.1'
          '~=3.1'         -> '3.1'
    """
    if not requested:
        return None
    m = re.search(r"(\d[\d.]*)", requested)
    return m.group(1) if m else None


def _years_since(iso_date: str) -> float:
    """Return fractional years elapsed since an ISO-8601 date string."""
    try:
        dt = datetime.fromisoformat(iso_date.replace("Z", "+00:00"))
        return (datetime.now(timezone.utc) - dt).days / 365.25
    except Exception:
        return 0.0


def _score_package(entry: Dict[str, Any]) -> Tuple[int, str]:
    """
    Score a single package out of 10 and return a human-readable reason.

    Scoring bands
    -------------
    10  up to date
     9  patch version behind
     7  1–2 minor versions behind
     5  3+ minor versions behind
     3  one major version behind
     1  two or more major versions behind
     0  deprecated  (no release in > 3 years)
     0  not found   (hallucinated / wrong name)
     8  found but version info insufficient to compare
    """
    if not entry.get("found"):
        return _SCORE_NOT_FOUND, "not found – possibly hallucinated or wrong name"

    # Deprecation check (stale regardless of version)
    release_date = entry.get("latest_release_date")
    if release_date:
        age = _years_since(release_date)
        if age >= _DEPRECATION_YEARS:
            return _SCORE_DEPRECATED, f"deprecated – last release {age:.1f} years ago"

    latest_str = entry.get("latest_version")
    requested_str = _extract_base_version(entry.get("requested"))

    if not latest_str:
        return _SCORE_UNKNOWN_VERSION, "found – version info unavailable"

    if not requested_str:
        # No pinned version – assume user is getting latest
        return _SCORE_UP_TO_DATE, "up to date (no version constraint)"

    latest   = _parse_semver(latest_str)
    requested = _parse_semver(requested_str)

    # Pad to same length
    length = max(len(latest), len(requested))
    latest    = latest    + (0,) * (length - len(latest))
    requested = requested + (0,) * (length - len(requested))

    lat_maj, lat_min, lat_pat = (latest + (0, 0, 0))[:3]
    req_maj, req_min, req_pat = (requested + (0, 0, 0))[:3]

    maj_diff = lat_maj - req_maj
    min_diff = lat_min - req_min if maj_diff == 0 else 0
    pat_diff = lat_pat - req_pat if maj_diff == 0 and min_diff == 0 else 0

    if maj_diff >= 2:
        return _SCORE_MAJOR_BEHIND_MANY, f"{maj_diff} major versions behind ({requested_str} → {latest_str})"
    if maj_diff == 1:
        return _SCORE_MAJOR_BEHIND_ONE,  f"1 major version behind ({requested_str} → {latest_str})"
    if min_diff >= 3:
        return _SCORE_MANY_MINOR_BEHIND, f"{min_diff} minor versions behind ({requested_str} → {latest_str})"
    if min_diff in (1, 2):
        return _SCORE_MINOR_BEHIND,      f"{min_diff} minor version(s) behind ({requested_str} → {latest_str})"
    if pat_diff > 0:
        return _SCORE_PATCH_BEHIND,      f"patch behind ({requested_str} → {latest_str})"
    if latest > requested:
        # newer but difference is within patch — treat as patch behind
        return _SCORE_PATCH_BEHIND,      f"slightly behind ({requested_str} → {latest_str})"

    return _SCORE_UP_TO_DATE, f"up to date ({latest_str})"


def compute_health_score(results: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Aggregate per-package scores into an overall repository health score out of 10.

    The score is the mean of all individual package scores, normalised to [0, 10].
    An empty dependency list scores 10 (nothing to be wrong).

    Returns a report with:
      - score            : float, 0-10
      - total_packages   : int
      - summary          : human-readable one-liner
      - up_to_date       : list of package names
      - outdated         : list of {package, requested, latest, reason}
      - deprecated       : list of {package, requested, latest, reason}
      - not_found        : list of {package, requested, reason}
    """
    if not results:
        return {
            "score":          10.0,
            "total_packages": 0,
            "summary":        "No dependencies found.",
            "up_to_date":     [],
            "outdated":       [],
            "deprecated":     [],
            "not_found":      [],
        }

    categories: Dict[str, list] = {
        "up_to_date":  [],
        "outdated":    [],
        "deprecated":  [],
        "not_found":   [],
    }

    score_sum = 0
    for entry in results:
        pkg_score, reason = _score_package(entry)
        score_sum += pkg_score
        name     = entry["package"]
        req      = entry.get("requested")
        latest   = entry.get("latest_version")

        if not entry.get("found"):
            categories["not_found"].append({
                "package":   name,
                "requested": req,
                "reason":    reason,
            })
        elif pkg_score == 0:  # found but deprecated
            categories["deprecated"].append({
                "package":   name,
                "requested": req,
                "latest":    latest,
                "reason":    reason,
            })
        elif pkg_score == _SCORE_UP_TO_DATE:
            categories["up_to_date"].append(name)
        else:
            categories["outdated"].append({
                "package":   name,
                "requested": req,
                "latest":    latest,
                "reason":    reason,
            })

    total = len(results)
    score = round(score_sum / total, 1)

    # Human-readable summary
    parts = []
    if categories["up_to_date"]:
        parts.append(f"{len(categories['up_to_date'])} up to date")
    if categories["outdated"]:
        parts.append(f"{len(categories['outdated'])} outdated")
    if categories["deprecated"]:
        parts.append(f"{len(categories['deprecated'])} deprecated")
    if categories["not_found"]:
        parts.append(f"{len(categories['not_found'])} not found / hallucinated")
    summary = ", ".join(parts) + f" ({total} total)"

    return {
        "score":          score,
        "total_packages": total,
        "summary":        summary,
        **categories,
    }


def main(argv: Optional[List[str]] = None) -> int:
    root = os.getcwd() if not argv else (argv[0] if argv else os.getcwd())
    results  = scan_repository(root)
    report   = compute_health_score(results)
    json.dump(report, sys.stdout, indent=2, ensure_ascii=False)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))