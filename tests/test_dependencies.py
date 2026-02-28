"""Tests for vibe_audit.analyzers.dependencies"""
from __future__ import annotations

import io
import json
import os
import sys
import tempfile
import textwrap
import unittest
from unittest.mock import patch, MagicMock
import urllib.error

from vibe_audit.analyzers.dependencies import (
    find_config_files,
    parse_requirements,
    parse_package_json,
    parse_pyproject_toml,
    check_pypi,
    check_npm,
    determine_registry,
    check_entries,
    scan_repository,
    main,
    _parse_semver,
    _extract_base_version,
    _score_package,
    compute_health_score,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _write(path: str, content: str) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(textwrap.dedent(content))


# ---------------------------------------------------------------------------
# find_config_files
# ---------------------------------------------------------------------------

class TestFindConfigFiles(unittest.TestCase):
    def test_finds_requirements_and_package_json(self):
        with tempfile.TemporaryDirectory() as root:
            req = os.path.join(root, "requirements.txt")
            pkg = os.path.join(root, "sub", "package.json")
            ppt = os.path.join(root, "pyproject.toml")
            _write(req, "flask==2.0\n")
            _write(pkg, "{}")
            _write(ppt, "[project]\n")
            found = find_config_files(root)
            self.assertIn(req, found)
            self.assertIn(pkg, found)
            self.assertIn(ppt, found)

    def test_ignores_other_files(self):
        with tempfile.TemporaryDirectory() as root:
            _write(os.path.join(root, "setup.py"), "")
            _write(os.path.join(root, "Pipfile"), "")
            self.assertEqual(find_config_files(root), [])

    def test_empty_directory(self):
        with tempfile.TemporaryDirectory() as root:
            self.assertEqual(find_config_files(root), [])


# ---------------------------------------------------------------------------
# parse_requirements
# ---------------------------------------------------------------------------

class TestParseRequirements(unittest.TestCase):
    def _parse(self, content: str):
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".txt", delete=False, encoding="utf-8"
        ) as fh:
            fh.write(textwrap.dedent(content))
            path = fh.name
        try:
            return parse_requirements(path)
        finally:
            os.unlink(path)

    def test_simple_pinned(self):
        entries = self._parse("flask==2.0.1\n")
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]["name"], "flask")
        self.assertEqual(entries[0]["requested"], "==2.0.1")

    def test_range_specifier(self):
        entries = self._parse("requests>=2.25,<3.0\n")
        self.assertEqual(entries[0]["name"], "requests")
        self.assertEqual(entries[0]["requested"], ">=2.25,<3.0")

    def test_no_version(self):
        entries = self._parse("numpy\n")
        self.assertEqual(entries[0]["name"], "numpy")
        self.assertIsNone(entries[0]["requested"])

    def test_skips_comments_and_blank_lines(self):
        entries = self._parse("# comment\n\nflask==1.0\n")
        self.assertEqual(len(entries), 1)

    def test_skips_editable_and_vcs(self):
        entries = self._parse("-e .\ngit+https://github.com/x/y.git\ndjango==4.0\n")
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]["name"], "django")

    def test_strips_extras_in_brackets(self):
        entries = self._parse("uvicorn[standard]==0.20\n")
        self.assertEqual(entries[0]["name"], "uvicorn")

    def test_inline_comment_stripped(self):
        entries = self._parse("boto3==1.26  # AWS SDK\n")
        self.assertEqual(entries[0]["name"], "boto3")

    def test_environment_marker_stripped(self):
        entries = self._parse("pywin32>=1.0; sys_platform=='win32'\n")
        self.assertEqual(entries[0]["name"], "pywin32")

    def test_source_field_is_path(self):
        with tempfile.NamedTemporaryFile(
            mode="w", suffix="requirements.txt", delete=False, encoding="utf-8"
        ) as fh:
            fh.write("flask==2.0\n")
            path = fh.name
        try:
            entries = parse_requirements(path)
            self.assertEqual(entries[0]["source"], path)
        finally:
            os.unlink(path)


# ---------------------------------------------------------------------------
# parse_pyproject_toml
# ---------------------------------------------------------------------------

class TestParsePyprojectToml(unittest.TestCase):
    def _parse(self, content: str):
        with tempfile.NamedTemporaryFile(
            mode="wb", suffix="pyproject.toml", delete=False
        ) as fh:
            fh.write(content.encode())
            path = fh.name
        try:
            return parse_pyproject_toml(path)
        finally:
            os.unlink(path)

    def test_project_dependencies(self):
        entries = self._parse(
            '[project]\ndependencies = ["flask>=2.0", "requests"]\n'
        )
        names = {e["name"] for e in entries}
        self.assertIn("flask", names)
        self.assertIn("requests", names)

    def test_project_dependencies_version_parsed(self):
        entries = self._parse('[project]\ndependencies = ["typer>=0.9.0"]\n')
        self.assertEqual(entries[0]["requested"], ">=0.9.0")

    def test_optional_dependencies(self):
        entries = self._parse(
            '[project.optional-dependencies]\nllm = ["openai>=1.0", "anthropic>=0.18"]\n'
        )
        names = {e["name"] for e in entries}
        self.assertIn("openai", names)
        self.assertIn("anthropic", names)

    def test_poetry_dependencies(self):
        entries = self._parse(
            '[tool.poetry.dependencies]\npython = "^3.10"\nflask = "^2.0"\n'
        )
        names = {e["name"] for e in entries}
        # python itself should be skipped
        self.assertNotIn("python", names)
        self.assertIn("flask", names)

    def test_invalid_toml_returns_empty(self):
        entries = self._parse("not valid toml {{{")
        self.assertEqual(entries, [])

    def test_no_deps_returns_empty(self):
        entries = self._parse('[project]\nname = "my-app"\nversion = "1.0.0"\n')
        self.assertEqual(entries, [])

    def test_source_field_is_path(self):
        with tempfile.NamedTemporaryFile(
            mode="wb", suffix="pyproject.toml", delete=False
        ) as fh:
            fh.write(b'[project]\ndependencies = ["flask>=2.0"]\n')
            path = fh.name
        try:
            entries = parse_pyproject_toml(path)
            self.assertEqual(entries[0]["source"], path)
        finally:
            os.unlink(path)

    def test_env_markers_stripped(self):
        entries = self._parse(
            '[project]\ndependencies = ["pywin32>=1.0; sys_platform == \'win32\'"]\n'
        )
        self.assertEqual(entries[0]["name"], "pywin32")


# ---------------------------------------------------------------------------
# parse_package_json
# ---------------------------------------------------------------------------

class TestParsePackageJson(unittest.TestCase):
    def _parse(self, data: dict):
        with tempfile.NamedTemporaryFile(
            mode="w", suffix="package.json", delete=False, encoding="utf-8"
        ) as fh:
            json.dump(data, fh)
            path = fh.name
        try:
            return parse_package_json(path)
        finally:
            os.unlink(path)

    def test_dependencies(self):
        entries = self._parse({"dependencies": {"express": "^4.17.1"}})
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]["name"], "express")
        self.assertEqual(entries[0]["requested"], "^4.17.1")

    def test_dev_and_peer_dependencies(self):
        entries = self._parse({
            "devDependencies": {"jest": "^27.0"},
            "peerDependencies": {"react": ">=17"},
        })
        names = {e["name"] for e in entries}
        self.assertIn("jest", names)
        self.assertIn("react", names)

    def test_all_dep_types(self):
        entries = self._parse({
            "dependencies": {"a": "1"},
            "devDependencies": {"b": "2"},
            "optionalDependencies": {"c": "3"},
            "peerDependencies": {"d": "4"},
        })
        self.assertEqual(len(entries), 4)

    def test_invalid_json_returns_empty(self):
        with tempfile.NamedTemporaryFile(
            mode="w", suffix="package.json", delete=False, encoding="utf-8"
        ) as fh:
            fh.write("not valid json{{{")
            path = fh.name
        try:
            self.assertEqual(parse_package_json(path), [])
        finally:
            os.unlink(path)

    def test_missing_dep_keys_returns_empty(self):
        entries = self._parse({"name": "my-app", "version": "1.0.0"})
        self.assertEqual(entries, [])


# ---------------------------------------------------------------------------
# check_pypi
# ---------------------------------------------------------------------------

PYPI_RESPONSE = {
    "info": {"version": "2.0.1", "summary": "A web framework"},
    "releases": {
        "2.0.1": [{"upload_time_iso_8601": "2021-05-11T12:00:00Z"}]
    },
}


class TestCheckPypi(unittest.TestCase):
    @patch("vibe_audit.analyzers.dependencies._http_get_json", return_value=PYPI_RESPONSE)
    def test_found(self, _mock):
        result = check_pypi("flask")
        self.assertTrue(result["found"])
        self.assertEqual(result["latest_version"], "2.0.1")
        self.assertEqual(result["latest_release_date"], "2021-05-11T12:00:00Z")
        self.assertEqual(result["summary"], "A web framework")

    @patch("vibe_audit.analyzers.dependencies._http_get_json", return_value={})
    def test_empty_response(self, _mock):
        result = check_pypi("nonexistent")
        self.assertFalse(result["found"])

    @patch("vibe_audit.analyzers.dependencies._http_get_json",
           side_effect=urllib.error.HTTPError(None, 404, "Not Found", {}, None))
    def test_404(self, _mock):
        result = check_pypi("ghost-pkg")
        self.assertFalse(result["found"])
        self.assertEqual(result.get("status"), 404)

    @patch("vibe_audit.analyzers.dependencies._http_get_json",
           side_effect=Exception("timeout"))
    def test_network_error(self, _mock):
        result = check_pypi("flask")
        self.assertFalse(result["found"])
        self.assertIn("error", result)


# ---------------------------------------------------------------------------
# check_npm
# ---------------------------------------------------------------------------

NPM_RESPONSE = {
    "dist-tags": {"latest": "4.17.21"},
    "time": {"4.17.21": "2021-03-02T00:00:00Z"},
    "description": "A JS utility library",
}


class TestCheckNpm(unittest.TestCase):
    @patch("vibe_audit.analyzers.dependencies._http_get_json", return_value=NPM_RESPONSE)
    def test_found(self, _mock):
        result = check_npm("lodash")
        self.assertTrue(result["found"])
        self.assertEqual(result["latest_version"], "4.17.21")
        self.assertEqual(result["latest_release_date"], "2021-03-02T00:00:00Z")
        self.assertEqual(result["summary"], "A JS utility library")

    @patch("vibe_audit.analyzers.dependencies._http_get_json", return_value={})
    def test_empty_response(self, _mock):
        result = check_npm("nonexistent")
        self.assertFalse(result["found"])

    @patch("vibe_audit.analyzers.dependencies._http_get_json",
           side_effect=urllib.error.HTTPError(None, 404, "Not Found", {}, None))
    def test_404(self, _mock):
        result = check_npm("ghost-pkg")
        self.assertFalse(result["found"])
        self.assertEqual(result.get("status"), 404)

    @patch("vibe_audit.analyzers.dependencies._http_get_json",
           side_effect=Exception("timeout"))
    def test_network_error(self, _mock):
        result = check_npm("lodash")
        self.assertFalse(result["found"])
        self.assertIn("error", result)


# ---------------------------------------------------------------------------
# determine_registry
# ---------------------------------------------------------------------------

class TestDetermineRegistry(unittest.TestCase):
    def test_requirements_txt_always_pypi(self):
        self.assertEqual(determine_registry("some-pkg", "/project/requirements.txt"), "pypi")
        self.assertEqual(determine_registry("@scoped/pkg", "/project/requirements.txt"), "pypi")

    def test_package_json_always_npm(self):
        self.assertEqual(determine_registry("flask", "/project/package.json"), "npm")

    def test_fallback_scoped_is_npm(self):
        self.assertEqual(determine_registry("@scope/pkg", "unknown.txt"), "npm")

    def test_fallback_hyphen_is_pypi(self):
        # hyphens are common in Python package names — should NOT be classified as npm
        self.assertEqual(determine_registry("flask-login", "unknown.txt"), "pypi")
        self.assertEqual(determine_registry("pytest-asyncio", "unknown.txt"), "pypi")

    def test_fallback_plain_name_is_pypi(self):
        self.assertEqual(determine_registry("numpy", "unknown.txt"), "pypi")

    def test_fallback_underscore_name_is_pypi(self):
        self.assertEqual(determine_registry("my_package", "unknown.txt"), "pypi")

    def test_pyproject_toml_always_pypi(self):
        self.assertEqual(determine_registry("flask", "/project/pyproject.toml"), "pypi")
        self.assertEqual(determine_registry("pytest-asyncio", "/project/pyproject.toml"), "pypi")


# ---------------------------------------------------------------------------
# check_entries
# ---------------------------------------------------------------------------

class TestCheckEntries(unittest.TestCase):
    @patch("vibe_audit.analyzers.dependencies.check_pypi", return_value={"found": True, "latest_version": "1.0"})
    @patch("vibe_audit.analyzers.dependencies.check_npm", return_value={"found": True, "latest_version": "2.0"})
    @patch("vibe_audit.analyzers.dependencies.time.sleep")
    def test_routes_by_registry(self, _sleep, mock_npm, mock_pypi):
        entries = [
            {"name": "flask", "requested": "==2.0", "source": "requirements.txt"},
            {"name": "express", "requested": "^4.0", "source": "package.json"},
        ]
        results = check_entries(entries)
        self.assertEqual(len(results), 2)
        pypi_result = next(r for r in results if r["package"] == "flask")
        npm_result = next(r for r in results if r["package"] == "express")
        self.assertEqual(pypi_result["package_type"], "pypi")
        self.assertEqual(npm_result["package_type"], "npm")
        mock_pypi.assert_called_once_with("flask")
        mock_npm.assert_called_once_with("express")

    @patch("vibe_audit.analyzers.dependencies.check_pypi", return_value={"found": True})
    @patch("vibe_audit.analyzers.dependencies.time.sleep")
    def test_deduplicates(self, _sleep, mock_pypi):
        entries = [
            {"name": "flask", "requested": "==2.0", "source": "requirements.txt"},
            {"name": "flask", "requested": "==2.0", "source": "requirements.txt"},
        ]
        results = check_entries(entries)
        self.assertEqual(len(results), 1)
        mock_pypi.assert_called_once()

    @patch("vibe_audit.analyzers.dependencies.check_pypi", return_value={"found": True})
    @patch("vibe_audit.analyzers.dependencies.time.sleep")
    def test_skips_missing_name(self, _sleep, _mock_pypi):
        entries = [{"name": None, "requested": None, "source": "requirements.txt"}]
        self.assertEqual(check_entries(entries), [])


# ---------------------------------------------------------------------------
# scan_repository
# ---------------------------------------------------------------------------

class TestScanRepository(unittest.TestCase):
    @patch("vibe_audit.analyzers.dependencies.check_pypi", return_value={"found": True, "latest_version": "1.0"})
    @patch("vibe_audit.analyzers.dependencies.check_npm", return_value={"found": True, "latest_version": "2.0"})
    @patch("vibe_audit.analyzers.dependencies.time.sleep")
    def test_full_scan(self, _sleep, _npm, _pypi):
        with tempfile.TemporaryDirectory() as root:
            _write(os.path.join(root, "requirements.txt"), "flask==2.0\nrequests>=2.25\n")
            _write(os.path.join(root, "package.json"), json.dumps({
                "dependencies": {"express": "^4.17.1"},
                "devDependencies": {"jest": "^27.0"},
            }))
            _write(os.path.join(root, "pyproject.toml"),
                   "[project]\ndependencies = [\"typer>=0.9\"]\n")
            results = scan_repository(root)
        self.assertEqual(len(results), 5)
        pkgs = {r["package"] for r in results}
        self.assertEqual(pkgs, {"flask", "requests", "express", "jest", "typer"})

    @patch("vibe_audit.analyzers.dependencies.time.sleep")
    def test_empty_repo(self, _sleep):
        with tempfile.TemporaryDirectory() as root:
            self.assertEqual(scan_repository(root), [])


# ---------------------------------------------------------------------------
# _parse_semver
# ---------------------------------------------------------------------------

class TestParseSemver(unittest.TestCase):
    def test_simple(self):
        self.assertEqual(_parse_semver("1.2.3"), (1, 2, 3))

    def test_two_part(self):
        self.assertEqual(_parse_semver("2.0"), (2, 0))

    def test_major_only(self):
        self.assertEqual(_parse_semver("3"), (3,))

    def test_pre_release(self):
        result = _parse_semver("1.2.3a4")
        self.assertEqual(result[0], 1)
        self.assertEqual(result[1], 2)

    def test_empty_string(self):
        self.assertEqual(_parse_semver(""), (0,))


# ---------------------------------------------------------------------------
# _extract_base_version
# ---------------------------------------------------------------------------

class TestExtractBaseVersion(unittest.TestCase):
    def test_pinned(self):
        self.assertEqual(_extract_base_version("==2.0.1"), "2.0.1")

    def test_gte(self):
        self.assertEqual(_extract_base_version(">=2.25"), "2.25")

    def test_caret(self):
        self.assertEqual(_extract_base_version("^4.17.1"), "4.17.1")

    def test_tilde(self):
        self.assertEqual(_extract_base_version("~=3.1"), "3.1")

    def test_range_takes_first(self):
        self.assertEqual(_extract_base_version(">=2.25,<3.0"), "2.25")

    def test_none_input(self):
        self.assertIsNone(_extract_base_version(None))

    def test_no_version_in_string(self):
        self.assertIsNone(_extract_base_version("*"))


# ---------------------------------------------------------------------------
# _score_package
# ---------------------------------------------------------------------------

class TestScorePackage(unittest.TestCase):
    def _entry(self, found=True, requested=None, latest=None, release_date=None):
        return {
            "found":               found,
            "requested":           requested,
            "latest_version":      latest,
            "latest_release_date": release_date,
        }

    def test_not_found_scores_zero(self):
        score, reason = _score_package(self._entry(found=False))
        self.assertEqual(score, 0)
        self.assertIn("not found", reason)

    def test_deprecated_scores_zero(self):
        # Release date > 3 years ago
        score, reason = _score_package(self._entry(
            latest="1.0", release_date="2019-01-01T00:00:00Z"
        ))
        self.assertEqual(score, 0)
        self.assertIn("deprecated", reason)

    def test_up_to_date_scores_ten(self):
        score, _ = _score_package(self._entry(requested="==2.0.1", latest="2.0.1"))
        self.assertEqual(score, 10)

    def test_no_constraint_scores_ten(self):
        score, _ = _score_package(self._entry(requested=None, latest="2.0.1"))
        self.assertEqual(score, 10)

    def test_patch_behind_scores_nine(self):
        score, _ = _score_package(self._entry(requested="==2.0.0", latest="2.0.5"))
        self.assertEqual(score, 9)

    def test_one_minor_behind_scores_seven(self):
        score, _ = _score_package(self._entry(requested="==2.0.0", latest="2.1.0"))
        self.assertEqual(score, 7)

    def test_two_minor_behind_scores_seven(self):
        score, _ = _score_package(self._entry(requested="==2.0.0", latest="2.2.0"))
        self.assertEqual(score, 7)

    def test_three_minor_behind_scores_five(self):
        score, _ = _score_package(self._entry(requested="==2.0.0", latest="2.3.0"))
        self.assertEqual(score, 5)

    def test_one_major_behind_scores_three(self):
        score, _ = _score_package(self._entry(requested="==1.0.0", latest="2.0.0"))
        self.assertEqual(score, 3)

    def test_two_major_behind_scores_one(self):
        score, _ = _score_package(self._entry(requested="==1.0.0", latest="3.0.0"))
        self.assertEqual(score, 1)

    def test_no_latest_version_scores_eight(self):
        score, _ = _score_package(self._entry(requested=">=1.0", latest=None))
        self.assertEqual(score, 8)


# ---------------------------------------------------------------------------
# compute_health_score
# ---------------------------------------------------------------------------

class TestComputeHealthScore(unittest.TestCase):
    def _make_results(self, specs):
        """specs: list of (found, requested, latest, release_date)"""
        return [
            {
                "package": f"pkg{i}",
                "package_type": "pypi",
                "found":               s[0],
                "requested":           s[1],
                "latest_version":      s[2],
                "latest_release_date": s[3] if len(s) > 3 else None,
            }
            for i, s in enumerate(specs)
        ]

    def test_empty_results_score_ten(self):
        report = compute_health_score([])
        self.assertEqual(report["score"], 10.0)
        self.assertEqual(report["total_packages"], 0)
        self.assertEqual(report["up_to_date"], [])
        self.assertEqual(report["outdated"], [])

    def test_scenario_from_spec(self):
        """
        6 up to date, 2 slightly outdated, 1 hallucinated, 1 deprecated
        Expected score ≈ (6*10 + 2*7 + 1*0 + 1*0) / 10 = 7.4
        """
        results = self._make_results([
            (True,  "==1.0.0", "1.0.0", None),           # up to date
            (True,  "==1.0.0", "1.0.0", None),           # up to date
            (True,  "==1.0.0", "1.0.0", None),           # up to date
            (True,  "==1.0.0", "1.0.0", None),           # up to date
            (True,  "==1.0.0", "1.0.0", None),           # up to date
            (True,  "==1.0.0", "1.0.0", None),           # up to date
            (True,  "==1.0.0", "1.1.0", None),           # 1 minor behind → 7
            (True,  "==1.0.0", "1.2.0", None),           # 2 minor behind → 7
            (False, None,      None,    None),            # not found → 0
            (True,  "==1.0.0", "1.0.0", "2019-01-01T00:00:00Z"),  # deprecated → 0
        ])
        report = compute_health_score(results)
        self.assertEqual(report["score"], 7.4)
        self.assertEqual(len(report["up_to_date"]),  6)
        self.assertEqual(len(report["outdated"]),    2)
        self.assertEqual(len(report["not_found"]),   1)
        self.assertEqual(len(report["deprecated"]),  1)

    def test_all_up_to_date_scores_ten(self):
        results = self._make_results([
            (True, "==1.0.0", "1.0.0", None),
            (True, "==2.0.0", "2.0.0", None),
        ])
        report = compute_health_score(results)
        self.assertEqual(report["score"], 10.0)
        self.assertEqual(len(report["up_to_date"]), 2)
        self.assertEqual(report["outdated"], [])

    def test_all_not_found_scores_zero(self):
        results = self._make_results([
            (False, None, None, None),
            (False, None, None, None),
        ])
        report = compute_health_score(results)
        self.assertEqual(report["score"], 0.0)
        self.assertEqual(len(report["not_found"]), 2)

    def test_report_has_required_keys(self):
        results = self._make_results([(True, "==1.0", "1.0", None)])
        report = compute_health_score(results)
        for key in ("score", "total_packages", "summary",
                    "up_to_date", "outdated", "deprecated", "not_found"):
            self.assertIn(key, report)

    def test_up_to_date_list_contains_names(self):
        results = self._make_results([(True, "==1.0", "1.0", None)])
        report = compute_health_score(results)
        self.assertIn("pkg0", report["up_to_date"])

    def test_outdated_list_contains_dicts(self):
        results = self._make_results([(True, "==1.0.0", "1.1.0", None)])
        report = compute_health_score(results)
        entry = report["outdated"][0]
        for key in ("package", "requested", "latest", "reason"):
            self.assertIn(key, entry)

    def test_not_found_list_contains_dicts(self):
        results = self._make_results([(False, None, None, None)])
        report = compute_health_score(results)
        entry = report["not_found"][0]
        for key in ("package", "requested", "reason"):
            self.assertIn(key, entry)

    def test_deprecated_list_contains_dicts(self):
        results = self._make_results([(True, "==1.0", "1.0", "2019-01-01T00:00:00Z")])
        report = compute_health_score(results)
        entry = report["deprecated"][0]
        for key in ("package", "requested", "latest", "reason"):
            self.assertIn(key, entry)


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------

class TestMain(unittest.TestCase):
    @patch("vibe_audit.analyzers.dependencies.scan_repository", return_value=[
        {"package": "flask", "package_type": "pypi", "found": True,
         "requested": "==2.0", "latest_version": "2.0", "latest_release_date": None}
    ])
    def test_outputs_json_health_report(self, _mock):
        captured = io.StringIO()
        with patch("sys.stdout", captured):
            code = main(["/some/dir"])
        self.assertEqual(code, 0)
        output = json.loads(captured.getvalue())
        for key in ("score", "summary", "up_to_date", "outdated", "deprecated", "not_found"):
            self.assertIn(key, output)
        self.assertIn("flask", output["up_to_date"])

    @patch("vibe_audit.analyzers.dependencies.scan_repository", return_value=[])
    def test_uses_cwd_when_no_args(self, mock_scan):
        with patch("sys.stdout", io.StringIO()):
            main([])
        mock_scan.assert_called_once_with(os.getcwd())


if __name__ == "__main__":
    unittest.main()
