#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia

"""
Ensure each .py file has:
1) SPDX Apache-2.0 header
2) Current-year copyright
3) (Optionally) `from __future__ import annotations`

Usage:
  ./tools/maintenance/add-required-python-headers.py [ROOT_DIR] [--exclude a,b] \
    [--future {auto,yes,no}] [--author "Name"] [--year 2025] [--verbose]
"""

from __future__ import annotations

import argparse
import ast
import os
import re
import sys
from datetime import datetime

DEFAULT_AUTHOR = "Maurice Garcia"
DEFAULT_YEAR = datetime.now().year
SPDX_ID = "Apache-2.0"
SPDX_LINE = f"# SPDX-License-Identifier: {SPDX_ID}\n"
COPYRIGHT_TEMPLATE = "# Copyright (c) {year} {author}\n"
FUTURE_LINE = "from __future__ import annotations\n"
DOCSTRING_NOT_FOUND = -1
MAX_HEADER_SCAN_LINES = 12
COPYRIGHT_INSERT_SCAN_LINES = 5

COPYRIGHT_RE = re.compile(r"^#\s*Copyright\s*\(c\)\s*(\d{4})(?:-(\d{4}))?\s+(.*)$")
ENCODING_RE = re.compile(r"^#.*coding[:=]\s*([-\w.]+)")
SPDX_RE = re.compile(r"^#\s*SPDX-License-Identifier:\s*(.+)$")

DEFAULT_EXCLUDED_DIRS: set[str] = {
    ".git",
    ".env",
    "env",
    "venv",
    ".venv",
    "__pycache__",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".tox",
    "node_modules",
    "build",
    "dist",
    ".idea",
    ".vscode",
}


class HeaderUpdater:
    """Update SPDX and copyright headers across a directory tree."""

    def __init__(
        self,
        author: str,
        year: int,
        add_future: bool,
        extra_excluded: set[str],
        verbose: bool,
    ) -> None:
        self.author = author
        self.year = year
        self.add_future = add_future
        self.extra_excluded = extra_excluded
        self.verbose = verbose

    def run(self, root: str) -> None:
        """Scan the root directory and update all Python files in place."""
        if self._should_skip_dir(root):
            if self.verbose:
                print(f"⏭ Root appears to be a virtualenv or excluded: {root}")
            return

        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [
                d
                for d in dirnames
                if not self._should_skip_dir(os.path.join(dirpath, d))
            ]
            for filename in filenames:
                if not filename.endswith(".py"):
                    continue
                full_path = os.path.join(dirpath, filename)
                try:
                    self._ensure_header_and_future(full_path)
                except Exception as exc:
                    print(f"❌ Error processing {full_path}: {exc}")

    def _ensure_header_and_future(self, path: str) -> None:
        with open(path, "r", encoding="utf-8") as handle:
            lines = handle.readlines()

        original = lines[:]
        prefix, remainder = self._split_shebang_encoding(lines)

        body: list[str] = []
        header_added = False
        header_updated = False

        spdx_idx = self._find_spdx_line_index(lines)
        if spdx_idx is None:
            body.append(SPDX_LINE)
            body.append(self._copyright_line())
            body.append("\n")
            header_added = True
        else:
            spdx_match = SPDX_RE.match(lines[spdx_idx])
            if spdx_match is not None:
                existing_spdx = spdx_match.group(1).strip()
                if existing_spdx != SPDX_ID:
                    lines[spdx_idx] = SPDX_LINE
                    header_updated = True

            copyright_idx = self._find_copyright_line_index(lines)
            if copyright_idx is not None:
                match = COPYRIGHT_RE.match(lines[copyright_idx])
                if match is not None:
                    start_year = int(match.group(1))
                    end_year_text = match.group(2)
                    old_author = match.group(3).strip()
                    if end_year_text is None:
                        if start_year != self.year:
                            lines[copyright_idx] = self._copyright_line(
                                author=old_author or self.author,
                                start_year=start_year,
                            )
                            header_updated = True
                    else:
                        end_year = int(end_year_text)
                        if end_year != self.year:
                            lines[copyright_idx] = self._copyright_line(
                                author=old_author or self.author,
                                start_year=start_year,
                            )
                            header_updated = True
            else:
                rem_copy = remainder[:]
                inserted = False
                for index, line in enumerate(rem_copy[:COPYRIGHT_INSERT_SCAN_LINES]):
                    if "SPDX-License-Identifier:" in line:
                        insert_at = index + 1
                        rem_copy.insert(insert_at, self._copyright_line())
                        rem_copy.insert(insert_at + 1, "\n")
                        remainder = rem_copy
                        header_updated = True
                        inserted = True
                        break
                if not inserted:
                    body.append(SPDX_LINE)
                    body.append(self._copyright_line())
                    body.append("\n")
                    header_added = True

        body.extend(remainder)

        future_added = False
        if self.add_future and not self._has_future_import(lines):
            ds_start, ds_end = self._find_module_docstring_span(body)
            insert_at = 0 if ds_start == DOCSTRING_NOT_FOUND else ds_end + 1
            if insert_at < len(body) and body[insert_at].strip():
                body.insert(insert_at, "\n")
                insert_at += 1
            body.insert(insert_at, FUTURE_LINE)
            insert_at += 1
            if insert_at >= len(body) or body[insert_at].strip():
                body.insert(insert_at, "\n")
            future_added = True

        new_lines = prefix + body

        if new_lines != original:
            with open(path, "w", encoding="utf-8") as handle:
                handle.writelines(new_lines)
            tags = []
            if header_added:
                tags.append("header")
            if header_updated and not header_added:
                tags.append("copyright-year")
            if future_added:
                tags.append("future")
            tag = "+".join(tags) if tags else "modified"
            print(f"✅ Updated ({tag}): {path}")
        else:
            if self.verbose:
                print(f"⏭ No changes: {path}")

    def _copyright_line(self, author: str | None = None, start_year: int | None = None) -> str:
        year_text = str(self.year)
        if start_year is not None and start_year != self.year:
            year_text = f"{start_year}-{self.year}"
        return COPYRIGHT_TEMPLATE.format(
            year=year_text,
            author=author or self.author,
        )

    def _find_spdx_line_index(self, lines: list[str]) -> int | None:
        for index, line in enumerate(lines[:MAX_HEADER_SCAN_LINES]):
            if SPDX_RE.match(line):
                return index
        return None

    def _find_copyright_line_index(self, lines: list[str]) -> int | None:
        for index, line in enumerate(lines[:MAX_HEADER_SCAN_LINES]):
            if COPYRIGHT_RE.match(line):
                return index
        return None

    def _has_future_import(self, lines: list[str]) -> bool:
        return "from __future__ import annotations" in "".join(lines)

    def _split_shebang_encoding(self, lines: list[str]) -> tuple[list[str], list[str]]:
        prefix: list[str] = []
        index = 0
        if lines and lines[0].startswith("#!"):
            prefix.append(lines[0])
            index = 1
        if len(lines) > index and ENCODING_RE.match(lines[index] or ""):
            prefix.append(lines[index])
            index += 1
        return prefix, lines[index:]

    def _find_module_docstring_span(self, body_lines: list[str]) -> tuple[int, int]:
        text = "".join(body_lines)
        try:
            module = ast.parse(text)
        except Exception:
            return DOCSTRING_NOT_FOUND, DOCSTRING_NOT_FOUND
        if not getattr(module, "body", None):
            return DOCSTRING_NOT_FOUND, DOCSTRING_NOT_FOUND
        first = module.body[0]
        if isinstance(first, ast.Expr) and isinstance(
            getattr(first, "value", None),
            (ast.Str, ast.Constant),
        ):
            value = (
                first.value.s
                if isinstance(first.value, ast.Str)
                else (
                    first.value.value
                    if isinstance(first.value, ast.Constant)
                    and isinstance(first.value.value, str)
                    else None
                )
            )
            if isinstance(value, str):
                return first.lineno - 1, first.end_lineno - 1
        return DOCSTRING_NOT_FOUND, DOCSTRING_NOT_FOUND

    def _is_virtualenv_dir(self, path: str) -> bool:
        if os.path.isfile(os.path.join(path, "pyvenv.cfg")):
            return True
        if os.path.isfile(os.path.join(path, "bin", "activate")):
            return True
        if os.path.isfile(os.path.join(path, "Scripts", "activate")):
            return True
        return False

    def _is_site_packages_path(self, path: str) -> bool:
        return "site-packages" in set(path.split(os.sep))

    def _should_skip_dir(self, path: str) -> bool:
        base = os.path.basename(path)
        if base in DEFAULT_EXCLUDED_DIRS or base in self.extra_excluded:
            return True
        if os.path.islink(path):
            return True
        if self._is_virtualenv_dir(path):
            return True
        if self._is_site_packages_path(path):
            return True
        return False


class HeaderCli:
    """Parse CLI arguments and run the header updater."""

    @staticmethod
    def parse_args() -> argparse.Namespace:
        parser = argparse.ArgumentParser(
            description=(
                "Ensure Apache-2.0 SPDX headers, current year, and future import"
                " across a tree."
            ),
        )
        parser.add_argument(
            "root",
            nargs="?",
            default=os.getcwd(),
            help="Root directory (default: CWD)",
        )
        parser.add_argument(
            "--exclude",
            default="",
            help="Comma-separated extra directory names to exclude.",
        )
        parser.add_argument(
            "--future",
            choices=("auto", "yes", "no"),
            default="auto",
            help="Control insertion of `from __future__ import annotations`.",
        )
        parser.add_argument(
            "--author",
            default=DEFAULT_AUTHOR,
            help="Author name (default: %(default)s)",
        )
        parser.add_argument(
            "--year",
            type=int,
            default=DEFAULT_YEAR,
            help="Year (default: current year)",
        )
        parser.add_argument(
            "--verbose",
            action="store_true",
            help="Print scan summary and unchanged files.",
        )
        return parser.parse_args()

    @staticmethod
    def decide_add_future(policy: str) -> bool:
        match policy:
            case "yes":
                return True
            case "no":
                return False
            case _:
                version_info = sys.version_info
                if version_info < (3, 14):
                    return True
                if sys.stdin.isatty():
                    prompt = (
                        "Python 3.14+ detected: annotations are lazy by default.\n"
                        "Insert `from __future__ import annotations` anyway? [y/N]: "
                    )
                    print(prompt, end="", flush=True)
                    try:
                        answer = input().strip().lower()
                    except EOFError:
                        answer = ""
                    return answer in ("y", "yes")
                return False


def main() -> None:
    """Entry point for CLI usage."""
    args = HeaderCli.parse_args()
    extra = {entry.strip() for entry in args.exclude.split(",") if entry.strip()}
    add_future = HeaderCli.decide_add_future(args.future)

    if args.verbose:
        print(f"Scanning for .py files under: {args.root}")
        if extra:
            print(f"Additional excludes: {sorted(extra)}")
        print(f"Adding future import: {'YES' if add_future else 'NO'}")
        print(f"Using author: {args.author} • year: {args.year}")

    updater = HeaderUpdater(
        author=args.author,
        year=args.year,
        add_future=add_future,
        extra_excluded=extra,
        verbose=args.verbose,
    )
    updater.run(args.root)

    if args.verbose:
        print("Done.")


if __name__ == "__main__":
    main()
