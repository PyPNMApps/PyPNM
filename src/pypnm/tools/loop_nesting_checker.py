# SPDX-License-Identifier: Apache-2.0

# Copyright (c) 2025-2026 Maurice Garcia

from __future__ import annotations

import ast
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import cast


@dataclass(frozen=True)
class LoopNestingFinding:
    file_path: str
    function_name: str
    line_number: int
    max_depth: int


class LoopNestingAnalyzer:
    _LOOP_TYPES = (ast.For, ast.AsyncFor, ast.While)
    _COMP_TYPES = (ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)
    _SKIP_TYPES = (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef)
    _TRY_TYPES  = (ast.Try, getattr(ast, "TryStar", ast.Try))

    @staticmethod
    def analyze_source(source: str, file_path: str) -> list[LoopNestingFinding]:
        tree = ast.parse(source, filename=file_path)
        return LoopNestingAnalyzer._analyze_tree(tree=tree, file_path=file_path)

    @staticmethod
    def analyze_path(path: Path) -> list[LoopNestingFinding]:
        source = path.read_text(encoding="utf-8")
        return LoopNestingAnalyzer.analyze_source(source=source, file_path=str(path))

    @staticmethod
    def _analyze_tree(tree: ast.AST, file_path: str) -> list[LoopNestingFinding]:
        visitor = _QualifiedFunctionVisitor(file_path=file_path)
        visitor.visit(tree)
        return visitor.findings

    @staticmethod
    def _max_depth_in_nodes(nodes: list[ast.stmt], current_depth: int) -> int:
        max_depth = current_depth
        for node in nodes:
            max_depth = max(max_depth, LoopNestingAnalyzer._max_depth_in_node(node, current_depth))
        return max_depth

    @staticmethod
    def _max_depth_in_node(node: ast.AST, current_depth: int) -> int:
        if isinstance(node, LoopNestingAnalyzer._SKIP_TYPES):
            return current_depth

        if isinstance(node, LoopNestingAnalyzer._LOOP_TYPES):
            loop_depth = current_depth + 1
            max_depth = loop_depth
            max_depth = max(max_depth, LoopNestingAnalyzer._max_depth_in_nodes(node.body, loop_depth))
            max_depth = max(max_depth, LoopNestingAnalyzer._max_depth_in_nodes(node.orelse, loop_depth))
            return max_depth

        if isinstance(node, LoopNestingAnalyzer._COMP_TYPES):
            return LoopNestingAnalyzer._max_depth_in_comprehension(node, current_depth)

        max_depth = current_depth
        for block in LoopNestingAnalyzer._child_blocks(node):
            max_depth = max(max_depth, LoopNestingAnalyzer._max_depth_in_nodes(block, current_depth))
        max_depth = max(max_depth, LoopNestingAnalyzer._max_depth_in_expr_nodes(node, current_depth))
        return max_depth

    @staticmethod
    def _child_blocks(node: ast.AST) -> list[list[ast.stmt]]:
        blocks: list[list[ast.stmt]] = []
        if isinstance(node, ast.If):
            blocks.append(node.body)
            blocks.append(node.orelse)
        elif isinstance(node, (ast.With, ast.AsyncWith)):
            blocks.append(node.body)
        elif isinstance(node, ast.Try):
            blocks.append(node.body)
            blocks.append(node.orelse)
            blocks.append(node.finalbody)
            for handler in node.handlers:
                blocks.append(handler.body)
        elif hasattr(ast, "TryStar") and isinstance(node, getattr(ast, "TryStar")):
            try_node = cast(ast.Try, node)
            blocks.append(try_node.body)
            blocks.append(try_node.orelse)
            blocks.append(try_node.finalbody)
            for handler in try_node.handlers:
                blocks.append(handler.body)
        elif isinstance(node, ast.Match):
            for case in node.cases:
                blocks.append(case.body)
        elif isinstance(node, ast.ExceptHandler):
            blocks.append(node.body)
        return blocks

    @staticmethod
    def _max_depth_in_expr_nodes(node: ast.AST, current_depth: int) -> int:
        max_depth = current_depth
        for child in ast.iter_child_nodes(node):
            if isinstance(child, ast.expr):
                max_depth = max(max_depth, LoopNestingAnalyzer._max_depth_in_expr(child, current_depth))
        return max_depth

    @staticmethod
    def _max_depth_in_expr(node: ast.expr, current_depth: int) -> int:
        if isinstance(node, ast.Lambda):
            return current_depth
        if isinstance(node, LoopNestingAnalyzer._COMP_TYPES):
            return LoopNestingAnalyzer._max_depth_in_comprehension(node, current_depth)

        max_depth = current_depth
        for child in ast.iter_child_nodes(node):
            if isinstance(child, ast.expr):
                max_depth = max(max_depth, LoopNestingAnalyzer._max_depth_in_expr(child, current_depth))
        return max_depth

    @staticmethod
    def _max_depth_in_comprehension(node: ast.AST, current_depth: int) -> int:
        max_depth = current_depth
        generator_depth = current_depth
        generators: list[ast.comprehension] = []

        if isinstance(node, (ast.ListComp, ast.SetComp, ast.GeneratorExp)):
            generators = node.generators
        elif isinstance(node, ast.DictComp):
            generators = node.generators

        for generator in generators:
            generator_depth += 1
            max_depth = max(max_depth, generator_depth)
            max_depth = max(
                max_depth,
                LoopNestingAnalyzer._max_depth_in_expr(generator.iter, generator_depth),
            )
            for if_expr in generator.ifs:
                max_depth = max(
                    max_depth,
                    LoopNestingAnalyzer._max_depth_in_expr(if_expr, generator_depth),
                )

        if isinstance(node, ast.DictComp):
            max_depth = max(
                max_depth,
                LoopNestingAnalyzer._max_depth_in_expr(node.key, generator_depth),
            )
            max_depth = max(
                max_depth,
                LoopNestingAnalyzer._max_depth_in_expr(node.value, generator_depth),
            )
        elif isinstance(node, (ast.ListComp, ast.SetComp, ast.GeneratorExp)):
            max_depth = max(
                max_depth,
                LoopNestingAnalyzer._max_depth_in_expr(node.elt, generator_depth),
            )

        return max_depth


class _QualifiedFunctionVisitor(ast.NodeVisitor):
    def __init__(self, file_path: str) -> None:
        self._file_path = file_path
        self._stack: list[str] = []
        self.findings: list[LoopNestingFinding] = []

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self._stack.append(node.name)
        try:
            self.generic_visit(node)
        finally:
            self._stack.pop()

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._visit_function_like(node=node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._visit_function_like(node=node)

    def _visit_function_like(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        self._stack.append(node.name)
        try:
            function_name = ".".join(self._stack) if self._stack else node.name
            depth = LoopNestingAnalyzer._max_depth_in_nodes(node.body, 0)
            self.findings.append(
                LoopNestingFinding(
                    file_path=self._file_path,
                    function_name=function_name,
                    line_number=node.lineno,
                    max_depth=depth,
                )
            )
            self.generic_visit(node)
        finally:
            self._stack.pop()


class LoopNestingChecker:
    _FAIL_DEPTH = 3
    _WARN_DEPTH = 2

    _EXCLUDE_DIR_NAMES = {
        ".git",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        ".tox",
        ".venv",
        "__pycache__",
        "build",
        "dist",
        "site-packages",
        "venv",
    }

    @staticmethod
    def run(paths: list[str]) -> int:
        files = LoopNestingChecker._collect_files(paths)
        if not files:
            print("No Python files found for loop nesting check.", flush=True)
            return 2

        findings: list[LoopNestingFinding] = []
        parse_failures = 0

        for path in files:
            try:
                findings.extend(LoopNestingAnalyzer.analyze_path(path))
            except (SyntaxError, UnicodeDecodeError, OSError) as exc:
                parse_failures += 1
                print(f"ERROR: {path}: {exc.__class__.__name__}: {exc}", flush=True)

        findings.sort(key=lambda f: (f.file_path, f.line_number, f.function_name))

        warnings = [f for f in findings if f.max_depth == LoopNestingChecker._WARN_DEPTH]
        errors = [f for f in findings if f.max_depth >= LoopNestingChecker._FAIL_DEPTH]

        for finding in warnings:
            LoopNestingChecker._print_finding(prefix="WARNING", finding=finding)

        for finding in errors:
            LoopNestingChecker._print_finding(prefix="ERROR", finding=finding)

        if parse_failures:
            print(f"Loop nesting check encountered {parse_failures} file error(s).", flush=True)
            return 2

        if errors:
            print(
                f"Loop nesting check failed: {len(errors)} function(s) reach depth "
                f"{LoopNestingChecker._FAIL_DEPTH} or higher.",
                flush=True,
            )
            return 1

        print("Loop nesting check passed.", flush=True)
        return 0

    @staticmethod
    def _collect_files(paths: list[str]) -> list[Path]:
        files: list[Path] = []
        for raw in paths:
            files.extend(LoopNestingChecker._collect_from_path(Path(raw)))
        return LoopNestingChecker._dedupe_paths(files)

    @staticmethod
    def _collect_from_path(path: Path) -> list[Path]:
        if path.is_dir():
            return [
                p
                for p in path.rglob("*.py")
                if p.is_file() and not LoopNestingChecker._is_excluded_path(p)
            ]
        if path.is_file() and path.suffix == ".py":
            return [path]
        print(f"Skipping missing path: {path}", flush=True)
        return []

    @staticmethod
    def _is_excluded_path(path: Path) -> bool:
        parts = set(path.parts)
        return bool(parts & LoopNestingChecker._EXCLUDE_DIR_NAMES)

    @staticmethod
    def _dedupe_paths(paths: list[Path]) -> list[Path]:
        seen: set[Path] = set()
        unique: list[Path] = []
        for path in paths:
            if path in seen:
                continue
            seen.add(path)
            unique.append(path)
        return unique

    @staticmethod
    def _print_finding(prefix: str, finding: LoopNestingFinding) -> None:
        print(
            f"{prefix}: {finding.file_path}:{finding.line_number} "
            f"{finding.function_name} max_depth={finding.max_depth}",
            flush=True,
        )


def main() -> None:
    raw_args = sys.argv[1:]
    paths = raw_args if raw_args else ["src"]
    exit_code = LoopNestingChecker.run(paths=paths)
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
