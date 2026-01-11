# SPDX-License-Identifier: Apache-2.0

# Copyright (c) 2025-2026 Maurice Garcia

from __future__ import annotations

from pypnm.tools.loop_nesting_checker import LoopNestingAnalyzer


def _depths_by_function(source: str) -> dict[str, int]:
    findings = LoopNestingAnalyzer.analyze_source(source=source, file_path="snippet.py")
    return {finding.function_name: finding.max_depth for finding in findings}


def test_loop_depth_zero() -> None:
    source = "def demo():\n    value = 1\n"
    depths = _depths_by_function(source)
    assert depths["demo"] == 0


def test_loop_depth_one() -> None:
    source = "def demo():\n    for idx in range(3):\n        value = idx\n"
    depths = _depths_by_function(source)
    assert depths["demo"] == 1


def test_loop_depth_two() -> None:
    source = (
        "def demo():\n"
        "    for idx in range(3):\n"
        "        while idx > 0:\n"
        "            idx -= 1\n"
    )
    depths = _depths_by_function(source)
    assert depths["demo"] == 2


def test_loop_depth_three() -> None:
    source = (
        "def demo():\n"
        "    for idx in range(3):\n"
        "        if idx > 0:\n"
        "            while idx > 0:\n"
        "                for jdx in range(2):\n"
        "                    idx -= jdx\n"
    )
    depths = _depths_by_function(source)
    assert depths["demo"] == 3


def test_nested_function_loops_not_counted_in_parent() -> None:
    source = (
        "def demo():\n"
        "    for idx in range(2):\n"
        "        def inner():\n"
        "            for jdx in range(2):\n"
        "                for kdx in range(2):\n"
        "                    pass\n"
        "        value = idx\n"
    )
    depths = _depths_by_function(source)
    assert depths["demo"] == 1
    assert depths["demo.inner"] == 2


def test_comprehension_depth_one() -> None:
    source = "def demo():\n    values = [x for x in range(3)]\n"
    depths = _depths_by_function(source)
    assert depths["demo"] == 1


def test_comprehension_nested_generators_depth_two() -> None:
    source = "def demo():\n    values = [(x, y) for x in range(2) for y in range(2)]\n"
    depths = _depths_by_function(source)
    assert depths["demo"] == 2


def test_comprehension_nested_expression_depth_two() -> None:
    source = "def demo():\n    values = [[y for y in range(2)] for x in range(2)]\n"
    depths = _depths_by_function(source)
    assert depths["demo"] == 2


def test_comprehension_nested_depth_three() -> None:
    source = (
        "def demo():\n"
        "    values = [[z for z in range(2)] for x in range(2) for y in range(2)]\n"
    )
    depths = _depths_by_function(source)
    assert depths["demo"] == 3


def test_generator_expression_depth_one() -> None:
    source = "def demo():\n    values = (x for x in range(3))\n"
    depths = _depths_by_function(source)
    assert depths["demo"] == 1
