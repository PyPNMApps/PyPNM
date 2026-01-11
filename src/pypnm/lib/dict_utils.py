# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Maurice Garcia

from __future__ import annotations

from collections.abc import Iterable, Mapping, MutableMapping
from typing import Any

from pydantic import BaseModel


class DictGenerate:
    """
    A small collection of dictionary helpers:
      - rename_key / pop_key for shallow dicts
      - pop_keys_recursive for deep removal across nested containers
      - models_to_nested_dict to build payloads from Pydantic models (or dicts)
    """

    # ---------------------------
    # Shallow key utilities
    # ---------------------------
    @staticmethod
    def rename_key(d: MutableMapping[str, Any], old: str, new: str) -> bool:
        """
        Rename key `old` -> `new` in-place. Returns True if renamed, else False.
        """
        if old == new:
            return old in d
        try:
            d[new] = d.pop(old)
            return True
        except KeyError:
            return False

    @staticmethod
    def pop_key(d: MutableMapping[str, Any], key: str) -> bool:
        """
        Pop `key` from dict in-place. Returns True if key existed and was removed.
        """
        return d.pop(key, None) is not None

    # ---------------------------
    # Nested removal
    # ---------------------------
    @staticmethod
    def pop_keys_recursive(
        obj: object,
        keys_to_remove: Iterable[str],
        *,
        case_sensitive: bool = True,
        in_place: bool = True,
    ) -> object:
        """
        Recursively remove keys from nested dict/list/tuple/set structures.

        Parameters
        ----------
        obj : Any
            Arbitrary nested structure (dict/list/tuple/set/scalars).
        keys_to_remove : Iterable[str]
            Keys to remove from any dict encountered.
        case_sensitive : bool, default True
            Compare keys with exact case. If False, compare lowercased.
        in_place : bool, default True
            Mutate dicts/lists in place when possible. If False, return a cleaned copy.

        Returns
        -------
        Any
            The cleaned structure (same object when in_place=True where possible).
        """
        targets: set[str] = set(keys_to_remove)
        targets_lower: set[str] | None = (
            {k.lower() for k in targets} if not case_sensitive else None
        )

        NodeType = (
            dict[str, object] | list[object] | tuple[object, ...] | set[object] | object
        )

        def _walk(node: NodeType) -> NodeType:
            if isinstance(node, dict):
                d = node if in_place else dict(node)

                if case_sensitive:
                    to_delete = [k for k in list(d.keys()) if k in targets]
                else:
                    to_delete = [
                        k for k in list(d.keys()) if k.lower() in targets_lower
                    ]  # type: ignore[arg-type]

                for k in to_delete:
                    d.pop(k, None)

                for k, v in list(d.items()):
                    d[k] = _walk(v)
                return d

            if isinstance(node, list):
                if in_place:
                    for i, v in enumerate(node):
                        node[i] = _walk(v)
                    return node
                return [_walk(v) for v in node]

            if isinstance(node, tuple):
                return tuple(_walk(v) for v in node)

            if isinstance(node, set):
                # If nested results become unhashable, this may raise—callers should avoid such shapes.
                return {_walk(v) for v in node}

            return node

        return _walk(obj)

    # ---------------------------
    # Pydantic models → payloads
    # ---------------------------
    @staticmethod
    def models_to_nested_dict(
        items: Iterable[BaseModel | Mapping[int | str, Any]],
        parent_key: str,
        *,
        by: str | None = None,
        by_alias: bool = True,
        exclude_none: bool = True,
        exclude_unset: bool = False,
        exclude_defaults: bool = False,
    ) -> dict[str, Any]:
        """
        Build a nested dict from a list of Pydantic BaseModels (or already-dumped dicts).

        Shapes
        ------
        - If `by` is None (default):
            { parent_key: [ model_dump(item), ... ] }

        - If `by` is provided (e.g., 'id' or 'name'):
            { parent_key: { item.<by>: model_dump(item), ... } }

        Raises
        ------
        ValueError:
            - If `by` is provided and an item lacks that field/attribute.
            - If duplicate `by` keys are encountered.
        """

        def dump_one(obj: BaseModel | Mapping[str, Any]) -> dict[str, Any]:
            if isinstance(obj, BaseModel):  # type: ignore[arg-type]
                if hasattr(obj, "model_dump"):
                    return obj.model_dump(
                        by_alias=by_alias,
                        exclude_none=exclude_none,
                        exclude_unset=exclude_unset,
                        exclude_defaults=exclude_defaults,
                    )
                # pydantic v1 fallback
                return obj.dict(  # type: ignore[attr-defined]
                    by_alias=by_alias,
                    exclude_none=exclude_none,
                    exclude_unset=exclude_unset,
                    exclude_defaults=exclude_defaults,
                )
            return dict(obj)

        if by is None:
            out_list = [dump_one(item) for item in items]
            return {parent_key: out_list}

        keyed: dict[Any, dict[str, Any]] = {}
        for item in items:
            payload = dump_one(item)

            if by in payload:
                k = payload[by]
            elif isinstance(item, BaseModel) and hasattr(item, by):  # type: ignore[arg-type]
                k = getattr(item, by)
            else:
                raise ValueError(f"Item does not provide '{by}' for keying: {item!r}")

            if k in keyed:
                raise ValueError(f"Duplicate key for '{by}': {k!r}")
            keyed[k] = payload

        return {parent_key: keyed}
