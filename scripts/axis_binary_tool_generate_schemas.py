#!/usr/bin/env python3
"""
axis_binary_tool_generate_schemas.py

Walks a shared-output-style directory tree and infers a JSON Schema for
every .json file found, writing <name>.schema.json under a mirrored
directory structure.

Usage:
    python axis_binary_tool_generate_schemas.py --input shared-output --output schemas
    python axis_binary_tool_generate_schemas.py --input shared-output --output schemas --merge-by-name
    python axis_binary_tool_generate_schemas.py --input shared-output --output schemas --map-threshold 10 --sample-size 500

Options:
    --map-threshold N   A dict with more than N keys is treated as a map
                         (patternProperties) rather than a record
                         (properties). Default: 8.
    --sample-size N     When building the value-schema for a map, only
                         scan up to N of its values (evenly spaced) rather
                         than all of them. 0 = scan everything.
                         Default: 300.
    --merge-by-name     Merge files with the same basename across
                         different os/build/arch subfolders into one
                         schema, so fields that only appear in one build
                         (e.g. hashes_by_name.json currently only exists
                         for win11) are visible as optional rather than
                         producing divergent per-build schemas.
"""

import argparse
import json
from collections import defaultdict
from pathlib import Path

SCALAR_TYPES = {
    bool: "boolean",
    int: "integer",
    float: "number",
    str: "string",
    type(None): "null",
}


def sample_values(values, sample_size):
    if sample_size <= 0 or len(values) <= sample_size:
        return values
    step = len(values) / sample_size
    return [values[int(i * step)] for i in range(sample_size)]


def infer_schema(value, map_threshold, sample_size):
    if isinstance(value, dict):
        if len(value) > map_threshold:
            # Map-shaped: keys are data (paths/names), not schema fields.
            vals = sample_values(list(value.values()), sample_size)
            value_schema = None
            for v in vals:
                value_schema = merge_schema(
                    value_schema, infer_schema(v, map_threshold, sample_size)
                )
            example_keys = list(value.keys())[:3]
            return {
                "type": "object",
                "patternProperties": {".*": value_schema or {}},
                "additionalProperties": False,
                "x-mapKeyCount": len(value),
                "x-exampleKeys": example_keys,
            }
        else:
            props = {}
            for k, v in value.items():
                props[k] = infer_schema(v, map_threshold, sample_size)
            return {
                "type": "object",
                "properties": props,
                "required": sorted(value.keys()),
            }

    if isinstance(value, list):
        if not value:
            return {"type": "array", "items": {}}
        vals = sample_values(value, sample_size)
        items_schema = None
        for v in vals:
            items_schema = merge_schema(
                items_schema, infer_schema(v, map_threshold, sample_size)
            )
        return {"type": "array", "items": items_schema or {}}

    return {"type": SCALAR_TYPES.get(type(value), "string")}


def _as_type_set(schema):
    t = schema.get("type")
    if t is None:
        return set()
    return set(t) if isinstance(t, list) else {t}


def merge_schema(a, b):
    if a is None:
        return b
    if b is None:
        return a

    types = sorted(_as_type_set(a) | _as_type_set(b))

    is_obj_a, is_obj_b = "object" in _as_type_set(a), "object" in _as_type_set(b)
    if is_obj_a and is_obj_b:
        a_map = "patternProperties" in a
        b_map = "patternProperties" in b
        if a_map or b_map:
            a_val = a["patternProperties"][".*"] if a_map else a
            b_val = b["patternProperties"][".*"] if b_map else b
            merged = {
                "type": "object",
                "patternProperties": {".*": merge_schema(a_val, b_val)},
                "additionalProperties": False,
            }
            for k in ("x-mapKeyCount", "x-exampleKeys"):
                if k in a:
                    merged[k] = a[k]
                elif k in b:
                    merged[k] = b[k]
            return merged
        else:
            props = dict(a.get("properties", {}))
            for k, v in b.get("properties", {}).items():
                props[k] = merge_schema(props.get(k), v)
            required = sorted(set(a.get("required", [])) & set(b.get("required", [])))
            return {"type": "object", "properties": props, "required": required}

    is_arr_a, is_arr_b = "array" in _as_type_set(a), "array" in _as_type_set(b)
    if is_arr_a and is_arr_b:
        return {
            "type": "array",
            "items": merge_schema(a.get("items"), b.get("items")),
        }

    # Different shapes (or scalar/scalar, scalar/object, etc.) -- fall back
    # to a plain type union. Good enough for documentation purposes.
    result = {"type": types[0] if len(types) == 1 else types}
    return result


def find_json_files(root: Path):
    return sorted(p for p in root.rglob("*.json") if p.is_file())


def schema_for_file(path, map_threshold, sample_size):
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    return infer_schema(data, map_threshold, sample_size)


def main():
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("--input", required=True, type=Path)
    ap.add_argument("--output", required=True, type=Path)
    ap.add_argument("--map-threshold", type=int, default=8)
    ap.add_argument("--sample-size", type=int, default=300)
    ap.add_argument("--merge-by-name", action="store_true")
    args = ap.parse_args()

    json_files = find_json_files(args.input)
    if not json_files:
        raise SystemExit(f"No .json files found under {args.input}")

    args.output.mkdir(parents=True, exist_ok=True)

    if args.merge_by_name:
        groups = defaultdict(list)
        for p in json_files:
            groups[p.name].append(p)
        for name, paths in sorted(groups.items()):
            print(f"Building merged schema for {name} ({len(paths)} file(s))...")
            schema = None
            for p in paths:
                try:
                    schema = merge_schema(
                        schema,
                        schema_for_file(p, args.map_threshold, args.sample_size),
                    )
                except (json.JSONDecodeError, OSError) as e:
                    print(f"  skipping {p} ({e})")
            out_path = args.output / f"{Path(name).stem}.schema.json"
            out_path.write_text(json.dumps(schema, indent=2))
            print(f"  wrote {out_path}")
    else:
        for p in json_files:
            rel = p.relative_to(args.input)
            print(f"Building schema for {rel}...")
            try:
                schema = schema_for_file(p, args.map_threshold, args.sample_size)
            except (json.JSONDecodeError, OSError) as e:
                print(f"  skipping {p} ({e})")
                continue
            out_path = args.output / rel.parent / f"{p.stem}.schema.json"
            out_path.parent.mkdir(parents=True, exist_ok=True)
            out_path.write_text(json.dumps(schema, indent=2))
            print(f"  wrote {out_path}")


if __name__ == "__main__":
    main()