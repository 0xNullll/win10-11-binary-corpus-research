# AXIS Windows Binary Corpus — Tools & Data

Supplementary tools and precomputed data accompanying *"A Corpus-Scale Static
Analysis of Windows 10/11 System Binaries: Structural Anomalies and
Cross-Build Differences"* (paper 1 of a planned three-paper series on
Windows binary analysis).

This repo does **not** contain the full corpus. It contains:

- the scripts used to generate and validate the analysis data (`scripts/`)
- precomputed output for the two builds studied in the paper (`shared-output/`)
- a pointer to the raw corpus, provided separately due to size (`corpus/`)

Everything under `shared-output/` is reproducible from the corpus using the
scripts in this repo — it's included so the results can be inspected without
re-running the full pipeline.

## Corpus

The raw binary corpus (~16GB, unzipped) is hosted externally rather than in
this repo:

**[LINK TO CORPUS ARCHIVE, I SWEAR TO GOD IF U FORGET..]**

The `corpus/` folder is a placeholder — extract the archive there (or point
the scripts at wherever you extracted it) to reproduce `shared-output/` from
scratch.

## Repo structure

```
.
├── corpus/                     # placeholder — see "Corpus" above
├── scripts/                    # generation, validation, and tracing tools
└── shared-output/              # precomputed results, one folder per OS build
    ├── win10/10.0.19045/x64/
    └── win11/10.0.26200/x64/
```

## Scripts

| Script | Purpose |
|---|---|
| `axis_binary_tool_python.py` | Main analysis script. Runs the core corpus analysis behind most of the paper's tables and statistics — imports, exports, security-relevant characteristics, signature status, and the Win10/Win11 comparison. Results are printed directly to the CLI. This is also the script that surfaced `inpoutx64.sys` as an anomaly. Produces more than what made it into the paper — see it for extra characteristics/statistics not covered there. |
| `axis_binary_tool_python_generator.py` | Interactive generator. Prompts for the Windows version/build/arch to target, then presents a menu (DLL dependency graph / export index / hash index / build all) and writes the corresponding JSON files to `shared-output/<os>/<build>/<arch>/`. No CLI flags — just run it and answer the prompts. |
| `axis_binary_tool_python_validate_data.py` | Validates an already-generated `binary_paths.json` (no flags, no other input needed — reads it directly). Prints live progress and a summary (total checked / clean / flagged, plus the first 10 flagged entries) to the CLI, and writes the full validation report to JSON. Entries with no problems aren't included in the report. |
| `axis_binary_tool_python_graph.py` | DLL dependency graph viewer. Run directly (no flags) — it opens an interactive dependency graph in a local web page. |
| `axis_binary_tool_python_trace.py` | Function-level tracer — resolves and traces individual exported/imported functions across the corpus, outputting JSON. Run directly; usable standalone, independent of the graph viewer. |
| `axis_binary_tool_python_graph2.py` | Function trace visualizer — consumes `trace.py` output. Run directly (no flags) — it opens an interactive graph in a local web page. `trace.py` is the backbone of this tool. |

### Setup

```bash
pip install -r scripts/requirements.txt
```

### Running the scripts

None of these scripts take CLI flags — run them directly and follow the
prompts where applicable:

```bash
python scripts/axis_binary_tool_python_generator.py
# -> prompts for Windows version/build/arch, then a menu:
#    1. DLL dependency graph  2. Export index  3. Hash index  4. Build all
# writes to shared-output/<os>/<build>/<arch>/

python scripts/axis_binary_tool_python_validate_data.py
# -> reads binary_paths.json from the matching shared-output folder,
#    validates every entry, prints a summary, writes the full report to JSON

python scripts/axis_binary_tool_python.py
# -> runs the main corpus analysis (imports/exports/security/signatures/
#    Win10 vs Win11), prints results to the CLI

python scripts/axis_binary_tool_python_graph.py
python scripts/axis_binary_tool_python_graph2.py
# -> each opens an interactive visualization in a local web page
```

**Note on hashing:** `hashes.json` (and `hashes_by_name.json`, where present)
are only generated when the machine running the generator matches the
Windows version the output folder is labeled for. Running the generator on a
mismatched OS version will produce every other output file but skip hashing.

## Output files

Each `shared-output/<os>/<build>/<arch>/` folder contains:

| File | Contents |
|---|---|
| `binary_paths.json` | Canonical paths of every binary included in this build's corpus subset. |
| `hashes.json` | Per-binary hashes. Only generated when the host OS version matches the labeled build (see note above). |
| `hashes_by_name.json` | Name-scoped hash index (win11 output only, as generated). |
| `module_name_index.json` | Lookup index from module name to resolved binary entries. |
| `dll_dependencies.json` | Resolved DLL dependency edges per binary. |
| `dll_imported_by.json` | Reverse index of `dll_dependencies.json` — which binaries import a given DLL. |
| `dll_versions.json` | Version metadata extracted per DLL. |
| `export_index.json` | Export table index across the corpus subset. |
| `binary_data_validation.json` | Output of the validation script; keyed by module name, each entry listing its path and the specific problems found. Entries with no problems aren't included — an empty/small report means most of the corpus validated clean. |

For the exact structure of each of these, see `scripts/axis_binary_tool_generate_schemas.py`
(below) or the auto-generated schema files it produces.

## JSON schemas

`scripts/axis_binary_tool_generate_schemas.py` infers a JSON Schema for
every file in `shared-output/` and writes one `<name>.schema.json` per
input file to `schemas/`. No external dependencies. Run:

```bash
python scripts/axis_binary_tool_generate_schemas.py --input shared-output --output schemas
```

Most of these output files are keyed by binary path or DLL name (thousands
of keys per file), so a naive schema inferencer would emit one property per
key. This script instead detects map-shaped dicts (many keys, homogeneous
values) and describes them with a single `patternProperties` value-schema,
versus record-shaped dicts (few, fixed, meaningful keys) which get literal
`properties`. Useful flags:

- `--map-threshold N` — a dict with more than N keys is treated as a map
  rather than a fixed record (default 8; raise this if a real per-binary
  record in your data legitimately has more fields than that)
- `--sample-size N` — only scan up to N values per map when inferring its
  shape, for speed on large files (default 300; `0` scans everything)
- `--merge-by-name` — merge same-named files across win10/win11 into one
  schema, so build-specific fields (e.g. `hashes_by_name.json` currently
  only exists for win11) show up as expected rather than producing
  divergent per-build schemas

This gives a machine-readable field-by-field description of every output
file without hand-maintaining documentation as the pipeline evolves.

## License

Released under the **MIT License**. See [LICENSE](LICENSE) for full text.