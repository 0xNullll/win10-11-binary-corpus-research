# AXIS Windows Binary Corpus — Tools & Data

Supplementary tools accompanying a two-paper series on Windows 10/11 system
binary analysis, both drawn from the same corpus and extraction pipeline:

1. *"A Corpus-Scale Static Analysis of Windows 10/11 System Binaries:
   Characterization and Cross-Build Differences"* — corpus-scale statistics
   (imports, exports, security-relevant characteristics, signature status).
2. *"Structural Anomalies in a Windows 10/11 System Binary Corpus:
   Cross-Build Outliers and a `inpoutx64.sys` Case Study"* —
   structural anomalies, including the unsigned
   Windows 10 cluster, field-level anomalies, and the `inpoutx64.sys` case
   study.

## Papers

Pre-print drafts of both papers are in [`papers/`](papers/). This is a
temporary home: once each paper is submitted to and announced on arXiv,
the PDFs here will be replaced with links to the arXiv entries, and this
section will be removed. Until then, treat the PDFs in `papers/` as
unpublished drafts, not final versions — content may still change.
Licensing for the papers is noted inside that folder and is separate from
this repo's MIT license (see License below).

This repo does **not** contain the full corpus, nor any precomputed output.
It contains:

- the scripts used to generate and validate the analysis data (`scripts/`)
- a pointer to the raw corpus, provided separately due to size (`corpus/`)
- an empty `shared-output/` folder, populated by running the scripts against
  the corpus
- pre-print drafts of both papers (`papers/`), temporary until arXiv publication

All results referenced in both papers are reproducible from the corpus using
the scripts in this repo, with one exception noted below (`hashes.json`).

## Corpus

The raw binary corpus (~13.5GB, unzipped) will be hosted externally and linked here once the corpus archive is published.

**Corpus archive:** *Link will be added upon publication.*

The `corpus/` folder is a placeholder. Once the corpus is available, extract it there (or point the scripts at wherever you extracted it) to generate `shared-output/` from scratch.

## Repo structure
```
.
├── corpus/               # placeholder — see "Corpus" above
├── papers/               # pre-print drafts, temporary until arXiv publication
├── scripts/              # generation, validation, and tracing tools
└── shared-output/        # populated by running the generator, one subfolder per OS build
    ├── win10/10.0.19045/x64/
    └── win11/10.0.26200/x64/
```

The per-build subfolders and their JSON contents are not tracked by git —
only the top-level `shared-output/` folder itself exists in the repo as a
placeholder, mirroring `corpus/`.

## Scripts

| Script | Purpose |
|---|---|
| `axis_binary_tool_python.py` | Main analysis script. Runs the core corpus analysis behind most of Paper 1's tables and statistics — imports, exports, security-relevant characteristics, signature status, and the Win10/Win11 comparison. Results are printed directly to the CLI. This is also the script whose RWX-permission check first surfaced `inpoutx64.sys` as an outlier, which became the central case study of Paper 2. Produces more than what made it into either paper — see it for extra characteristics/statistics not covered in the text. |
| `axis_binary_tool_python_generator.py` | Interactive generator. Prompts for the Windows version/build/arch to target, then presents a menu (DLL dependency graph / export index / hash index / build all) and writes the corresponding JSON files to `shared-output/<os>/<build>/<arch>/`. No CLI flags — just run it and answer the prompts. |
| `axis_binary_tool_python_validate_data.py` | Validates a generated `binary_paths.json` (no flags, no other input needed — reads it directly). Prints live progress and a summary (total checked / clean / flagged, plus the first 10 flagged entries) to the CLI, and writes the full validation report to JSON. Entries with no problems aren't included in the report. |
| `axis_binary_tool_python_graph.py` | DLL dependency graph viewer. Run directly (no flags) — it opens an interactive dependency graph in a local web page, built from your generated `dll_dependencies.json`. |
| `axis_binary_tool_python_trace.py` | Function-level tracer — resolves and traces individual exported/imported functions across the corpus, outputting JSON. Run directly; usable standalone, independent of the graph viewer. |
| `axis_binary_tool_python_graph2.py` | Function trace visualizer — consumes `trace.py` output. Run directly (no flags) — it opens an interactive graph in a local web page. `trace.py` is the backbone of this tool. |

### Setup

```bash
pip install -r scripts/requirements.txt
```

### Running the scripts

None of these scripts take CLI flags — run them directly and follow the
prompts where applicable. You'll need the corpus extracted locally first
(see "Corpus" above) before any of these produce output:

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
can only be generated on a machine actually running the exact Windows
version/build the output folder is labeled for — the script hashes the
binaries directly off disk, so it needs the real files, not just corpus
metadata. Running the generator on a mismatched OS version produces every
other output file but skips hashing entirely. Unlike the rest of this
pipeline's outputs, which are reproducible on any machine once you have the
corpus, `hashes.json` is **not** reproducible unless you happen to be running
that specific Windows 10/11 build yourself.

## Output files

Running the generator populates `shared-output/<os>/<build>/<arch>/` with:

| File | Contents |
|---|---|
| `binary_paths.json` | Canonical paths of every binary included in this build's corpus subset. |
| `hashes.json` | Per-binary hashes. **Not reproducible on an arbitrary machine** — requires running the generator on a host that is itself the exact Windows version/build being hashed (see note above). |
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
every file in a `shared-output/` folder you've generated and writes one
`<name>.schema.json` per input file to `schemas/`. No external dependencies.
Run:

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

## A note on this repo
 
Nothing here from scripts, folder layout, README included — was
built to be a polished, general-purpose release. This is a research
artifact: what was actually used to produce the data behind both papers,
shared as-is for transparency and reproducibility. It was written and
organized for one person working against one specific corpus, iterated on as
the research progressed, not engineered or cleaned up for outside use.
Expect rough edges throughout — inconsistent conventions, minimal
validation, hardcoded assumptions that held for this corpus specifically,
and the occasional odd naming choice. If something behaves unexpectedly or
looks inconsistent, that's the nature of a research artifact rather than a
maintained tool.

## License

Released under the **MIT License**. See [LICENSE](LICENSE) for full text.
The papers in `papers/` are separately licensed — see that folder for details.