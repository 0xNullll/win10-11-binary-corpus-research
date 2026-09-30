# AXIS Windows Binary Corpus: Tools and Data

Supplementary tools accompanying a two-paper series on Windows 10/11 system
binary analysis. Both papers are drawn from the same corpus and extraction
pipeline:

1. *"A Corpus-Scale Static Analysis of Windows 10/11 System Binaries:
   Characterization and Cross-Build Differences"*: corpus-scale statistics
   (imports, exports, security-relevant characteristics, signature status).
2. *"Structural Anomalies in a Windows 10/11 System Binary Corpus:
   Cross-Build Outliers and an `inpoutx64.sys` Case Study"*: structural
   anomalies, including the unsigned Windows 10 cluster, field-level
   anomalies, and the `inpoutx64.sys` case study.

## Research artifacts

| Artifact | Location |
|---|---|
| Paper one | [Zenodo, DOI 10.5281/zenodo.23069220](https://zenodo.org/records/23069220) |
| Paper two | [Zenodo, DOI 10.5281/zenodo.23069474](https://zenodo.org/records/23069474) |
| Corpus (derived JSON dataset) | [Zenodo, DOI 10.5281/zenodo.23067342](https://zenodo.org/records/23067342) |
| Scripts | This repository |

This repository does **not** contain the corpus or any precomputed output. It
contains:

- the scripts used to generate and validate the analysis data (`scripts/`)
- a placeholder folder for the corpus (`corpus/`)
- an empty `shared-output/` folder, populated by running the scripts against
  the corpus

All results referenced in both papers can be reproduced from the corpus using
the scripts in this repository, with one exception noted below (`hashes.json`).

## Corpus

The corpus is published on Zenodo as a fixed snapshot of derived metadata:
one set of JSON files per binary, for Windows 10 (10.0.19045) and Windows 11
(10.0.26200). It contains derived metadata only. The Microsoft binaries
themselves are not redistributed.

The parser that produced the JSON is closed-source and is not released, and
its output schema has since changed, so the archived files are the
authoritative version of the data analyzed in the papers.

**Dataset:** https://doi.org/10.5281/zenodo.23067342

### Archives

| File | Size | SHA-256 |
|---|---|---|
| `win10_19045_json.tar.gz` | about 890 MB | `504999e62615e460270522f8db8f295974818a2cc0660aae8749b7afc74fe059` |
| `win11_26200_json.tar.gz` | about 911 MB | `2cd8963c71eb7e15424d310f7997dd4bf70b88269fe97a53c52c88723b39035c` |

Together the archives are about 1.8 GB compressed and roughly 13.3 GB extracted.
Each archive unpacks into a top-level `win10` or `win11` folder.

### Verify and extract

Download both archives and `SHA256SUMS.txt` from the Zenodo record, then
verify them.

Linux and macOS:

```bash
sha256sum -c SHA256SUMS.txt
```

Windows (PowerShell):

```powershell
Get-FileHash -Algorithm SHA256 win10_19045_json.tar.gz, win11_26200_json.tar.gz
```

Compare the output against the table above. Then extract both archives into
the `corpus/` folder:

```bash
tar -xzf win10_19045_json.tar.gz -C corpus
tar -xzf win11_26200_json.tar.gz -C corpus
```

`tar` is included with recent versions of Windows, macOS, and Linux. After
extraction, `corpus/win10/` and `corpus/win11/` contain the per-binary JSON
files. The scripts can also be pointed at any other location where you
extracted the archives.

## Repo structure

```
.
├── corpus/               # extract the corpus archives here (see "Corpus")
├── scripts/              # generation, validation, and tracing tools
└── shared-output/        # populated by running the generator, one subfolder per OS build
    ├── win10/10.0.19045/x64/
    └── win11/10.0.26200/x64/
```

The per-build subfolders and their JSON contents are not tracked by git. Only
the top-level `shared-output/` folder exists in the repository, as a
placeholder mirroring `corpus/`.

## Scripts

| Script | Purpose |
|---|---|
| `axis_binary_tool_python.py` | Main analysis script. Runs the core corpus analysis behind most of Paper 1's tables and statistics: imports, exports, security-relevant characteristics, signature status, and the Win10/Win11 comparison. Results are printed directly to the CLI. This is also the script whose RWX-permission check first surfaced `inpoutx64.sys` as an outlier, which became the central case study of Paper 2. It produces more than what made it into either paper, so see it for extra characteristics and statistics not covered in the text. |
| `axis_binary_tool_python_generator.py` | Interactive generator. Prompts for the Windows version, build, and architecture to target, then presents a menu (DLL dependency graph, export index, hash index, build all) and writes the corresponding JSON files to `shared-output/<os>/<build>/<arch>/`. No CLI flags: run it and answer the prompts. |
| `axis_binary_tool_python_validate_data.py` | Validates a generated `binary_paths.json`. Takes no flags and no other input, and reads the file directly. Prints live progress and a summary (total checked, clean, flagged, plus the first 10 flagged entries) to the CLI, and writes the full validation report to JSON. Entries with no problems are not included in the report. |
| `axis_binary_tool_python_graph.py` | DLL dependency graph viewer. Run directly with no flags. It opens an interactive dependency graph in a local web page, built from your generated `dll_dependencies.json`. |
| `axis_binary_tool_python_trace.py` | Function-level tracer. Resolves and traces individual exported and imported functions across the corpus, and outputs JSON. Run directly. It can be used standalone, independent of the graph viewer. |
| `axis_binary_tool_python_graph2.py` | Function trace visualizer that consumes the output of `trace.py`. Run directly with no flags. It opens an interactive graph in a local web page. |

### Setup

```bash
pip install -r scripts/requirements.txt
```

### Running the scripts

None of these scripts take CLI flags. Run them directly and follow the prompts
where applicable. The corpus must be extracted locally first (see "Corpus")
before any of them produce output:

```bash
python scripts/axis_binary_tool_python_generator.py
# prompts for Windows version/build/arch, then a menu:
#   1. DLL dependency graph  2. Export index  3. Hash index  4. Build all
# writes to shared-output/<os>/<build>/<arch>/

python scripts/axis_binary_tool_python_validate_data.py
# reads binary_paths.json from the matching shared-output folder,
# validates every entry, prints a summary, writes the full report to JSON

python scripts/axis_binary_tool_python.py
# runs the main corpus analysis (imports, exports, security, signatures,
# Win10 vs Win11) and prints results to the CLI

python scripts/axis_binary_tool_python_graph.py
python scripts/axis_binary_tool_python_graph2.py
# each opens an interactive visualization in a local web page
```

**Note on hashing:** `hashes.json` (and `hashes_by_name.json`, where present)
can only be generated on a machine that is actually running the exact Windows
version and build the output folder is labeled for. The script hashes the
binaries directly off disk, so it needs the real files, not just corpus
metadata. Running the generator on a mismatched OS version produces every
other output file but skips hashing entirely. Unlike the rest of the
pipeline's outputs, which are reproducible on any machine once you have the
corpus, `hashes.json` is **not** reproducible unless you are running that
specific Windows 10 or 11 build yourself.

## Output files

Running the generator populates `shared-output/<os>/<build>/<arch>/` with:

| File | Contents |
|---|---|
| `binary_paths.json` | Canonical paths of every binary included in this build's corpus subset. |
| `hashes.json` | Per-binary hashes. **Not reproducible on an arbitrary machine.** It requires running the generator on a host that is itself the exact Windows version and build being hashed (see the note above). |
| `module_name_index.json` | Lookup index from module name to resolved binary entries. |
| `dll_dependencies.json` | Resolved DLL dependency edges per binary. |
| `dll_imported_by.json` | Reverse index of `dll_dependencies.json`, listing which binaries import a given DLL. |
| `dll_versions.json` | Version metadata extracted per DLL. |
| `export_index.json` | Export table index across the corpus subset. |
| `binary_data_validation.json` | Output of the validation script, keyed by module name, with each entry listing its path and the specific problems found. Entries with no problems are not included, so an empty or small report means most of the corpus validated clean. |

For the exact structure of each of these files, see
`scripts/axis_binary_tool_generate_schemas.py` (below) or the auto-generated
schema files it produces.

## JSON schemas

`scripts/axis_binary_tool_generate_schemas.py` infers a JSON Schema for every
file in a `shared-output/` folder you have generated and writes one
`<name>.schema.json` per input file to `schemas/`. It has no external
dependencies. Run:

```bash
python scripts/axis_binary_tool_generate_schemas.py --input shared-output --output schemas
```

Most of the output files are keyed by binary path or DLL name, with thousands
of keys per file, so a naive schema inferencer would emit one property per
key. This script instead detects map-shaped dicts (many keys, homogeneous
values) and describes them with a single `patternProperties` value schema,
while record-shaped dicts (few, fixed, meaningful keys) get literal
`properties`. Useful flags:

- `--map-threshold N`: a dict with more than N keys is treated as a map rather
  than a fixed record (default 8; raise this if a real per-binary record in
  your data legitimately has more fields than that)
- `--sample-size N`: only scan up to N values per map when inferring its
  shape, for speed on large files (default 300; `0` scans everything)
- `--merge-by-name`: merge same-named files across win10 and win11 into one
  schema, so build-specific fields (for example, `hashes_by_name.json`
  currently only exists for win11) show up as expected instead of producing
  divergent per-build schemas

This gives a machine-readable, field-by-field description of every output file
without hand-maintaining documentation as the pipeline evolves.

## A note on this repo

Nothing here, including the scripts, folder layout, and this README, was built
as a polished, general-purpose release. This is a research artifact: what was
actually used to produce the data behind both papers, shared as-is for
transparency and reproducibility. It was written and organized for one person
working against one specific corpus, and iterated on as the research
progressed, not engineered or cleaned up for outside use. Expect rough edges
throughout, including inconsistent conventions, minimal validation, hardcoded
assumptions that held for this corpus specifically, and the occasional odd
naming choice. If something behaves unexpectedly or looks inconsistent, that
is the nature of a research artifact rather than a maintained tool.

## License

The code is released under the **MIT License**. See [LICENSE](LICENSE) for the
full text. The corpus dataset on Zenodo is licensed separately under CC BY 4.0.