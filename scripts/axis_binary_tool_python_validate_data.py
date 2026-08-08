import json
from pathlib import Path

WIN_VERSION = "win11"
WIN_ARCH = "x64"

def get_windows_build():
    if WIN_VERSION == "win11":
        return "10.0.26200"
    else:
        return "10.0.19045"


WIN_BUILD = get_windows_build()

SCRIPT_DIR = Path(__file__).resolve().parent.parent

OUTPUT_DIR = (
    SCRIPT_DIR
    / "shared-output"
    / WIN_VERSION
    / WIN_BUILD
    / WIN_ARCH
)

OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

BINARY_PATHS_FILE = OUTPUT_DIR / "binary_paths.json"
VALIDATION_REPORT_FILE = OUTPUT_DIR / "binary_data_validation.json"

# Fragment paths inside tables.*.files (e.g. "Boot\\EFI\\Foo.efi.relocs.0.json")
# are stored RELATIVE TO THE CORPUS ROOT, not relative to the meta file's own
# folder -- same convention as build_dll_dependency_graph's ROOT_DIR / fragment_name.

ROOT_DIR = (
    SCRIPT_DIR
    / "axis-binary-output"
    / WIN_VERSION
    / WIN_BUILD
    / WIN_ARCH
)


def load_json(path: Path):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        return None, str(e)
    return None, "unknown"


def try_load(path: Path):
    """Returns (data, error). error is None on success."""
    if not path.exists():
        return None, "file does not exist on disk"
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f), None
    except Exception as e:
        return None, f"failed to parse: {e}"

def validate_export_entries(tables: dict, ordinal_free_expected: bool = False):
    """
    Every export entry must have a non-null ordinal (PE exports always
    have one). If hasName is True, name must be a non-empty string; if
    hasName is False, name must be None. Catches binaries still holding
    stale pre-fix export data (missing ordinal, or a mismatch between
    hasName and the actual name field).
    """
    problems = []

    exports_table = tables.get("exports")
    if not exports_table:
        return problems

    for frag_name in exports_table.get("files", []):
        frag_path = ROOT_DIR / frag_name
        frag_data, err = try_load(frag_path)
        if err:
            problems.append(f"exports fragment unreadable: {frag_name} ({err})")
            continue

        for entry in frag_data.get("entries", []):
            if entry.get("role") not in ("export", "alias"):
                continue

            if entry.get("ordinal") is None:
                problems.append(
                    f"export entry missing ordinal: {entry.get('name') or '<unnamed>'}"
                )

            has_name = entry.get("hasName")
            name = entry.get("name")

            if has_name and not name:
                problems.append(
                    f"export entry hasName=true but name is empty (ordinal {entry.get('ordinal')})"
                )
            if not has_name and name:
                problems.append(
                    f"export entry hasName=false but name is set: {name} (ordinal {entry.get('ordinal')})"
                )

    return problems

def validate_entry(module_name: str, meta_path_str: str):
    """
    Checks one binary_paths.json entry against its actual .meta.json.
    Returns a list of problem strings (empty list = clean).
    """
    problems = []
    meta_path = Path(meta_path_str)

    data, err = try_load(meta_path)
    if err:
        problems.append(err)
        return problems

    # --- structural presence checks ---
    descriptor = data.get("descriptor")
    analysis = data.get("analysis")
    segments = data.get("segments")
    tables = data.get("tables")

    if not descriptor:
        problems.append("missing 'descriptor' block")
    if not analysis:
        problems.append("missing 'analysis' block")
    if not segments or segments.get("count", 0) == 0:
        problems.append("missing or empty 'segments' block")
    if not tables:
        problems.append("missing 'tables' block")

    # NOTE: has_exports/has_imports/has_relocations reflect header/directory
    # PRESENCE (parsed from the PE header), while tables.*.totalCount reflects
    # actual TABLE CONTENT. These are intentionally independent -- a directory
    # can legitimately be present but empty (e.g. apisetschema.dll, GUID-prefixed
    # proxy stub DLLs). That combination is not a data-integrity problem, so it
    # is not checked here.

    # --- referenced fragment files actually exist ---
    if tables:
        for table_name, table_info in tables.items():
            for frag_name in table_info.get("files", []):
                frag_path = ROOT_DIR / frag_name
                if not frag_path.exists():
                    problems.append(f"missing fragment file for {table_name}: {frag_name}")
        # --- export entry schema consistency (post ordinal/hasName fix) ---
        problems.extend(validate_export_entries(tables))

    return problems


def main():
    if not BINARY_PATHS_FILE.exists():
        print(f"Could not find {BINARY_PATHS_FILE}")
        return

    with open(BINARY_PATHS_FILE, "r", encoding="utf-8") as f:
        binary_paths = json.load(f)

    total = len(binary_paths)
    clean_count = 0
    report = {}

    for index, (module_name, meta_path_str) in enumerate(binary_paths.items(), start=1):
        if index % 200 == 0 or index == total:
            print(f"\rValidated {index:,}/{total:,}", end="", flush=True)

        problems = validate_entry(module_name, meta_path_str)
        if problems:
            report[module_name] = {
                "path": meta_path_str,
                "problems": problems,
            }
        else:
            clean_count += 1

    print()

    with open(VALIDATION_REPORT_FILE, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)

    print(f"\nTotal entries checked: {total:,}")
    print(f"Clean (real data, internally consistent): {clean_count:,}")
    print(f"Flagged with problems: {len(report):,}")
    print(f"Saved {VALIDATION_REPORT_FILE.name}")

    if report:
        print("\nFirst 10 flagged entries:")
        for name, info in list(report.items())[:10]:
            print(f"  {name}: {info['problems']}")


if __name__ == "__main__":
    main()