import json
from pathlib import Path
from collections import defaultdict
import platform
import hashlib

WIN_VERSION = None
WIN_BUILD = None
WIN_ARCH = "x64"

_HOST_WIN_VERSION = None

# -------------------------- SHARED HELPERS --------------------------

def iter_meta_files(root: Path):
    yield from root.rglob("*.meta.json")


def load_json(path: Path):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


def resolve_path(meta_path, desc, is_meta_file: bool):
    if is_meta_file:
        p = desc.get("path")
        if p:
            return p

    name = meta_path.name

    if name.endswith(".json"):
        name = name[:-5]

    while True:
        original = name

        parts = name.rsplit(".", 2)
        if len(parts) == 3:
            base, tag, idx = parts
            if tag in {
                "exports", "imports", "relocs", "relocations",
                "unwind", "debug", "tls"
            } and idx.isdigit():
                name = base
                continue

        for suffix in [
            ".exports", ".imports", ".relocs", ".relocations",
            ".unwind", ".debug", ".tls"
        ]:
            if name.endswith(suffix):
                name = name[:-len(suffix)]
                break

        if name == original:
            break

    return name


def binary_key(path_str: str) -> str:
    """
    Canonical key for a SPECIFIC binary instance on disk (full path,
    normalized). This is the only safe way to identify a binary uniquely --
    System32\\kernel32.dll and SysWOW64\\kernel32.dll share a filename but
    are different files with potentially different exports, architectures,
    and hashes. Every per-binary data structure (exports, hashes, versions,
    what-this-binary-imports) must key on this, never on bare filename.
    """
    return str(Path(path_str)).strip().lower().replace("/", "\\")


def filename_key(path_str_or_name: str) -> str:
    """
    Lowercased filename only. Used ONLY for the things that are genuinely
    name-scoped and can't be resolved to a specific path from static data:
    - import table entries (they record a library NAME, never a path)
    - cross-referencing against external name-keyed sources like LOLDrivers
    """
    return Path(path_str_or_name).name.strip().lower()


def lowercase_extension_only(name: str) -> str:
    """
    Preserves original stem casing, lowercases extension only.
    e.g. 'HAL.DLL' -> 'HAL.dll'. Used for display names.
    """
    name = name.strip()
    if "." not in name:
        return name
    stem, _, ext = name.rpartition(".")
    return f"{stem}.{ext.lower()}"


def detect_arch_context(path_str: str) -> str:
    """
    Best-effort human-readable tag for readability/filtering only.
    NEVER used as a uniqueness key.

    Order matters: more specific directories should be checked before
    their parents.
    """
    lowered = path_str.lower().replace("/", "\\")

    checks = (
        # Architecture-specific
        ("\\sysnative\\", "sysnative"),
        ("\\syswow64\\", "syswow64"),
        ("\\system32\\", "system32"),
        ("\\sychpe32\\", "sychpe32"),
        ("\\sysarm32\\", "sysarm32"),

        # Side-by-side assemblies
        ("\\winsxs\\", "winsxs"),

        # DriverStore
        ("\\driverstore\\filerepository\\", "driverstore"),

        # Drivers
        ("\\system32\\drivers\\", "drivers"),
        ("\\syswow64\\drivers\\", "wow64_drivers"),

        # Downlevel shims
        ("\\system32\\downlevel\\", "downlevel"),
        ("\\syswow64\\downlevel\\", "wow64_downlevel"),

        # WMI
        ("\\system32\\wbem\\", "wbem"),
        ("\\syswow64\\wbem\\", "wow64_wbem"),

        # Security
        ("\\securityhealth\\", "securityhealth"),
        ("\\windows defender\\platform\\", "defender_platform"),
        ("\\program files\\windows defender\\", "defender"),

        # Printing
        ("\\spool\\drivers\\", "spool"),

        # UWP inbox apps
        ("\\systemapps\\", "systemapps"),

        # Recovery
        ("\\system32\\recovery\\", "recovery"),

        # Compatibility shims
        ("\\apppatch\\apppatch64\\", "apppatch64"),
        ("\\apppatch\\", "apppatch"),

        # PowerShell
        ("\\windowspowershell\\", "powershell"),

        # OpenSSH
        ("\\openssh\\", "openssh"),

        # Speech
        ("\\speech_onecore\\", "speech_onecore"),
        ("\\speech\\", "speech"),

        # DISM
        ("\\dism\\", "dism"),

        # Sysprep
        ("\\sysprep\\", "sysprep"),

        # WinRM
        ("\\winrm\\", "winrm"),

        # Boot
        ("\\boot\\efi\\", "boot_efi"),
        ("\\boot\\dvd\\efi\\", "boot_dvd_efi"),
        ("\\boot\\dvd\\pcat\\", "boot_dvd_pcat"),
    )

    for needle, tag in checks:
        if needle in lowered:
            return tag

    return "other"


def extract_windows_version(meta_root: dict):
    """
    Pulls the Windows build info out of the top-level 'meta' block:
    {
      "meta": {
        "schema": "axis.binary.meta.v1",
        "windows": {"major": 10, "minor": 0, "build": 26200, "string": "10.0.26200"}
      }
    }
    Returns the version string (e.g. "10.0.26200") or None if absent/malformed.
    """
    windows_info = meta_root.get("meta", {}).get("windows", {})
    version_str = windows_info.get("string")
    if version_str:
        return version_str

    major = windows_info.get("major")
    minor = windows_info.get("minor")
    build = windows_info.get("build")
    if major is not None and minor is not None and build is not None:
        return f"{major}.{minor}.{build}"

    return None


def get_binary_path(meta_path: Path, meta: dict) -> str:
    desc = meta.get("descriptor", {})
    path_str = desc.get("path")
    if not path_str:
        path_str = resolve_path(meta_path, desc, True)
    return path_str

def get_binary_architecture(meta: dict) -> str | None:
    desc = meta.get("descriptor", {})
    return desc.get("architecture")

# -------------------------- DLL DEPENDENCIES TABLE --------------------------

# per-scanned-binary (keyed by full path)
display_names = {}          # binary_key -> display filename (case-preserved stem, lowercase ext)
versions_graph = defaultdict(set)   # binary_key -> {version strings}
dll_versions = {}                   # binary_key -> version string
imports_graph = defaultdict(set)    # binary_key -> {imported library NAMES}

# name-scoped (can't be resolved to a specific path from static import data)
imported_by_graph = defaultdict(set)   # library name -> {binary_key of importers}
# filename_to_paths = defaultdict(set)   # library/binary name -> {binary_keys sharing that name}

filename_candidates = defaultdict(list)

binary_arch = {}

def register_display_name(bkey: str, raw_candidate: str, path_str: str = None):
    display_names[bkey] = lowercase_extension_only(Path(raw_candidate).name)


def build_dll_dependency_graph():
    print("\n=== Building DLL dependency graph ===")

    seen_binaries = set()
    meta_files = list(iter_meta_files(ROOT_DIR))
    total = len(meta_files)

    for index, meta_path in enumerate(meta_files, start=1):

        if index % 100 == 0 or index == total:
            print(f"\rProcessed {index:,}/{total:,}", end="", flush=True)

        meta = load_json(meta_path)
        if not meta:
            continue

        tables = meta.get("tables", {})
        path_str = get_binary_path(meta_path, meta)
        architecture = get_binary_architecture(meta)

        bkey = binary_key(path_str)
        if bkey in seen_binaries:
            continue
        seen_binaries.add(bkey)

        raw_binary_name = Path(path_str).name
        fkey = filename_key(raw_binary_name)

        register_display_name(bkey, raw_binary_name)

        filename_candidates[fkey].append({
            "path": bkey,
            "arch": architecture,
        })

        # filename_to_paths[fkey].add(bkey)

        # ---------------- VERSION (per exact file) ----------------
        version_str = extract_windows_version(meta)
        if version_str:
            versions_graph[bkey].add(version_str)
            dll_versions[bkey] = version_str

        imports = tables.get("imports", {})

        for fragment_name in imports.get("files", []):

            fragment = load_json(ROOT_DIR / fragment_name)
            if not fragment:
                continue

            for entry in fragment.get("entries", []):

                raw_library = entry.get("library")
                if not raw_library:
                    continue

                lib_fkey = filename_key(raw_library)

                # This binary (exact file) imports a library by NAME.
                # We cannot know which physical copy (e.g. System32 vs
                # SysWOW64) it resolves to without separate arch analysis
                # of the importer -- so the import target stays name-keyed.
                imports_graph[bkey].add(lib_fkey)
                imported_by_graph[lib_fkey].add(bkey)

    print()

    output = {}
    for bkey in sorted(seen_binaries):
        output[bkey] = {
            "filename": display_names.get(bkey, Path(bkey).name),
            "architecture": architecture,
            "arch_context": detect_arch_context(bkey),
            "imports": sorted(imports_graph[bkey]),
            "versions": sorted(versions_graph.get(bkey, set())),
        }

    imported_by_output = {}
    for fkey in sorted(imported_by_graph.keys()):
        candidate_entries = sorted(
            filename_candidates.get(fkey, []),
            key=lambda x: x["path"]
        )
        # candidate_paths = sorted(filename_to_paths.get(fkey, set()))
        imported_by_output[fkey] = {
            "importedByPaths": sorted(imported_by_graph[fkey]),
            # All scanned binaries sharing this filename -- i.e. the set
            # of possible resolutions if this name has 2+ physical copies
            # in the corpus (e.g. System32 + SysWOW64). Ambiguous by
            # design; not a claim about which one actually gets loaded.

            # Every scanned binary with this filename, including its architecture.
            "candidatePaths": candidate_entries,

            "hasMultipleCandidates": len(candidate_entries) > 1,
        }

    with open(DLL_DEPENDENCIES_FILE, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)

    with open(DLL_IMPORTED_BY_FILE, "w", encoding="utf-8") as f:
        json.dump(imported_by_output, f, indent=2, ensure_ascii=False)

    with open(DLL_VERSIONS_FILE, "w", encoding="utf-8") as f:
        json.dump(
            {k: v for k, v in sorted(dll_versions.items())},
            f, indent=2, ensure_ascii=False,
        )

    # dup_names = sum(1 for v in filename_to_paths.values() if len(v) > 1)

    dup_names = sum(
        1
        for candidates in filename_candidates.values()
        if len(candidates) > 1
    )

    print(f"Scanned binaries: {len(output):,}")
    print(f"Distinct library names referenced (import side): {len(imported_by_output):,}")
    print(f"Filenames with 2+ distinct physical copies in corpus: {dup_names:,}")
    print(f"Saved {DLL_DEPENDENCIES_FILE.name}, {DLL_IMPORTED_BY_FILE.name}, {DLL_VERSIONS_FILE.name}")


# -------------------------- EXPORT INDEX --------------------------

def func_key(entry: dict):
    """
    Canonical key for an export. When both a name and ordinal exist
    (the common case), combine them into one key so the record is
    stored once, unambiguously representing "this is one export with
    both identities" rather than two separate lookup paths that happen
    to point at duplicated data.
    """
    name = entry.get("name") if entry.get("hasName") else None
    ordinal = entry.get("ordinal")

    if name and ordinal is not None:
        return f"o:{ordinal}|n:{name.strip().lower()}"
    if name:
        return f"n:{name.strip().lower()}"
    if ordinal is not None:
        return f"o:{ordinal}"
    return None


def build_export_index():
    print("\n=== Building export index ===")

    export_table = defaultdict(dict)
    binary_paths = {}
    seen_binaries = set()
    name_index = defaultdict(list)

    meta_files = list(iter_meta_files(ROOT_DIR))
    total = len(meta_files)

    for index, meta_path in enumerate(meta_files, start=1):

        if index % 100 == 0 or index == total:
            print(f"\rProcessed {index:,}/{total:,}", end="", flush=True)

        meta = load_json(meta_path)
        if not meta:
            continue

        tables = meta.get("tables", {})
        path_str = get_binary_path(meta_path, meta)

        bkey = binary_key(path_str)

        # dedup on FULL PATH -- previously deduped on bare filename, which
        # silently dropped e.g. the SysWOW64 copy whenever a System32 copy
        # with the same name had already been seen.
        if bkey in seen_binaries:
            continue
        seen_binaries.add(bkey)

        binary_paths[bkey] = str(meta_path)
        fkey = filename_key(path_str)
        name_index[fkey].append(bkey)

        exports = tables.get("exports", {})

        for fragment_name in exports.get("files", []):

            fragment = load_json(ROOT_DIR / fragment_name)
            if not fragment:
                continue

            for entry in fragment.get("entries", []):

                fk = func_key(entry)
                if fk is None:
                    continue

                record = {
                    "name": entry.get("name"),        # None when hasName is False
                    "hasName": entry.get("hasName"),
                    "ordinal": entry.get("ordinal"),   # always present now
                    "address": entry.get("address"),
                    "role": entry.get("role"),
                    "state": entry.get("state"),
                    "forward": entry.get("forward"),
                }

                export_table[bkey][fk] = record

    print()

    with open(EXPORT_INDEX_FILE, "w", encoding="utf-8") as f:
        json.dump(export_table, f, indent=2, ensure_ascii=False)

    with open(BINARY_PATHS_FILE, "w", encoding="utf-8") as f:
        json.dump(binary_paths, f, indent=2, ensure_ascii=False)

    with open(MODULE_NAME_INDEX_FILE, "w", encoding="utf-8") as f:
        json.dump(name_index, f, indent=2, ensure_ascii=False)


    dup_names = sum(1 for v in name_index.values() if len(v) > 1)

    print(f"Modules with exports indexed: {len(export_table):,}")
    print(f"Filenames with 2+ distinct physical copies: {dup_names:,}")
    print(f"Saved {EXPORT_INDEX_FILE.name}, {BINARY_PATHS_FILE.name} And {MODULE_NAME_INDEX_FILE.name}")


# -------------------------- HASH INDEX --------------------------

def get_host_windows_version():
    global _HOST_WIN_VERSION
    if _HOST_WIN_VERSION is not None:
        return _HOST_WIN_VERSION

    ver = platform.version()
    release = platform.release()

    _HOST_WIN_VERSION = {"build": ver, "release": release}
    return _HOST_WIN_VERSION


def get_meta_windows_version(meta):
    try:
        return meta.get("meta", {}).get("windows", {}).get("string")
    except AttributeError:
        return None


def versions_match(meta_version_str, host_info):
    if not meta_version_str:
        return False
    return host_info["build"] in meta_version_str or meta_version_str in host_info["build"]


def hash_file(path, chunk_size=1024 * 1024):
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()

    with open(path, "rb") as f:
        while chunk := f.read(chunk_size):
            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)

    return {
        "md5": md5.hexdigest(),
        "sha1": sha1.hexdigest(),
        "sha256": sha256.hexdigest(),
    }


def build_hash_index():
    print("\n=== Building hash index ===")

    host_info = get_host_windows_version()
    print(f"Host Windows version: {host_info['build']} (release {host_info['release']})")

    hash_table = {}
    name_index = defaultdict(list)
    skipped_mismatch = []
    skipped_missing = []
    seen_paths = set()

    meta_files = list(iter_meta_files(ROOT_DIR))
    total = len(meta_files)

    for index, meta_path in enumerate(meta_files, start=1):

        if index % 100 == 0 or index == total:
            print(f"\rProcessed {index:,}/{total:,}", end="", flush=True)

        meta = load_json(meta_path)
        if not meta:
            continue

        path_str = get_binary_path(meta_path, meta)
        bkey = binary_key(path_str)

        if bkey in seen_paths:
            continue
        seen_paths.add(bkey)

        filename = Path(path_str).name
        fkey = filename_key(path_str)
        arch_context = detect_arch_context(path_str)

        meta_version = get_meta_windows_version(meta)

        if not versions_match(meta_version, host_info):
            skipped_mismatch.append({
                "path": bkey,
                "expected": meta_version,
                "host": host_info["build"],
            })
            continue

        file_path = Path(path_str)
        if not file_path.exists():
            skipped_missing.append(bkey)
            continue

        try:
            digests = hash_file(file_path)
        except OSError:
            skipped_missing.append(bkey)
            continue

        hash_table[bkey] = {
            "filename": filename,
            "path": str(file_path),
            "arch_context": arch_context,
            "windows_version": meta_version,
            **digests,
        }

        name_index[fkey].append(bkey)

    print()

    if skipped_mismatch:
        print(f"\nERROR: Found {len(skipped_mismatch):,} Windows version mismatches.")
        print("Aborting without writing any hash index files.")

        print("\nFirst 5 mismatches:")
        for entry in skipped_mismatch[:5]:
            print(f"  {entry['path']}: expected {entry['expected']}, host is {entry['host']}")

        return

    with open(HASH_INDEX_FILE, "w", encoding="utf-8") as f:
        json.dump(hash_table, f, indent=2, ensure_ascii=False)

    dup_names = sum(1 for v in name_index.values() if len(v) > 1)

    print(f"Binaries hashed: {len(hash_table):,}")
    print(f"Filenames with 2+ distinct copies (e.g. System32/SysWOW64): {dup_names:,}")
    print(f"Skipped (version mismatch): {len(skipped_mismatch):,}")
    print(f"Skipped (missing/unreadable): {len(skipped_missing):,}")

    print(f"Saved {HASH_INDEX_FILE.name}")


# -------------------------- MENU --------------------------
def select_windows_version():
    global WIN_VERSION, WIN_BUILD

    print("========== Windows Dataset ==========")
    print("1. Windows 10 (10.0.19045)")
    print("2. Windows 11 (10.0.26200)")

    choice = input("\nSelect version (1-2): ").strip()

    if choice == "1":
        WIN_VERSION = "win10"
        WIN_BUILD = "10.0.19045"

    elif choice == "2":
        WIN_VERSION = "win11"
        WIN_BUILD = "10.0.26200"

    else:
        raise ValueError("Invalid Windows version selection.")

    print("\nSelected dataset:")
    print(f"Version : {WIN_VERSION}")
    print(f"Build   : {WIN_BUILD}")
    print(f"Arch    : {WIN_ARCH}")

def main():

    select_windows_version()

    global SCRIPT_DIR
    global OUTPUT_DIR
    global EXPORT_INDEX_FILE
    global MODULE_NAME_INDEX_FILE
    global BINARY_PATHS_FILE
    global DLL_DEPENDENCIES_FILE
    global DLL_IMPORTED_BY_FILE
    global DLL_VERSIONS_FILE
    global HASH_INDEX_FILE
    global ROOT_DIR

    SCRIPT_DIR = Path(__file__).resolve().parent

    OUTPUT_DIR = SCRIPT_DIR.parent / "shared-output" / WIN_VERSION / WIN_BUILD / WIN_ARCH
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    EXPORT_INDEX_FILE = OUTPUT_DIR / "export_index.json"
    MODULE_NAME_INDEX_FILE = OUTPUT_DIR / "module_name_index.json"
    BINARY_PATHS_FILE = OUTPUT_DIR / "binary_paths.json"
    DLL_DEPENDENCIES_FILE = OUTPUT_DIR / "dll_dependencies.json"
    DLL_IMPORTED_BY_FILE = OUTPUT_DIR / "dll_imported_by.json"
    DLL_VERSIONS_FILE = OUTPUT_DIR / "dll_versions.json"
    HASH_INDEX_FILE = OUTPUT_DIR / "hashes.json"

    ROOT_DIR = (
        SCRIPT_DIR.parent
        / "axis-binary-output"
        / WIN_VERSION
        / WIN_BUILD
        / WIN_ARCH
    )

    print("\n========== Build Menu ==========")
    print("1. DLL dependency graph")
    print("2. Export index")
    print("3. Hash index")
    print("4. Build all")

    choice = input("\nEnter choice (1-4): ").strip()

    if choice == "1":
        build_dll_dependency_graph()

    elif choice == "2":
        build_export_index()

    elif choice == "3":
        build_hash_index()

    elif choice == "4":
        build_dll_dependency_graph()
        print()
        build_export_index()
        print()
        build_hash_index()

    else:
        print("Invalid choice.")


if __name__ == "__main__":
    main()