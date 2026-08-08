import json
from pathlib import Path
from collections import Counter

WIN_ARCH = "x64"

# version -> build number
CORPORA = {
    "win10": "10.0.19045",
    "win11": "10.0.26200",
}

SCRIPT_DIR = Path(__file__).resolve().parent.parent


def get_root_dir(win_version: str, win_build: str) -> Path:
    return (
        SCRIPT_DIR
        / "axis-binary-output"
        / win_version
        / win_build
        / WIN_ARCH
    )


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
                name = name[: -len(suffix)]
                break

        if name == original:
            break

    return name


def normalize_binary_key(path_str: str):
    return path_str.strip().lower().replace("/", "\\")


WINDOWS_FUNCTION_PREFIXES = [
    # Runtime Library
    "Rtl",

    # Native System Services
    "Nt",
    "Zw",

    # Loader
    "Ldr",

    # Heap Manager
    "RtlHeap",
    "Heap",

    # Security
    "Se",
    "Sep",

    # Object Manager
    "Ob",
    "Obp",

    # Memory Manager
    "Mm",
    "Mi",

    # Process / Thread Manager
    "Ps",
    "Psp",

    # I/O Manager
    "Io",
    "Iop",

    # Configuration Manager (Registry)
    "Cm",
    "Cmp",

    # Cache Manager
    "Cc",

    # Executive
    "Ex",
    "Exp",

    # Kernel
    "Ke",
    "Ki",

    # HAL
    "Hal",
    "Hali",

    # Interrupts
    "Ki",
    "Kx",

    # Scheduler
    "Ki",
    "Ke",

    # Power Manager
    "Po",
    "Pop",

    # Plug and Play
    "Pi",
    "Pip",

    # LPC / ALPC
    "Lpc",
    "Alpc",

    # File Systems
    "Fs",
    "FsRtl",

    # Filter Manager
    "Flt",
    "Fltp",

    # Network
    "Net",
    "Nsi",

    # WMI
    "Wmi",

    # ETW
    "Etw",

    # Debugging
    "Dbg",
    "Kd",
    "Kdp",

    # Exception / Unwind
    "Rtlp",
    "RtlUnwind",
    "RtlRestore",

    # Synchronization
    "Interlocked",

    # CSR
    "Csr",

    # Session Manager
    "Sm",

    # User-mode CSR
    "Base",

    # Window Manager
    "NtUser",
    "xxx",

    # GDI
    "NtGdi",
    "Gre",
    "Eng",

    # DirectX
    "Dxgk",
    "D3DKMT",

    # COM / RPC
    "Co",
    "Ole",
    "Rpc",
    "Ndr",

    # CRT
    "_",
    "__",
    "_Crt",

    # C++ Runtime
    "__std",
    "__Cxx",
    "__crt",

    # Win32
    "Get",
    "Set",
    "Create",
    "Open",
    "Close",
    "Read",
    "Write",
    "Delete",
    "Find",
    "Enum",
    "Register",
    "Unregister",
    "Initialize",
    "Uninitialize",
    "Query",
    "Lookup",
    "Wait",
    "Signal",
    "Map",
    "Unmap",
    "Load",
    "Free",
    "Copy",
    "Move",
    "Compare",
    "Format",
    "Expand",
    "Verify",
    "Lock",
    "Unlock",
    "Acquire",
    "Release",

    # Activation Context
    "RtlActivate",
    "CreateActCtx",

    # API Set
    "ApiSet",

    # AppContainer
    "AppContainer",

    # AppModel
    "AppPolicy",

    # BCrypt / Crypto
    "BCrypt",
    "Crypt",
    "NCrypt",

    # Winsock
    "WSA",
    "WSC",

    # HTTP
    "Http",

    # WinHTTP
    "WinHttp",

    # WinINet
    "Internet",

    # DNS
    "Dns",

    # URL
    "Url",

    # Version
    "Ver",

    # SxS
    "Sxs",

    # Shell
    "SH",

    # Setup API
    "Setup",

    # Device Installation
    "Di",

    # Performance Counters
    "Perf",

    # Service Control Manager
    "Sc",

    # Terminal Services
    "WinStation",

    # Event Log
    "Elf",

    # Compression
    "RtlCompress",
    "RtlDecompress",

    # String Helpers
    "RtlString",
    "RtlUnicode",
    "RtlAnsi",

    # Misc Internal
    "Basep",
    "Ldrp",
    "Rtlp",
    "Ntdll",
]

# Longest prefixes first (important: NtUser before Nt, FsRtl before Fs, etc.)
WINDOWS_FUNCTION_PREFIXES.sort(key=len, reverse=True)

def process_table_fragments(root: Path, table: dict, is_import: bool,
                             import_stats: dict):
    """
    Reads fragmented import/export tables.

    Imports:
        - Counts imported function references.
        - Counts imported DLL references.
        - Counts DLL dependencies (once per binary).

    Exports:
        - Counts exported function references.
    """
    seen_import_libraries = set()

    for relative_path in table.get("files", []):
        fragment = load_json(root / relative_path)
        if not fragment:
            continue

        for entry in fragment.get("entries", []):
            library = entry.get("library")
            function = entry.get("name")

            if is_import:
                if library:
                    import_stats["library_imports"][library] += 1
                    if library not in seen_import_libraries:
                        seen_import_libraries.add(library)
                        import_stats["library_import_dependencies"][library] += 1
                if function:
                    import_stats["function_imports"][function] += 1
            else:
                if function:
                    import_stats["function_exports"][function] += 1

def is_mangled_cpp_name(name: str) -> bool:
    """
    MSVC C++ decorated (mangled) names start with '?'.
    e.g. ??0ClassName@@QAE@XZ, ?func@@YAHXZ
    Also catches '??_' variants (vtables, RTTI, etc.)
    """
    return name.startswith("?")

def compute_prefix_counts(function_counter: Counter, lengths=(2, 3, 4)) -> dict:
    """
    Buckets a {function_name: count} Counter by leading N characters,
    for N in `lengths`. Weighted by call count.

    Mangled C++ names are excluded -- they're compiler encoding
    artifacts, not subsystem naming conventions, and would otherwise
    dominate the 2-char bucket with noise like '??'.
    """
    result = {n: Counter() for n in lengths}
    mangled_count = 0

    for name, count in function_counter.items():
        if not name:
            continue
        if is_mangled_cpp_name(name):
            mangled_count += 1
            continue
        for n in lengths:
            if len(name) >= n:
                result[n][name[:n]] += count

    result["_mangled_cpp_excluded"] = mangled_count
    return result

def compute_system_prefix_counts(function_counter, prefixes):
    counts = {p: 0 for p in prefixes}
    counts["Other"] = 0

    # Longest prefixes first so "RtlDecompress" wins over "Rtl"
    prefixes = sorted(prefixes, key=len, reverse=True)

    for name, count in function_counter.items():
        if not name or is_mangled_cpp_name(name):
            continue

        matched = False
        for prefix in prefixes:
            if name.startswith(prefix):
                counts[prefix] += count
                matched = True
                break

        if not matched:
            counts["Other"] += count

    return counts

def scan_and_analyze(root: Path, label: str) -> dict:
    meta_files = list(iter_meta_files(root))
    total_meta_files = len(meta_files)
    processed_meta_files = 0

    stats = {
        "total": 0,
        "x64": 0,
        "x86": 0,
        "executables": 0,
        "dlls": 0,
        "drivers": 0,
        "signed": 0,
        "unsigned": 0,
        "signature_unknown": 0,
        "microsoft_signed": 0,
        "third_party_signed": 0,
    }

    import_stats = {
        "total_imports": 0,
        "total_exports": 0,
        "largest_import_table": ("", 0),
        "largest_export_table": ("", 0),
        "library_imports": Counter(),
        "function_imports": Counter(),
        "function_exports": Counter(),
        "library_import_dependencies": Counter(),
        "import_prefix_counts": Counter(),
        "export_prefix_counts": Counter(),
        "import_system_prefix_counts": Counter(),
        "export_system_prefix_counts": Counter(),
    }

    feature_counts = {}
    signer_counts = {}
    signature_status_counts = {}

    examples = {
        "missing_debug": [],
        "missing_relocations": [],
        "missing_rich_header": [],
        "has_clr": [],
        "supports_hotpatch": [],
        "has_hotpatch_table": [],
        "supports_appcontainer": [],
        "relocations_stripped": [],
        "dynamic_base_without_relocations_no_entryPoint": [],
        "dynamic_base_without_relocations": [],
        "has_all_permissions": [],
        "unsigned_binaries": [],
        "third_party_signed": [],
    }

    signature_examples = {}

    section_name_counts = {}
    section_permission_counts = {}
    section_alignment_counts = {}
    section_content_counts = {}
    section_size_total = 0
    section_size_count = 0
    section_examples = {
        "largest_section": (None, 0),
        "smallest_nonzero_section": (None, float("inf")),
        "execute_only_sections": [],
        "rwx_sections": [],
    }

    seen_binaries = set()

    for meta_path in meta_files:
        processed_meta_files += 1
        meta = load_json(meta_path)
        if not meta:
            continue

        desc = meta.get("descriptor", {})
        segments = meta.get("segments", {})
        analysis = meta.get("analysis", {})
        tables = meta.get("tables", {})
        signature = meta.get("signature", {})

        imports = tables.get("imports", {})
        exports = tables.get("exports", {})

        is_meta_file = "meta" in meta_path.name
        path_str = resolve_path(meta_path, desc, is_meta_file)

        key = normalize_binary_key(path_str)
        if key in seen_binaries:
            continue
        seen_binaries.add(key)

        if processed_meta_files % 100 == 0 or processed_meta_files == total_meta_files:
            remaining = total_meta_files - processed_meta_files
            percent = processed_meta_files * 100.0 / total_meta_files if total_meta_files else 100.0
            line = (
                f"[{label}] Processed {processed_meta_files:,}/{total_meta_files:,} "
                f"({percent:5.1f}%) | Remaining: {remaining:,} | "
                f"Unique binaries: {len(seen_binaries):,}"
            )
            print(f"\r{line}\033[K", end="", flush=True)

        # ---------------- ARCH / TYPE ----------------
        stats["total"] += 1

        bitness = desc.get("bitness")
        if bitness == 64:
            stats["x64"] += 1
        elif bitness == 32:
            stats["x86"] += 1

        if analysis.get("is_executable"):
            stats["executables"] += 1
        if analysis.get("is_dll"):
            stats["dlls"] += 1
        if analysis.get("is_driver"):
            stats["drivers"] += 1

        # ---------------- SIGNATURE ----------------
        sig_status = signature.get("status", "unknown")
        signature_status_counts[sig_status] = signature_status_counts.get(sig_status, 0) + 1

        if sig_status != "valid":
            signature_examples.setdefault(sig_status, []).append(path_str)

        if sig_status == "valid":
            stats["signed"] += 1
        elif sig_status == "unsigned":
            stats["unsigned"] += 1
            examples["unsigned_binaries"].append(path_str)
        else:
            stats["signature_unknown"] += 1

        signer = signature.get("signer", "")
        is_microsoft = signature.get("isMicrosoft", False)

        if sig_status == "valid":
            if is_microsoft:
                stats["microsoft_signed"] += 1
            else:
                stats["third_party_signed"] += 1
                examples["third_party_signed"].append(path_str)

        if signer:
            signer_counts[signer] = signer_counts.get(signer, 0) + 1

        # ---------------- UNIFIED FEATURE MODEL ----------------
        features = {
            "has_exports": analysis.get("has_exports") or tables.get("exports", {}).get("totalCount", 0) > 0,
            "has_imports": analysis.get("has_imports") or tables.get("imports", {}).get("totalCount", 0) > 0,
        }

        for k, v in analysis.items():
            if isinstance(v, bool) and k not in ("has_exports", "has_imports"):
                features[k] = v

        for k, v in features.items():
            feature_counts.setdefault(k, 0)
            if v:
                feature_counts[k] += 1

        # ---------------- SPECIAL EXAMPLES ----------------
        if not features.get("has_debug", False):
            examples["missing_debug"].append(path_str)

        if not features.get("has_relocations", False):
            examples["missing_relocations"].append(path_str)

        if not features.get("has_rich_header", False):
            examples["missing_rich_header"].append(path_str)

        if features.get("has_clr"):
            examples["has_clr"].append(path_str)

        if analysis.get("supports_hotpatch"):
            examples["supports_hotpatch"].append(path_str)

        if analysis.get("has_hotpatch_table"):
            examples["has_hotpatch_table"].append(path_str)

        if analysis.get("supports_appcontainer"):
            examples["supports_appcontainer"].append(path_str)

        if analysis.get("relocations_stripped"):
            examples["relocations_stripped"].append(path_str)

        if (tables.get("relocations", {}).get("totalCount") == 0 and
                analysis.get("supports_dynamic_base", False) and
                desc.get("entry_point") == 0):
            examples["dynamic_base_without_relocations_no_entryPoint"].append(path_str)

        if (tables.get("relocations", {}).get("totalCount") == 0 and
                analysis.get("supports_dynamic_base", False) and
                desc.get("entry_point") != 0):
            examples["dynamic_base_without_relocations"].append(path_str)

        for segment in segments.get("entries", []):
            perms = segment.get("permissions")
            if perms == "rwx":
                examples["has_all_permissions"].append(path_str)

            name = segment.get("name", "")
            alignment = segment.get("alignment")
            content = segment.get("content", "")
            size = segment.get("size", 0)

            section_name_counts[name] = section_name_counts.get(name, 0) + 1

            if perms:
                section_permission_counts[perms] = section_permission_counts.get(perms, 0) + 1

            if alignment is not None:
                section_alignment_counts[alignment] = section_alignment_counts.get(alignment, 0) + 1

            if content:
                section_content_counts[content] = section_content_counts.get(content, 0) + 1

            if perms == "--x":
                section_examples["execute_only_sections"].append(f"{path_str} [{name}]")

            if perms == "rwx":
                section_examples["rwx_sections"].append(f"{path_str} [{name}]")

            if size > 0:
                section_size_total += size
                section_size_count += 1

                if size > section_examples["largest_section"][1]:
                    section_examples["largest_section"] = (f"{path_str} [{name}]", size)

                if size < section_examples["smallest_nonzero_section"][1]:
                    section_examples["smallest_nonzero_section"] = (f"{path_str} [{name}]", size)

        # ---------------- IMPORTS/EXPORTS STATS ----------------
        import_count = imports.get("totalCount", 0)
        export_count = exports.get("totalCount", 0)

        import_stats["total_imports"] += import_count
        import_stats["total_exports"] += export_count

        if import_count > import_stats["largest_import_table"][1]:
            import_stats["largest_import_table"] = (path_str, import_count)

        if export_count > import_stats["largest_export_table"][1]:
            import_stats["largest_export_table"] = (path_str, export_count)

        process_table_fragments(root, imports, True, import_stats)
        process_table_fragments(root, exports, False, import_stats)

        import_stats["import_prefix_counts"] = compute_prefix_counts(
            import_stats["function_imports"]
        )
        import_stats["export_prefix_counts"] = compute_prefix_counts(
            import_stats["function_exports"]
        )

        import_stats["import_system_prefix_counts"] = compute_system_prefix_counts(
            import_stats["function_imports"],
            WINDOWS_FUNCTION_PREFIXES,
        )

        import_stats["export_system_prefix_counts"] = compute_system_prefix_counts(
            import_stats["function_exports"],
            WINDOWS_FUNCTION_PREFIXES,
        )

    print()

    return {
        "stats": stats,
        "feature_counts": feature_counts,
        "examples": examples,
        "import_stats": import_stats,
        "signer_counts": signer_counts,
        "signature_status_counts": signature_status_counts,
        "signature_examples": signature_examples,
        "section_name_counts": section_name_counts,
        "section_permission_counts": section_permission_counts,
        "section_alignment_counts": section_alignment_counts,
        "section_content_counts": section_content_counts,
        "section_size_total": section_size_total,
        "section_size_count": section_size_count,
        "section_examples": section_examples,
    }


# =========================================================================
# SINGLE-CORPUS REPORT (unchanged behavior, per corpus)
# =========================================================================

def print_results(label: str, data: dict):
    stats = data["stats"]
    feature_counts = data["feature_counts"]
    examples = data["examples"]
    import_stats = data["import_stats"]
    signer_counts = data["signer_counts"]
    signature_status_counts = data["signature_status_counts"]
    signature_examples = data["signature_examples"]
    section_name_counts = data["section_name_counts"]
    section_permission_counts = data["section_permission_counts"]
    section_alignment_counts = data["section_alignment_counts"]
    section_content_counts = data["section_content_counts"]
    section_size_total = data["section_size_total"]
    section_size_count = data["section_size_count"]
    section_examples = data["section_examples"]

    print(f"\n=== AXIS BINARY ANALYSIS SUMMARY [{label}] ===")
    for k, v in stats.items():
        print(f"{k}: {v}")

    print(f"\n=== FEATURE PRESENCE DISTRIBUTION [{label}] ===")
    for k, v in sorted(feature_counts.items(), key=lambda x: -x[1]):
        print(f"{k}: {v}")

    print(f"\n=== RARE / INTERESTING CASES [{label}] ===")

    def dump(title, items, limit=1000):
        print(f"\n[{title}] count={len(items)} (Dump Limit={limit})")
        for p in items[:limit]:
            print(p)

    dump("NO DEBUG", examples["missing_debug"])
    dump("NO RELOCATIONS", examples["missing_relocations"])
    dump("NO RICH HEADER", examples["missing_rich_header"])
    dump("HAS CLR (.NET BINARIES)", examples["has_clr"])
    dump("SUPPORTS HOTPATCH", examples["supports_hotpatch"])
    dump("HAS HOTPATCH TABLE", examples["has_hotpatch_table"])
    dump("SUPPORTS APPCONTAINER", examples["supports_appcontainer"])
    dump("RELOCATIONS STRIPPED", examples["relocations_stripped"])
    dump("DYNAMIC BASE WITHOUT RELOCATIONS (EntryPoint == 0)", examples["dynamic_base_without_relocations_no_entryPoint"])
    dump("DYNAMIC BASE WITHOUT RELOCATIONS (EntryPoint != 0)", examples["dynamic_base_without_relocations"])
    dump("HAS ALL PERMISSIONS", examples["has_all_permissions"])
    dump("UNSIGNED BINARIES", examples["unsigned_binaries"])
    dump("THIRD-PARTY SIGNED", examples["third_party_signed"])

    print(f"\n=== SIGNATURE SUMMARY [{label}] ===")
    total = stats.get("total", 0) or 1
    print(f"Signed (valid)      : {stats.get('signed', 0):,}  ({stats.get('signed', 0) * 100.0 / total:5.1f}%)")
    print(f"Unsigned            : {stats.get('unsigned', 0):,}  ({stats.get('unsigned', 0) * 100.0 / total:5.1f}%)")
    print(f"Signature unknown   : {stats.get('signature_unknown', 0):,}  ({stats.get('signature_unknown', 0) * 100.0 / total:5.1f}%)")
    print()
    print(f"Microsoft-signed    : {stats.get('microsoft_signed', 0):,}")
    print(f"Third-party signed  : {stats.get('third_party_signed', 0):,}")

    print(f"\n=== SIGNATURE STATUS BREAKDOWN [{label}] ===")
    for status, count in sorted(signature_status_counts.items(), key=lambda x: -x[1]):
        print(f"{count:>8,}  {status}")

    print(f"\n=== TOP SIGNERS [{label}] ===")
    for signer, count in sorted(signer_counts.items(), key=lambda x: -x[1]):
        print(f"{count:>8,}  {signer}")

    print(f"\n=== NON-VALID SIGNATURE CASES [{label}] ===")
    for status, paths in signature_examples.items():
        print(f"\n[{status}] count={len(paths)}")
        for p in paths:
            print(p)

    print(f"\n=== IMPORT / EXPORT SUMMARY [{label}] ===")
    print(f"Total Imports : {import_stats['total_imports']:,}")
    print(f"Total Exports : {import_stats['total_exports']:,}")
    print()
    binary, count = import_stats["largest_import_table"]
    print(f"Largest Import Table : {count:,}\n{binary}")
    print()
    binary, count = import_stats["largest_export_table"]
    print(f"Largest Export Table : {count:,}\n{binary}")
    print()
    print(f"Unique Imported DLLs         : {len(import_stats['library_imports']):,}")
    print(f"Unique Imported Functions    : {len(import_stats['function_imports']):,}")
    print(f"Unique Exported Functions    : {len(import_stats['function_exports']):,}")
    print()

    print(f"=== DLL DEPENDENCIES (Per Binary) [{label}] ===")
    for dll, count in import_stats["library_import_dependencies"].most_common(25):
        print(f"{count:>8,}  {dll}")
    print()

    print(f"=== DLL REFERENCES (Imported Functions) [{label}] ===")
    for dll, count in import_stats["library_imports"].most_common(25):
        print(f"{count:>8,}  {dll}")
    print()

    print(f"=== TOP IMPORTED FUNCTIONS [{label}] ===")
    for func, count in import_stats["function_imports"].most_common(50):
        print(f"{count:>8,}  {func}")
    print()

    print(f"=== TOP EXPORTED FUNCTIONS [{label}] ===")
    for func, count in import_stats["function_exports"].most_common(50):
        print(f"{count:>8,}  {func}")

    print(f"\n=== IMPORT FUNCTION PREFIXES [{label}] ===")
    import_excluded = import_stats["import_prefix_counts"].get("_mangled_cpp_excluded", 0)
    print(f"(excluded {import_excluded:,} mangled C++ names from prefix buckets)")
    for n in sorted(k for k in import_stats["import_prefix_counts"].keys() if isinstance(k, int)):
        print(f"\n--- {n}-char prefixes ---")
        for prefix, count in import_stats["import_prefix_counts"][n].most_common(20):
            print(f"{count:>8,}  {prefix}")

    print(f"\n=== EXPORT FUNCTION PREFIXES [{label}] ===")
    export_excluded = import_stats["export_prefix_counts"].get("_mangled_cpp_excluded", 0)
    print(f"(excluded {export_excluded:,} mangled C++ names from prefix buckets)")
    for n in sorted(k for k in import_stats["export_prefix_counts"].keys() if isinstance(k, int)):
        print(f"\n--- {n}-char prefixes ---")
        for prefix, count in import_stats["export_prefix_counts"][n].most_common(20):
            print(f"{count:>8,}  {prefix}")

    print(f"=== IMPORT SYSTEM PREFIXES [{label}] ===")
    for prefix in sorted(
        WINDOWS_FUNCTION_PREFIXES,
        key=lambda p: import_stats["import_system_prefix_counts"].get(p, 0),
        reverse=True,
    ):
        print(f"{import_stats['import_system_prefix_counts'].get(prefix, 0):>8,}  {prefix}")
    print(f"{import_stats['import_system_prefix_counts'].get('Other', 0):>8,}  Other")

    print()

    print(f"=== EXPORT SYSTEM PREFIXES [{label}] ===")
    for prefix in sorted(
        WINDOWS_FUNCTION_PREFIXES,
        key=lambda p: import_stats["export_system_prefix_counts"].get(p, 0),
        reverse=True,
    ):
        print(f"{import_stats['export_system_prefix_counts'].get(prefix, 0):>8,}  {prefix}")
    print(f"{import_stats['export_system_prefix_counts'].get('Other', 0):>8,}  Other")

    print(f"\n=== SECTION (SEGMENT) ANALYSIS [{label}] ===")
    print(f"Total sections scanned : {sum(section_name_counts.values()):,}")
    avg_size = (section_size_total / section_size_count) if section_size_count else 0
    print(f"Average section size    : {avg_size:,.0f} bytes")

    print("\n--- TOP SECTION NAMES ---")
    for name, count in sorted(section_name_counts.items(), key=lambda x: -x[1])[:30]:
        label_name = name if name else "(unnamed)"
        print(f"{count:>8,}  {label_name}")

    print("\n--- SECTION PERMISSIONS ---")
    for perms, count in sorted(section_permission_counts.items(), key=lambda x: -x[1]):
        print(f"{count:>8,}  {perms}")

    print("\n--- SECTION CONTENT TYPES ---")
    for content, count in sorted(section_content_counts.items(), key=lambda x: -x[1]):
        print(f"{count:>8,}  {content}")

    print("\n--- SECTION ALIGNMENTS ---")
    for alignment, count in sorted(section_alignment_counts.items(), key=lambda x: -x[1]):
        print(f"{count:>8,}  {alignment}")

    print("\n--- SIZE EXTREMES ---")
    largest_name, largest_size = section_examples["largest_section"]
    print(f"Largest section  : {largest_size:,} bytes\n  {largest_name}")
    smallest_name, smallest_size = section_examples["smallest_nonzero_section"]
    print(f"\nSmallest nonzero section : {smallest_size:,} bytes\n  {smallest_name}")

    print(f"\n--- EXECUTE-ONLY (--x) SECTIONS --- count={len(section_examples['execute_only_sections']):,}")
    for entry in section_examples["execute_only_sections"]:
        print(entry)

    print(f"\n--- RWX SECTIONS --- count={len(section_examples['rwx_sections']):,}")
    for entry in section_examples["rwx_sections"]:
        print(entry)


# =========================================================================
# COMPARISON REPORT (win10 vs win11)
# =========================================================================

def pct_change(a, b):
    if a == 0:
        return float("inf") if b else 0.0
    return (b - a) * 100.0 / a


def diff_dict(a: dict, b: dict, top_n=25):
    """
    Compares two {key: count} dicts (or Counters).
    Returns list of (key, count_a, count_b, delta) sorted by |delta| desc,
    plus explicit added/removed key lists.
    """
    keys = set(a.keys()) | set(b.keys())
    rows = []
    for k in keys:
        va = a.get(k, 0)
        vb = b.get(k, 0)
        rows.append((k, va, vb, vb - va))
    rows.sort(key=lambda r: -abs(r[3]))

    added = sorted([k for k in keys if a.get(k, 0) == 0 and b.get(k, 0) > 0])
    removed = sorted([k for k in keys if b.get(k, 0) == 0 and a.get(k, 0) > 0])

    return rows[:top_n], added, removed


def diff_example_set(label_a, label_b, list_a, list_b, limit=100):
    """
    Compares two lists of binary paths for the same category.
    Uses normalized path as identity key -- same binary present under
    both corpora but only flagged in one indicates a version-specific change.
    """
    set_a = {normalize_binary_key(p) for p in list_a}
    set_b = {normalize_binary_key(p) for p in list_b}

    only_a = sorted(set_a - set_b)
    only_b = sorted(set_b - set_a)
    common = set_a & set_b

    print(f"  {label_a}: {len(set_a):,}   {label_b}: {len(set_b):,}   "
          f"common: {len(common):,}   delta: {len(set_b) - len(set_a):+,}")

    if only_a:
        print(f"  -- only in {label_a} (count={len(only_a)}) --")
        for p in only_a[:limit]:
            print(f"    {p}")
    if only_b:
        print(f"  -- only in {label_b} (count={len(only_b)}) --")
        for p in only_b[:limit]:
            print(f"    {p}")


def compare_corpora(label_a: str, data_a: dict, label_b: str, data_b: dict):
    print(f"\n\n########## COMPARISON REPORT: {label_a} vs {label_b} ##########")

    # ---------------- CORE STATS ----------------
    print(f"\n=== CORE STATS DIFF ({label_a} -> {label_b}) ===")
    stats_a, stats_b = data_a["stats"], data_b["stats"]
    keys = sorted(set(stats_a.keys()) | set(stats_b.keys()))
    for k in keys:
        va, vb = stats_a.get(k, 0), stats_b.get(k, 0)
        print(f"{k:<22} {va:>10,}  ->  {vb:>10,}   delta: {vb - va:+,}   ({pct_change(va, vb):+.1f}%)")

    # ---------------- FEATURE PRESENCE ----------------
    print(f"\n=== FEATURE PRESENCE DIFF ({label_a} -> {label_b}) ===")
    rows, added, removed = diff_dict(data_a["feature_counts"], data_b["feature_counts"], top_n=1000)
    for k, va, vb, d in rows:
        print(f"{k:<30} {va:>8,}  ->  {vb:>8,}   delta: {d:+,}")
    if added:
        print(f"\nFeatures with zero presence in {label_a} but present in {label_b}: {added}")
    if removed:
        print(f"Features present in {label_a} but zero presence in {label_b}: {removed}")

    # ---------------- RARE / INTERESTING CASES ----------------
    print(f"\n=== RARE / INTERESTING CASES DIFF ({label_a} vs {label_b}) ===")
    ex_a, ex_b = data_a["examples"], data_b["examples"]
    for category in ex_a.keys():
        print(f"\n[{category}]")
        diff_example_set(label_a, label_b, ex_a.get(category, []), ex_b.get(category, []))

    # ---------------- SIGNATURES ----------------
    print(f"\n=== SIGNATURE STATUS DIFF ({label_a} -> {label_b}) ===")
    rows, added, removed = diff_dict(data_a["signature_status_counts"], data_b["signature_status_counts"], top_n=1000)
    for k, va, vb, d in rows:
        print(f"{k:<20} {va:>8,}  ->  {vb:>8,}   delta: {d:+,}")

    print(f"\n=== TOP SIGNERS DIFF ({label_a} -> {label_b}, top movers) ===")
    rows, added, removed = diff_dict(data_a["signer_counts"], data_b["signer_counts"], top_n=25)
    for k, va, vb, d in rows:
        print(f"{k:<60} {va:>8,}  ->  {vb:>8,}   delta: {d:+,}")
    if added:
        print(f"\nSigners new in {label_b}: {added}")
    if removed:
        print(f"Signers absent in {label_b}: {removed}")

    # ---------------- IMPORT / EXPORT SUMMARY ----------------
    imp_a, imp_b = data_a["import_stats"], data_b["import_stats"]
    print(f"\n=== IMPORT / EXPORT SUMMARY DIFF ({label_a} -> {label_b}) ===")
    print(f"Total Imports  : {imp_a['total_imports']:,}  ->  {imp_b['total_imports']:,}   "
          f"delta: {imp_b['total_imports'] - imp_a['total_imports']:+,}")
    print(f"Total Exports  : {imp_a['total_exports']:,}  ->  {imp_b['total_exports']:,}   "
          f"delta: {imp_b['total_exports'] - imp_a['total_exports']:+,}")
    print(f"Unique Imported DLLs      : {len(imp_a['library_imports']):,}  ->  {len(imp_b['library_imports']):,}")
    print(f"Unique Imported Functions : {len(imp_a['function_imports']):,}  ->  {len(imp_b['function_imports']):,}")
    print(f"Unique Exported Functions : {len(imp_a['function_exports']):,}  ->  {len(imp_b['function_exports']):,}")

    la_bin, la_cnt = imp_a["largest_import_table"]
    lb_bin, lb_cnt = imp_b["largest_import_table"]
    print(f"\nLargest Import Table: {label_a}={la_cnt:,} ({la_bin})  |  {label_b}={lb_cnt:,} ({lb_bin})")

    ea_bin, ea_cnt = imp_a["largest_export_table"]
    eb_bin, eb_cnt = imp_b["largest_export_table"]
    print(f"Largest Export Table: {label_a}={ea_cnt:,} ({ea_bin})  |  {label_b}={eb_cnt:,} ({eb_bin})")

    print(f"\n=== DLL DEPENDENCIES DIFF ({label_a} -> {label_b}, top movers) ===")
    rows, added, removed = diff_dict(imp_a["library_import_dependencies"], imp_b["library_import_dependencies"], top_n=25)
    for k, va, vb, d in rows:
        print(f"{k:<50} {va:>8,}  ->  {vb:>8,}   delta: {d:+,}")
    if added:
        print(f"\nDLLs newly depended on in {label_b} (count={len(added)}): {added[:50]}")
    if removed:
        print(f"DLLs no longer depended on in {label_b} (count={len(removed)}): {removed[:50]}")

    print(f"\n=== DLL REFERENCES DIFF ({label_a} -> {label_b}, top movers) ===")
    rows, added, removed = diff_dict(imp_a["library_imports"], imp_b["library_imports"], top_n=25)
    for k, va, vb, d in rows:
        print(f"{k:<50} {va:>8,}  ->  {vb:>8,}   delta: {d:+,}")

    print(f"\n=== TOP IMPORTED FUNCTIONS DIFF ({label_a} -> {label_b}, top movers) ===")
    rows, added, removed = diff_dict(imp_a["function_imports"], imp_b["function_imports"], top_n=50)
    for k, va, vb, d in rows:
        print(f"{k:<40} {va:>8,}  ->  {vb:>8,}   delta: {d:+,}")

    print(f"\n=== TOP EXPORTED FUNCTIONS DIFF ({label_a} -> {label_b}, top movers) ===")
    rows, added, removed = diff_dict(imp_a["function_exports"], imp_b["function_exports"], top_n=50)
    for k, va, vb, d in rows:
        print(f"{k:<40} {va:>8,}  ->  {vb:>8,}   delta: {d:+,}")

    print(f"\n=== IMPORT PREFIX DIFF ({label_a} -> {label_b}) ===")
    for n in sorted(k for k in imp_a["import_prefix_counts"].keys() if isinstance(k, int)):
        print(f"\n--- {n}-char prefixes (top movers) ---")
        rows, added, removed = diff_dict(
            imp_a["import_prefix_counts"][n],
            imp_b["import_prefix_counts"][n],
            top_n=20
        )
        for k, va, vb, d in rows:
            print(f"{k:<10} {va:>10,}  ->  {vb:>10,}   delta: {d:+,}")
        if added:
            print(f"  New in {label_b}: {added}")
        if removed:
            print(f"  Absent in {label_b}: {removed}")

    excl_a = imp_a["import_prefix_counts"].get("_mangled_cpp_excluded", 0)
    excl_b = imp_b["import_prefix_counts"].get("_mangled_cpp_excluded", 0)
    print(f"\nMangled C++ names excluded: {label_a}={excl_a:,}  {label_b}={excl_b:,}  delta: {excl_b - excl_a:+,}")

    print(f"\n=== EXPORT PREFIX DIFF ({label_a} -> {label_b}) ===")
    for n in sorted(k for k in imp_a["export_prefix_counts"].keys() if isinstance(k, int)):
        print(f"\n--- {n}-char prefixes (top movers) ---")
        rows, added, removed = diff_dict(
            imp_a["export_prefix_counts"][n],
            imp_b["export_prefix_counts"][n],
            top_n=20
        )
        for k, va, vb, d in rows:
            print(f"{k:<10} {va:>10,}  ->  {vb:>10,}   delta: {d:+,}")
        if added:
            print(f"  New in {label_b}: {added}")
        if removed:
            print(f"  Absent in {label_b}: {removed}")

    excl_a = imp_a["export_prefix_counts"].get("_mangled_cpp_excluded", 0)
    excl_b = imp_b["export_prefix_counts"].get("_mangled_cpp_excluded", 0)
    print(f"\nMangled C++ names excluded: {label_a}={excl_a:,}  {label_b}={excl_b:,}  delta: {excl_b - excl_a:+,}")

    print(f"\n=== IMPORT SYSTEM PREFIX DIFF ({label_a} -> {label_b}) ===")
    rows, added, removed = diff_dict(
        imp_a["import_system_prefix_counts"],
        imp_b["import_system_prefix_counts"],
        top_n=len(WINDOWS_FUNCTION_PREFIXES) + 1,
    )

    for k, va, vb, d in rows:
        print(f"{k:<12} {va:>10,}  ->  {vb:>10,}   delta: {d:+,}")

    if added:
        print(f"\nNew in {label_b}: {added}")
    if removed:
        print(f"\nAbsent in {label_b}: {removed}")

    print(f"\n=== EXPORT SYSTEM PREFIX DIFF ({label_a} -> {label_b}) ===")
    rows, added, removed = diff_dict(
        imp_a["export_system_prefix_counts"],
        imp_b["export_system_prefix_counts"],
        top_n=len(WINDOWS_FUNCTION_PREFIXES) + 1,
    )

    for k, va, vb, d in rows:
        print(f"{k:<12} {va:>10,}  ->  {vb:>10,}   delta: {d:+,}")

    if added:
        print(f"\nNew in {label_b}: {added}")
    if removed:
        print(f"\nAbsent in {label_b}: {removed}")

    # ---------------- SECTION ANALYSIS ----------------
    print(f"\n=== SECTION ANALYSIS DIFF ({label_a} -> {label_b}) ===")
    total_a = sum(data_a["section_name_counts"].values())
    total_b = sum(data_b["section_name_counts"].values())
    print(f"Total sections scanned : {total_a:,}  ->  {total_b:,}   delta: {total_b - total_a:+,}")

    avg_a = (data_a["section_size_total"] / data_a["section_size_count"]) if data_a["section_size_count"] else 0
    avg_b = (data_b["section_size_total"] / data_b["section_size_count"]) if data_b["section_size_count"] else 0
    print(f"Average section size    : {avg_a:,.0f} bytes  ->  {avg_b:,.0f} bytes   delta: {avg_b - avg_a:+,.0f}")

    print("\n--- TOP SECTION NAMES DIFF (top movers) ---")
    rows, added, removed = diff_dict(data_a["section_name_counts"], data_b["section_name_counts"], top_n=30)
    for k, va, vb, d in rows:
        label_name = k if k else "(unnamed)"
        print(f"{label_name:<20} {va:>8,}  ->  {vb:>8,}   delta: {d:+,}")
    if added:
        print(f"\nSection names new in {label_b}: {added}")
    if removed:
        print(f"Section names absent in {label_b}: {removed}")

    print("\n--- SECTION PERMISSIONS DIFF ---")
    rows, added, removed = diff_dict(data_a["section_permission_counts"], data_b["section_permission_counts"], top_n=1000)
    for k, va, vb, d in rows:
        print(f"{k:<10} {va:>8,}  ->  {vb:>8,}   delta: {d:+,}")

    print("\n--- SECTION CONTENT TYPES DIFF ---")
    rows, added, removed = diff_dict(data_a["section_content_counts"], data_b["section_content_counts"], top_n=1000)
    for k, va, vb, d in rows:
        print(f"{k:<15} {va:>8,}  ->  {vb:>8,}   delta: {d:+,}")

    print("\n--- SECTION ALIGNMENTS DIFF ---")
    rows, added, removed = diff_dict(data_a["section_alignment_counts"], data_b["section_alignment_counts"], top_n=1000)
    for k, va, vb, d in rows:
        print(f"{k!s:<10} {va:>8,}  ->  {vb:>8,}   delta: {d:+,}")

    print("\n--- SIZE EXTREMES ---")
    la_name, la_size = data_a["section_examples"]["largest_section"]
    lb_name, lb_size = data_b["section_examples"]["largest_section"]
    print(f"Largest section: {label_a}={la_size:,}B ({la_name})  |  {label_b}={lb_size:,}B ({lb_name})")

    sa_name, sa_size = data_a["section_examples"]["smallest_nonzero_section"]
    sb_name, sb_size = data_b["section_examples"]["smallest_nonzero_section"]
    print(f"Smallest nonzero section: {label_a}={sa_size:,}B ({sa_name})  |  {label_b}={sb_size:,}B ({sb_name})")

    print(f"\n--- EXECUTE-ONLY (--x) SECTIONS DIFF ---")
    diff_example_set(label_a, label_b,
                      data_a["section_examples"]["execute_only_sections"],
                      data_b["section_examples"]["execute_only_sections"])

    print(f"\n--- RWX SECTIONS DIFF ---")
    diff_example_set(label_a, label_b,
                      data_a["section_examples"]["rwx_sections"],
                      data_b["section_examples"]["rwx_sections"])


def main():
    results = {}
    for version, build in CORPORA.items():
        root = get_root_dir(version, build)
        print(f"\n>>> Scanning corpus: {version} (build {build}) at {root}")
        results[version] = scan_and_analyze(root, version)

    for version, data in results.items():
        print_results(version, data)

    compare_corpora("win10", results["win10"], "win11", results["win11"])


if __name__ == "__main__":
    main()