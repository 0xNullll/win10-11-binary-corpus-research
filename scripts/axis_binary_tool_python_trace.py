"""
trace_function.py

Given a (module, function) pair, answers: "which binaries in the corpus
actually call this function, and where does it really live after
forwarder resolution?"

Algorithm (matches the design you described):
  1. Resolve the function's forward chain in export_index.json until we
     hit a terminal (non-forwarded) implementation, or run off the edge
     of the corpus (module not indexed -> unresolved-external).
  2. Use dll_dependencies.json's importedBy[terminal_module] as the
     candidate set -- this is the pruning step. We never scan binaries
     that don't already depend on the terminal module.
  3. For each candidate, re-open its own .meta.json import fragments
     (via binary_paths.json) and check whether it actually imports the
     terminal (module, function) pair -- by name OR by ordinal, since a
     binary can reference the same export either way.

Output is a flat dict designed to be consumed directly as graph
edges by the Dash tool: each confirmed candidate becomes one edge
{caller, module, function, binding, unresolved}.

Note on export_index.json keys: since a PE export always has an ordinal
and optionally a name, export_index.json stores each export once under
a canonical combined key ("o:N|n:name", "o:N", or "n:name" depending on
what the export actually has). Callers of this module look up by a
*simple* key ("n:foo" or "o:52") -- resolve_export_key() bridges that
gap by matching against either half of the combined key.

Usage:
    python trace_function.py KERNEL32.dll AcquireSRWLockExclusive
    python trace_function.py --ordinal ws2_32.dll 52
"""

import argparse
import json
from pathlib import Path

WINDOWS_VERSION = "win11"
WIN_BUILD = None
WIN_ARCH = "x64"

SCRIPT_DIR = Path(__file__).resolve().parent.parent

EXPORT_INDEX_FILE = "export_index.json"
MODULE_NAME_INDEX_FILE = "module_name_index.json"
BINARY_PATHS_FILE = "binary_paths.json"
DLL_IMPORTED_BY_FILE = "dll_imported_by.json"
DLL_VERSIONS_FILE = "dll_versions.json"

MAX_FORWARD_HOPS = 8


def set_windows_version(version: str):
    global WINDOWS_VERSION
    WINDOWS_VERSION = version
    set_windows_build()


def set_windows_build():
    global WIN_BUILD

    if WINDOWS_VERSION == "win11":
        WIN_BUILD = "10.0.26200"
    else:
        WIN_BUILD = "10.0.19045"

def get_data_dir():
    return (
        SCRIPT_DIR
        / "shared-output"
        / WINDOWS_VERSION
        / WIN_BUILD
        / WIN_ARCH
    )


def get_root_dir():
    return (
        SCRIPT_DIR
        / "axis-binary-output"
        / WINDOWS_VERSION
        / WIN_BUILD
        / WIN_ARCH
    )


def load_json(filename: str):
    with open(get_data_dir() / filename, "r", encoding="utf-8") as f:
        return json.load(f)

def normalize(name: str) -> str:
    return name.strip().lower()

def lowercase_extension_only(name: str) -> str:
    """
    Preserves the original casing of the stem ('name' part) but
    lowercases the extension. e.g. 'HAL.DLL' -> 'HAL.dll',
    'RTKVHD64.SYS' -> 'RTKVHD64.sys'. If there's no extension,
    returns the name unchanged.

    DISPLAY ONLY. Never use this for identity/equality checks --
    module name comparisons must use a full case-fold (normalize()),
    since the loader treats DLL names as fully case-insensitive,
    stem included.
    """
    name = name.strip()
    if "." not in name:
        return name
    stem, _, ext = name.rpartition(".")
    return f"{stem}.{ext.lower()}"

def module_name_only(path: str) -> str:
    """
    Extracts the bare module filename from either a full path or an
    already-bare module name, then fully normalizes it for identity
    comparisons.

    Examples:
        'C:\\Windows\\System32\\KERNELBASE.DLL' -> 'kernelbase.dll'
        'C:/Windows/System32/kernelbase.dll'    -> 'kernelbase.dll'
        'kernelbase.dll'                        -> 'kernelbase.dll'
    """
    path = path.strip().replace("\\", "/")
    return normalize(path.rsplit("/", 1)[-1])

def parse_ordinal(symbol: str) -> int | None:
    symbol = symbol.strip().lower()

    try:
        # 0x prefix -> hex
        if symbol.startswith("0x"):
            return int(symbol, 16)

        # MASM-style hex suffix (e.g. 1Ah, ffh)
        if symbol.endswith("h") and len(symbol) > 1:
            return int(symbol[:-1], 16)

        # pure decimal
        if symbol.isdigit():
            return int(symbol)

        # fallback: hex (e.g. "1a")
        return int(symbol, 16)

    except ValueError:
        return None

def name_key(name: str) -> str:
    return "n:" + normalize(name)


def ordinal_key(ordinal) -> str:
    return "o:" + str(ordinal)


def resolve_export_key(table: dict, query_key: str):
    """
    table is keyed by canonical combined form: 'o:N|n:name', 'o:N', or
    'n:name'. query_key is a simple form: 'o:N' or 'n:name' (what a
    caller or forwarder symbol resolves to). Find the canonical key
    whose ordinal or name component matches the query, since a query
    for either identity should resolve to the same underlying export.
    """
    if query_key in table:
        return query_key

    for canonical_key in table:
        parts = canonical_key.split("|")
        if query_key in parts:
            return canonical_key

    return None

class TraceResult:
    def __init__(self):
        self.chain = []          # list of {module, key, record} -- module is a bkey (full path)
        self.terminal_module = None
        self.terminal_key = None
        self.status = None       # "resolved" | "unresolved-external" | "cycle"


def resolve_module_candidates(module_name_index: dict, module: str) -> list[str]:
    """
    Bare module name (e.g. 'KERNELBASE.dll') -> list of physical bkeys.
    Accepts either a bare DLL name or a full path.
    """
    key = module_name_only(module)
    return module_name_index.get(key, [])

def _resolve_chain_for_bkey(export_index: dict, module_name_index: dict,
                             bkey: str, key: str) -> TraceResult:
    """
    Walks the forward chain starting from one specific physical binary
    (bkey), which is a full lowercased path directly usable as an
    export_index key. Forward hops resolve the forwarder's bare library
    name back through module_name_index to get the next bkey.
    """
    result = TraceResult()
    visited = set()

    for _ in range(MAX_FORWARD_HOPS):

        if (bkey, key) in visited:
            result.status = "cycle"
            if result.chain:
                last = result.chain[-1]
                result.terminal_module = last["module"]
                result.terminal_key = last["key"]
            else:
                result.terminal_module = bkey
                result.terminal_key = key
            return result

        visited.add((bkey, key))

        table = export_index.get(bkey)

        if table is None:
            result.status = "unresolved-external"
            result.terminal_module = bkey
            result.terminal_key = key
            return result

        resolved_key = resolve_export_key(table, key)
        record = table.get(resolved_key) if resolved_key else None

        if record is None:
            result.status = "unresolved-external"
            result.terminal_module = bkey
            result.terminal_key = key
            return result

        result.chain.append({
            "module": bkey,
            "key": resolved_key,
            "record": record
        })

        forward = record.get("forward")

        if not forward:
            result.status = "resolved"
            result.terminal_module = bkey
            result.terminal_key = resolved_key
            return result

        next_candidates = resolve_module_candidates(module_name_index, forward["library"])

        if not next_candidates:
            # Could not continue resolving the forward chain.
            # Keep the forward target as the terminal information.
            result.status = "unresolved-external"

            result.terminal_module = normalize(forward["library"])
            result.terminal_key = (
                name_key(forward["symbol"])
                if forward.get("symbol")
                else resolved_key
            )

            # Preserve what caused the failure
            result.chain.append({
                "module": result.terminal_module,
                "key": result.terminal_key,
                "record": {
                    "forward": None,
                    "unresolved_target": True
                }
            })

            return result

        # Forwarders normally stay within the same arch family as the
        # forwarding binary. Picking the candidate matching bkey's own
        # directory (system32 vs syswow64) avoids silently crossing
        # architectures; fall back to the first candidate otherwise.
        same_arch = [c for c in next_candidates if _bitness_bucket(c) == _bitness_bucket(bkey)]
        bkey = same_arch[0] if same_arch else next_candidates[0]
        key = name_key(forward["symbol"]) if forward.get("symbol") else resolved_key

    result.status = "cycle"
    if result.chain:
        last = result.chain[-1]
        result.terminal_module = last["module"]
        result.terminal_key = last["key"]
    else:
        result.terminal_module = bkey
        result.terminal_key = key
    return result


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


def _bitness_bucket(path_str: str) -> str:
    """
    Coarser bucket than detect_arch_context, specifically for
    same-arch forwarder preference: collapses all the WoW64-adjacent
    tags (syswow64, wow64_drivers, wow64_downlevel, wow64_wbem) into
    one 'wow64' bucket vs everything else, since what matters for
    forward-chain resolution is "does this stay in the same bitness
    as the forwarding binary", not the full directory taxonomy.
    """
    tag = detect_arch_context(path_str)
    if tag.startswith("wow64_") or tag == "syswow64":
        return "wow64"
    return "native"


def resolve_forward_chain(export_index: dict, module_name_index: dict,
                           module: str, key: str) -> list[TraceResult]:
    """
    Resolves a bare module name to its physical candidate(s) via
    module_name_index, then walks the forward chain independently for
    each candidate. Returns one TraceResult per physical binary that
    implements `module` (typically 1-2: System32 and SysWOW64 copies).
    """
    candidates = resolve_module_candidates(module_name_index, module)

    if not candidates:
        r = TraceResult()
        r.status = "unresolved-external"
        r.terminal_module = lowercase_extension_only(module)
        r.terminal_key = key
        return [r]

    return [
        _resolve_chain_for_bkey(export_index, module_name_index, bkey, key)
        for bkey in candidates
    ]


def find_binary_import_match(meta_path: str, terminal_module: str, terminal_record: dict):
    """
    Opens one candidate binary's own meta file, walks its import
    fragments, and checks whether it references the terminal
    (module, function) pair by name or ordinal. Returns the matching
    import entry, or None.

    terminal_module is a bkey (full lowercased path) -- import
    descriptors only carry the bare filename, so we compare against
    just that component, strictly case-folded.
    """
    root_dir = Path(meta_path).resolve().parent
    while root_dir.name != "axis-binary-output/win11" and root_dir.parent != root_dir:
        root_dir = root_dir.parent

    meta = load_json(Path(meta_path))
    tables = meta.get("tables", {})
    imports = tables.get("imports", {})

    target_module_name = normalize(terminal_module)
    target_name = terminal_record.get("name")
    target_ordinal = terminal_record.get("ordinal")

    for fragment_name in imports.get("files", []):
        fragment_path = get_root_dir() / fragment_name
        # print(fragment_path)
        try:
            fragment = load_json(fragment_path)
        except Exception:
            continue
        if not fragment:
            continue

        for entry in fragment.get("entries", []):
            lib = entry.get("library")
            if not lib or normalize(lib) != target_module_name:
                continue

            if target_name and entry.get("name") and \
                    normalize(entry["name"]) == normalize(target_name):
                return entry

            if target_ordinal is not None and entry.get("ordinal") == target_ordinal:
                return entry

    return None


def trace_function(module: str, function=None, ordinal=None, windows_version=None,
                    export_index=None, module_name_index=None,
                    binary_paths=None, dll_imported_by=None, dll_versions=None):
    if windows_version is not None:
        set_windows_version(windows_version)

    set_windows_build()

    if export_index is None:
        export_index = load_json(EXPORT_INDEX_FILE)

    if module_name_index is None:
        module_name_index = load_json(MODULE_NAME_INDEX_FILE)

    if binary_paths is None:
        binary_paths = load_json(BINARY_PATHS_FILE)

    if dll_imported_by is None:
        dll_imported_by = load_json(DLL_IMPORTED_BY_FILE)

    if dll_versions is None:
        dll_versions = load_json(DLL_VERSIONS_FILE)
        dll_versions = {
            lowercase_extension_only(k): v
            for k, v in dll_versions.items()
        }

    if ordinal is not None:
        parsed_ordinal = parse_ordinal(ordinal)
        if parsed_ordinal is None:
            return {
                "query": {"module": module, "function": function, "ordinal": ordinal},
                "status": "invalid-ordinal",
                "error": f"Invalid ordinal: {ordinal!r}",
                "chain": [],
                "terminal_module": None,
                "terminal_version": None,
                "callers": [],
            }

        start_key = ordinal_key(parsed_ordinal)
    else:
        start_key = name_key(function)

    # One logical DLL name may resolve to multiple physical binaries
    # (System32, SysWOW64, WinSxS, etc.), each with its own forward chain.
    # Trace every candidate independently instead of assuming a 1:1 mapping
    # between DLL name and implementation.
    traces = resolve_forward_chain(export_index, module_name_index, module, start_key)

    if "\\" in module or "/" in module:
        traces = [
            trace
            for trace in traces
            if trace.chain
            and normalize(trace.chain[0]["module"]) == normalize(module)
        ]

    output = {
        "query": {"module": module, "function": function, "ordinal": ordinal},
        "results": [],
    }

    for trace in traces:

        # Version metadata is keyed by bare DLL name, whereas the forward
        # chain records physical binary paths. Normalize before lookup.
        for hop in trace.chain:
            hop["version"] = dll_versions.get(
                lowercase_extension_only(hop["module"])
            )

        result = {
            "status": trace.status,
            "chain": trace.chain,
            "terminal_module": trace.terminal_module,
            "terminal_version": (
                dll_versions.get(lowercase_extension_only(trace.terminal_module))
                if trace.terminal_module
                else None
            ),
            "callers": [],
        }

        if trace.status == "resolved":

            seen_callers = set()

            # Check EVERY hop in the chain, not just the terminal -- a caller may
            # have imported the function at any point along the forward chain
            # (most commonly the first hop, the public/stable name), and would
            # never reference the terminal implementation module/name directly.
            # e.g. kernel32.dll!AcquireSRWLockExclusive forwards to
            # ntdll.dll!RtlAcquireSRWLockExclusive -- a caller that imports the
            # kernel32 name would never show up if we only checked the ntdll hop.
            for hop in trace.chain:

                # Forward-chain resolution stores physical paths as modules,
                # while dependency lookups are keyed by bare DLL name.
                hop_module = module_name_only(hop["module"])
                hop_record = hop["record"]

                dep_entry = dll_imported_by.get(hop_module)

                if dep_entry is None:
                    continue

                # Determine which physical implementation of this DLL this trace
                # resolved to (e.g. System32 x64 vs SysWOW64 x86). Caller binaries
                # should only be matched against the same architecture.
                hop_arch = None

                for candidate in dep_entry.get("candidatePaths", []):
                    if normalize(candidate["path"]) == normalize(hop["module"]):
                        hop_arch = candidate["arch"]
                        break

                candidates = dep_entry.get("importedByPaths", [])

                for caller_display_name in candidates:
                    caller_arch = (
                        "x86"
                        if _bitness_bucket(caller_display_name) == "wow64"
                        else "x86_64"
                    )

                    if hop_arch is not None and caller_arch != hop_arch:
                        continue

                    meta_path = binary_paths.get(caller_display_name)

                    if meta_path is None:
                        continue

                    if caller_display_name in seen_callers:
                        continue

                    match = find_binary_import_match(
                        meta_path,
                        hop_module,
                        hop_record,
                    )

                    if not match:
                        continue

                    seen_callers.add(caller_display_name)

                    result["callers"].append({
                        "caller": caller_display_name,
                        "version": dll_versions.get(
                            lowercase_extension_only(caller_display_name)
                        ),
                        # Preserve the physical binary that satisfied the match
                        # even though the lookup itself used the normalized name.
                        "matched_at": hop["module"],
                        "matched_symbol": (
                            hop_record.get("name")
                            or f"ord{hop_record.get('ordinal')}"
                        ),
                        "binding": match.get("binding"),
                        "address": match.get("address"),
                        "state": match.get("state"),
                    })

            if not result["callers"]:
                result["status"] = "resolved-but-not-in-dependency-graph"

        output["results"].append(result)

    return output

def find_exporting_modules(export_index: dict, function_name: str):
    """
    Returns every module exporting the given function. export_index
    stores exports under canonical combined keys, so a simple name
    key won't directly hit -- resolve it per-module the same way
    resolve_forward_chain does.
    """
    key = name_key(function_name)

    matches = []

    for module, exports in export_index.items():
        resolved_key = resolve_export_key(exports, key)
        if resolved_key is None:
            continue
        record = exports.get(resolved_key)
        if record is not None:
            matches.append({
                "module": module,
                "record": record,
            })

    return matches


def deep_trace_function(function_name: str, windows_version=None):
    if windows_version is not None:
        set_windows_version(windows_version)
    set_windows_build()

    export_index = load_json(EXPORT_INDEX_FILE)
    module_name_index = load_json(MODULE_NAME_INDEX_FILE)
    binary_paths = load_json(BINARY_PATHS_FILE)
    dll_imported_by = load_json(DLL_IMPORTED_BY_FILE)
    dll_versions = load_json(DLL_VERSIONS_FILE)
    dll_versions = {lowercase_extension_only(k): v for k, v in dll_versions.items()}

    exports = find_exporting_modules(export_index, function_name)

    if not exports:
        return {
            "query": function_name,
            "status": "not-found",
            "matches": []
        }

    results = []

    for export in exports:
        results.append(trace_function(
            export["module"], function=function_name,
            export_index=export_index, module_name_index=module_name_index,
            binary_paths=binary_paths, dll_imported_by=dll_imported_by,
            dll_versions=dll_versions,
        ))

    return {
        "query": function_name,
        "status": "ok",
        "export_count": len(exports),
        "matches": results,
    }

def main():
    parser = argparse.ArgumentParser(
        description="Trace a function across the corpus."
    )

    parser.add_argument(
        "args",
        nargs="+",
        help="Either <dll> <function> or just <function> for deep lookup."
    )

    parser.add_argument(
        "--ordinal",
        action="store_true",
        help="Treat the symbol as an ordinal."
    )

    parser.add_argument(
        "--deep",
        action="store_true",
        help="Search every exporting DLL automatically."
    )

    parser.add_argument(
        "-w", "--windows",
        choices=["win10", "win11"],
        default=WINDOWS_VERSION,
        help="Select the Windows dataset to use (default: %(default)s)."
    )

    args = parser.parse_args()

    # Select database
    set_windows_version(args.windows)
    set_windows_build()

    # Deep lookup:
    #   trace_function.py --deep CreateFileW
    if args.deep:

        if len(args.args) != 1:
            parser.error("--deep expects exactly one function name.")

        if args.ordinal:
            parser.error(
                "Deep lookup by ordinal is not supported because ordinals are DLL-specific."
            )

        result = deep_trace_function(args.args[0])

    # Traditional lookup:
    #   trace_function.py kernel32.dll CreateFileW
    #   trace_function.py ws2_32.dll 52 --ordinal
    elif len(args.args) == 2:

        module, symbol = args.args

        if args.ordinal:
            result = trace_function(module=module, ordinal=symbol)
        else:
            result = trace_function(module=module, function=symbol)

    else:
        parser.error(
            "Expected either:\n"
            "  trace_function.py <dll> <function>\n"
            "or\n"
            "  trace_function.py --deep <function>"
        )

    print(json.dumps(result, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()