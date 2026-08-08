from collections import defaultdict, deque
import networkx as nx
import plotly.graph_objects as go
import numpy as np
import json

from dash import Dash, dcc, html
from dash import Input, Output, State
import dash_bootstrap_components as dbc

from pathlib import Path

from axis_binary_tool_python_trace import (
    trace_function,
    deep_trace_function
)

WIN_ARCH = "x64"

SCRIPT_DIR = Path(__file__).resolve().parent.parent

def get_windows_build(windows_version):
    if windows_version == "win11":
        return "10.0.26200"
    else:
        return "10.0.19045"


def load_version_map(windows_version):
    win_build = get_windows_build(windows_version)

    output_dir = (
        SCRIPT_DIR
        / "shared-output"
        / windows_version
        / win_build
        / WIN_ARCH
    )

    with open(output_dir / "dll_versions.json", "r", encoding="utf-8") as f:
        version_map = json.load(f)

    return {
        k.lower(): v
        for k, v in version_map.items()
    }

# ---------------- APP ----------------
import dash_bootstrap_components as dbc
app = Dash(__name__, external_stylesheets=[dbc.themes.LUMEN])

app.layout = html.Div([

    html.H2("Function Trace Explorer"),

    # ---------------- Search row ----------------
    html.Div([

        dcc.Input(
            id="dll-input",
            placeholder="DLL (optional for deep lookup)",
            debounce=True,
            style={"width": "250px"},
        ),

        dcc.Input(
            id="function-input",
            placeholder="Function (required)... (Press Enter)",
            debounce=True,
            style={"width": "300px"},
        ),

        html.Div(

            [

                dcc.RadioItems(
                    id="lookup-mode",
                    options=[
                        {"label": "Name", "value": "name"},
                        {"label": "Ordinal", "value": "ordinal"},
                    ],
                    value="name",
                    labelStyle={
                        "display": "block",
                        "marginBottom": "5px",
                    },
                ),

                dcc.RadioItems(
                    id="layout-mode",
                    options=[
                        {"label": "Radial (fixed)", "value": "radial"},
                        {"label": "Spring (force-directed)", "value": "spring"},
                    ],
                    value="radial",
                    labelStyle={
                        "display": "block",
                        "marginBottom": "5px",
                    },
                ),

            dcc.RadioItems(
                    id="windows-version",
                    options=[
                        {"label": "Windows 10", "value": "win10"},
                        {"label": "Windows 11", "value": "win11"},
                    ],
                    value="win11",
                    labelStyle={
                        "display": "block",
                        "marginBottom": "5px",
                    },
                ),

            ],

            style={
                "display": "flex",
                "alignItems": "flex-start",
                "gap": "30px",
            },

        )

    ], style={
        "display": "flex",
        "alignItems": "center",
        "gap": "20px",
        "marginBottom": "12px",
    }),

    # ---------------- Legend row ----------------
    html.Div([

        html.Span([
            html.Span(style={
                "display": "inline-block",
                "width": "10px",
                "height": "10px",
                "borderRadius": "50%",
                "backgroundColor": "black",
                "marginRight": "5px",
            }),
            "Query",
        ], style={
            "display": "flex",
            "alignItems": "center",
            "marginRight": "15px",
        }),

        html.Span([
            html.Span(style={
                "display": "inline-block",
                "width": "10px",
                "height": "10px",
                "borderRadius": "50%",
                "backgroundColor": "#2E86DE",
                "marginRight": "5px",
            }),
            "Implementation",
        ], style={
            "display": "flex",
            "alignItems": "center",
            "marginRight": "15px",
        }),

        html.Span([
            html.Span(style={
                "display": "inline-block",
                "width": "10px",
                "height": "10px",
                "borderRadius": "50%",
                "backgroundColor": "#F39C12",
                "marginRight": "5px",
            }),
            "Forwarder",
        ], style={
            "display": "flex",
            "alignItems": "center",
            "marginRight": "15px",
        }),

        html.Span([
            html.Span(style={
                "display": "inline-block",
                "width": "10px",
                "height": "10px",
                "borderRadius": "50%",
                "backgroundColor": "#27AE60",
                "marginRight": "5px",
            }),
            "Caller",
        ], style={
            "display": "flex",
            "alignItems": "center",
            "marginRight": "15px",
        }),

        html.Span([
            html.Span(style={
                "display": "inline-block",
                "width": "10px",
                "height": "10px",
                "borderRadius": "50%",
                "backgroundColor": "#95A5A6",
                "marginRight": "5px",
            }),
            "Unresolved / Cycle",
        ], style={
            "display": "flex",
            "alignItems": "center",
        }),

    ],
    
    style={
        "display": "flex",
        "alignItems": "center",
        "fontSize": "13px",
        "color": "#555",
        "marginBottom": "15px",
    }),

    html.Div(
        id="current-trace-display",
        style={
            "marginTop": "10px",
            "fontWeight": "bold"
        }
    ),

    html.Div(
        id="info-panel",
        style={
            "padding": "15px",
            "border": "1px solid lightgray",
            "borderRadius": "5px",
            "marginBottom": "20px",
            "maxHeight": "250px",
            "overflowY": "auto",
        },
    ),

    html.Div(
        dcc.Checklist(
            id="short-labels",
            options=[
                {"label": "Short labels", "value": "short"},
            ],
            value=[],
        ),
        style={
            "display": "inline-block",
            "border": "1px solid lightgray",
            "padding": "6px 10px",
            "borderRadius": "4px",
        },
    ),

    dcc.Graph(
        id="graph",
        style={
            "height": "900px"
        }
    )

])

def append_trace(trace, parent, nodes, edges, seen_edges=None):
    if seen_edges is None:
        seen_edges = set()

    def add_edge(a, b):
        key = (a, b)
        if key not in seen_edges:
            seen_edges.add(key)
            edges.append(key)

    chain = trace.get("chain", [])
    previous = parent
    implementation = None

    for hop in chain:
        module = hop.get("module", "unknown")
        record = hop.get("record", {})

        has_name = (
            record.get("hasName")
            and record.get("name")
        )

        ordinal = record.get("ordinal")

        if has_name:
            identity = record["name"]
            label = f"{module}\n{record['name']}"

            if ordinal is not None:
                label += f" (ord {ordinal})"

        elif ordinal is not None:
            identity = f"ord{ordinal}"
            label = f"{module}\nordinal {ordinal}"

        else:
            # unresolved import with no ordinal/name
            identity = "unresolved"
            label = f"{module}\nunresolved"

        node_id = f"{module}:{identity}"

        if record.get("forward"):
            kind = "forwarder"
        elif ordinal is None and not has_name:
            kind = "unresolved"
        else:
            kind = "implementation"

        if kind == "implementation":
            implementation = node_id

        if node_id not in nodes:
            nodes[node_id] = {
                "kind": kind,
                "module": module,
                "record": record,
                "label": label,
            }

        add_edge(previous, node_id)
        previous = node_id

    # No real implementation found
    if implementation is None and chain:
        implementation = previous

        if implementation in nodes:
            nodes[implementation]["kind"] = "unresolved"

    if implementation is None:
        return

    for caller in trace.get("callers", []):
        caller_name = caller["caller"]
        caller_id = f"caller:{caller_name}"

        if caller_id not in nodes:
            nodes[caller_id] = {
                "kind": "caller",
                "label": caller_name,
                "caller": caller,
            }

        add_edge(implementation, caller_id)

def build_graph(trace):
    nodes = {}
    edges = []
    seen_edges = set()

    def add_node(node_id, **attrs):
        if node_id not in nodes:
            nodes[node_id] = attrs

    if "matches" in trace:
        query = trace["query"]
        query_id = f"query:{query}"
        add_node(query_id, kind="query", label=query)

        for match in trace["matches"]:
            for result in match.get("results", []):
                append_trace(result, query_id, nodes, edges, seen_edges)

    else:
        # query = trace["query"]["function"]
        query = (
            trace["query"]["function"]
            or f"ordinal {trace['query']['ordinal']}"
        )
        query_id = f"query:{query}"
        add_node(query_id, kind="query", label=query)

        for result in trace.get("results", []):
            append_trace(result, query_id, nodes, edges, seen_edges)

    return nodes, edges

class InvalidOrdinalError(Exception):
    """Raised when an ordinal string is invalid."""
    pass

def build_radial_trace_figure(nodes: dict, edges: list, short_labels=False) -> go.Figure:

    query_id = None
    for node_id, node in nodes.items():
        if node["kind"] == "query":
            query_id = node_id
            break

    if query_id is None:
        return go.Figure()

    edge_map = {}
    reverse_map = {}
    for a, b in edges:
        edge_map.setdefault(a, []).append(b)
        reverse_map.setdefault(b, []).append(a)

    implementations = [
        node_id for node_id, node in nodes.items()
        if node["kind"] in ("implementation", "unresolved")
    ]
    if not implementations:
        return go.Figure()

    node_x, node_y = [], []
    labels = []          # always-visible text (empty string = no permanent label)
    hover_text = []      # full label, shown on hover regardless
    custom = []
    node_colors = []
    edge_x, edge_y = [], []
    positions = {}
    placed = set()
    visited = {query_id}

    ALWAYS_LABEL_KINDS = {
        "query",
        "implementation",
        "forwarder",
        "caller",
        "unresolved",
    }

    def fan_angles(count, center, span):
        if count <= 0:
            return []
        return [center - span + ((i + 0.5) / count) * (2 * span) for i in range(count)]

    def color_for_kind(kind):
        return {
            "implementation": "#2E86DE",
            "forwarder": "#F39C12",
            "caller": "#27AE60",
            "query": "black",
        }.get(kind, "#95A5A6")

    def place_node(node_id, x, y):
        if node_id in placed:
            return positions[node_id]
        positions[node_id] = (x, y)
        node_x.append(x)
        node_y.append(y)

        full_label = nodes[node_id]["label"]

        if short_labels:
            parts = full_label.split("\n", 1)

            if len(parts) == 2:
                module, rest = parts
                module = module.split("\\")[-1].split("/")[-1]
                display_label = f"{module}\n{rest}"
            else:
                display_label = full_label.split("\\")[-1].split("/")[-1]
        else:
            display_label = full_label

        labels.append(display_label if nodes[node_id]["kind"] in ALWAYS_LABEL_KINDS else "")
        hover_text.append(full_label)

        # label = nodes[node_id]["label"]
        # labels.append(label if nodes[node_id]["kind"] in ALWAYS_LABEL_KINDS else "")
        # hover_text.append(label)
        custom.append(node_id)
        node_colors.append(color_for_kind(nodes[node_id]["kind"]))
        placed.add(node_id)
        return (x, y)

    # ---------------------------------------------------------
    # Iterative BFS placement — replaces recursion entirely.
    # Queue items: (node_id, x, y, angle, spread, radius, direction, depth)
    # ---------------------------------------------------------

    RADIUS_DECAY = 0.82
    SPREAD_DECAY = 0.88

    def place_all(start_id, sx, sy, base_angle, spread, radius, direction, allowed_kinds):
        queue = deque([(start_id, sx, sy, base_angle, spread, radius, 0)])

        while queue:
            current_id, cx, cy, angle_c, sp, rad, depth = queue.popleft()

            neighbors = edge_map.get(current_id, []) if direction == "forward" \
                else reverse_map.get(current_id, [])

            children = [
                n for n in neighbors
                if n not in visited and (allowed_kinds is None or nodes[n]["kind"] in allowed_kinds)
            ]
            if not children:
                continue

            for n in children:
                visited.add(n)

            angles = fan_angles(len(children), angle_c, sp)

            for child_id, angle in zip(children, angles):
                x = cx + rad * np.cos(angle)
                y = cy + rad * np.sin(angle)
                x, y = place_node(child_id, x, y)

                if direction == "forward":
                    edge_x.extend([cx, x, None])
                    edge_y.extend([cy, y, None])
                else:
                    edge_x.extend([x, cx, None])
                    edge_y.extend([y, cy, None])

                queue.append((
                    child_id, x, y, angle,
                    sp * SPREAD_DECAY, rad * RADIUS_DECAY,
                    depth + 1,
                ))

    # ---------------------------------------------------------
    # Query node
    # ---------------------------------------------------------

    place_node(query_id, 0, 0)

    # ---------------------------------------------------------
    # Implementation row
    # ---------------------------------------------------------

    spacing = 6.0
    start_x = -(len(implementations) - 1) * spacing / 2
    branch_radius = 1.8

    for index, impl in enumerate(implementations):
        impl_x = start_x + index * spacing
        impl_y = -2
        impl_x, impl_y = place_node(impl, impl_x, impl_y)
        visited.add(impl)

        edge_x.extend([0, impl_x, None])
        edge_y.extend([0, impl_y, None])

        place_all(
            impl, impl_x, impl_y,
            base_angle=np.pi / 2, spread=np.pi / 2, radius=branch_radius,
            direction="backward", allowed_kinds={"forwarder"},
        )
        place_all(
            impl, impl_x, impl_y,
            base_angle=-np.pi / 2, spread=np.pi / 2, radius=branch_radius,
            direction="forward", allowed_kinds={"caller"},
        )

    # ---------------------------------------------------------
    # Traces — Scattergl, and text only for query/implementation.
    # Everything else labels on hover only, to keep per-frame
    # paint cost flat regardless of node count.
    # ---------------------------------------------------------

    edge_trace = go.Scatter(
        x=edge_x,
        y=edge_y,
        mode="lines",
        line=dict(
            width=1,
            color="rgba(120,120,120,0.4)",
        ),
        hoverinfo="none",
    )

    node_trace = go.Scatter(
        x=node_x,
        y=node_y,
        mode="markers+text",
        text=labels,
        hovertext=hover_text,
        customdata=custom,
        textposition="top center",
        hoverinfo="text",
        marker=dict(
            size=12,
            color=node_colors,
            line=dict(width=1, color="white"),
        ),
    )

    fig = go.Figure(data=[edge_trace, node_trace])
    fig.update_layout(
        title="Function Trace (Radial Layout)",
        showlegend=False,
        xaxis=dict(visible=False),
        yaxis=dict(visible=False),
        margin=dict(l=20, r=20, t=40, b=20),
    )
    return fig

@app.callback(
    Output("graph", "figure"),
    Output("info-panel", "children"),
    Output("current-trace-display", "children"),

    Input("function-input", "n_submit"),
    Input("layout-mode", "value"),
    Input("short-labels", "value"),
    Input("windows-version", "value"),

    State("function-input", "value"),
    State("dll-input", "value"),
    State("lookup-mode", "value"),

    prevent_initial_call=True,
)
def perform_trace(n_submit, layout_mode, short_labels, windows_version, function, dll, mode):

    version_map = load_version_map(windows_version)

    def fail(message):
        return (
            go.Figure(),
            html.Div(message),
            "",
        )

    if not function:
        return fail("Function is required.")

    if dll:

        if mode == "ordinal":

            try:
                trace = trace_function(module=dll, ordinal=function, windows_version=windows_version)

            except InvalidOrdinalError as e:
                trace = {
                    "results": [],
                    "error": str(e)
                }

            if not any(result.get("chain") for result in trace.get("results", [])):
                return fail("Function not found.")

        else:

            trace = trace_function(
                module=dll,
                function=function,
                windows_version=windows_version
            )

            if not any(result.get("chain") for result in trace.get("results", [])):
                return fail("Function not found.")

    else:

        if mode == "ordinal":
            return fail("Deep ordinal lookup is unsupported.")

        trace = deep_trace_function(function, windows_version=windows_version)

        if "matches" in trace:
            if not trace["matches"]:
                return fail("Function not found.")
        else:
            if not any(result.get("chain") for result in trace.get("results", [])):
                return fail("Function not found.")

    nodes, edges = build_graph(trace)

    # ---------------- RENDER ----------------

    if layout_mode == "spring":

        G = nx.DiGraph()

        # ---------------- BUILD GRAPH ----------------

        for node_id in nodes:
            G.add_node(node_id)

        for source, target in edges:
            G.add_edge(source, target)

        # ---------------- LAYOUT ----------------

        pos = nx.spring_layout(
            G,
            seed=42,
            k=1.4,
            iterations=100
        )

        edge_x = []
        edge_y = []

        for source, target in G.edges():

            x0, y0 = pos[source]
            x1, y1 = pos[target]

            edge_x.extend([x0, x1, None])
            edge_y.extend([y0, y1, None])

        node_x = []
        node_y = []

        labels = []
        hover_text = []
        custom = []

        colors = []

        for node in G.nodes():

            x, y = pos[node]

            node_x.append(x)
            node_y.append(y)

            data = nodes[node]

            full_label = data.get("label", node)

            if short_labels:
                display_label = "\n".join(
                    [full_label.split("\n", 1)[0].split("\\")[-1].split("/")[-1]]
                    + full_label.split("\n")[1:]
                )
            else:
                display_label = full_label

            labels.append(display_label)
            hover_text.append(full_label)
            custom.append(node)

            kind = data.get("kind")

            if kind == "query":
                colors.append("black")

            elif kind == "implementation":
                colors.append("#2E86DE")      # blue

            elif kind == "forwarder":
                colors.append("#F39C12")      # orange

            elif kind == "caller":
                colors.append("#27AE60")      # green

            else:
                colors.append("gray")

        # ---------------- EDGE TRACE ----------------

        edge_trace = go.Scatter(

            x=edge_x,
            y=edge_y,

            mode="lines",

            line=dict(
                width=1,
                color="rgba(120,120,120,.35)"
            ),

            hoverinfo="none"

        )

        # ---------------- NODE TRACE ----------------

        node_trace = go.Scatter(

            x=node_x,
            y=node_y,

            mode="markers+text",

            text=labels,
            hovertext=hover_text,

            textposition="top center",

            customdata=custom,

            hoverinfo="text",

            marker=dict(

                size=14,

                color=colors,

                line=dict(
                    width=1,
                    color="white"
                )

            )

        )

        fig = go.Figure(
            data=[
                edge_trace,
                node_trace
            ]
        )

        fig.update_layout(

            title="Function Trace (Spring Layout)",

            showlegend=False,

            xaxis=dict(
                visible=False
            ),

            yaxis=dict(
                visible=False
            ),

            margin=dict(
                l=20,
                r=20,
                t=40,
                b=20
            )

        )

    else:

        # was: an inline `def build_radial_trace_figure(...)` that was
        # never invoked, leaving `fig` unassigned. Now uses the
        # module-level version and actually calls it.
        fig = build_radial_trace_figure(
            nodes,
            edges,
            short_labels=("short" in short_labels),
        )

    # ---------------- INFO PANEL ----------------

    implementation_count = sum(
        1 for n in nodes.values()
        if n["kind"] == "implementation"
    )

    forwarder_count = sum(
        1 for n in nodes.values()
        if n["kind"] == "forwarder"
    )

    caller_count = sum(
        1 for n in nodes.values()
        if n["kind"] == "caller"
    )

    unresolved_count = sum(
        1 for n in nodes.values()
        if n["kind"] == "unresolved"
    )

    impl_by_version = defaultdict(list)
    caller_by_version = defaultdict(list)
    unresolved_by_version = defaultdict(list)

    for node in nodes.values():
        # ---------------- IMPLEMENTATIONS --------------------
        if node["kind"] == "implementation":

            module = node["module"]
            version = version_map.get(module.lower(), "Unknown")

            display = node.get("label", module).replace("\n", "  ")
            impl_by_version[version].append(display)

        # ---------------- IMPORTING / CALLERS ----------------
        elif node["kind"] == "caller":

            # CASE 1: direct caller string
            caller_name = None

            if isinstance(node.get("caller"), str):
                caller_name = node["caller"]

            # CASE 2: dict form (sometimes nested)
            elif isinstance(node.get("caller"), dict):
                caller_name = node["caller"].get("caller") or node["caller"].get("module")

            # fallback safety
            if caller_name:
                version = version_map.get(caller_name.lower(), "Unknown")
                caller_by_version[version].append(caller_name)


        # ---------------- FORWARD / CHAIN IMPORTS  -----------
        elif node["kind"] == "forwarder":

            module = node.get("module")

            if module:
                version = version_map.get(module.lower(), "Unknown")
                caller_by_version[version].append(module)


        # ---------------- UNRESOLVED / CYCLE TERMINALS -------
        elif node["kind"] == "unresolved":

            module = node.get("module")

            if module:
                version = version_map.get(module.lower(), "Unknown")
                unresolved_by_version[version].append(module)

    info_panel = html.Div([
        html.H2(function),

        html.Hr(),

        html.H3("Statistics"),
        html.Ul([
            html.Li(f"Implementation DLLs: {implementation_count}"),
            html.Li(f"Forwarders: {forwarder_count}"),
            html.Li(f"Caller Binaries: {caller_count}"),
            html.Li(f"Unresolved / Cycles: {unresolved_count}"),
            html.Li(f"Total Nodes: {len(nodes)}"),
            html.Li(f"Total Relationships: {len(edges)}"),
        ]),

        html.H3("Implementation DLLs"),
        (
            html.Div([
                html.Div([
                    html.B(f"{ver}:"),
                    html.Div([
                        html.Div(dll)
                        for dll in sorted(dlls)
                    ], style={"marginLeft": "15px"})
                ])
                for ver, dlls in sorted(impl_by_version.items())
            ])
            if impl_by_version else
            html.Div("None", style={"color": "#999", "marginLeft": "15px"})
        ),

        html.Hr(),

        html.H3("Importing DLLs"),
        (
            html.Div([
                html.Div([
                    html.B(f"{ver}:"),
                    html.Div([
                        html.Div(caller)
                        for caller in sorted(callers)
                    ], style={"marginLeft": "15px"})
                ])
                for ver, callers in sorted(caller_by_version.items())
            ])
            if caller_by_version else
            html.Div("None", style={"color": "#999", "marginLeft": "15px"})
        ),

        html.Hr(),

        html.H3("Unresolved / Cycles"),
        (
            html.Div([
                html.Div([
                    html.B(f"{ver}:"),
                    html.Div([
                        html.Div(mod)
                        for mod in sorted(mods)
                    ], style={"marginLeft": "15px"})
                ])
                for ver, mods in sorted(unresolved_by_version.items())
            ])
            if unresolved_by_version else
            html.Div("None", style={"color": "#999", "marginLeft": "15px"})
        ),

    ])

    current_text = (
        f"{dll} :: {function}"
        if dll
        else f"Deep Trace :: {function}"
    )

    return (
        fig,
        info_panel,
        current_text
    )

# ---------------- RUN ----------------
app.run(debug=True)