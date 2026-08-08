import networkx as nx
from dash import Dash, dcc, html, Input, Output, State, ctx, no_update
import plotly.graph_objects as go
import numpy as np
from pathlib import Path
import json

# ---------------- PATHS ----------------
WIN_ARCH = "x64"

SCRIPT_DIR = Path(__file__).resolve().parent.parent


def get_windows_build(windows_version):
    if windows_version == "win11":
        return "10.0.26200"
    else:
        return "10.0.19045"


def get_version_paths(windows_version):
    """
    Returns paths for a specific Windows version.
    """

    win_build = get_windows_build(windows_version)

    input_dir = (
        SCRIPT_DIR
        / "shared-output"
        / windows_version
        / win_build
        / WIN_ARCH
    )

    return {
        "input_dir": input_dir,
        "dependencies": input_dir / "dll_dependencies.json",
        "imported_by": input_dir / "dll_imported_by.json",
    }


# ---------------- LOAD DATA ----------------
def load_dll_data(windows_version):
    """
    Loads DLL dependency and imported-by databases
    for the selected Windows version.
    """

    paths = get_version_paths(windows_version)

    with open(paths["dependencies"], "r", encoding="utf-8") as f:
        dll_graph = json.load(f)

    with open(paths["imported_by"], "r", encoding="utf-8") as f:
        dll_imported_by = json.load(f)

    return dll_graph, dll_imported_by

# ---------------- APP ----------------
import dash_bootstrap_components as dbc
app = Dash(__name__, external_stylesheets=[dbc.themes.LUMEN])

app.layout = html.Div([

    html.H3("DLL Dependency Explorer"),

    html.Div([

        dcc.Input(
            id="dll-input",
            type="text",
            placeholder="DLL (required)... (Press Enter)",
            maxLength=260,
            debounce=True,
            style={
                "width": "300px",
                "padding": "8px",
                "borderRadius": "6px",
                "border": "1px solid #ccc"
            }
        ),

        html.Button("<- Back", id="btn-back", n_clicks=0, disabled=True,
                    style={"marginLeft": "10px"}),
        html.Button("Forward ->", id="btn-forward", n_clicks=0, disabled=True,
                    style={"marginLeft": "5px"}),

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
            style={
                "marginLeft": "20px",
                "fontSize": "13px",
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

    ], style={
        "display": "flex",
        "alignItems": "center",
        "gap": "10px",
        "marginBottom": "10px"
    }),

    html.Div(id="current-dll-display", style={
        "fontSize": "13px",
        "color": "#777",
        "marginBottom": "10px"
    }),

    html.Div([
        html.Span([
            html.Span(style={
                "display": "inline-block", "width": "10px", "height": "10px",
                "borderRadius": "50%", "backgroundColor": "red", "marginRight": "5px"
            }),
            "Imports"
        ], style={"display": "flex", "alignItems": "center", "marginRight": "15px"}),

        html.Span([
            html.Span(style={
                "display": "inline-block", "width": "10px", "height": "10px",
                "borderRadius": "50%", "backgroundColor": "green", "marginRight": "5px"
            }),
            "Imported By"
        ], style={"display": "flex", "alignItems": "center", "marginRight": "15px"}),

        html.Span([
            html.Span(style={
                "display": "inline-block", "width": "10px", "height": "10px",
                "borderRadius": "50%", "backgroundColor": "purple", "marginRight": "5px"
            }),
            "Mutual"
        ], style={"display": "flex", "alignItems": "center"})

    ], style={
        "display": "flex",
        "alignItems": "center",
        "marginBottom": "15px",
        "fontSize": "13px",
        "color": "#555"
    }),

    html.Div(
        id="info-panel",
        style={
            "padding": "15px",
            "border": "1px solid lightgray",
            "borderRadius": "5px",
            "marginBottom": "20px",
            "maxHeight": "250px",
            "overflowY": "auto"
        }
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
            "width": "100%",
            "height": "850px"
        }
    ),

    dcc.Store(id="nav-history", data={"stack": [], "index": -1})

])


# ---------------- NAV HISTORY CALLBACK ----------------
@app.callback(
    Output("nav-history", "data"),
    Input("dll-input", "value"),
    Input("graph", "clickData"),
    Input("btn-back", "n_clicks"),
    Input("btn-forward", "n_clicks"),
    State("nav-history", "data"),
    prevent_initial_call=True
)
def update_history(dll_value, click_data, back_clicks, forward_clicks, history):

    triggered_id = ctx.triggered_id

    stack = [
        x.lower() if isinstance(x, str) else x
        for x in history.get("stack", [])
    ]

    index = history.get("index", -1)

    current = stack[index] if 0 <= index < len(stack) else None

    if triggered_id == "dll-input":

        if not dll_value:
            return no_update

        name = dll_value.strip().lower()

        if not name or name == current:
            return no_update

        stack = stack[:index + 1]
        stack.append(name)
        index = len(stack) - 1


    elif triggered_id == "graph":

        if not click_data:
            return no_update

        point = click_data["points"][0]

        name = point.get("customdata")

        if isinstance(name, str):
            name = name.lower()

        if not name or name == current:
            return no_update

        stack = stack[:index + 1]
        stack.append(name)
        index = len(stack) - 1


    elif triggered_id == "btn-back":

        if index > 0:
            index -= 1
        else:
            return no_update


    elif triggered_id == "btn-forward":

        if index < len(stack) - 1:
            index += 1
        else:
            return no_update


    else:
        return no_update


    return {
        "stack": stack,
        "index": index
    }


# ---------------- BUTTON STATE CALLBACK ----------------
@app.callback(
    Output("btn-back", "disabled"),
    Output("btn-forward", "disabled"),
    Input("nav-history", "data")

)
def update_button_states(history):
    stack = history.get("stack", [])
    index = history.get("index", -1)

    back_disabled = index <= 0
    forward_disabled = index >= len(stack) - 1

    return back_disabled, forward_disabled

def resolve_import(importer_arch: str, library_name: str, dll_imported_by: dict) -> str:
    info = dll_imported_by.get(library_name.lower())
    if not info:
        return library_name

    candidates = info.get("candidatePaths", [])

    if len(candidates) == 1:
        return candidates[0]["path"]

    matches = [
        c["path"]
        for c in candidates
        if c["arch"] == importer_arch
    ]

    if len(matches) == 1:
        return matches[0]

    # Still ambiguous (e.g. multiple x64 copies)
    return library_name

# ---------------- RENDER CALLBACK ----------------
@app.callback(
    Output("graph", "figure"),
    Output("info-panel", "children"),
    Output("current-dll-display", "children"),
    Input("nav-history", "data"),
    Input("layout-mode", "value"),
    Input("short-labels", "value"),
    Input("windows-version", "value"),
)
def render_graph(history, layout_mode, short_labels, windows_version):

    dll_graph, dll_imported_by = load_dll_data(windows_version)

    stack = history.get("stack", [])
    index = history.get("index", -1)

    if not stack or not (0 <= index < len(stack)):
        return (
            go.Figure(),
            html.Div("Search for a DLL to begin."),
            ""
        )

    dll_name = stack[index]

    if dll_name not in dll_graph:
        return (
            go.Figure(layout=dict(title=f"{dll_name} not found")),
            html.Div([
                html.H3(dll_name),
                html.P("DLL not found.")
            ]),
            f"Currently viewing: {dll_name} (not found)"
        )

    entry = dll_graph[dll_name]

    importer_arch = entry["architecture"]

    imports = [
        resolve_import(importer_arch, dll, dll_imported_by)
        for dll in entry["imports"]
    ]

    imported_by = dll_imported_by.get(
        entry["filename"].lower(), {}
    ).get("importedByPaths", [])

    # Single source of truth for grouping. Computed ONCE, here, before
    # either layout branch, so both branches see identical groups.
    mutual_set = set(imports) & set(imported_by)
    only_imports = [x for x in imports if x not in mutual_set]
    only_imported_by = [x for x in imported_by if x not in mutual_set]
    mutual_list = sorted(mutual_set)

    total_relationships = len(only_imports) + len(only_imported_by) + len(mutual_list)

    versions = entry.get("versions", [])

    info_panel = html.Div([

        html.H2(dll_name),

        html.Hr(),

        html.H3("Statistics"),

        html.Ul([
            html.Li(f"Imports: {len(imports)}"),
            html.Li(f"Imported By: {len(imported_by)}"),
            html.Li(f"Mutual: {len(mutual_list)}"),
            html.Li(f"Total Unique Relationships: {total_relationships}")
        ]),

        html.Hr(),

        html.H3("Windows Version"),

        html.Ul(
            [html.Li(v) for v in versions]
            if versions else
            [html.Li("Not directly scanned (referenced only as a dependency)")]
        ),

        html.Hr(),

        html.H3("Classification"),

        html.Ul([
            html.Li(
                "Acts as an importer"
                if imports else
                "Does not import other DLLs"
            ),

            html.Li(
                "Acts as a dependency"
                if imported_by else
                "No DLL imports this one"
            )
        ]),

        html.Hr(),

        html.H3("Imports"),

        html.Div(
            [html.Div(x) for x in imports]
            if imports else
            [html.Div("None")]
        ),

        html.Hr(),

        html.H3("Imported By"),

        html.Div(
            [html.Div(x) for x in imported_by]
            if imported_by else
            [html.Div("None")]
        )

    ])

    def format_label(full_label):
        if short_labels:
            return "\n".join(
                [full_label.split("\n", 1)[0].split("\\")[-1].split("/")[-1]]
                + full_label.split("\n")[1:]
            )
        return full_label

    def add_node(x, y, full_label, color):
        node_x.append(x)
        node_y.append(y)

        labels.append(format_label(full_label))
        hover_labels.append(full_label)
        custom.append(full_label)

        node_colors.append(color)

    node_x = []
    node_y = []
    labels = []
    hover_labels = []
    custom = []
    node_colors = []
    edge_x = []
    edge_y = []

    # ================= RADIAL LAYOUT =================
    if layout_mode == "radial":

        center_x, center_y = 0, 0
        radius = 1.5

        def fan_angles(n, group_center, span):
            if n <= 0:
                return []
            return [
                group_center - span + ((i + 0.5) / n) * (2 * span)
                for i in range(n)
            ]

        add_node(center_x, center_y, dll_name, "black")

        # Imports only -> upper fan
        import_angles = fan_angles(len(only_imports), np.pi / 2, np.pi / 2)

        for lib, angle in zip(only_imports, import_angles):
            x = radius * np.cos(angle)
            y = radius * np.sin(angle)

            add_node(x, y, lib, "red")

            edge_x += [center_x, x, None]
            edge_y += [center_y, y, None]

        # Imported-by only -> lower fan
        imported_by_angles = fan_angles(len(only_imported_by), -np.pi / 2, np.pi / 2)

        for lib, angle in zip(only_imported_by, imported_by_angles):
            x = radius * np.cos(angle)
            y = radius * np.sin(angle)

            add_node(x, y, lib, "green")

            edge_x += [x, center_x, None]
            edge_y += [y, center_y, None]

        # Mutual -> separate fan facing left, own radius, each label once
        mutual_radius = radius * 1.35
        mutual_angles = fan_angles(len(mutual_list), np.pi, np.pi / 3)
        for lib, angle in zip(mutual_list, mutual_angles):
            x = mutual_radius * np.cos(angle)
            y = mutual_radius * np.sin(angle)

            add_node(x, y, lib, "purple")
            
            edge_x += [center_x, x, None]
            edge_y += [center_y, y, None]

    # ================= SPRING LAYOUT =================
    else:

        G = nx.DiGraph()
        G.add_node(dll_name)

        for lib in only_imports:
            G.add_edge(dll_name, lib)

        for lib in only_imported_by:
            G.add_edge(lib, dll_name)

        for lib in mutual_list:
            G.add_edge(dll_name, lib)
            G.add_edge(lib, dll_name)

        pos = nx.spring_layout(G, k=1.2, seed=42)

        for node in G.nodes:
            x, y = pos[node]

            node_x.append(x)
            node_y.append(y)

            labels.append(format_label(node))
            hover_labels.append(node)
            custom.append(node)

            if node == dll_name:
                node_colors.append("black")
            elif node in mutual_set:
                node_colors.append("purple")
            elif node in only_imports:
                node_colors.append("red")
            elif node in only_imported_by:
                node_colors.append("green")
            else:
                node_colors.append("gray")

        for a, b in G.edges:
            x0, y0 = pos[a]
            x1, y1 = pos[b]

            edge_x += [x0, x1, None]
            edge_y += [y0, y1, None]

    # ---------------- EDGE TRACE ----------------
    edge_trace = go.Scatter(
        x=edge_x,
        y=edge_y,
        mode="lines",
        line=dict(width=1, color="rgba(120,120,120,0.4)"),
        hoverinfo="none"
    )

    # ---------------- NODE TRACE ----------------
    node_trace = go.Scatter(
        x=node_x,
        y=node_y,
        mode="markers+text",
        text=labels,
        hovertext=hover_labels,
        customdata=custom,
        textposition="top center",
        marker=dict(
            size=12,
            color=node_colors,
            line=dict(width=1, color="white")
        ),
        hoverinfo="text"
    )

    fig = go.Figure(data=[edge_trace, node_trace])

    fig.update_layout(
        title=f"Dependencies for {dll_name} ({layout_mode})",
        showlegend=False,
        xaxis=dict(visible=False),
        yaxis=dict(visible=False),
        margin=dict(l=20, r=20, t=40, b=20)
    )

    return fig, info_panel, f"Currently viewing: {dll_name}"

# ---------------- RUN ----------------
app.run(debug=True)