"""
Dashboard UI Components
"""

from dash import dcc, html, dash_table
import plotly.graph_objs as go


class MetricsPanel:
    """Real-time metrics panel"""
    
    def create_layout(self):
        return html.Div([
            html.H3("System Metrics", className="panel-title"),
            
            html.Div([
                html.Div([
                    html.H4("0", id="packets-processed", className="metric-value"),
                    html.P("Packets Processed", className="metric-label")
                ], className="metric-card"),
                
                html.Div([
                    html.H4("0", id="packets-allowed", className="metric-value"),
                    html.P("Packets Allowed", className="metric-label")
                ], className="metric-card"),
                
                html.Div([
                    html.H4("0", id="packets-blocked", className="metric-value"),
                    html.P("Packets Blocked", className="metric-label")
                ], className="metric-card"),
                
                html.Div([
                    html.H4("0%", id="cpu-usage", className="metric-value"),
                    html.P("CPU Usage", className="metric-label")
                ], className="metric-card"),
                
                html.Div([
                    html.H4("0%", id="memory-usage", className="metric-value"),
                    html.P("Memory Usage", className="metric-label")
                ], className="metric-card")
            ], className="metrics-grid")
        ], className="panel metrics-panel")


class TrafficPanel:
    """Traffic visualization panel"""
    
    def create_layout(self):
        return html.Div([
            html.H3("Traffic Analysis", className="panel-title"),
            
            # Real-time traffic chart
            html.Div([
                dcc.Graph(
                    id='traffic-chart',
                    config={'displayModeBar': False}
                )
            ], className="chart-container"),
            
            # Protocol distribution
            html.Div([
                html.Div([
                    dcc.Graph(
                        id='protocol-chart',
                        config={'displayModeBar': False}
                    )
                ], style={'width': '50%', 'display': 'inline-block'}),
                
                html.Div([
                    dcc.Graph(
                        id='action-chart',
                        config={'displayModeBar': False}
                    )
                ], style={'width': '50%', 'display': 'inline-block'})
            ], className="charts-row")
        ], className="panel traffic-panel")


class RulesPanel:
    """Firewall rules management panel"""
    
    def create_layout(self):
        return html.Div([
            html.H3("Firewall Rules", className="panel-title"),
            
            # Add rule form
            html.Div([
                html.H4("Add New Rule"),
                
                html.Div([
                    html.Label("Rule Name:"),
                    dcc.Input(
                        id='rule-name',
                        type='text',
                        placeholder='Enter rule name',
                        className="form-input"
                    )
                ], className="form-group"),
                
                html.Div([
                    html.Label("Source IP:"),
                    dcc.Input(
                        id='rule-src-ip',
                        type='text',
                        placeholder='e.g., 192.168.1.0/24',
                        className="form-input"
                    )
                ], className="form-group"),
                
                html.Div([
                    html.Label("Destination IP:"),
                    dcc.Input(
                        id='rule-dst-ip',
                        type='text',
                        placeholder='e.g., 10.0.0.1',
                        className="form-input"
                    )
                ], className="form-group"),
                
                html.Div([
                    html.Label("Action:"),
                    dcc.Dropdown(
                        id='rule-action',
                        options=[
                            {'label': 'Allow', 'value': 'ALLOW'},
                            {'label': 'Drop', 'value': 'DROP'},
                            {'label': 'Log', 'value': 'LOG'},
                            {'label': 'Quarantine', 'value': 'QUARANTINE'}
                        ],
                        value='ALLOW',
                        className="form-input"
                    )
                ], className="form-group"),
                
                html.Div([
                    html.Button("Add Rule", id="add-rule-button", className="btn btn-primary"),
                    html.Button("Delete Selected", id="delete-rule-button", className="btn btn-danger")
                ], className="form-actions"),
                
                html.Div(id="rules-feedback", className="feedback-message")
            ], className="add-rule-form"),
            
            # Rules table
            html.Div([
                dash_table.DataTable(
                    id='rules-table',
                    columns=[
                        {'name': 'ID', 'id': 'id'},
                        {'name': 'Name', 'id': 'name'},
                        {'name': 'Action', 'id': 'action'},
                        {'name': 'Priority', 'id': 'priority'},
                        {'name': 'Enabled', 'id': 'enabled'},
                        {'name': 'Hits', 'id': 'hit_count'}
                    ],
                    data=[],
                    row_selectable='single',
                    selected_rows=[],
                    style_cell={'textAlign': 'left'},
                    style_data={'fontSize': '12px'},
                    style_header={'fontWeight': 'bold'},
                    page_size=10
                )
            ], className="rules-table-container")
        ], className="panel rules-panel")


class ControlPanel:
    """System control panel"""
    
    def create_layout(self):
        return html.Div([
            html.H3("System Control", className="panel-title"),
            
            html.Div([
                html.Button("Start Capture", id="start-button", className="btn btn-success"),
                html.Button("Stop Capture", id="stop-button", className="btn btn-warning"),
                html.Button("Reset System", id="reset-button", className="btn btn-danger")
            ], className="control-buttons"),
            
            html.Div(id="control-feedback", className="feedback-message"),
            
            # RL Agent Status
            html.Div([
                html.H4("RL Agent Status"),
                html.Div([
                    html.Span("Mode: "),
                    html.Span("Training", id="rl-mode", className="status-badge"),
                    html.Br(),
                    html.Span("Episodes: "),
                    html.Span("0", id="rl-episodes"),
                    html.Br(),
                    html.Span("Reward: "),
                    html.Span("0.00", id="rl-reward")
                ], className="rl-status")
            ], className="rl-panel"),
            
            # Configuration
            html.Div([
                html.H4("Quick Settings"),
                
                html.Div([
                    html.Label("Default Action:"),
                    dcc.Dropdown(
                        id='default-action',
                        options=[
                            {'label': 'Allow', 'value': 'allow'},
                            {'label': 'Drop', 'value': 'drop'},
                            {'label': 'Log', 'value': 'log'}
                        ],
                        value='allow',
                        className="form-input"
                    )
                ], className="form-group"),
                
                html.Div([
                    html.Label("Capture Interface:"),
                    dcc.Input(
                        id='capture-interface',
                        type='text',
                        value='eth0',
                        className="form-input"
                    )
                ], className="form-group"),
                
                html.Div([
                    html.Label("Max Packet Rate:"),
                    dcc.Input(
                        id='max-packet-rate',
                        type='number',
                        value=1000,
                        className="form-input"
                    )
                ], className="form-group")
            ], className="settings-panel")
        ], className="panel control-panel")