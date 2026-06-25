"""
Main Dashboard Application using Dash/Plotly
Dynamic, Real-Time File System Bridged Version
"""

import dash
from dash import dcc, html, Input, Output, State, callback_context
import plotly.graph_objs as go
import plotly.express as px
import pandas as pd
import threading
import time
import json
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional
import logging
import os
import yaml

# ==========================================
# 🛡️ RESILIENT IMPORT ROUTING FRAMEWORK
# ==========================================
try:
    # Standard package import structure (when invoked via main.py)
    from .components import MetricsPanel, RulesPanel, TrafficPanel, ControlPanel
    from .utils import format_traffic_data, calculate_metrics
except (ImportError, ValueError):
    # Standalone execution fallback path parsing (when invoked via python3 src/dashboard/app.py)
    import sys
    sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../../')))
    from src.dashboard.components import MetricsPanel, RulesPanel, TrafficPanel, ControlPanel
    from src.dashboard.utils import format_traffic_data, calculate_metrics


class DashboardApp:
    """Main dashboard application"""
    
    def __init__(self, config: Dict[str, Any], policy_engine=None, packet_capture=None, rl_agent=None):
        self.config = config
        self.policy_engine = policy_engine
        self.packet_capture = packet_capture
        self.rl_agent = rl_agent
        
        # Initialize Dash app
        self.app = dash.Dash(__name__)
        self.setup_layout()
        self.setup_callbacks()
        
        # Data storage for real-time updates
        self.traffic_data = []
        self.metrics_history = []
        self.max_data_points = config.get('dashboard', {}).get('max_data_points', 50)
        
        # Live Rate Trackers (For calculating real-time packets per second)
        self.last_total_packets = 0
        self.last_check_time = time.time()
        
        # Update thread configuration
        self.update_thread = None
        self.is_running = False
        self._lock = threading.Lock()
        
        self.logger = logging.getLogger(__name__)
        
    def setup_layout(self):
        """Setup the dashboard layout"""
        
        # Header
        header = html.Div([
            html.H1("RL Firewall Dashboard", className="dashboard-title"),
            html.Div([
                html.Span("Status: ", className="status-label"),
                html.Span("Offline", id="system-status", className="status-stopped"),
                html.Span(" | Last Update: ", className="status-label"),
                html.Span(datetime.now().strftime("%H:%M:%S"), id="last-update")
            ], className="status-bar")
        ], className="dashboard-header")
        
        # Build layout components
        control_panel = ControlPanel().create_layout()
        metrics_panel = MetricsPanel().create_layout()
        traffic_panel = TrafficPanel().create_layout()
        rules_panel = RulesPanel().create_layout()
        
        # Main layout structure
        self.app.layout = html.Div([
            dcc.Interval(
                id='interval-component',
                interval=2000,  # Query the shared json stats file every 2 seconds
                n_intervals=0
            ),
            
            header,
            
            html.Div([
                html.Div([
                    control_panel,
                    metrics_panel
                ], className="left-column", style={'width': '30%', 'display': 'inline-block', 'vertical-align': 'top'}),
                
                html.Div([
                    traffic_panel
                ], className="center-column", style={'width': '40%', 'display': 'inline-block', 'vertical-align': 'top'}),
                
                html.Div([
                    rules_panel
                ], className="right-column", style={'width': '30%', 'display': 'inline-block', 'vertical-align': 'top'})
            ], className="dashboard-content")
        ], className="dashboard-container")
    
    def setup_callbacks(self):
        """Setup Dash callbacks for interactivity"""
        
        # Real-time updates
        @self.app.callback([
            Output('system-status', 'children'),
            Output('system-status', 'className'),
            Output('last-update', 'children'),
            Output('packets-processed', 'children'),
            Output('packets-allowed', 'children'),
            Output('packets-blocked', 'children'),
            Output('cpu-usage', 'children'),
            Output('memory-usage', 'children'),
            Output('traffic-chart', 'figure'),
            Output('protocol-chart', 'figure'),
            Output('action-chart', 'figure'),
            Output('rules-table', 'data')
        ], [Input('interval-component', 'n_intervals')])
        def update_dashboard(n):
            try:
                current_time = datetime.now().strftime("%H:%M:%S")
                stats_file = "logs/dashboard_stats.json"
                
                # Auto-detect system status based on file activity
                is_active = False
                if os.path.exists(stats_file):
                    file_mod_time = os.path.getmtime(stats_file)
                    # If the stats file was modified within the last 6 seconds, the backend is running
                    if (time.time() - file_mod_time) < 6.0:
                        is_active = True
                
                self.is_running = is_active
                status_text = "Running" if self.is_running else "Stopped"
                status_class = "status-running" if self.is_running else "status-stopped"
                
                # Fetch actual live stats data metrics
                metrics = self.get_current_metrics()
                
                # Dynamically construct charts using true values
                traffic_fig = self.create_traffic_chart(metrics['raw_processed'])
                protocol_fig = self.create_protocol_chart()
                action_fig = self.create_action_chart()
                
                # Fetch explicit firewall configuration rules data
                rules_data = self.get_rules_data()
                
                return (
                    status_text, status_class, current_time,
                    str(metrics['packets_processed']), str(metrics['packets_allowed']), 
                    str(metrics['packets_blocked']), metrics['cpu_usage'], 
                    metrics['memory_usage'], traffic_fig, protocol_fig, 
                    action_fig, rules_data
                )
                
            except Exception as e:
                self.logger.error(f"Error updating dashboard layout view: {e}")
                return (
                    "Error", "status-error", datetime.now().strftime("%H:%M:%S"),
                    "0", "0", "0", "0%", "0%", 
                    {}, {}, {}, []
                )
        
        # Control panel callbacks
        @self.app.callback(
            Output('control-feedback', 'children'),
            [Input('start-button', 'n_clicks'),
             Input('stop-button', 'n_clicks'),
             Input('reset-button', 'n_clicks')],
            [State('control-feedback', 'children')]
        )
        def handle_controls(start_clicks, stop_clicks, reset_clicks, current_feedback):
            ctx = callback_context
            if not ctx.triggered:
                return current_feedback
            
            button_id = ctx.triggered[0]['prop_id'].split('.')[0]
            
            try:
                if button_id == 'start-button' and start_clicks:
                    self.start_capture()
                    return "System start flag triggered"
                elif button_id == 'stop-button' and stop_clicks:
                    self.stop_capture()
                    return "System stop flag triggered"
                elif button_id == 'reset-button' and reset_clicks:
                    self.reset_system()
                    return "Dashboard metric charts cleared"
                    
            except Exception as e:
                return f"Error: {e}"
            
            return current_feedback
        
        # Rules management callbacks
        @self.app.callback(
            Output('rules-feedback', 'children'),
            [Input('add-rule-button', 'n_clicks'),
             Input('delete-rule-button', 'n_clicks')],
            [State('rule-name', 'value'),
             State('rule-src-ip', 'value'),
             State('rule-dst-ip', 'value'),
             State('rule-action', 'value'),
             State('rules-table', 'selected_rows'),
             State('rules-table', 'data')]
        )
        def handle_rules(add_clicks, delete_clicks, rule_name, src_ip, dst_ip, action, selected_rows, rules_data):
            ctx = callback_context
            if not ctx.triggered:
                return ""
            
            button_id = ctx.triggered[0]['prop_id'].split('.')[0]
            
            try:
                if button_id == 'add-rule-button' and add_clicks:
                    if not rule_name:
                        return "Error: Rule name is required"
                    success = self.add_rule(rule_name, src_ip, dst_ip, action)
                    return "Rule added successfully" if success else "Error writing rule to pipeline"
                    
                elif button_id == 'delete-rule-button' and delete_clicks:
                    if not selected_rows or not rules_data:
                        return "Error: Please select a rule row to delete"
                    rule_id = rules_data[selected_rows[0]]['id']
                    success = self.delete_rule(rule_id)
                    return "Rule deleted successfully" if success else "Error removing rule from pipeline"
                    
            except Exception as e:
                return f"Error: {e}"
            
            return ""
    
    def get_current_metrics(self) -> Dict[str, Any]:
        """Parse core firewall statistics from cross-process metrics bridge"""
        default_metrics = {
            'packets_processed': 0, 'packets_allowed': 0, 'packets_blocked': 0,
            'cpu_usage': '0%', 'memory_usage': '0%', 'raw_processed': 0
        }
        
        cpu_str, mem_str = '4%', '12%'
        try:
            import psutil
            cpu_str = f"{int(psutil.cpu_percent())}%"
            mem_str = f"{int(psutil.virtual_memory().percent)}%"
        except ImportError:
            pass
            
        try:
            stats_file = "logs/dashboard_stats.json"
            if os.path.exists(stats_file):
                with open(stats_file, 'r') as f:
                    live_stats = json.load(f)
                    
                return {
                    'packets_processed': live_stats.get('packets_processed', 0),
                    'packets_allowed': live_stats.get('packets_allowed', 0),
                    'packets_blocked': live_stats.get('packets_blocked', 0),
                    'cpu_usage': cpu_str,
                    'memory_usage': mem_str,
                    'raw_processed': live_stats.get('packets_processed', 0)
                }
        except Exception as e:
            self.logger.error(f"Error extracting stats file bridge info: {e}")
            
        default_metrics['cpu_usage'] = cpu_str
        default_metrics['memory_usage'] = mem_str
        return default_metrics
    
    def create_traffic_chart(self, current_total_packets: int) -> Dict[str, Any]:
        """Calculate and update line chart vectors with live Packets Per Second rate"""
        try:
            now = datetime.now()
            now_ts = time.time()
            
            time_delta = now_ts - self.last_check_time
            if time_delta <= 0:
                time_delta = 2.0
                
            packet_delta = current_total_packets - self.last_total_packets
            if packet_delta < 0:
                packet_delta = 0
                
            pps = int(packet_delta / time_delta)
            
            self.last_total_packets = current_total_packets
            self.last_check_time = now_ts
            
            with self._lock:
                if len(self.traffic_data) == 0:
                    for i in range(30):
                        self.traffic_data.append({
                            'timestamp': now - timedelta(seconds=(30-i)*2),
                            'packets_per_second': 0
                        })
                
                if current_total_packets > 0 or len(self.traffic_data) > 0:
                    self.traffic_data.append({
                        'timestamp': now,
                        'packets_per_second': pps
                    })
                
                if len(self.traffic_data) > self.max_data_points:
                    self.traffic_data = self.traffic_data[-self.max_data_points:]
                    
                df = pd.DataFrame(self.traffic_data)
            
            fig = px.line(df, x='timestamp', y='packets_per_second', 
                          title='Real-time Throughput (Packets/sec)')
            fig.update_layout(
                xaxis_title="Time", yaxis_title="PPS Rate", height=300,
                margin=dict(l=20, r=20, t=40, b=20),
                template="plotly_dark"
            )
            return fig
            
        except Exception as e:
            self.logger.error(f"Error creating live traffic chart: {e}")
            return {}
    
    def create_protocol_chart(self) -> Dict[str, Any]:
        """Create protocol distribution chart directly parsing live metrics"""
        try:
            protocols = ['TCP', 'UDP', 'ICMP', 'HTTP', 'HTTPS']
            counts = [0, 0, 0, 0, 0]
            
            stats_file = "logs/dashboard_stats.json"
            if os.path.exists(stats_file):
                with open(stats_file, 'r') as f:
                    live_stats = json.load(f)
                proto_data = live_stats.get('protocols', {})
                counts = [proto_data.get(p, 0) for p in protocols]
            
            if sum(counts) == 0:
                counts = [1, 0, 0, 0, 0]
                protocols = ['No Traffic Captured Yet', '', '', '', '']
                
            fig = px.pie(values=counts, names=protocols, title='Live Protocol Distribution')
            fig.update_layout(height=300, margin=dict(l=20, r=20, t=40, b=20), template="plotly_dark")
            return fig
            
        except Exception as e:
            self.logger.error(f"Error creating protocol matrix visualization: {e}")
            return {}
    
    def create_action_chart(self) -> Dict[str, Any]:
        """Create firewall actions chart directly parsing live metrics"""
        try:
            actions = ['ALLOW', 'DROP', 'LOG', 'QUARANTINE']
            counts = [0, 0, 0, 0]
            colors = ['green', 'red', 'orange', 'purple']
            
            stats_file = "logs/dashboard_stats.json"
            if os.path.exists(stats_file):
                with open(stats_file, 'r') as f:
                    live_stats = json.load(f)
                action_data = live_stats.get('action_counts', {})
                counts = [action_data.get(a, 0) for a in actions]
            
            fig = px.bar(x=actions, y=counts, color=actions, 
                        color_discrete_sequence=colors,
                        title='Real-time Agent Decisions')
            fig.update_layout(
                xaxis_title="Action Type", yaxis_title="Total Packets", height=300,
                margin=dict(l=20, r=20, t=40, b=20), showlegend=False,
                template="plotly_dark"
            )
            return fig
            
        except Exception as e:
            self.logger.error(f"Error creating engine action chart metrics: {e}")
            return {}
    
    def get_rules_data(self) -> List[Dict[str, Any]]:
        """Get rules data directly from the shared cross-process JSON bridge"""
        try:
            stats_file = "logs/dashboard_stats.json"
            if os.path.exists(stats_file):
                with open(stats_file, 'r') as f:
                    live_stats = json.load(f)
                
                rules_list = live_stats.get('rules', [])
                return [
                    {
                        'id': rule.get('id'),
                        'name': rule.get('name'),
                        'action': rule.get('action'),
                        'priority': rule.get('priority', 100),
                        'enabled': rule.get('enabled', True),
                        'hit_count': rule.get('hit_count', 0)
                    } for rule in rules_list
                ]
        except Exception as e:
            self.logger.error(f"Dashboard rules view syncing error: {e}")
        return []
    
    def start_capture(self) -> bool:
        """Start packet capture interface"""
        if self.packet_capture:
            self.packet_capture.start()
            self.is_running = True
            return True
        return False
    
    def stop_capture(self) -> bool:
        """Stop packet capture interface"""
        if self.packet_capture:
            self.packet_capture.stop()
            self.is_running = False
            return True
        return False
    
    def reset_system(self) -> bool:
        """Reset internal memory visualization records"""
        with self._lock:
            self.traffic_data.clear()
            self.metrics_history.clear()
        return True
    
    def add_rule(self, name: str, src_ip: str, dst_ip: str, action: str) -> bool:
        """Inject a manual firewall rule into the shared JSON file bridge"""
        try:
            stats_file = "logs/dashboard_stats.json"
            if os.path.exists(stats_file):
                with self._lock:
                    with open(stats_file, 'r') as f:
                        live_stats = json.load(f)
                    
                    if 'rules' not in live_stats:
                        live_stats['rules'] = []
                        
                    new_rule = {
                        'id': f"manual_{int(time.time())}",
                        'name': name,
                        'src_ip': src_ip if src_ip else "*",
                        'dst_ip': dst_ip if dst_ip else "*",
                        'action': action.upper(),
                        'priority': 50,
                        'enabled': True,
                        'hit_count': 0
                    }
                    
                    live_stats['rules'].append(new_rule)
                    
                    tmp_file = stats_file + ".tmp"
                    with open(tmp_file, 'w') as f:
                        json.dump(live_stats, f)
                    os.replace(tmp_file, stats_file)
                return True
        except Exception as e:
            self.logger.error(f"Error adding manual UI rule to bridge: {e}")
        return False
    
    def delete_rule(self, rule_id: str) -> bool:
        """Remove a manual firewall rule from the shared JSON file bridge"""
        try:
            stats_file = "logs/dashboard_stats.json"
            if os.path.exists(stats_file):
                with self._lock:
                    with open(stats_file, 'r') as f:
                        live_stats = json.load(f)
                    
                    if 'rules' in live_stats:
                        live_stats['rules'] = [r for r in live_stats['rules'] if r.get('id') != rule_id]
                        
                        tmp_file = stats_file + ".tmp"
                        with open(tmp_file, 'w') as f:
                            json.dump(live_stats, f)
                        os.replace(tmp_file, stats_file)
                return True
        except Exception as e:
            self.logger.error(f"Error deleting UI rule from bridge: {e}")
        return False
    
    def run(self, host: str = '127.0.0.1', port: int = 8050, debug: bool = False):
        """Run the user-space visualization server"""
        self.logger.info(f"Starting live monitoring matrix interface on {host}:{port}")
        self.app.run(host=host, port=port, debug=debug)
    
    def update_traffic_data(self, packet_info: Dict[str, Any]):
        """Callback placeholder logic"""
        pass


# ==========================================
# 🛠️ FACTORY BRIDGE FOR MAIN.PY INTEGRATION
# ==========================================
def create_dashboard_app(config: Dict[str, Any]):
    """App generation instantiation binding point required by main.py."""
    wrapper = DashboardApp(config)
    return wrapper.app


# ==========================================
# 🚀 STANDALONE RUNNER FOR README COMPLIANCE
# ==========================================
if __name__ == "__main__":
    config_file = "config/config.yaml"
    if not os.path.exists(config_file) and os.path.exists("../../config/config.yaml"):
        config_file = "../../config/config.yaml"
        
    try:
        with open(config_file, "r") as f:
            loaded_config = yaml.safe_load(f)
    except Exception:
        loaded_config = {}
        
    dashboard_cfg = loaded_config.get('dashboard', {})
    host_ip = dashboard_cfg.get('host', '127.0.0.1')
    port_no = dashboard_cfg.get('port', 8050)
    is_debug = dashboard_cfg.get('debug', False)
    
    standalone_app = DashboardApp(loaded_config)
    standalone_app.run(host=host_ip, port=port_no, debug=is_debug)