"""
Main Dashboard Application using Dash/Plotly
"""

import dash
from dash import dcc, html, Input, Output, State, callback_context
import plotly.graph_objs as go
import plotly.express as px
import pandas as pd
import threading
import time
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional
import logging

from .components import MetricsPanel, RulesPanel, TrafficPanel, ControlPanel
from .utils import format_traffic_data, calculate_metrics


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
        self.max_data_points = config.get('dashboard', {}).get('max_data_points', 1000)
        
        # Update thread
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
                html.Span("Running", id="system-status", className="status-running"),
                html.Span(" | Last Update: ", className="status-label"),
                html.Span(datetime.now().strftime("%H:%M:%S"), id="last-update")
            ], className="status-bar")
        ], className="dashboard-header")
        
        # Control panel
        control_panel = ControlPanel().create_layout()
        
        # Metrics panel
        metrics_panel = MetricsPanel().create_layout()
        
        # Traffic visualization
        traffic_panel = TrafficPanel().create_layout()
        
        # Rules management
        rules_panel = RulesPanel().create_layout()
        
        # Main layout
        self.app.layout = html.Div([
            dcc.Interval(
                id='interval-component',
                interval=2000,  # Update every 2 seconds
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
                # Get system status
                status_text = "Running" if self.is_running else "Stopped"
                status_class = "status-running" if self.is_running else "status-stopped"
                
                # Get current timestamp
                current_time = datetime.now().strftime("%H:%M:%S")
                
                # Get metrics
                metrics = self.get_current_metrics()
                
                # Update charts
                traffic_fig = self.create_traffic_chart()
                protocol_fig = self.create_protocol_chart()
                action_fig = self.create_action_chart()
                
                # Get rules data
                rules_data = self.get_rules_data()
                
                return (
                    status_text, status_class, current_time,
                    metrics['packets_processed'], metrics['packets_allowed'], 
                    metrics['packets_blocked'], metrics['cpu_usage'], 
                    metrics['memory_usage'], traffic_fig, protocol_fig, 
                    action_fig, rules_data
                )
                
            except Exception as e:
                self.logger.error(f"Error updating dashboard: {e}")
                return (
                    "Error", "status-error", current_time,
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
                    return "System started successfully"
                elif button_id == 'stop-button' and stop_clicks:
                    self.stop_capture()
                    return "System stopped"
                elif button_id == 'reset-button' and reset_clicks:
                    self.reset_system()
                    return "System reset"
                    
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
                    return "Rule added successfully" if success else "Error adding rule"
                    
                elif button_id == 'delete-rule-button' and delete_clicks:
                    if not selected_rows or not rules_data:
                        return "Error: Please select a rule to delete"
                    
                    rule_id = rules_data[selected_rows[0]]['id']
                    success = self.delete_rule(rule_id)
                    return "Rule deleted successfully" if success else "Error deleting rule"
                    
            except Exception as e:
                return f"Error: {e}"
            
            return ""
    
    def get_current_metrics(self) -> Dict[str, Any]:
        """Get current system metrics"""
        default_metrics = {
            'packets_processed': 0,
            'packets_allowed': 0,
            'packets_blocked': 0,
            'cpu_usage': '0%',
            'memory_usage': '0%'
        }
        
        try:
            if self.policy_engine:
                stats = self.policy_engine.get_statistics()
                engine_stats = stats.get('engine_stats', {})
                enforcement_stats = stats.get('enforcement_stats', {})
                
                return {
                    'packets_processed': engine_stats.get('packets_processed', 0),
                    'packets_allowed': enforcement_stats.get('action_counts', {}).get('ALLOW', 0),
                    'packets_blocked': enforcement_stats.get('action_counts', {}).get('DROP', 0),
                    'cpu_usage': '15%',  # Placeholder - would integrate with system monitoring
                    'memory_usage': '23%'  # Placeholder
                }
            
        except Exception as e:
            self.logger.error(f"Error getting metrics: {e}")
        
        return default_metrics
    
    def create_traffic_chart(self) -> Dict[str, Any]:
        """Create real-time traffic chart"""
        try:
            # Generate sample data for demonstration
            with self._lock:
                if len(self.traffic_data) == 0:
                    # Initialize with sample data
                    now = datetime.now()
                    for i in range(50):
                        self.traffic_data.append({
                            'timestamp': now - timedelta(seconds=50-i),
                            'packets_per_second': 10 + (i % 20),
                            'bytes_per_second': 1000 + (i % 5000)
                        })
                
                df = pd.DataFrame(self.traffic_data[-50:])  # Last 50 points
            
            fig = px.line(df, x='timestamp', y='packets_per_second', 
                         title='Real-time Traffic (Packets/sec)')
            fig.update_layout(
                xaxis_title="Time",
                yaxis_title="Packets/sec",
                height=300,
                margin=dict(l=20, r=20, t=40, b=20)
            )
            
            return fig
            
        except Exception as e:
            self.logger.error(f"Error creating traffic chart: {e}")
            return {}
    
    def create_protocol_chart(self) -> Dict[str, Any]:
        """Create protocol distribution chart"""
        try:
            # Sample protocol data
            protocols = ['TCP', 'UDP', 'ICMP', 'HTTP', 'HTTPS']
            counts = [45, 30, 10, 8, 7]
            
            fig = px.pie(values=counts, names=protocols, title='Protocol Distribution')
            fig.update_layout(height=300, margin=dict(l=20, r=20, t=40, b=20))
            
            return fig
            
        except Exception as e:
            self.logger.error(f"Error creating protocol chart: {e}")
            return {}
    
    def create_action_chart(self) -> Dict[str, Any]:
        """Create firewall actions chart"""
        try:
            actions = ['ALLOW', 'DROP', 'LOG', 'QUARANTINE']
            counts = [70, 20, 8, 2]
            colors = ['green', 'red', 'orange', 'purple']
            
            fig = px.bar(x=actions, y=counts, color=actions, 
                        color_discrete_sequence=colors,
                        title='Firewall Actions')
            fig.update_layout(
                xaxis_title="Action",
                yaxis_title="Count",
                height=300,
                margin=dict(l=20, r=20, t=40, b=20),
                showlegend=False
            )
            
            return fig
            
        except Exception as e:
            self.logger.error(f"Error creating action chart: {e}")
            return {}
    
    def get_rules_data(self) -> List[Dict[str, Any]]:
        """Get rules data for table"""
        try:
            if self.policy_engine:
                rules = self.policy_engine.list_rules()
                return [
                    {
                        'id': rule.id,
                        'name': rule.name,
                        'action': rule.action.value,
                        'priority': rule.priority,
                        'enabled': rule.enabled,
                        'hit_count': rule.hit_count
                    }
                    for rule in rules
                ]
            
        except Exception as e:
            self.logger.error(f"Error getting rules data: {e}")
        
        return []
    
    def start_capture(self) -> bool:
        """Start packet capture and processing"""
        try:
            if self.packet_capture:
                self.packet_capture.start()
            
            if self.policy_engine:
                self.policy_engine.start()
            
            self.is_running = True
            self.logger.info("Dashboard: Started capture")
            return True
            
        except Exception as e:
            self.logger.error(f"Error starting capture: {e}")
            return False
    
    def stop_capture(self) -> bool:
        """Stop packet capture and processing"""
        try:
            if self.packet_capture:
                self.packet_capture.stop()
            
            if self.policy_engine:
                self.policy_engine.stop()
            
            self.is_running = False
            self.logger.info("Dashboard: Stopped capture")
            return True
            
        except Exception as e:
            self.logger.error(f"Error stopping capture: {e}")
            return False
    
    def reset_system(self) -> bool:
        """Reset system statistics and state"""
        try:
            with self._lock:
                self.traffic_data.clear()
                self.metrics_history.clear()
            
            self.logger.info("Dashboard: Reset system")
            return True
            
        except Exception as e:
            self.logger.error(f"Error resetting system: {e}")
            return False
    
    def add_rule(self, name: str, src_ip: str, dst_ip: str, action: str) -> bool:
        """Add a new firewall rule"""
        try:
            if not self.policy_engine:
                return False
            
            from ..policy_engine.rules import Rule, RuleCondition, RuleAction
            
            # Create rule condition
            condition = RuleCondition(
                src_ip=src_ip if src_ip else None,
                dst_ip=dst_ip if dst_ip else None
            )
            
            # Create rule
            rule_data = {
                'id': f'manual_{int(time.time())}',
                'name': name,
                'condition': condition.__dict__,
                'action': action.upper(),
                'priority': 100,
                'enabled': True,
                'created_by': 'dashboard',
                'description': f'Rule created via dashboard: {name}'
            }
            
            self.policy_engine.add_manual_rule(rule_data)
            return True
            
        except Exception as e:
            self.logger.error(f"Error adding rule: {e}")
            return False
    
    def delete_rule(self, rule_id: str) -> bool:
        """Delete a firewall rule"""
        try:
            if not self.policy_engine:
                return False
            
            return self.policy_engine.remove_rule(rule_id)
            
        except Exception as e:
            self.logger.error(f"Error deleting rule: {e}")
            return False
    
    def run(self, host: str = '127.0.0.1', port: int = 8050, debug: bool = False):
        """Run the dashboard server"""
        self.logger.info(f"Starting dashboard server on {host}:{port}")
        self.app.run_server(host=host, port=port, debug=debug)
    
    def update_traffic_data(self, packet_info: Dict[str, Any]):
        """Update traffic data with new packet"""
        try:
            with self._lock:
                self.traffic_data.append({
                    'timestamp': datetime.now(),
                    'src_ip': packet_info.get('src_ip'),
                    'dst_ip': packet_info.get('dst_ip'),
                    'protocol': packet_info.get('protocol'),
                    'size': packet_info.get('packet_size', 0)
                })
                
                # Keep only recent data
                if len(self.traffic_data) > self.max_data_points:
                    self.traffic_data = self.traffic_data[-self.max_data_points:]
                    
        except Exception as e:
            self.logger.error(f"Error updating traffic data: {e}")