"""
Utility functions for the dashboard
"""

import pandas as pd
from datetime import datetime, timedelta
from typing import Dict, Any, List
import logging


def format_traffic_data(traffic_data: List[Dict[str, Any]], 
                       time_window_minutes: int = 30) -> pd.DataFrame:
    """
    Format traffic data for visualization
    
    Args:
        traffic_data: List of traffic records
        time_window_minutes: Time window to include in minutes
        
    Returns:
        Formatted pandas DataFrame
    """
    if not traffic_data:
        return pd.DataFrame()
    
    # Convert to DataFrame
    df = pd.DataFrame(traffic_data)
    
    # Ensure timestamp column
    if 'timestamp' not in df.columns:
        df['timestamp'] = datetime.now()
    
    # Convert timestamp to datetime if needed
    if not pd.api.types.is_datetime64_any_dtype(df['timestamp']):
        df['timestamp'] = pd.to_datetime(df['timestamp'])
    
    # Filter to time window
    cutoff_time = datetime.now() - timedelta(minutes=time_window_minutes)
    df = df[df['timestamp'] >= cutoff_time]
    
    # Sort by timestamp
    df = df.sort_values('timestamp')
    
    return df


def calculate_metrics(traffic_data: List[Dict[str, Any]], 
                     rules_data: List[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    Calculate system metrics from traffic and rules data
    
    Args:
        traffic_data: List of traffic records
        rules_data: List of rules data
        
    Returns:
        Dictionary of calculated metrics
    """
    
    metrics = {
        'total_packets': 0,
        'packets_per_second': 0.0,
        'bytes_per_second': 0.0,
        'unique_sources': 0,
        'unique_destinations': 0,
        'protocol_distribution': {},
        'action_distribution': {},
        'top_sources': [],
        'top_destinations': [],
        'threat_score': 0.0
    }
    
    if not traffic_data:
        return metrics
    
    try:
        df = pd.DataFrame(traffic_data)
        
        # Basic counts
        metrics['total_packets'] = len(df)
        
        # Time-based metrics (last minute)
        if 'timestamp' in df.columns:
            if not pd.api.types.is_datetime64_any_dtype(df['timestamp']):
                df['timestamp'] = pd.to_datetime(df['timestamp'])
            
            recent_df = df[df['timestamp'] >= datetime.now() - timedelta(minutes=1)]
            metrics['packets_per_second'] = len(recent_df) / 60.0
            
            if 'size' in recent_df.columns:
                metrics['bytes_per_second'] = recent_df['size'].sum() / 60.0
        
        # Unique addresses
        if 'src_ip' in df.columns:
            metrics['unique_sources'] = df['src_ip'].nunique()
            # Top sources
            top_sources = df['src_ip'].value_counts().head(5)
            metrics['top_sources'] = [
                {'ip': ip, 'count': count} 
                for ip, count in top_sources.items()
            ]
        
        if 'dst_ip' in df.columns:
            metrics['unique_destinations'] = df['dst_ip'].nunique()
            # Top destinations
            top_destinations = df['dst_ip'].value_counts().head(5)
            metrics['top_destinations'] = [
                {'ip': ip, 'count': count} 
                for ip, count in top_destinations.items()
            ]
        
        # Protocol distribution
        if 'protocol' in df.columns:
            protocol_counts = df['protocol'].value_counts()
            metrics['protocol_distribution'] = protocol_counts.to_dict()
        
        # Action distribution (if available)
        if 'action' in df.columns:
            action_counts = df['action'].value_counts()
            metrics['action_distribution'] = action_counts.to_dict()
        
        # Calculate threat score based on various factors
        metrics['threat_score'] = calculate_threat_score(df)
        
    except Exception as e:
        logging.getLogger(__name__).error(f"Error calculating metrics: {e}")
    
    return metrics


def calculate_threat_score(df: pd.DataFrame) -> float:
    """
    Calculate a threat score based on traffic patterns
    
    Args:
        df: DataFrame with traffic data
        
    Returns:
        Threat score between 0.0 and 1.0
    """
    
    threat_score = 0.0
    
    try:
        if df.empty:
            return 0.0
        
        # Factor 1: High packet rate (max 0.3)
        packet_rate = len(df) / 60.0  # per second
        if packet_rate > 100:
            threat_score += min(0.3, packet_rate / 1000.0)
        
        # Factor 2: Port scanning patterns (max 0.3)
        if 'dst_port' in df.columns:
            unique_ports_per_source = df.groupby('src_ip')['dst_port'].nunique()
            max_ports_per_source = unique_ports_per_source.max() if not unique_ports_per_source.empty else 0
            if max_ports_per_source > 10:
                threat_score += min(0.3, max_ports_per_source / 100.0)
        
        # Factor 3: Unusual protocols (max 0.2)
        if 'protocol' in df.columns:
            protocol_counts = df['protocol'].value_counts()
            unusual_protocols = ['ICMP', 'GRE', 'ESP']
            unusual_count = sum(protocol_counts.get(proto, 0) for proto in unusual_protocols)
            if unusual_count > 0:
                threat_score += min(0.2, unusual_count / len(df))
        
        # Factor 4: Geographic anomalies (placeholder - max 0.2)
        # Would integrate with IP geolocation in real implementation
        if 'src_ip' in df.columns:
            unique_sources = df['src_ip'].nunique()
            if unique_sources > 50:
                threat_score += min(0.2, (unique_sources - 50) / 200.0)
        
    except Exception as e:
        logging.getLogger(__name__).error(f"Error calculating threat score: {e}")
    
    return min(1.0, threat_score)


def format_bytes(bytes_value: int) -> str:
    """Format bytes value to human readable string"""
    
    for unit in ['B', 'KB', 'MB', 'GB']:
        if bytes_value < 1024.0:
            return f"{bytes_value:.1f} {unit}"
        bytes_value /= 1024.0
    return f"{bytes_value:.1f} TB"


def format_duration(seconds: float) -> str:
    """Format duration in seconds to human readable string"""
    
    if seconds < 60:
        return f"{seconds:.1f}s"
    elif seconds < 3600:
        return f"{seconds//60:.0f}m {seconds%60:.0f}s"
    else:
        hours = seconds // 3600
        minutes = (seconds % 3600) // 60
        return f"{hours:.0f}h {minutes:.0f}m"


def get_color_for_action(action: str) -> str:
    """Get color code for firewall action"""
    
    color_map = {
        'ALLOW': '#28a745',  # Green
        'DROP': '#dc3545',   # Red
        'LOG': '#ffc107',    # Yellow
        'QUARANTINE': '#6f42c1'  # Purple
    }
    
    return color_map.get(action.upper(), '#6c757d')  # Default gray


def aggregate_traffic_by_time(df: pd.DataFrame, interval: str = '1min') -> pd.DataFrame:
    """
    Aggregate traffic data by time intervals
    
    Args:
        df: DataFrame with traffic data and timestamp column
        interval: Pandas time interval string (e.g., '1min', '5min', '1H')
        
    Returns:
        Aggregated DataFrame
    """
    
    if df.empty or 'timestamp' not in df.columns:
        return pd.DataFrame()
    
    try:
        # Ensure timestamp is datetime
        if not pd.api.types.is_datetime64_any_dtype(df['timestamp']):
            df['timestamp'] = pd.to_datetime(df['timestamp'])
        
        # Set timestamp as index
        df = df.set_index('timestamp')
        
        # Aggregate by time interval
        agg_functions = {
            'packet_count': 'size',
            'total_bytes': ('size', 'sum') if 'size' in df.columns else ('packet_count', 'count'),
            'unique_sources': ('src_ip', 'nunique') if 'src_ip' in df.columns else ('packet_count', 'count'),
            'unique_destinations': ('dst_ip', 'nunique') if 'dst_ip' in df.columns else ('packet_count', 'count')
        }
        
        # Filter valid aggregation functions
        valid_agg_functions = {}
        for key, (col, func) in agg_functions.items():
            if col in df.columns or key == 'packet_count':
                if key == 'packet_count':
                    valid_agg_functions[key] = 'size'
                else:
                    valid_agg_functions[key] = (col, func)
        
        aggregated = df.resample(interval).agg(valid_agg_functions)
        
        # Reset index to get timestamp as column
        aggregated = aggregated.reset_index()
        
        return aggregated
        
    except Exception as e:
        logging.getLogger(__name__).error(f"Error aggregating traffic data: {e}")
        return pd.DataFrame()


def detect_anomalies(df: pd.DataFrame, window_size: int = 10) -> List[Dict[str, Any]]:
    """
    Detect anomalies in traffic data using simple statistical methods
    
    Args:
        df: DataFrame with traffic data
        window_size: Rolling window size for anomaly detection
        
    Returns:
        List of detected anomalies
    """
    
    anomalies = []
    
    if df.empty or len(df) < window_size:
        return anomalies
    
    try:
        # Detect packet rate anomalies
        if 'timestamp' in df.columns:
            df = df.sort_values('timestamp')
            
            # Calculate rolling statistics
            df['packet_rate'] = df.groupby(df['timestamp'].dt.floor('S')).size()
            rolling_mean = df['packet_rate'].rolling(window=window_size).mean()
            rolling_std = df['packet_rate'].rolling(window=window_size).std()
            
            # Detect outliers (packets rate > mean + 2*std)
            threshold = rolling_mean + 2 * rolling_std
            anomaly_indices = df['packet_rate'] > threshold
            
            for idx in df[anomaly_indices].index:
                anomalies.append({
                    'type': 'high_packet_rate',
                    'timestamp': df.loc[idx, 'timestamp'],
                    'value': df.loc[idx, 'packet_rate'],
                    'threshold': threshold.loc[idx] if idx in threshold.index else None,
                    'severity': 'medium'
                })
        
        # Detect port scanning
        if 'src_ip' in df.columns and 'dst_port' in df.columns:
            port_scans = df.groupby('src_ip')['dst_port'].nunique()
            scan_threshold = 10  # More than 10 different ports from same source
            
            for src_ip, port_count in port_scans.items():
                if port_count > scan_threshold:
                    anomalies.append({
                        'type': 'port_scan',
                        'src_ip': src_ip,
                        'port_count': port_count,
                        'severity': 'high' if port_count > 50 else 'medium'
                    })
        
        # Detect unusual protocols
        if 'protocol' in df.columns:
            protocol_counts = df['protocol'].value_counts()
            total_packets = len(df)
            
            for protocol, count in protocol_counts.items():
                ratio = count / total_packets
                
                # Flag if unusual protocol makes up significant portion
                if protocol.upper() in ['ICMP', 'GRE', 'ESP'] and ratio > 0.1:
                    anomalies.append({
                        'type': 'unusual_protocol',
                        'protocol': protocol,
                        'count': count,
                        'ratio': ratio,
                        'severity': 'medium'
                    })
        
    except Exception as e:
        logging.getLogger(__name__).error(f"Error detecting anomalies: {e}")
    
    return anomalies