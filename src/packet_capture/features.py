"""
Feature Extraction Module
Extract meaningful features from network packets for RL agent
"""

import numpy as np
import pandas as pd
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass
from collections import defaultdict, deque
import ipaddress
import time
import math
from scipy import stats

from .capture import PacketInfo, FlowTracker
from loguru import logger


@dataclass
class FeatureVector:
    """Structure to hold extracted feature vector"""
    features: np.ndarray
    feature_names: List[str]
    timestamp: float
    flow_id: str
    label: Optional[int] = None  # For supervised learning


class FeatureExtractor:
    """Extract features from network packets and flows"""
    
    def __init__(self, config: Dict):
        self.config = config
        self.feature_names = []
        self.scaler_stats = {}  # For normalization
        self.categorical_encoders = {}  # For categorical encoding
        
        # Flow-based feature tracking
        self.flow_windows = defaultdict(lambda: deque(maxlen=10))  # Rolling windows
        self.port_stats = defaultdict(int)
        self.protocol_stats = defaultdict(int)
        
        # Initialize feature extraction methods
        self._init_feature_extractors()
        
    def _init_feature_extractors(self) -> None:
        """Initialize feature extraction components"""
        # Basic packet features
        if self.config.get('extract_ip', True):
            self.feature_names.extend(['src_ip_int', 'dst_ip_int', 'ip_flags'])
            
        if self.config.get('extract_ports', True):
            self.feature_names.extend(['src_port', 'dst_port', 'port_ratio'])
            
        if self.config.get('extract_protocol', True):
            self.feature_names.extend(['protocol_tcp', 'protocol_udp', 'protocol_icmp', 'protocol_other'])
            
        if self.config.get('extract_packet_size', True):
            self.feature_names.extend(['packet_size', 'packet_size_log'])
            
        if self.config.get('extract_flags', True):
            self.feature_names.extend(['tcp_syn', 'tcp_ack', 'tcp_fin', 'tcp_rst', 'tcp_psh', 'tcp_urg'])
            
        # Flow-based features
        if self.config.get('extract_flow_duration', True):
            self.feature_names.extend(['flow_duration', 'flow_duration_log'])
            
        if self.config.get('extract_bytes_transferred', True):
            self.feature_names.extend(['bytes_total', 'bytes_rate', 'avg_packet_size'])
            
        if self.config.get('extract_packet_count', True):
            self.feature_names.extend(['packet_count', 'packet_rate'])
            
        # Statistical features
        if self.config.get('extract_packet_rate', True):
            self.feature_names.extend(['packet_rate_mean', 'packet_rate_std', 'packet_rate_max'])
            
        if self.config.get('extract_byte_rate', True):
            self.feature_names.extend(['byte_rate_mean', 'byte_rate_std', 'byte_rate_max'])
            
        # Advanced behavioral features
        self.feature_names.extend([
            'direction_changes', 'direction_ratio',
            'port_entropy', 'time_entropy', 
            'payload_entropy', 'size_variance',
            'is_weekend', 'hour_of_day', 'is_business_hours'
        ])
        
        logger.info(f"Initialized {len(self.feature_names)} feature extractors")
    
    def _ip_to_int(self, ip_str: str) -> int:
        """Convert IP address to integer representation"""
        try:
            return int(ipaddress.ip_address(ip_str))
        except:
            return 0
    
    def _extract_ip_features(self, packet_info: PacketInfo) -> List[float]:
        """Extract IP-based features"""
        src_ip_int = self._ip_to_int(packet_info.src_ip)
        dst_ip_int = self._ip_to_int(packet_info.dst_ip)
        
        # Simple IP flags (private, multicast, etc.)
        ip_flags = 0
        try:
            src_ip_obj = ipaddress.ip_address(packet_info.src_ip)
            dst_ip_obj = ipaddress.ip_address(packet_info.dst_ip)
            
            if src_ip_obj.is_private:
                ip_flags |= 1
            if dst_ip_obj.is_private:
                ip_flags |= 2
            if src_ip_obj.is_multicast:
                ip_flags |= 4
            if dst_ip_obj.is_multicast:
                ip_flags |= 8
        except:
            pass
            
        return [float(src_ip_int % 2**16), float(dst_ip_int % 2**16), float(ip_flags)]
    
    def _extract_port_features(self, packet_info: PacketInfo) -> List[float]:
        """Extract port-based features"""
        src_port = float(packet_info.src_port)
        dst_port = float(packet_info.dst_port)
        
        # Port ratio (for asymmetric connections)
        port_ratio = src_port / max(dst_port, 1.0)
        
        return [src_port, dst_port, port_ratio]
    
    def _extract_protocol_features(self, packet_info: PacketInfo) -> List[float]:
        """Extract protocol-based features (one-hot encoding)"""
        protocol = packet_info.protocol.upper()
        return [
            1.0 if protocol == 'TCP' else 0.0,
            1.0 if protocol == 'UDP' else 0.0,
            1.0 if protocol == 'ICMP' else 0.0,
            1.0 if protocol not in ['TCP', 'UDP', 'ICMP'] else 0.0
        ]
    
    def _extract_packet_size_features(self, packet_info: PacketInfo) -> List[float]:
        """Extract packet size features"""
        size = float(packet_info.packet_size)
        size_log = math.log(max(size, 1.0))
        return [size, size_log]
    
    def _extract_tcp_flag_features(self, packet_info: PacketInfo) -> List[float]:
        """Extract TCP flag features"""
        flags = packet_info.flags.lower()
        return [
            1.0 if 'syn' in flags else 0.0,
            1.0 if 'ack' in flags else 0.0,
            1.0 if 'fin' in flags else 0.0,
            1.0 if 'rst' in flags else 0.0,
            1.0 if 'psh' in flags else 0.0,
            1.0 if 'urg' in flags else 0.0
        ]
    
    def _extract_flow_features(self, flow_features: Dict) -> List[float]:
        """Extract flow-based features"""
        features = []
        
        # Duration features
        duration = flow_features.get('duration', 0.0)
        features.extend([
            duration,
            math.log(max(duration, 0.001))
        ])
        
        # Byte and packet features
        bytes_total = flow_features.get('bytes_total', 0.0)
        packet_count = flow_features.get('packet_count', 1.0)
        
        features.extend([
            bytes_total,
            flow_features.get('byte_rate', 0.0),
            flow_features.get('avg_packet_size', 0.0)
        ])
        
        # Packet count and rate
        features.extend([
            packet_count,
            flow_features.get('packet_rate', 0.0)
        ])
        
        return features
    
    def _extract_statistical_features(self, packet_info: PacketInfo, flow_features: Dict) -> List[float]:
        """Extract statistical features from flow windows"""
        flow_id = packet_info.flow_id
        window = self.flow_windows[flow_id]
        
        # Add current packet to window
        window.append({
            'timestamp': packet_info.timestamp,
            'size': packet_info.packet_size,
            'port': packet_info.dst_port
        })
        
        if len(window) < 2:
            return [0.0] * 6  # Return zeros if not enough data
        
        # Calculate time-based statistics
        timestamps = [p['timestamp'] for p in window]
        inter_arrival_times = np.diff(timestamps)
        
        packet_rate_stats = [
            np.mean(1.0 / np.maximum(inter_arrival_times, 0.001)),
            np.std(1.0 / np.maximum(inter_arrival_times, 0.001)),
            np.max(1.0 / np.maximum(inter_arrival_times, 0.001))
        ]
        
        # Calculate size-based statistics  
        sizes = np.array([p['size'] for p in window])
        byte_rate_stats = [
            np.mean(sizes),
            np.std(sizes),
            np.max(sizes)
        ]
        
        return packet_rate_stats + byte_rate_stats
    
    def _extract_behavioral_features(self, packet_info: PacketInfo, flow_features: Dict) -> List[float]:
        """Extract behavioral and temporal features"""
        features = []
        
        # Direction changes
        direction_changes = flow_features.get('direction_changes', 0)
        packet_count = flow_features.get('packet_count', 1)
        direction_ratio = direction_changes / max(packet_count - 1, 1)
        
        features.extend([float(direction_changes), direction_ratio])
        
        # Port entropy (measure of port randomness)
        flow_id = packet_info.flow_id
        window = self.flow_windows[flow_id]
        
        if len(window) > 1:
            ports = [p['port'] for p in window]
            port_entropy = self._calculate_entropy(ports)
            
            timestamps = [p['timestamp'] for p in window]
            time_diffs = np.diff(timestamps)
            time_entropy = self._calculate_entropy(time_diffs)
        else:
            port_entropy = 0.0
            time_entropy = 0.0
            
        features.extend([port_entropy, time_entropy])
        
        # Payload entropy (approximation from packet size variance)
        if len(window) > 1:
            sizes = [p['size'] for p in window]
            payload_entropy = self._calculate_entropy(sizes)
            size_variance = np.var(sizes)
        else:
            payload_entropy = 0.0
            size_variance = 0.0
            
        features.extend([payload_entropy, size_variance])
        
        # Temporal features
        timestamp = packet_info.timestamp
        dt = time.localtime(timestamp)
        
        is_weekend = 1.0 if dt.tm_wday >= 5 else 0.0
        hour_of_day = float(dt.tm_hour) / 24.0
        is_business_hours = 1.0 if 9 <= dt.tm_hour <= 17 and dt.tm_wday < 5 else 0.0
        
        features.extend([is_weekend, hour_of_day, is_business_hours])
        
        return features
    
    def _calculate_entropy(self, data: List) -> float:
        """Calculate Shannon entropy of data"""
        if not data:
            return 0.0
            
        # Convert to pandas series for value_counts
        series = pd.Series(data)
        probabilities = series.value_counts(normalize=True)
        
        # Calculate entropy
        entropy = -np.sum(probabilities * np.log2(probabilities + 1e-10))
        return entropy
    
    def extract_features(self, packet_info: PacketInfo, flow_features: Dict) -> FeatureVector:
        """Extract complete feature vector from packet and flow data"""
        all_features = []
        
        # Extract different feature groups
        if self.config.get('extract_ip', True):
            all_features.extend(self._extract_ip_features(packet_info))
            
        if self.config.get('extract_ports', True):
            all_features.extend(self._extract_port_features(packet_info))
            
        if self.config.get('extract_protocol', True):
            all_features.extend(self._extract_protocol_features(packet_info))
            
        if self.config.get('extract_packet_size', True):
            all_features.extend(self._extract_packet_size_features(packet_info))
            
        if self.config.get('extract_flags', True):
            all_features.extend(self._extract_tcp_flag_features(packet_info))
            
        if self.config.get('extract_flow_duration', True) or self.config.get('extract_bytes_transferred', True) or self.config.get('extract_packet_count', True):
            all_features.extend(self._extract_flow_features(flow_features))
            
        if self.config.get('extract_packet_rate', True) or self.config.get('extract_byte_rate', True):
            all_features.extend(self._extract_statistical_features(packet_info, flow_features))
            
        # Always extract behavioral features
        all_features.extend(self._extract_behavioral_features(packet_info, flow_features))
        
        # Convert to numpy array
        feature_array = np.array(all_features, dtype=np.float32)
        
        # Handle NaN and infinite values
        feature_array = np.nan_to_num(feature_array, nan=0.0, posinf=1e6, neginf=-1e6)
        
        return FeatureVector(
            features=feature_array,
            feature_names=self.feature_names.copy(),
            timestamp=packet_info.timestamp,
            flow_id=packet_info.flow_id
        )
    
    def normalize_features(self, feature_vector: FeatureVector) -> FeatureVector:
        """Normalize features using running statistics"""
        features = feature_vector.features.copy()
        
        # Update running statistics and normalize
        for i, (feature_name, value) in enumerate(zip(self.feature_names, features)):
            if feature_name not in self.scaler_stats:
                self.scaler_stats[feature_name] = {'mean': 0.0, 'var': 1.0, 'count': 0}
            
            stats = self.scaler_stats[feature_name]
            
            # Online mean and variance update (Welford's algorithm)
            stats['count'] += 1
            delta = value - stats['mean']
            stats['mean'] += delta / stats['count']
            stats['var'] += delta * (value - stats['mean'])
            
            # Normalize using current statistics
            if stats['count'] > 1:
                std = math.sqrt(stats['var'] / (stats['count'] - 1))
                features[i] = (value - stats['mean']) / max(std, 1e-6)
            else:
                features[i] = 0.0
        
        # Create new normalized feature vector
        normalized_vector = FeatureVector(
            features=features,
            feature_names=feature_vector.feature_names,
            timestamp=feature_vector.timestamp,
            flow_id=feature_vector.flow_id,
            label=feature_vector.label
        )
        
        return normalized_vector
    
    def get_feature_importance(self) -> Dict[str, float]:
        """Get feature importance scores (placeholder for now)"""
        # This could be enhanced with actual feature importance calculation
        # from trained models or statistical analysis
        return {name: 1.0 / len(self.feature_names) for name in self.feature_names}
    
    def save_scaler_stats(self, filepath: str) -> None:
        """Save normalization statistics"""
        import pickle
        with open(filepath, 'wb') as f:
            pickle.dump(self.scaler_stats, f)
        logger.info(f"Saved scaler statistics to {filepath}")
    
    def load_scaler_stats(self, filepath: str) -> None:
        """Load normalization statistics"""
        import pickle
        try:
            with open(filepath, 'rb') as f:
                self.scaler_stats = pickle.load(f)
            logger.info(f"Loaded scaler statistics from {filepath}")
        except FileNotFoundError:
            logger.warning(f"Scaler stats file not found: {filepath}")


# Example usage
def main():
    """Example usage of FeatureExtractor"""
    config = {
        'extract_ip': True,
        'extract_ports': True,
        'extract_protocol': True,
        'extract_packet_size': True,
        'extract_flags': True,
        'extract_flow_duration': True,
        'extract_bytes_transferred': True,
        'extract_packet_count': True,
        'extract_packet_rate': True,
        'extract_byte_rate': True
    }
    
    extractor = FeatureExtractor(config)
    
    # Example packet info
    packet_info = PacketInfo(
        timestamp=time.time(),
        src_ip="192.168.1.100",
        dst_ip="8.8.8.8",
        src_port=12345,
        dst_port=53,
        protocol="UDP",
        packet_size=64,
        flags="",
        flow_id="192.168.1.100:12345-8.8.8.8:53-UDP",
        is_inbound=False
    )
    
    # Example flow features
    flow_features = {
        'duration': 1.5,
        'packet_count': 5,
        'bytes_total': 320,
        'packet_rate': 3.33,
        'byte_rate': 213.33,
        'avg_packet_size': 64.0,
        'direction_changes': 2
    }
    
    # Extract features
    feature_vector = extractor.extract_features(packet_info, flow_features)
    normalized_vector = extractor.normalize_features(feature_vector)
    
    logger.info(f"Extracted {len(feature_vector.features)} features")
    logger.info(f"Feature vector: {feature_vector.features[:10]}...")  # Show first 10
    logger.info(f"Normalized vector: {normalized_vector.features[:10]}...")


if __name__ == "__main__":
    main()