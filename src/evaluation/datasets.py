"""
Synthetic data generation for testing and evaluation
"""

import random
import time
import numpy as np
from typing import Dict, Any, List
from datetime import datetime, timedelta


class SyntheticDataGenerator:
    """Generates synthetic network traffic for testing"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        
        # Common IP ranges for generation
        self.internal_ips = [
            "192.168.1.{}",
            "10.0.0.{}",
            "172.16.0.{}"
        ]
        
        self.external_ips = [
            "8.8.8.8", "8.8.4.4",  # Google DNS
            "1.1.1.1", "1.0.0.1",  # Cloudflare DNS
            "203.0.113.{}",        # Test network
            "198.51.100.{}",       # Test network
            "185.199.108.{}"       # GitHub
        ]
        
        # Common ports
        self.common_ports = {
            'tcp': [80, 443, 22, 21, 25, 53, 110, 143, 993, 995],
            'udp': [53, 67, 68, 123, 161, 162, 514]
        }
        
        # Attack patterns
        self.attack_patterns = {
            'ddos': {
                'source_count': (100, 1000),
                'packet_rate': (1000, 5000),
                'target_ports': [80, 443, 22]
            },
            'port_scan': {
                'port_range': (1, 65535),
                'scan_rate': (10, 100),
                'common_ports': [21, 22, 23, 25, 53, 80, 110, 443, 993, 995]
            },
            'brute_force': {
                'target_ports': [22, 21, 25, 110, 143],
                'attempt_rate': (1, 10),
                'source_variation': (1, 5)
            }
        }
    
    def generate_normal_packet(self) -> Dict[str, Any]:
        """Generate a normal network packet"""
        
        # Random source (usually internal)
        if random.random() < 0.8:
            src_ip = random.choice(self.internal_ips).format(random.randint(2, 254))
        else:
            src_ip = random.choice(self.external_ips)
            if '{}' in src_ip:
                src_ip = src_ip.format(random.randint(1, 254))
        
        # Random destination
        if random.random() < 0.6:
            dst_ip = random.choice(self.external_ips)
            if '{}' in dst_ip:
                dst_ip = dst_ip.format(random.randint(1, 254))
        else:
            dst_ip = random.choice(self.internal_ips).format(random.randint(2, 254))
        
        # Random protocol
        protocol = random.choice(['TCP', 'UDP'])
        
        # Random ports based on protocol
        src_port = random.randint(1024, 65535)
        dst_port = random.choice(self.common_ports[protocol.lower()])
        
        # Random packet size (typical web traffic)
        packet_size = int(np.random.normal(1500, 500))
        packet_size = max(64, min(packet_size, 9000))  # Realistic bounds
        
        return {
            'timestamp': time.time(),
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'src_port': src_port,
            'dst_port': dst_port,
            'protocol': protocol,
            'packet_size': packet_size,
            'flags': self._generate_normal_flags(protocol),
            'flow_id': f"{src_ip}:{src_port}-{dst_ip}:{dst_port}",
            'is_inbound': src_ip.startswith(('192.168', '10.0', '172.16'))
        }
    
    def generate_ddos_packet(self) -> Dict[str, Any]:
        """Generate a DDoS attack packet"""
        
        attack_config = self.attack_patterns['ddos']
        
        # Random source IP (many different sources)
        src_ip = f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
        
        # Target internal server
        dst_ip = random.choice(self.internal_ips).format(random.randint(10, 50))
        
        # Target common services
        dst_port = random.choice(attack_config['target_ports'])
        src_port = random.randint(1024, 65535)
        
        # Usually TCP for web DDoS
        protocol = 'TCP'
        
        # Small packets for DDoS (SYN flood)
        packet_size = random.randint(40, 100)
        
        return {
            'timestamp': time.time(),
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'src_port': src_port,
            'dst_port': dst_port,
            'protocol': protocol,
            'packet_size': packet_size,
            'flags': 'SYN',  # SYN flood pattern
            'flow_id': f"{src_ip}:{src_port}-{dst_ip}:{dst_port}",
            'is_inbound': False,
            'attack_type': 'ddos'
        }
    
    def generate_port_scan_packet(self) -> Dict[str, Any]:
        """Generate a port scanning packet"""
        
        attack_config = self.attack_patterns['port_scan']
        
        # Single source scanning multiple ports
        src_ip = f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
        
        # Target internal network
        dst_ip = random.choice(self.internal_ips).format(random.randint(2, 254))
        
        # Sequential or random port scanning
        if random.random() < 0.7:
            # Sequential scan
            dst_port = random.randint(1, 1024)
        else:
            # Random common ports
            dst_port = random.choice(attack_config['common_ports'])
        
        src_port = random.randint(1024, 65535)
        protocol = 'TCP'
        
        # Small packets for scanning
        packet_size = random.randint(40, 80)
        
        return {
            'timestamp': time.time(),
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'src_port': src_port,
            'dst_port': dst_port,
            'protocol': protocol,
            'packet_size': packet_size,
            'flags': 'SYN',  # SYN scan
            'flow_id': f"{src_ip}:{src_port}-{dst_ip}:{dst_port}",
            'is_inbound': False,
            'attack_type': 'port_scan'
        }
    
    def generate_brute_force_packet(self) -> Dict[str, Any]:
        """Generate a brute force attack packet"""
        
        attack_config = self.attack_patterns['brute_force']
        
        # Attacker source
        src_ip = f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
        
        # Target server (usually same target)
        dst_ip = random.choice(self.internal_ips).format(random.randint(10, 50))
        
        # Target authentication services
        dst_port = random.choice(attack_config['target_ports'])
        src_port = random.randint(1024, 65535)
        
        protocol = 'TCP'
        
        # Variable packet size for authentication attempts
        packet_size = random.randint(200, 800)
        
        return {
            'timestamp': time.time(),
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'src_port': src_port,
            'dst_port': dst_port,
            'protocol': protocol,
            'packet_size': packet_size,
            'flags': 'PSH,ACK',  # Data transfer
            'flow_id': f"{src_ip}:{src_port}-{dst_ip}:{dst_port}",
            'is_inbound': False,
            'attack_type': 'brute_force'
        }
    
    def _generate_normal_flags(self, protocol: str) -> str:
        """Generate realistic TCP flags for normal traffic"""
        
        if protocol.upper() != 'TCP':
            return ''
        
        # Common TCP flag combinations
        flag_combinations = [
            'SYN',
            'SYN,ACK', 
            'ACK',
            'PSH,ACK',
            'FIN,ACK',
            'RST',
            'RST,ACK'
        ]
        
        return random.choice(flag_combinations)
    
    def generate_traffic_burst(self, duration_seconds: int, packets_per_second: int, 
                              traffic_type: str = 'normal') -> List[Dict[str, Any]]:
        """
        Generate a burst of traffic for a specified duration
        
        Args:
            duration_seconds: How long to generate traffic
            packets_per_second: Rate of packet generation
            traffic_type: Type of traffic ('normal', 'ddos', 'port_scan', 'brute_force')
            
        Returns:
            List of generated packets
        """
        
        packets = []
        total_packets = duration_seconds * packets_per_second
        
        for i in range(total_packets):
            if traffic_type == 'normal':
                packet = self.generate_normal_packet()
            elif traffic_type == 'ddos':
                packet = self.generate_ddos_packet()
            elif traffic_type == 'port_scan':
                packet = self.generate_port_scan_packet()
            elif traffic_type == 'brute_force':
                packet = self.generate_brute_force_packet()
            else:
                packet = self.generate_normal_packet()
            
            # Adjust timestamp for realistic timing
            packet['timestamp'] = time.time() + (i / packets_per_second)
            packets.append(packet)
        
        return packets
    
    def generate_mixed_traffic(self, duration_seconds: int, base_rate: int = 100) -> List[Dict[str, Any]]:
        """
        Generate mixed traffic with various attack types
        
        Args:
            duration_seconds: Duration of traffic generation
            base_rate: Base packets per second
            
        Returns:
            List of mixed traffic packets
        """
        
        packets = []
        
        # Traffic distribution
        traffic_distribution = {
            'normal': 0.70,
            'ddos': 0.10,
            'port_scan': 0.15,
            'brute_force': 0.05
        }
        
        total_packets = duration_seconds * base_rate
        
        for i in range(total_packets):
            # Choose traffic type based on distribution
            rand_val = random.random()
            cumulative_prob = 0
            
            traffic_type = 'normal'  # default
            for t_type, prob in traffic_distribution.items():
                cumulative_prob += prob
                if rand_val <= cumulative_prob:
                    traffic_type = t_type
                    break
            
            # Generate packet of chosen type
            if traffic_type == 'normal':
                packet = self.generate_normal_packet()
            elif traffic_type == 'ddos':
                packet = self.generate_ddos_packet()
            elif traffic_type == 'port_scan':
                packet = self.generate_port_scan_packet()
            else:  # brute_force
                packet = self.generate_brute_force_packet()
            
            # Adjust timestamp
            packet['timestamp'] = time.time() + (i / base_rate)
            packets.append(packet)
        
        return packets


class TrafficDataset:
    """Manages datasets of network traffic for evaluation"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.datasets = {}
        self.generator = SyntheticDataGenerator(config)
    
    def create_dataset(self, name: str, size: int, traffic_types: List[str] = None) -> List[Dict[str, Any]]:
        """
        Create a labeled dataset for evaluation
        
        Args:
            name: Name of the dataset
            size: Number of packets in dataset
            traffic_types: Types of traffic to include
            
        Returns:
            List of labeled packets
        """
        
        if traffic_types is None:
            traffic_types = ['normal', 'ddos', 'port_scan', 'brute_force']
        
        packets = []
        packets_per_type = size // len(traffic_types)
        
        for traffic_type in traffic_types:
            for _ in range(packets_per_type):
                if traffic_type == 'normal':
                    packet = self.generator.generate_normal_packet()
                    packet['label'] = 0  # benign
                elif traffic_type == 'ddos':
                    packet = self.generator.generate_ddos_packet()
                    packet['label'] = 1  # malicious
                elif traffic_type == 'port_scan':
                    packet = self.generator.generate_port_scan_packet()
                    packet['label'] = 1  # malicious
                elif traffic_type == 'brute_force':
                    packet = self.generator.generate_brute_force_packet()
                    packet['label'] = 1  # malicious
                
                packet['traffic_type'] = traffic_type
                packets.append(packet)
        
        # Shuffle the dataset
        random.shuffle(packets)
        
        # Store dataset
        self.datasets[name] = packets
        
        return packets
    
    def get_dataset(self, name: str) -> List[Dict[str, Any]]:
        """Get a stored dataset"""
        return self.datasets.get(name, [])
    
    def save_dataset(self, name: str, filepath: str):
        """Save dataset to file"""
        import json
        
        dataset = self.datasets.get(name)
        if dataset:
            with open(filepath, 'w') as f:
                json.dump(dataset, f, indent=2, default=str)
    
    def load_dataset(self, name: str, filepath: str):
        """Load dataset from file"""
        import json
        
        with open(filepath, 'r') as f:
            dataset = json.load(f)
        
        self.datasets[name] = dataset
    
    def get_statistics(self, name: str) -> Dict[str, Any]:
        """Get statistics for a dataset"""
        
        dataset = self.datasets.get(name, [])
        if not dataset:
            return {}
        
        # Count by traffic type
        type_counts = {}
        label_counts = {0: 0, 1: 0}  # benign vs malicious
        
        for packet in dataset:
            traffic_type = packet.get('traffic_type', 'unknown')
            label = packet.get('label', 0)
            
            type_counts[traffic_type] = type_counts.get(traffic_type, 0) + 1
            label_counts[label] = label_counts.get(label, 0) + 1
        
        return {
            'total_packets': len(dataset),
            'traffic_types': type_counts,
            'label_distribution': label_counts,
            'benign_ratio': label_counts[0] / len(dataset),
            'malicious_ratio': label_counts[1] / len(dataset)
        }