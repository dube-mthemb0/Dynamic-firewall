"""
Firewall RL Environment
Custom Gymnasium environment for training reinforcement learning agents on firewall decisions
"""

import gymnasium as gym
from gymnasium import spaces
import numpy as np
from typing import Dict, Tuple, List, Optional, Any
from dataclasses import dataclass
from collections import deque, defaultdict
import time
import random

from ..packet_capture.features import FeatureVector, FeatureExtractor
from ..packet_capture.capture import PacketInfo
from loguru import logger


@dataclass
class FirewallAction:
    """Represents a firewall action"""
    action_type: int  # 0=ALLOW, 1=DROP, 2=LOG, 3=QUARANTINE
    confidence: float = 1.0
    
    @property
    def name(self) -> str:
        action_names = {0: "ALLOW", 1: "DROP", 2: "LOG", 3: "QUARANTINE"}
        return action_names.get(self.action_type, "UNKNOWN")


class TrafficSimulator:
    """Simulate network traffic for training"""
    
    def __init__(self, config: Dict):
        self.config = config
        self.benign_traffic_ratio = config.get('benign_traffic_ratio', 0.8)
        self.attack_types = config.get('attack_types', ['port_scan', 'ddos', 'brute_force'])
        self.packet_counter = 0
        
    def generate_benign_packet(self) -> PacketInfo:
        """Generate simulated benign network packet"""
        timestamp = time.time()
        
        # Common benign traffic patterns
        traffic_patterns = [
            # Web traffic
            {"src_port": random.randint(32768, 65535), "dst_port": 80, "protocol": "TCP", "size": random.randint(60, 1500)},
            {"src_port": random.randint(32768, 65535), "dst_port": 443, "protocol": "TCP", "size": random.randint(60, 1500)},
            # DNS
            {"src_port": random.randint(32768, 65535), "dst_port": 53, "protocol": "UDP", "size": random.randint(40, 100)},
            # Email
            {"src_port": random.randint(32768, 65535), "dst_port": 25, "protocol": "TCP", "size": random.randint(100, 2000)},
            {"src_port": random.randint(32768, 65535), "dst_port": 993, "protocol": "TCP", "size": random.randint(100, 2000)},
            # SSH (legitimate)
            {"src_port": random.randint(32768, 65535), "dst_port": 22, "protocol": "TCP", "size": random.randint(60, 200)},
        ]
        
        pattern = random.choice(traffic_patterns)
        
        return PacketInfo(
            timestamp=timestamp,
            src_ip=f"192.168.1.{random.randint(2, 254)}",
            dst_ip=f"10.0.0.{random.randint(1, 254)}",
            src_port=pattern["src_port"],
            dst_port=pattern["dst_port"],
            protocol=pattern["protocol"],
            packet_size=pattern["size"],
            flags="ACK" if pattern["protocol"] == "TCP" else "",
            flow_id=f"flow_{self.packet_counter}",
            is_inbound=random.choice([True, False])
        )
    
    def generate_malicious_packet(self, attack_type: str) -> PacketInfo:
        """Generate simulated malicious network packet"""
        timestamp = time.time()
        
        if attack_type == "port_scan":
            return PacketInfo(
                timestamp=timestamp,
                src_ip=f"10.0.1.{random.randint(1, 10)}",
                dst_ip=f"192.168.1.{random.randint(1, 254)}",
                src_port=random.randint(32768, 65535),
                dst_port=random.randint(1, 65535),
                protocol="TCP",
                packet_size=random.randint(40, 80),
                flags="SYN",
                flow_id=f"scan_flow_{self.packet_counter}",
                is_inbound=True
            )
            
        elif attack_type == "ddos":
            return PacketInfo(
                timestamp=timestamp,
                src_ip=f"10.0.{random.randint(1, 255)}.{random.randint(1, 255)}",
                dst_ip="192.168.1.100",
                src_port=random.randint(1024, 65535),
                dst_port=80,
                protocol="TCP",
                packet_size=random.randint(1000, 1500),
                flags="SYN,ACK",
                flow_id=f"ddos_flow_{self.packet_counter}",
                is_inbound=True
            )
            
        elif attack_type == "brute_force":
            return PacketInfo(
                timestamp=timestamp,
                src_ip=f"10.0.2.{random.randint(1, 50)}",
                dst_ip="192.168.1.10",
                src_port=random.randint(32768, 65535),
                dst_port=22,
                protocol="TCP",
                packet_size=random.randint(100, 300),
                flags="PSH,ACK",
                flow_id=f"brute_flow_{self.packet_counter}",
                is_inbound=True
            )
            
        else:
            return PacketInfo(
                timestamp=timestamp,
                src_ip=f"192.168.100.{random.randint(1, 50)}",
                dst_ip=f"192.168.1.{random.randint(1, 254)}",
                src_port=random.randint(1024, 65535),
                dst_port=random.randint(1, 1024),
                protocol=random.choice(["TCP", "UDP"]),
                packet_size=random.randint(50, 1500),
                flags=random.choice(["SYN", "RST", "FIN", ""]),
                flow_id=f"malicious_flow_{self.packet_counter}",
                is_inbound=True
            )
    
    def generate_packet(self) -> Tuple[PacketInfo, bool]:
        """Generate a packet with label (True=benign, False=malicious)"""
        self.packet_counter += 1
        
        if random.random() < self.benign_traffic_ratio:
            packet = self.generate_benign_packet()
            return packet, True
        else:
            attack_type = random.choice(self.attack_types)
            packet = self.generate_malicious_packet(attack_type)
            return packet, False


class FirewallEnv(gym.Env):
    """Gymnasium environment for firewall policy learning"""
    
    def __init__(self, config: Dict):
        super(FirewallEnv, self).__init__()
        
        self.config = config
        self.reward_config = config.get('rewards', {})
        
        # Environment configuration
        self.state_size = config.get('state_size', 20)
        self.max_episode_steps = config.get('max_episode_steps', 1000)
        
        # Action space: 4 possible actions
        self.action_space = spaces.Discrete(4)
        
        # Observation space: continuous feature vector
        self.observation_space = spaces.Box(
            low=-np.inf, 
            high=np.inf, 
            shape=(self.state_size,), 
            dtype=np.float32
        )
        
        # Initialize components
        self.traffic_simulator = TrafficSimulator(config)
        self.feature_extractor = FeatureExtractor(config)
        
        # Episode state
        self.current_step = 0
        self.episode_reward = 0
        self.current_packet = None
        self.current_label = None
        self.current_features = None
        
        # Performance tracking
        self.performance_metrics = {
            'true_positives': 0,   # Correctly blocked malicious
            'true_negatives': 0,   # Correctly allowed benign
            'false_positives': 0,  # Incorrectly blocked benign
            'false_negatives': 0,  # Incorrectly allowed malicious
            'total_packets': 0
        }
        
        # Flow tracking for context
        self.flow_tracker = defaultdict(lambda: {
            'packet_count': 0,
            'last_seen': 0,
            'actions': deque(maxlen=10),
            'features_history': deque(maxlen=10)
        })
        
        logger.info("FirewallEnv initialized")
    
    def _get_flow_features(self, packet_info: PacketInfo) -> Dict:
        """Generate mock flow features for simulation"""
        flow_id = packet_info.flow_id
        flow = self.flow_tracker[flow_id]
        
        flow['packet_count'] += 1
        flow['last_seen'] = packet_info.timestamp
        
        return {
            'duration': max(packet_info.timestamp - flow.get('start_time', packet_info.timestamp), 0.001),
            'packet_count': flow['packet_count'],
            'bytes_total': flow['packet_count'] * packet_info.packet_size,
            'packet_rate': flow['packet_count'] / max(packet_info.timestamp - flow.get('start_time', packet_info.timestamp), 0.001),
            'byte_rate': (flow['packet_count'] * packet_info.packet_size) / max(packet_info.timestamp - flow.get('start_time', packet_info.timestamp), 0.001),
            'avg_packet_size': packet_info.packet_size,
            'direction_changes': random.randint(0, flow['packet_count'] // 2)
        }
    
    def _calculate_reward(self, action: int, is_benign: bool) -> float:
        """Calculate reward based on action and ground truth"""
        correct_allow = self.reward_config.get('correct_allow', 1.0)
        correct_block = self.reward_config.get('correct_block', 1.0)
        false_positive = self.reward_config.get('false_positive', -2.0)
        false_negative = self.reward_config.get('false_negative', -5.0)
        
        if action == 0:  # ALLOW
            if is_benign:
                self.performance_metrics['true_negatives'] += 1
                return correct_allow
            else:
                self.performance_metrics['false_negatives'] += 1
                return false_negative
        elif action == 1:  # DROP
            if is_benign:
                self.performance_metrics['false_positives'] += 1
                return false_positive
            else:
                self.performance_metrics['true_positives'] += 1
                return correct_block
        elif action == 2:  # LOG
            if is_benign:
                return correct_allow * 0.5
            else:
                return false_negative * 0.5
        else:  # QUARANTINE (action == 3)
            if is_benign:
                self.performance_metrics['false_positives'] += 1
                return false_positive * 0.7
            else:
                self.performance_metrics['true_positives'] += 1
                return correct_block * 0.8
    
    def _get_state(self) -> np.ndarray:
        """Get current state as feature vector"""
        if self.current_features is None:
            return np.zeros(self.state_size, dtype=np.float32)
        
        features = self.current_features.features
        if len(features) > self.state_size:
            features = features[:self.state_size]
        elif len(features) < self.state_size:
            features = np.pad(features, (0, self.state_size - len(features)), 'constant')
        
        return features.astype(np.float32)
    
    def reset(self, seed: Optional[int] = None, options: Optional[Dict] = None) -> Tuple[np.ndarray, Dict[str, Any]]:
        """Reset environment to initial state (Gymnasium compliance)"""
        super().reset(seed=seed)
        
        self.current_step = 0
        self.episode_reward = 0
        
        # Reset performance metrics
        for key in self.performance_metrics:
            self.performance_metrics[key] = 0
        
        # Generate first packet
        self.current_packet, self.current_label = self.traffic_simulator.generate_packet()
        flow_features = self._get_flow_features(self.current_packet)
        self.current_features = self.feature_extractor.extract_features(self.current_packet, flow_features)
        self.current_features = self.feature_extractor.normalize_features(self.current_features)
        
        self.performance_metrics['total_packets'] = 1
        
        # Return state and an empty info dictionary
        return self._get_state(), {}
    
    def step(self, action: int) -> Tuple[np.ndarray, float, bool, bool, Dict]:
        """Execute one step in the environment (Gymnasium compliance)"""
        
        # Calculate reward for current action
        reward = self._calculate_reward(action, self.current_label)
        self.episode_reward += reward
        
        # Update flow tracking
        if self.current_packet:
            flow_id = self.current_packet.flow_id
            self.flow_tracker[flow_id]['actions'].append(action)
            self.flow_tracker[flow_id]['features_history'].append(self.current_features.features)
        
        # Move to next step
        self.current_step += 1
        
        # Gymnasium parameters: separated termination vs truncation
        terminated = False
        truncated = self.current_step >= self.max_episode_steps
        
        # Generate next packet if the run isn't over
        if not (terminated or truncated):
            self.current_packet, self.current_label = self.traffic_simulator.generate_packet()
            flow_features = self._get_flow_features(self.current_packet)
            self.current_features = self.feature_extractor.extract_features(self.current_packet, flow_features)
            self.current_features = self.feature_extractor.normalize_features(self.current_features)
            self.performance_metrics['total_packets'] += 1
        
        next_state = self._get_state()
        
        info = {
            'packet_info': {
                'src_ip': self.current_packet.src_ip if self.current_packet else None,
                'dst_ip': self.current_packet.dst_ip if self.current_packet else None,
                'protocol': self.current_packet.protocol if self.current_packet else None,
                'is_benign': self.current_label
            },
            'action_taken': FirewallAction(action).name,
            'episode_reward': self.episode_reward,
            'step': self.current_step,
            'performance': self._get_performance_metrics()
        }
        
        return next_state, reward, terminated, truncated, info
    
    def _get_performance_metrics(self) -> Dict:
        """Calculate current performance metrics"""
        metrics = self.performance_metrics.copy()
        
        total = metrics['total_packets']
        if total > 0:
            metrics['accuracy'] = (metrics['true_positives'] + metrics['true_negatives']) / total
            metrics['precision'] = metrics['true_positives'] / max(metrics['true_positives'] + metrics['false_positives'], 1)
            metrics['recall'] = metrics['true_positives'] / max(metrics['true_positives'] + metrics['false_negatives'], 1)
            metrics['f1_score'] = 2 * (metrics['precision'] * metrics['recall']) / max(metrics['precision'] + metrics['recall'], 1)
            metrics['false_positive_rate'] = metrics['false_positives'] / max(metrics['false_positives'] + metrics['true_negatives'], 1)
            metrics['false_negative_rate'] = metrics['false_negatives'] / max(metrics['false_negatives'] + metrics['true_positives'], 1)
        else:
            metrics.update({
                'accuracy': 0.0, 'precision': 0.0, 'recall': 0.0, 
                'f1_score': 0.0, 'false_positive_rate': 0.0, 'false_negative_rate': 0.0
            })
        
        return metrics
    
    def render(self) -> Optional[str]:
        """Render the environment metrics status"""
        metrics = self._get_performance_metrics()
        print(f"\nFirewall Environment Status:")
        print(f"Step: {self.current_step}/{self.max_episode_steps}")
        print(f"Episode Reward: {self.episode_reward:.2f}")
        print(f"Accuracy: {metrics['accuracy']:.3f}")
        print(f"Precision: {metrics['precision']:.3f}")
        print(f"Recall: {metrics['recall']:.3f}")
        print(f"F1 Score: {metrics['f1_score']:.3f}")
        
        if self.current_packet:
            print(f"\nCurrent Packet:")
            print(f"  {self.current_packet.src_ip}:{self.current_packet.src_port} -> {self.current_packet.dst_ip}:{self.current_packet.dst_port}")
            print(f"  Label: {'Benign' if self.current_label else 'Malicious'}")
    
    def close(self):
        """Clean up resources"""
        pass
    
    def get_action_meanings(self) -> List[str]:
        """Get human-readable action meanings"""
        return ["ALLOW", "DROP", "LOG", "QUARANTINE"]


# Factory function for creating environments
def make_firewall_env(config: Dict) -> FirewallEnv:
    """Factory function to create configured firewall environment"""
    return FirewallEnv(config)


# Example usage
def main():
    """Example usage of FirewallEnv"""
    config = {
        'state_size': 20,
        'max_episode_steps': 100,
        'benign_traffic_ratio': 0.7,
        'attack_types': ['port_scan', 'ddos', 'brute_force'],
        'rewards': {
            'correct_allow': 1.0,
            'correct_block': 1.0,
            'false_positive': -2.0,
            'false_negative': -5.0
        }
    }
    
    env = make_firewall_env(config)
    
    # Gymnasium unpacking compatibility check
    state, info = env.reset()
    done = False
    step = 0
    
    logger.info("Starting firewall environment test...")
    
    while not done and step < 20:
        action = env.action_space.sample()
        
        # Unpack the 5 parameters returned by gymnasium envs
        next_state, reward, terminated, truncated, info = env.step(action)
        done = terminated or truncated
        
        logger.info(f"Step {step}: Action={env.get_action_meanings()[action]}, "
                    f"Reward={reward:.2f}, Benign={info['packet_info']['is_benign']}")
        
        state = next_state
        step += 1
    
    env.render()
    env.close()


if __name__ == "__main__":
    main()