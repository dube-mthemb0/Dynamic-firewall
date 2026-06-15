"""
Evaluation metrics for the RL firewall system
"""

from dataclasses import dataclass, field
from typing import Dict, List, Any, Optional
import numpy as np
from datetime import datetime, timedelta
import json


@dataclass
class PerformanceMetrics:
    """Performance metrics for system evaluation"""
    
    # Throughput metrics
    packets_per_second: float = 0.0
    bytes_per_second: float = 0.0
    processing_latency_ms: float = 0.0
    
    # Resource utilization
    cpu_usage_percent: float = 0.0
    memory_usage_mb: float = 0.0
    disk_io_rate: float = 0.0
    
    # Network metrics
    dropped_packets: int = 0
    retransmissions: int = 0
    connection_errors: int = 0
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            'packets_per_second': self.packets_per_second,
            'bytes_per_second': self.bytes_per_second,
            'processing_latency_ms': self.processing_latency_ms,
            'cpu_usage_percent': self.cpu_usage_percent,
            'memory_usage_mb': self.memory_usage_mb,
            'disk_io_rate': self.disk_io_rate,
            'dropped_packets': self.dropped_packets,
            'retransmissions': self.retransmissions,
            'connection_errors': self.connection_errors
        }


@dataclass 
class SecurityMetrics:
    """Security effectiveness metrics"""
    
    # Detection metrics
    true_positives: int = 0
    false_positives: int = 0
    true_negatives: int = 0
    false_negatives: int = 0
    
    # Attack detection
    attacks_detected: int = 0
    attacks_missed: int = 0
    attack_types_detected: List[str] = field(default_factory=list)
    
    # Response metrics
    average_response_time_ms: float = 0.0
    false_alarm_rate: float = 0.0
    
    def precision(self) -> float:
        """Calculate precision"""
        if (self.true_positives + self.false_positives) == 0:
            return 0.0
        return self.true_positives / (self.true_positives + self.false_positives)
    
    def recall(self) -> float:
        """Calculate recall"""
        if (self.true_positives + self.false_negatives) == 0:
            return 0.0
        return self.true_positives / (self.true_positives + self.false_negatives)
    
    def f1_score(self) -> float:
        """Calculate F1 score"""
        p = self.precision()
        r = self.recall()
        if (p + r) == 0:
            return 0.0
        return 2 * (p * r) / (p + r)
    
    def accuracy(self) -> float:
        """Calculate accuracy"""
        total = self.true_positives + self.false_positives + self.true_negatives + self.false_negatives
        if total == 0:
            return 0.0
        return (self.true_positives + self.true_negatives) / total
    
    def detection_rate(self) -> float:
        """Calculate attack detection rate"""
        total_attacks = self.attacks_detected + self.attacks_missed
        if total_attacks == 0:
            return 0.0
        return self.attacks_detected / total_attacks
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            'true_positives': self.true_positives,
            'false_positives': self.false_positives,
            'true_negatives': self.true_negatives,
            'false_negatives': self.false_negatives,
            'attacks_detected': self.attacks_detected,
            'attacks_missed': self.attacks_missed,
            'attack_types_detected': self.attack_types_detected,
            'average_response_time_ms': self.average_response_time_ms,
            'false_alarm_rate': self.false_alarm_rate,
            'precision': self.precision(),
            'recall': self.recall(),
            'f1_score': self.f1_score(),
            'accuracy': self.accuracy(),
            'detection_rate': self.detection_rate()
        }


@dataclass
class RLMetrics:
    """Reinforcement Learning specific metrics"""
    
    # Training metrics
    total_episodes: int = 0
    total_steps: int = 0
    average_reward: float = 0.0
    reward_std: float = 0.0
    
    # Learning metrics
    policy_loss: float = 0.0
    value_loss: float = 0.0
    entropy: float = 0.0
    learning_rate: float = 0.0
    
    # Decision metrics
    action_distribution: Dict[str, int] = field(default_factory=dict)
    decision_confidence: float = 0.0
    exploration_rate: float = 0.0
    
    # Performance over time
    reward_history: List[float] = field(default_factory=list)
    loss_history: List[float] = field(default_factory=list)
    
    def add_episode_reward(self, reward: float):
        """Add reward from completed episode"""
        self.reward_history.append(reward)
        self.total_episodes += 1
        
        # Update running statistics
        if self.reward_history:
            self.average_reward = np.mean(self.reward_history)
            self.reward_std = np.std(self.reward_history)
    
    def add_loss(self, loss: float):
        """Add training loss"""
        self.loss_history.append(loss)
    
    def get_recent_performance(self, window: int = 100) -> Dict[str, float]:
        """Get performance over recent episodes"""
        if len(self.reward_history) < window:
            recent_rewards = self.reward_history
        else:
            recent_rewards = self.reward_history[-window:]
        
        if not recent_rewards:
            return {'mean': 0.0, 'std': 0.0, 'min': 0.0, 'max': 0.0}
        
        return {
            'mean': np.mean(recent_rewards),
            'std': np.std(recent_rewards),
            'min': np.min(recent_rewards),
            'max': np.max(recent_rewards)
        }
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            'total_episodes': self.total_episodes,
            'total_steps': self.total_steps,
            'average_reward': self.average_reward,
            'reward_std': self.reward_std,
            'policy_loss': self.policy_loss,
            'value_loss': self.value_loss,
            'entropy': self.entropy,
            'learning_rate': self.learning_rate,
            'action_distribution': self.action_distribution,
            'decision_confidence': self.decision_confidence,
            'exploration_rate': self.exploration_rate,
            'recent_performance': self.get_recent_performance()
        }


@dataclass
class EvaluationMetrics:
    """Comprehensive evaluation metrics"""
    
    # Timestamp and metadata
    timestamp: datetime = field(default_factory=datetime.now)
    evaluation_duration: timedelta = field(default_factory=timedelta)
    test_name: str = ""
    description: str = ""
    
    # Component metrics
    performance: PerformanceMetrics = field(default_factory=PerformanceMetrics)
    security: SecurityMetrics = field(default_factory=SecurityMetrics)
    rl_metrics: RLMetrics = field(default_factory=RLMetrics)
    
    # Custom metrics
    custom_metrics: Dict[str, Any] = field(default_factory=dict)
    
    def overall_score(self) -> float:
        """Calculate overall system score (0-100)"""
        
        # Performance score (0-30)
        perf_score = 0.0
        if self.performance.packets_per_second > 0:
            # Normalize based on expected performance
            expected_pps = 1000  # packets per second
            perf_score = min(30.0, (self.performance.packets_per_second / expected_pps) * 30)
        
        # Security score (0-50)
        security_score = 0.0
        if hasattr(self.security, 'f1_score'):
            security_score = self.security.f1_score() * 50
        
        # RL performance score (0-20)
        rl_score = 0.0
        if self.rl_metrics.average_reward != 0:
            # Normalize reward to 0-20 range (assuming reward range -100 to 100)
            normalized_reward = (self.rl_metrics.average_reward + 100) / 200
            rl_score = max(0.0, min(20.0, normalized_reward * 20))
        
        return perf_score + security_score + rl_score
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization"""
        return {
            'timestamp': self.timestamp.isoformat(),
            'evaluation_duration': str(self.evaluation_duration),
            'test_name': self.test_name,
            'description': self.description,
            'performance': self.performance.to_dict(),
            'security': self.security.to_dict(),
            'rl_metrics': self.rl_metrics.to_dict(),
            'custom_metrics': self.custom_metrics,
            'overall_score': self.overall_score()
        }
    
    def save_to_file(self, filepath: str):
        """Save metrics to JSON file"""
        with open(filepath, 'w') as f:
            json.dump(self.to_dict(), f, indent=2)
    
    @classmethod
    def load_from_file(cls, filepath: str) -> 'EvaluationMetrics':
        """Load metrics from JSON file"""
        with open(filepath, 'r') as f:
            data = json.load(f)
        
        # Reconstruct object (simplified version)
        metrics = cls()
        metrics.test_name = data.get('test_name', '')
        metrics.description = data.get('description', '')
        
        # Load performance metrics
        perf_data = data.get('performance', {})
        metrics.performance = PerformanceMetrics(**perf_data)
        
        # Load security metrics
        sec_data = data.get('security', {})
        security_metrics = SecurityMetrics()
        for key, value in sec_data.items():
            if hasattr(security_metrics, key) and not callable(getattr(security_metrics, key)):
                setattr(security_metrics, key, value)
        metrics.security = security_metrics
        
        # Load RL metrics
        rl_data = data.get('rl_metrics', {})
        rl_metrics = RLMetrics()
        for key, value in rl_data.items():
            if hasattr(rl_metrics, key) and not callable(getattr(rl_metrics, key)):
                setattr(rl_metrics, key, value)
        metrics.rl_metrics = rl_metrics
        
        metrics.custom_metrics = data.get('custom_metrics', {})
        
        return metrics


class MetricsCollector:
    """Collects and aggregates metrics during evaluation"""
    
    def __init__(self):
        self.metrics_history: List[EvaluationMetrics] = []
        self.current_metrics: Optional[EvaluationMetrics] = None
        
    def start_evaluation(self, test_name: str, description: str = ""):
        """Start a new evaluation session"""
        self.current_metrics = EvaluationMetrics(
            test_name=test_name,
            description=description,
            timestamp=datetime.now()
        )
    
    def end_evaluation(self):
        """End current evaluation session"""
        if self.current_metrics:
            self.current_metrics.evaluation_duration = datetime.now() - self.current_metrics.timestamp
            self.metrics_history.append(self.current_metrics)
            self.current_metrics = None
    
    def record_performance(self, **kwargs):
        """Record performance metrics"""
        if self.current_metrics:
            for key, value in kwargs.items():
                if hasattr(self.current_metrics.performance, key):
                    setattr(self.current_metrics.performance, key, value)
    
    def record_security(self, **kwargs):
        """Record security metrics"""
        if self.current_metrics:
            for key, value in kwargs.items():
                if hasattr(self.current_metrics.security, key):
                    setattr(self.current_metrics.security, key, value)
    
    def record_rl_metrics(self, **kwargs):
        """Record RL metrics"""
        if self.current_metrics:
            for key, value in kwargs.items():
                if hasattr(self.current_metrics.rl_metrics, key):
                    setattr(self.current_metrics.rl_metrics, key, value)
    
    def record_custom(self, **kwargs):
        """Record custom metrics"""
        if self.current_metrics:
            self.current_metrics.custom_metrics.update(kwargs)
    
    def get_summary(self) -> Dict[str, Any]:
        """Get summary of all evaluations"""
        if not self.metrics_history:
            return {}
        
        scores = [m.overall_score() for m in self.metrics_history]
        
        return {
            'total_evaluations': len(self.metrics_history),
            'average_score': np.mean(scores),
            'best_score': np.max(scores),
            'worst_score': np.min(scores),
            'score_std': np.std(scores),
            'latest_evaluation': self.metrics_history[-1].to_dict()
        }
    
    def save_all(self, directory: str):
        """Save all metrics to directory"""
        import os
        os.makedirs(directory, exist_ok=True)
        
        for i, metrics in enumerate(self.metrics_history):
            filename = f"evaluation_{i:03d}_{metrics.test_name.replace(' ', '_')}.json"
            filepath = os.path.join(directory, filename)
            metrics.save_to_file(filepath)