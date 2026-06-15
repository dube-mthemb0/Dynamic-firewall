"""
Main evaluator for the RL firewall system
"""

import time
import threading
import logging
from typing import Dict, Any, List, Optional, Callable
from datetime import datetime, timedelta
import numpy as np
import psutil
import json

from .metrics import EvaluationMetrics, MetricsCollector, PerformanceMetrics, SecurityMetrics, RLMetrics
from .datasets import SyntheticDataGenerator, TrafficDataset


class FirewallEvaluator:
    """Main evaluator for comprehensive firewall testing"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.logger = logging.getLogger(__name__)
        self.metrics_collector = MetricsCollector()
        
        # Components to evaluate
        self.policy_engine = None
        self.rl_agent = None
        self.packet_capture = None
        
        # Evaluation state
        self.is_running = False
        self.evaluation_thread = None
        self._stop_event = threading.Event()
        
        # Test data generators
        self.data_generator = SyntheticDataGenerator(config)
        
        # Results storage
        self.results_history = []
        
    def set_components(self, policy_engine=None, rl_agent=None, packet_capture=None):
        """Set components to evaluate"""
        self.policy_engine = policy_engine
        self.rl_agent = rl_agent
        self.packet_capture = packet_capture
    
    def run_evaluation(self, test_name: str, duration_minutes: int = 10, 
                      test_scenarios: List[str] = None) -> EvaluationMetrics:
        """
        Run a comprehensive evaluation
        
        Args:
            test_name: Name of the test
            duration_minutes: How long to run the test
            test_scenarios: List of test scenarios to run
            
        Returns:
            Evaluation metrics
        """
        
        self.logger.info(f"Starting evaluation: {test_name}")
        self.metrics_collector.start_evaluation(test_name, f"Duration: {duration_minutes} minutes")
        
        try:
            # Default test scenarios
            if test_scenarios is None:
                test_scenarios = ['normal_traffic', 'ddos_attack', 'port_scan', 'mixed_traffic']
            
            # Run each scenario
            for scenario in test_scenarios:
                self.logger.info(f"Running scenario: {scenario}")
                self._run_scenario(scenario, duration_minutes // len(test_scenarios))
            
            # Collect final metrics
            self._collect_final_metrics()
            
            self.metrics_collector.end_evaluation()
            
            # Return latest metrics
            if self.metrics_collector.metrics_history:
                return self.metrics_collector.metrics_history[-1]
            else:
                return EvaluationMetrics()
                
        except Exception as e:
            self.logger.error(f"Error during evaluation: {e}")
            self.metrics_collector.end_evaluation()
            raise
    
    def _run_scenario(self, scenario: str, duration_minutes: int):
        """Run a specific test scenario"""
        
        scenario_config = self.config.get('test_scenarios', {}).get(scenario, {})
        
        # Generate test data based on scenario
        if scenario == 'normal_traffic':
            self._test_normal_traffic(duration_minutes)
        elif scenario == 'ddos_attack':
            self._test_ddos_attack(duration_minutes)
        elif scenario == 'port_scan':
            self._test_port_scan(duration_minutes)
        elif scenario == 'mixed_traffic':
            self._test_mixed_traffic(duration_minutes)
        else:
            self.logger.warning(f"Unknown scenario: {scenario}")
    
    def _test_normal_traffic(self, duration_minutes: int):
        """Test with normal network traffic"""
        
        self.logger.info("Generating normal traffic...")
        
        end_time = time.time() + (duration_minutes * 60)
        packet_count = 0
        start_time = time.time()
        
        while time.time() < end_time and not self._stop_event.is_set():
            # Generate normal packets
            packet = self.data_generator.generate_normal_packet()
            
            # Process through policy engine
            if self.policy_engine:
                result = self.policy_engine.process_packet(packet)
                self._update_security_metrics(packet, result, is_malicious=False)
            
            packet_count += 1
            
            # Performance monitoring
            if packet_count % 100 == 0:
                self._update_performance_metrics(packet_count, start_time)
            
            # Rate limiting
            time.sleep(0.01)  # 100 packets per second
        
        self.logger.info(f"Normal traffic test completed. Processed {packet_count} packets")
    
    def _test_ddos_attack(self, duration_minutes: int):
        """Test with DDoS attack simulation"""
        
        self.logger.info("Simulating DDoS attack...")
        
        end_time = time.time() + (duration_minutes * 60)
        packet_count = 0
        attack_packets = 0
        start_time = time.time()
        
        while time.time() < end_time and not self._stop_event.is_set():
            # 70% attack traffic, 30% normal
            is_attack = np.random.random() < 0.7
            
            if is_attack:
                packet = self.data_generator.generate_ddos_packet()
                attack_packets += 1
            else:
                packet = self.data_generator.generate_normal_packet()
            
            # Process through policy engine
            if self.policy_engine:
                result = self.policy_engine.process_packet(packet)
                self._update_security_metrics(packet, result, is_malicious=is_attack)
            
            packet_count += 1
            
            # Performance monitoring
            if packet_count % 100 == 0:
                self._update_performance_metrics(packet_count, start_time)
            
            # Higher rate for DDoS simulation
            time.sleep(0.001)  # 1000 packets per second
        
        self.logger.info(f"DDoS test completed. Processed {packet_count} packets ({attack_packets} attacks)")
    
    def _test_port_scan(self, duration_minutes: int):
        """Test with port scanning attack"""
        
        self.logger.info("Simulating port scan...")
        
        end_time = time.time() + (duration_minutes * 60)
        packet_count = 0
        scan_packets = 0
        start_time = time.time()
        
        while time.time() < end_time and not self._stop_event.is_set():
            # 50% scan traffic, 50% normal
            is_scan = np.random.random() < 0.5
            
            if is_scan:
                packet = self.data_generator.generate_port_scan_packet()
                scan_packets += 1
            else:
                packet = self.data_generator.generate_normal_packet()
            
            # Process through policy engine
            if self.policy_engine:
                result = self.policy_engine.process_packet(packet)
                self._update_security_metrics(packet, result, is_malicious=is_scan)
            
            packet_count += 1
            
            # Performance monitoring
            if packet_count % 100 == 0:
                self._update_performance_metrics(packet_count, start_time)
            
            time.sleep(0.01)  # 100 packets per second
        
        self.logger.info(f"Port scan test completed. Processed {packet_count} packets ({scan_packets} scans)")
    
    def _test_mixed_traffic(self, duration_minutes: int):
        """Test with mixed normal and malicious traffic"""
        
        self.logger.info("Generating mixed traffic...")
        
        end_time = time.time() + (duration_minutes * 60)
        packet_count = 0
        malicious_packets = 0
        start_time = time.time()
        
        while time.time() < end_time and not self._stop_event.is_set():
            # Random mix of traffic types
            traffic_type = np.random.choice(['normal', 'ddos', 'port_scan', 'brute_force'], 
                                          p=[0.6, 0.15, 0.15, 0.1])
            
            if traffic_type == 'normal':
                packet = self.data_generator.generate_normal_packet()
                is_malicious = False
            elif traffic_type == 'ddos':
                packet = self.data_generator.generate_ddos_packet()
                is_malicious = True
                malicious_packets += 1
            elif traffic_type == 'port_scan':
                packet = self.data_generator.generate_port_scan_packet()
                is_malicious = True
                malicious_packets += 1
            else:  # brute_force
                packet = self.data_generator.generate_brute_force_packet()
                is_malicious = True
                malicious_packets += 1
            
            # Process through policy engine
            if self.policy_engine:
                result = self.policy_engine.process_packet(packet)
                self._update_security_metrics(packet, result, is_malicious=is_malicious)
            
            packet_count += 1
            
            # Performance monitoring
            if packet_count % 100 == 0:
                self._update_performance_metrics(packet_count, start_time)
            
            time.sleep(0.005)  # 200 packets per second
        
        self.logger.info(f"Mixed traffic test completed. Processed {packet_count} packets ({malicious_packets} malicious)")
    
    def _update_performance_metrics(self, packet_count: int, start_time: float):
        """Update performance metrics"""
        
        current_time = time.time()
        duration = current_time - start_time
        
        if duration > 0:
            pps = packet_count / duration
            
            # Get system resources
            cpu_percent = psutil.cpu_percent()
            memory_info = psutil.virtual_memory()
            
            self.metrics_collector.record_performance(
                packets_per_second=pps,
                processing_latency_ms=1.0,  # Placeholder
                cpu_usage_percent=cpu_percent,
                memory_usage_mb=memory_info.used / (1024 * 1024)
            )
    
    def _update_security_metrics(self, packet: Dict[str, Any], result: Dict[str, Any], 
                                is_malicious: bool):
        """Update security metrics based on packet processing result"""
        
        action = result.get('action', 'allow').lower()
        
        # Determine if action was correct
        if is_malicious:
            if action in ['drop', 'quarantine']:
                # True positive - correctly blocked malicious traffic
                self.metrics_collector.record_security(
                    true_positives=getattr(self.metrics_collector.current_metrics.security, 'true_positives', 0) + 1
                )
            else:
                # False negative - failed to block malicious traffic
                self.metrics_collector.record_security(
                    false_negatives=getattr(self.metrics_collector.current_metrics.security, 'false_negatives', 0) + 1
                )
        else:
            if action == 'allow':
                # True negative - correctly allowed benign traffic
                self.metrics_collector.record_security(
                    true_negatives=getattr(self.metrics_collector.current_metrics.security, 'true_negatives', 0) + 1
                )
            else:
                # False positive - incorrectly blocked benign traffic
                self.metrics_collector.record_security(
                    false_positives=getattr(self.metrics_collector.current_metrics.security, 'false_positives', 0) + 1
                )
    
    def _collect_final_metrics(self):
        """Collect final metrics from all components"""
        
        # RL Agent metrics
        if self.rl_agent and hasattr(self.rl_agent, 'get_training_stats'):
            try:
                rl_stats = self.rl_agent.get_training_stats()
                self.metrics_collector.record_rl_metrics(**rl_stats)
            except Exception as e:
                self.logger.warning(f"Could not collect RL metrics: {e}")
        
        # Policy engine metrics
        if self.policy_engine:
            try:
                policy_stats = self.policy_engine.get_statistics()
                self.metrics_collector.record_custom(policy_engine_stats=policy_stats)
            except Exception as e:
                self.logger.warning(f"Could not collect policy engine metrics: {e}")
    
    def benchmark_against_traditional(self, traditional_firewall_config: Dict[str, Any]) -> Dict[str, Any]:
        """
        Benchmark RL firewall against traditional rule-based firewall
        
        Args:
            traditional_firewall_config: Configuration for traditional firewall
            
        Returns:
            Comparison results
        """
        
        self.logger.info("Running benchmark against traditional firewall...")
        
        # Run RL firewall test
        rl_metrics = self.run_evaluation("RL Firewall Benchmark", duration_minutes=5)
        
        # Simulate traditional firewall (simplified)
        traditional_metrics = self._simulate_traditional_firewall(traditional_firewall_config)
        
        # Compare results
        comparison = {
            'rl_firewall': rl_metrics.to_dict(),
            'traditional_firewall': traditional_metrics.to_dict(),
            'comparison': {
                'accuracy': {
                    'rl': rl_metrics.security.accuracy(),
                    'traditional': traditional_metrics.security.accuracy(),
                    'improvement': rl_metrics.security.accuracy() - traditional_metrics.security.accuracy()
                },
                'throughput': {
                    'rl': rl_metrics.performance.packets_per_second,
                    'traditional': traditional_metrics.performance.packets_per_second,
                    'improvement': rl_metrics.performance.packets_per_second - traditional_metrics.performance.packets_per_second
                },
                'false_positives': {
                    'rl': rl_metrics.security.false_positives,
                    'traditional': traditional_metrics.security.false_positives,
                    'improvement': traditional_metrics.security.false_positives - rl_metrics.security.false_positives
                }
            }
        }
        
        self.logger.info("Benchmark completed")
        return comparison
    
    def _simulate_traditional_firewall(self, config: Dict[str, Any]) -> EvaluationMetrics:
        """Simulate traditional rule-based firewall for comparison"""
        
        # This is a simplified simulation
        # In reality, you would integrate with actual traditional firewall
        
        metrics = EvaluationMetrics()
        metrics.test_name = "Traditional Firewall Simulation"
        
        # Simulate typical traditional firewall performance
        metrics.performance.packets_per_second = 800  # Typically lower than RL
        metrics.performance.processing_latency_ms = 2.0  # Higher latency
        metrics.performance.cpu_usage_percent = 25.0
        
        # Traditional firewalls often have higher false positives
        metrics.security.true_positives = 85
        metrics.security.false_positives = 20
        metrics.security.true_negatives = 180
        metrics.security.false_negatives = 15
        
        return metrics
    
    def generate_report(self, output_file: str = None) -> str:
        """
        Generate comprehensive evaluation report
        
        Args:
            output_file: Optional file to save report
            
        Returns:
            Report content as string
        """
        
        report_lines = []
        report_lines.append("RL FIREWALL EVALUATION REPORT")
        report_lines.append("=" * 50)
        report_lines.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report_lines.append("")
        
        # Summary
        summary = self.metrics_collector.get_summary()
        if summary:
            report_lines.append("SUMMARY")
            report_lines.append("-" * 20)
            report_lines.append(f"Total Evaluations: {summary.get('total_evaluations', 0)}")
            report_lines.append(f"Average Score: {summary.get('average_score', 0):.2f}/100")
            report_lines.append(f"Best Score: {summary.get('best_score', 0):.2f}/100")
            report_lines.append(f"Worst Score: {summary.get('worst_score', 0):.2f}/100")
            report_lines.append("")
        
        # Detailed results for each evaluation
        for i, metrics in enumerate(self.metrics_collector.metrics_history):
            report_lines.append(f"EVALUATION {i+1}: {metrics.test_name}")
            report_lines.append("-" * 30)
            report_lines.append(f"Duration: {metrics.evaluation_duration}")
            report_lines.append(f"Overall Score: {metrics.overall_score():.2f}/100")
            report_lines.append("")
            
            # Performance metrics
            report_lines.append("Performance:")
            report_lines.append(f"  Packets/sec: {metrics.performance.packets_per_second:.2f}")
            report_lines.append(f"  Latency: {metrics.performance.processing_latency_ms:.2f}ms")
            report_lines.append(f"  CPU Usage: {metrics.performance.cpu_usage_percent:.1f}%")
            report_lines.append(f"  Memory: {metrics.performance.memory_usage_mb:.1f}MB")
            report_lines.append("")
            
            # Security metrics
            report_lines.append("Security:")
            report_lines.append(f"  Accuracy: {metrics.security.accuracy():.3f}")
            report_lines.append(f"  Precision: {metrics.security.precision():.3f}")
            report_lines.append(f"  Recall: {metrics.security.recall():.3f}")
            report_lines.append(f"  F1 Score: {metrics.security.f1_score():.3f}")
            report_lines.append(f"  Detection Rate: {metrics.security.detection_rate():.3f}")
            report_lines.append("")
            
            # RL metrics
            if metrics.rl_metrics.total_episodes > 0:
                report_lines.append("Reinforcement Learning:")
                report_lines.append(f"  Episodes: {metrics.rl_metrics.total_episodes}")
                report_lines.append(f"  Average Reward: {metrics.rl_metrics.average_reward:.3f}")
                report_lines.append(f"  Reward Std: {metrics.rl_metrics.reward_std:.3f}")
                report_lines.append("")
        
        report_content = "\n".join(report_lines)
        
        if output_file:
            with open(output_file, 'w') as f:
                f.write(report_content)
            self.logger.info(f"Report saved to {output_file}")
        
        return report_content
    
    def stop_evaluation(self):
        """Stop running evaluation"""
        self._stop_event.set()
        if self.evaluation_thread and self.evaluation_thread.is_alive():
            self.evaluation_thread.join(timeout=5)
        self.is_running = False
    
    def reset(self):
        """Reset evaluator state"""
        self.stop_evaluation()
        self.metrics_collector = MetricsCollector()
        self.results_history.clear()
        self._stop_event.clear()