"""
Benchmark suite for RL Firewall evaluation
"""

import time
import logging
from typing import Dict, Any, List, Tuple
from datetime import datetime

from .evaluator import FirewallEvaluator
from .metrics import EvaluationMetrics


class BenchmarkSuite:
    """Comprehensive benchmark suite for RL Firewall"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.logger = logging.getLogger(__name__)
        self.evaluator = FirewallEvaluator(config)
        
        # Define benchmark scenarios
        self.scenarios = [
            ("Baseline Performance", self._baseline_performance_test),
            ("Low Traffic Load", self._low_traffic_test),
            ("Medium Traffic Load", self._medium_traffic_test),
            ("High Traffic Load", self._high_traffic_test),
            ("Attack Detection", self._attack_detection_test),
            ("Port Scan Detection", self._port_scan_test),
            ("DDoS Mitigation", self._ddos_test),
            ("Mixed Attack Scenario", self._mixed_attack_test),
            ("Long Duration Test", self._endurance_test),
            ("Stress Test", self._stress_test)
        ]
    
    def run_all_benchmarks(self, firewall_system) -> List[EvaluationMetrics]:
        """Run complete benchmark suite"""
        
        self.logger.info("Starting comprehensive benchmark suite")
        results = []
        
        for scenario_name, test_func in self.scenarios:
            self.logger.info(f"Running benchmark: {scenario_name}")
            
            try:
                # Setup test environment
                test_config = test_func()
                
                # Run evaluation with custom config
                result = self.evaluator.evaluate_system(firewall_system, scenario_name)
                
                # Add custom metrics from test
                if isinstance(test_config, dict):
                    result.custom_metrics.update(test_config.get('custom_metrics', {}))
                
                results.append(result)
                
                self.logger.info(f"Completed {scenario_name}: Score {result.overall_score():.2f}")
                
                # Brief pause between tests
                time.sleep(2)
                
            except Exception as e:
                self.logger.error(f"Benchmark {scenario_name} failed: {e}")
        
        self.logger.info("Benchmark suite completed")
        return results
    
    def _baseline_performance_test(self) -> Dict[str, Any]:
        """Baseline performance with minimal load"""
        return {
            'packet_rate': 10,
            'duration': 60,
            'attack_ratio': 0.0,
            'description': 'Baseline performance measurement',
            'custom_metrics': {
                'test_type': 'baseline',
                'expected_pps': 10
            }
        }
    
    def _low_traffic_test(self) -> Dict[str, Any]:
        """Low traffic load test"""
        return {
            'packet_rate': 50,
            'duration': 120,
            'attack_ratio': 0.05,
            'description': 'Low traffic load with minimal attacks',
            'custom_metrics': {
                'test_type': 'low_load',
                'expected_pps': 50
            }
        }
    
    def _medium_traffic_test(self) -> Dict[str, Any]:
        """Medium traffic load test"""
        return {
            'packet_rate': 200,
            'duration': 180,
            'attack_ratio': 0.1,
            'description': 'Medium traffic load with moderate attacks',
            'custom_metrics': {
                'test_type': 'medium_load',
                'expected_pps': 200
            }
        }
    
    def _high_traffic_test(self) -> Dict[str, Any]:
        """High traffic load test"""
        return {
            'packet_rate': 1000,
            'duration': 300,
            'attack_ratio': 0.15,
            'description': 'High traffic load stress test',
            'custom_metrics': {
                'test_type': 'high_load',
                'expected_pps': 1000
            }
        }
    
    def _attack_detection_test(self) -> Dict[str, Any]:
        """Focused attack detection test"""
        return {
            'packet_rate': 100,
            'duration': 240,
            'attack_ratio': 0.3,
            'attack_types': ['port_scan', 'ddos', 'brute_force'],
            'description': 'Attack detection accuracy test',
            'custom_metrics': {
                'test_type': 'attack_detection',
                'focus': 'security'
            }
        }
    
    def _port_scan_test(self) -> Dict[str, Any]:
        """Port scan detection test"""
        return {
            'packet_rate': 150,
            'duration': 180,
            'attack_ratio': 0.4,
            'attack_types': ['port_scan'],
            'description': 'Port scan detection test',
            'custom_metrics': {
                'test_type': 'port_scan',
                'attack_focus': 'port_scan'
            }
        }
    
    def _ddos_test(self) -> Dict[str, Any]:
        """DDoS mitigation test"""
        return {
            'packet_rate': 500,
            'duration': 300,
            'attack_ratio': 0.5,
            'attack_types': ['ddos'],
            'description': 'DDoS mitigation effectiveness test',
            'custom_metrics': {
                'test_type': 'ddos',
                'attack_focus': 'ddos'
            }
        }
    
    def _mixed_attack_test(self) -> Dict[str, Any]:
        """Mixed attack scenario"""
        return {
            'packet_rate': 300,
            'duration': 360,
            'attack_ratio': 0.25,
            'attack_types': ['port_scan', 'ddos', 'brute_force'],
            'description': 'Mixed attack scenario test',
            'custom_metrics': {
                'test_type': 'mixed_attacks',
                'complexity': 'high'
            }
        }
    
    def _endurance_test(self) -> Dict[str, Any]:
        """Long duration endurance test"""
        return {
            'packet_rate': 100,
            'duration': 1800,  # 30 minutes
            'attack_ratio': 0.1,
            'description': 'Long duration endurance test',
            'custom_metrics': {
                'test_type': 'endurance',
                'duration_minutes': 30
            }
        }
    
    def _stress_test(self) -> Dict[str, Any]:
        """Maximum load stress test"""
        return {
            'packet_rate': 2000,
            'duration': 180,
            'attack_ratio': 0.2,
            'description': 'Maximum load stress test',
            'custom_metrics': {
                'test_type': 'stress',
                'max_load': True
            }
        }
    
    def generate_benchmark_report(self, results: List[EvaluationMetrics]) -> str:
        """Generate comprehensive benchmark report"""
        
        if not results:
            return "No benchmark results available."
        
        report = []
        report.append("# RL Firewall Benchmark Report")
        report.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report.append(f"Total Benchmarks: {len(results)}")
        report.append("")
        
        # Overall statistics
        scores = [r.overall_score() for r in results]
        report.append("## Overall Performance")
        report.append(f"Average Score: {sum(scores)/len(scores):.2f}/100")
        report.append(f"Best Performance: {max(scores):.2f}/100")
        report.append(f"Worst Performance: {min(scores):.2f}/100")
        report.append("")
        
        # Performance by category
        performance_tests = [r for r in results if 'load' in r.custom_metrics.get('test_type', '')]
        security_tests = [r for r in results if r.custom_metrics.get('focus') == 'security']
        
        if performance_tests:
            perf_scores = [r.overall_score() for r in performance_tests]
            report.append("## Performance Tests")
            report.append(f"Average Performance Score: {sum(perf_scores)/len(perf_scores):.2f}/100")
            report.append("")
        
        if security_tests:
            sec_scores = [r.overall_score() for r in security_tests]
            report.append("## Security Tests")
            report.append(f"Average Security Score: {sum(sec_scores)/len(sec_scores):.2f}/100")
            report.append("")
        
        # Detailed results
        report.append("## Detailed Results")
        for result in results:
            report.append(f"### {result.test_name}")
            report.append(f"Score: {result.overall_score():.2f}/100")
            report.append(f"Duration: {result.evaluation_duration}")
            
            # Performance metrics
            perf = result.performance
            report.append(f"- Throughput: {perf.packets_per_second:.1f} packets/sec")
            report.append(f"- Latency: {perf.processing_latency_ms:.2f}ms")
            report.append(f"- CPU Usage: {perf.cpu_usage_percent:.1f}%")
            
            # Security metrics
            sec = result.security
            report.append(f"- Detection Accuracy: {sec.accuracy():.3f}")
            report.append(f"- False Positive Rate: {sec.false_alarm_rate:.3f}")
            
            report.append("")
        
        return "\n".join(report)
    
    def save_benchmark_results(self, results: List[EvaluationMetrics], directory: str):
        """Save benchmark results to directory"""
        import os
        
        os.makedirs(directory, exist_ok=True)
        
        # Save individual results
        for i, result in enumerate(results):
            filename = f"benchmark_{i:02d}_{result.test_name.replace(' ', '_').lower()}.json"
            filepath = os.path.join(directory, filename)
            result.save_to_file(filepath)
        
        # Save comprehensive report
        report = self.generate_benchmark_report(results)
        report_path = os.path.join(directory, "benchmark_report.md")
        with open(report_path, 'w') as f:
            f.write(report)
        
        self.logger.info(f"Benchmark results saved to {directory}")
    
    def compare_with_baseline(self, results: List[EvaluationMetrics]) -> Dict[str, Any]:
        """Compare results with baseline performance"""
        
        baseline_result = None
        for result in results:
            if result.custom_metrics.get('test_type') == 'baseline':
                baseline_result = result
                break
        
        if not baseline_result:
            return {'error': 'No baseline result found'}
        
        baseline_score = baseline_result.overall_score()
        comparisons = {}
        
        for result in results:
            if result.custom_metrics.get('test_type') != 'baseline':
                score_diff = result.overall_score() - baseline_score
                comparisons[result.test_name] = {
                    'score_difference': score_diff,
                    'performance_ratio': result.overall_score() / baseline_score if baseline_score > 0 else 0,
                    'improvement': score_diff > 0
                }
        
        return {
            'baseline_score': baseline_score,
            'comparisons': comparisons
        }