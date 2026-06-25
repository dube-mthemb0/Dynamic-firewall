"""
Main Application Entry Point
Dynamic Reinforcement Learning Firewall - README & Flag Compliant
"""

import argparse
import yaml
import sys
import os
import json  # Added for streaming dynamic stats to the dashboard
from pathlib import Path
from typing import Dict, Any
import numpy as np

# Add project directories to path for flexible execution contexts
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), 'src')))
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from loguru import logger
from src.packet_capture import PacketCapture, FeatureExtractor
from src.rl_agent import FirewallAgent, make_firewall_env
from src.policy_engine.engine import PolicyEngine as FirewallEngine 


def load_config(config_path: str) -> Dict[str, Any]:
    """Load configuration from YAML file"""
    try:
        with open(config_path, 'r') as f:
            config = yaml.safe_load(f)
        logger.info(f"Configuration loaded from {config_path}")
        return config
    except FileNotFoundError:
        logger.error(f"Configuration file not found: {config_path}")
        sys.exit(1)
    except yaml.YAMLError as e:
        logger.error(f"Error parsing configuration file: {e}")
        sys.exit(1)


def setup_logging(config: Dict) -> None:
    """Setup logging configuration"""
    log_level = config.get('logging', {}).get('level', 'INFO')
    log_format = config.get('logging', {}).get('format', 
                           '<green>{time:YYYY-MM-DD HH:mm:ss}</green> | '
                           '<level>{level: <8}</level> | '
                           '<cyan>{name}</cyan>:<cyan>{function}</cyan>:<cyan>{line}</cyan> | '
                           '<level>{message}</level>')
    
    logger.remove()
    logger.add(sys.stderr, level=log_level, format=log_format)
    
    if 'main_log' in config.get('logging', {}):
        log_file = config['logging']['main_log']
        os.makedirs(os.path.dirname(log_file), exist_ok=True)
        logger.add(
            log_file, level=log_level, format=log_format,
            rotation=config.get('logging', {}).get('max_size', '10MB'),
            retention=config.get('logging', {}).get('backup_count', 5)
        )


def cmd_capture(config: Dict, args: argparse.Namespace) -> None:
    """Run packet capture mode"""
    logger.info("Starting packet capture mode...")
    
    capture_config = config.get('packet_capture', {})
    capture_config.update(config.get('network', {}))
    
    capture = PacketCapture(capture_config)
    feature_extractor = FeatureExtractor(config.get('features', {}))
    
    def packet_processor(packet_info, flow_features):
        feature_vector = feature_extractor.extract_features(packet_info, flow_features)
        logger.debug(f"Captured packet: {packet_info.src_ip}:{packet_info.src_port} -> "
                    f"{packet_info.dst_ip}:{packet_info.dst_port} ({packet_info.protocol})")
    
    capture.add_packet_callback(packet_processor)
    
    try:
        capture.start_capture()
        logger.info("Packet capture started. Press Ctrl+C to stop.")
        import time
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        logger.info("Capture interrupted by user")
    finally:
        capture.stop_capture()
        stats = capture.get_statistics()
        logger.info(f"Capture statistics: {stats}")


def cmd_train(config: Dict, args: argparse.Namespace) -> None:
    """Run training mode"""
    logger.info("Starting RL agent training...")
    
    agent_config = config.get('rl_agent', {})
    agent_config.update(config.get('features', {}))
    agent_config.update(config.get('rewards', {}))
    
    # 🎯 FORCE FEATURE ALIGNMENT
    # Automatically scale training observations to match all 40 live features
    agent_config['state_size'] = 40
    logger.info("Training environment optimized to accept 40 feature matrix dimensions.")
    
    if args.algorithm:
        agent_config['algorithm'] = args.algorithm
    if args.timesteps:
        agent_config['total_timesteps'] = args.timesteps
    if args.model_path:
        agent_config['model_save_path'] = args.model_path
    if args.dataset:
        agent_config['dataset_path'] = args.dataset
        logger.info(f"Targeting training dataset: {args.dataset}")
    
    agent = FirewallAgent(agent_config)
    
    try:
        agent.train(resume_training=args.resume)
        logger.info("Evaluating trained model...")
        results = agent.evaluate(n_episodes=50)
        logger.info("Training completed successfully!")
        logger.info(f"Final evaluation results: {results}")
    except Exception as e:
        logger.error(f"Training failed: {e}")
        sys.exit(1)


def cmd_firewall(config: Dict, args: argparse.Namespace) -> None:
    """Run live firewall mode"""
    logger.info("Starting live firewall mode...")
    
    try:
        capture_config = config.get('packet_capture', {})
        capture_config.update(config.get('network', {}))
        
        agent_config = config.get('rl_agent', {})
        agent_config.update(config.get('features', {}))
        
        capture = PacketCapture(capture_config)
        feature_extractor = FeatureExtractor(config.get('features', {}))
        agent = FirewallAgent(agent_config)
        
        # ==========================================
        # 📊 TWO-WAY DYNAMIC RULES INTERFACE BRIDGE
        # ==========================================
        stats_file = os.path.join("logs", "dashboard_stats.json")
        os.makedirs("logs", exist_ok=True)
        
        firewall_stats = {
            "packets_processed": 0,
            "packets_allowed": 0,
            "packets_blocked": 0,
            "action_counts": {"ALLOW": 0, "DROP": 0, "LOG": 0, "QUARANTINE": 0},
            "protocols": {"TCP": 0, "UDP": 0, "ICMP": 0, "HTTP": 0, "HTTPS": 0},
            "rules": [
                {"id": "rule_1", "name": "Block Target Subnet", "src_ip": "20.87.245.6", "dst_ip": "*", "action": "DROP", "priority": 10, "enabled": True, "hit_count": 0},
                {"id": "rule_2", "name": "Allow Local DNS", "src_ip": "*", "dst_ip": "8.8.8.8", "action": "ALLOW", "priority": 20, "enabled": True, "hit_count": 0},
                {"id": "rule_3", "name": "Dynamic RL Active Policy", "src_ip": "*", "dst_ip": "*", "action": "ALLOW", "priority": 99, "enabled": True, "hit_count": 0}
            ]
        }
        
        # Seed the shared pipeline configuration metrics
        with open(stats_file, 'w') as f:
            json.dump(firewall_stats, f)
        
        # Determine model path location
        target_path = args.model_path or "models/"
        if os.path.exists(target_path):
            if os.path.isdir(target_path):
                agent.model_save_path = target_path
                agent.model = agent.load_model(None)
            else:
                base_dir = os.path.dirname(target_path)
                filename = os.path.basename(target_path)
                if filename.endswith('.zip'):
                    filename = filename[:-4]
                if base_dir:
                    agent.model_save_path = base_dir
                agent.model = agent.load_model(filename)
        else:
            logger.warning(f"No trained model found at '{target_path}', defaulting to active policy scanning")
            agent.model = agent.load_model(None) if os.path.exists("models/") else None
        
        def firewall_processor(packet_info, flow_features):
            nonlocal firewall_stats
            try:
                # 🔄 Hot-reload external policy modifications injected by the UI process
                if os.path.exists(stats_file):
                    try:
                        with open(stats_file, 'r') as f:
                            disk_stats = json.load(f)
                            if "rules" in disk_stats:
                                firewall_stats["rules"] = disk_stats["rules"]
                    except Exception:
                        pass  # Safely drop read collisions during fast writes
                
                feature_vector = feature_extractor.extract_features(packet_info, flow_features)
                normalized_features = feature_extractor.normalize_features(feature_vector)
                
                if hasattr(normalized_features, 'features'):
                    raw_features = normalized_features.features
                else:
                    raw_features = normalized_features
                
                if not isinstance(raw_features, np.ndarray):
                    raw_features = np.array(raw_features)
                
                # Dynamic model feature alignment guard
                expected_dim = 40
                if agent.model and hasattr(agent.model, 'observation_space') and agent.model.observation_space is not None:
                    expected_dim = agent.model.observation_space.shape[0]
                    
                if raw_features.shape[0] > expected_dim:
                    raw_features = raw_features[:expected_dim]
                elif raw_features.shape[0] < expected_dim:
                    raw_features = np.pad(raw_features, (0, expected_dim - raw_features.shape[0]), 'constant')
                
                if agent.model:
                    action, confidence = agent.predict(raw_features)
                    if hasattr(action, 'item'):
                        action = int(action.item())
                    elif isinstance(action, (np.ndarray, list)):
                        action = int(np.asarray(action).flat[0])
                    else:
                        action = int(action)
                        
                    action_name = ["ALLOW", "DROP", "LOG", "QUARANTINE"][action]
                else:
                    action, action_name, confidence = 0, "ALLOW", 0.5
                
                logger.info(f"Firewall decision: {action_name} for "
                            f"{packet_info.src_ip}:{packet_info.src_port} -> "
                            f"{packet_info.dst_ip}:{packet_info.dst_port}")
                
                # 🔍 Intercept frame criteria against ACL chains to track hit metrics
                rule_matched = False
                src = str(packet_info.src_ip)
                dst = str(packet_info.dst_ip)
                
                for rule in firewall_stats["rules"]:
                    if not rule.get('enabled', True):
                        continue
                    r_src = rule.get('src_ip', '*')
                    r_dst = rule.get('dst_ip', '*')
                    
                    src_match = (r_src == '*' or r_src == src)
                    dst_match = (r_dst == '*' or r_dst == dst)
                    
                    if src_match and dst_match:
                        rule['hit_count'] = rule.get('hit_count', 0) + 1
                        rule_matched = True
                        break
                        
                # Catch-all assignment if no explicit IP boundaries trigger
                if not rule_matched and len(firewall_stats["rules"]) > 0:
                    for rule in firewall_stats["rules"]:
                        if rule.get('id') == 'rule_3':
                            rule['hit_count'] = rule.get('hit_count', 0) + 1
                
                # Global metrics monitoring track updates
                firewall_stats["packets_processed"] += 1
                
                proto = getattr(packet_info, 'protocol', 'TCP')
                if not isinstance(proto, str):
                    proto = str(proto)
                proto = proto.upper()
                if proto in firewall_stats["protocols"]:
                    firewall_stats["protocols"][proto] += 1
                
                # Accumulate action distributions
                if action_name == "ALLOW":
                    firewall_stats["packets_allowed"] += 1
                    firewall_stats["action_counts"]["ALLOW"] += 1
                elif action_name in ["DROP", "QUARANTINE"]:
                    firewall_stats["packets_blocked"] += 1
                    firewall_stats["action_counts"][action_name] += 1
                else:
                    firewall_stats["action_counts"][action_name] += 1
                
                # Flush back atomic JSON payload updates for dashboard capture
                tmp_file = stats_file + ".tmp"
                with open(tmp_file, 'w') as sf:
                    json.dump(firewall_stats, sf)
                os.replace(tmp_file, stats_file)
                            
            except Exception as callback_err:
                logger.debug(f"Firewall interface tracking trace: {callback_err}")
        
        capture.add_packet_callback(firewall_processor)
        capture.start_capture()
        logger.info("Live firewall started. Press Ctrl+C to stop.")
        
        import time
        while True:
            time.sleep(1)
            
    except KeyboardInterrupt:
        logger.info("Firewall stopped by user")
    except Exception as e:
        logger.error(f"Firewall error: {e}")
        sys.exit(1)
    finally:
        if 'capture' in locals():
            capture.stop_capture()


def cmd_dashboard(config: Dict, args: argparse.Namespace) -> None:
    """Run dashboard mode"""
    logger.info("Starting dashboard...")
    dashboard_config = config.get('dashboard', {})
    try:
        from src.dashboard.app import create_dashboard_app
        app = create_dashboard_app(config)
        host = dashboard_config.get('host', '127.0.0.1')
        port = dashboard_config.get('port', 8050)
        debug = dashboard_config.get('debug', False)
        logger.info(f"Dashboard starting on http://{host}:{port}")
        app.run(host=host, port=port, debug=debug)
    except ImportError:
        logger.error("Dashboard module not available.")
        sys.exit(1)


def cmd_evaluate(config: Dict, args: argparse.Namespace) -> None:
    """Run evaluation mode"""
    logger.info("Starting model evaluation...")
    if not args.model_path:
        logger.error("Model path required for evaluation")
        sys.exit(1)
    
    agent_config = config.get('rl_agent', {})
    agent_config.update(config.get('features', {}))
    agent = FirewallAgent(agent_config)
    
    try:
        if os.path.isdir(args.model_path):
            agent.model_save_path = args.model_path
            agent.model = agent.load_model(None)
        else:
            base_dir = os.path.dirname(args.model_path)
            filename = os.path.basename(args.model_path)
            if filename.endswith('.zip'):
                filename = filename[:-4]
            if base_dir:
                agent.model_save_path = base_dir
            agent.model = agent.load_model(filename)
            
        n_episodes = args.episodes or 100
        results = agent.evaluate(n_episodes=n_episodes)
        logger.info("Evaluation Results:")
        for key, value in results.items():
            logger.info(f"  {key}: {value}")
    except Exception as e:
        logger.error(f"Evaluation failed: {e}")
        sys.exit(1)


def main():
    """Main entry point supporting both positional and flag operation modes"""
    parser = argparse.ArgumentParser(description="Dynamic Reinforcement Learning Firewall")
    parser.add_argument('--config', '-c', default='config/config.yaml', help='Configuration file path')
    
    # 🛡️ README COMPLIANCE FLAG
    parser.add_argument('--mode', choices=['capture', 'train', 'firewall', 'dashboard', 'evaluate'], help='Operation mode flag')
    
    # Global flag options shared across configurations
    parser.add_argument('--duration', type=int, help='Capture duration in seconds')
    parser.add_argument('--algorithm', choices=['DQN', 'PPO'], help='RL algorithm')
    parser.add_argument('--timesteps', type=int, help='Total training timesteps')
    parser.add_argument('--model-path', help='Model path mapping')
    parser.add_argument('--resume', action='store_true', help='Resume training')
    parser.add_argument('--dataset', help='Dataset input location path')
    parser.add_argument('--episodes', type=int, help='Number of evaluation episodes')
    
    # Fallback support for positional tracking
    subparsers = parser.add_subparsers(dest='subparser_mode', help='Positional operation modes')
    subparsers.add_parser('capture')
    subparsers.add_parser('train')
    subparsers.add_parser('firewall')
    subparsers.add_parser('dashboard')
    subparsers.add_parser('evaluate')
    
    args = parser.parse_args()
    
    # Resolve the mode from either flag or subparser fallback
    selected_mode = args.mode or args.subparser_mode
    
    config = load_config(args.config)
    setup_logging(config)
    
    if selected_mode == 'capture':
        cmd_capture(config, args)
    elif selected_mode == 'train':
        cmd_train(config, args)
    elif selected_mode == 'firewall':
        cmd_firewall(config, args)
    elif selected_mode == 'dashboard':
        cmd_dashboard(config, args)
    elif selected_mode == 'evaluate':
        cmd_evaluate(config, args)
    else:
        logger.error("Please specify an operation mode using --mode or a positional command.")
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()