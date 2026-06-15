"""
Main Application Entry Point
Dynamic Reinforcement Learning Firewall
"""

import argparse
import yaml
import sys
import os
from pathlib import Path
from typing import Dict, Any

# Add src to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from loguru import logger
from src.packet_capture import PacketCapture, FeatureExtractor
from src.rl_agent import FirewallAgent, make_firewall_env
from src.policy_engine.firewall import FirewallEngine  # Will create this
from src.dashboard.app import create_dashboard_app  # Will create this


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
    
    # Configure loguru
    logger.remove()
    logger.add(sys.stderr, level=log_level, format=log_format)
    
    # Add file logging if configured
    if 'main_log' in config.get('logging', {}):
        log_file = config['logging']['main_log']
        os.makedirs(os.path.dirname(log_file), exist_ok=True)
        logger.add(
            log_file,
            level=log_level,
            format=log_format,
            rotation=config.get('logging', {}).get('max_size', '10MB'),
            retention=config.get('logging', {}).get('backup_count', 5)
        )


def cmd_capture(config: Dict, args: argparse.Namespace) -> None:
    """Run packet capture mode"""
    logger.info("Starting packet capture mode...")
    
    # Initialize packet capture
    capture_config = config.get('packet_capture', {})
    capture_config.update(config.get('network', {}))
    
    capture = PacketCapture(capture_config)
    feature_extractor = FeatureExtractor(config.get('features', {}))
    
    # Callback to process captured packets
    def packet_processor(packet_info, flow_features):
        feature_vector = feature_extractor.extract_features(packet_info, flow_features)
        logger.debug(f"Captured packet: {packet_info.src_ip}:{packet_info.src_port} -> "
                    f"{packet_info.dst_ip}:{packet_info.dst_port} ({packet_info.protocol})")
    
    capture.add_packet_callback(packet_processor)
    
    try:
        capture.start_capture()
        logger.info("Packet capture started. Press Ctrl+C to stop.")
        
        # Keep running until interrupted
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
    
    # Prepare agent configuration
    agent_config = config.get('rl_agent', {})
    agent_config.update(config.get('features', {}))
    agent_config.update(config.get('rewards', {}))
    
    # Override with command line arguments
    if args.algorithm:
        agent_config['algorithm'] = args.algorithm
    if args.timesteps:
        agent_config['total_timesteps'] = args.timesteps
    if args.model_path:
        agent_config['model_save_path'] = args.model_path
    
    # Create and train agent
    agent = FirewallAgent(agent_config)
    
    try:
        agent.train(resume_training=args.resume)
        
        # Evaluate trained model
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
    
    # This will integrate all components
    # For now, create a simple implementation
    
    try:
        # Initialize components
        capture_config = config.get('packet_capture', {})
        capture_config.update(config.get('network', {}))
        
        agent_config = config.get('rl_agent', {})
        agent_config.update(config.get('features', {}))
        
        # Create components
        capture = PacketCapture(capture_config)
        feature_extractor = FeatureExtractor(config.get('features', {}))
        agent = FirewallAgent(agent_config)
        
        # Load trained model
        if args.model_path and os.path.exists(args.model_path):
            agent.model = agent.load_model(args.model_path)
        else:
            logger.warning("No trained model specified, using random policy")
        
        # Packet processing callback
        def firewall_processor(packet_info, flow_features):
            # Extract features
            feature_vector = feature_extractor.extract_features(packet_info, flow_features)
            normalized_features = feature_extractor.normalize_features(feature_vector)
            
            # Make firewall decision
            if agent.model:
                action, confidence = agent.predict(normalized_features.features)
                action_name = ["ALLOW", "DROP", "LOG", "QUARANTINE"][action]
            else:
                action, action_name, confidence = 0, "ALLOW", 0.5  # Default allow
            
            logger.info(f"Firewall decision: {action_name} (confidence: {confidence:.3f}) for "
                       f"{packet_info.src_ip}:{packet_info.src_port} -> "
                       f"{packet_info.dst_ip}:{packet_info.dst_port}")
            
            # Here you would implement actual firewall rule application
            # For now, just log the decision
        
        capture.add_packet_callback(firewall_processor)
        
        # Start firewall
        capture.start_capture()
        logger.info("Live firewall started. Press Ctrl+C to stop.")
        
        # Keep running
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
    
    # Import dashboard app
    try:
        from src.dashboard.app import create_dashboard_app
        app = create_dashboard_app(config)
        
        host = dashboard_config.get('host', '127.0.0.1')
        port = dashboard_config.get('port', 8050)
        debug = dashboard_config.get('debug', False)
        
        logger.info(f"Dashboard starting on http://{host}:{port}")
        app.run_server(host=host, port=port, debug=debug)
        
    except ImportError:
        logger.error("Dashboard module not available. Please implement src/dashboard/app.py")
        sys.exit(1)


def cmd_evaluate(config: Dict, args: argparse.Namespace) -> None:
    """Run evaluation mode"""
    logger.info("Starting model evaluation...")
    
    if not args.model_path:
        logger.error("Model path required for evaluation")
        sys.exit(1)
    
    # Create agent and load model
    agent_config = config.get('rl_agent', {})
    agent_config.update(config.get('features', {}))
    
    agent = FirewallAgent(agent_config)
    
    try:
        agent.model = agent.load_model(args.model_path)
        
        # Run evaluation
        n_episodes = args.episodes or 100
        results = agent.evaluate(n_episodes=n_episodes)
        
        logger.info("Evaluation Results:")
        for key, value in results.items():
            logger.info(f"  {key}: {value}")
        
    except Exception as e:
        logger.error(f"Evaluation failed: {e}")
        sys.exit(1)


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(description="Dynamic Reinforcement Learning Firewall")
    parser.add_argument('--config', '-c', default='config/config.yaml',
                       help='Configuration file path')
    
    subparsers = parser.add_subparsers(dest='mode', help='Operation modes')
    
    # Packet capture mode
    capture_parser = subparsers.add_parser('capture', help='Capture network packets')
    capture_parser.add_argument('--duration', type=int, help='Capture duration in seconds')
    
    # Training mode
    train_parser = subparsers.add_parser('train', help='Train RL agent')
    train_parser.add_argument('--algorithm', choices=['DQN', 'PPO'], help='RL algorithm')
    train_parser.add_argument('--timesteps', type=int, help='Total training timesteps')
    train_parser.add_argument('--model-path', help='Model save path')
    train_parser.add_argument('--resume', action='store_true', help='Resume training')
    
    # Live firewall mode
    firewall_parser = subparsers.add_parser('firewall', help='Run live firewall')
    firewall_parser.add_argument('--model-path', help='Trained model path')
    
    # Dashboard mode
    dashboard_parser = subparsers.add_parser('dashboard', help='Launch monitoring dashboard')
    
    # Evaluation mode
    eval_parser = subparsers.add_parser('evaluate', help='Evaluate trained model')
    eval_parser.add_argument('--model-path', required=True, help='Model path to evaluate')
    eval_parser.add_argument('--episodes', type=int, help='Number of evaluation episodes')
    
    # Parse arguments
    args = parser.parse_args()
    
    # Load configuration
    config = load_config(args.config)
    setup_logging(config)
    
    # Route to appropriate command
    if args.mode == 'capture':
        cmd_capture(config, args)
    elif args.mode == 'train':
        cmd_train(config, args)
    elif args.mode == 'firewall':
        cmd_firewall(config, args)
    elif args.mode == 'dashboard':
        cmd_dashboard(config, args)
    elif args.mode == 'evaluate':
        cmd_evaluate(config, args)
    else:
        logger.error("Please specify an operation mode")
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()