"""
Quick Test Script
Test the core components of the RL Firewall without full dependencies
"""

import sys
import os
import time
import numpy as np

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

def test_environment():
    """Test the RL environment"""
    print("Testing RL Environment...")
    
    try:
        from rl_agent.environment import FirewallEnv, make_firewall_env, TrafficSimulator
        
        # Basic configuration
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
            },
            # Feature extraction config
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
        
        # Create environment
        env = make_firewall_env(config)
        print(f"✓ Environment created successfully")
        
        # Test basic functionality
        state = env.reset()
        print(f"✓ Environment reset, state shape: {state.shape}")
        
        # Run a few steps
        total_reward = 0
        for step in range(10):
            action = env.action_space.sample()
            next_state, reward, done, info = env.step(action)
            total_reward += reward
            
            if done:
                break
        
        print(f"✓ Completed {step + 1} steps, total reward: {total_reward:.2f}")
        
        # Test performance metrics
        metrics = env._get_performance_metrics()
        print(f"✓ Performance metrics: Accuracy={metrics['accuracy']:.3f}")
        
        env.close()
        return True
        
    except Exception as e:
        print(f"✗ Environment test failed: {e}")
        return False


def test_traffic_simulation():
    """Test traffic simulation"""
    print("\nTesting Traffic Simulation...")
    
    try:
        from rl_agent.environment import TrafficSimulator
        
        config = {
            'benign_traffic_ratio': 0.8,
            'attack_types': ['port_scan', 'ddos', 'brute_force']
        }
        
        simulator = TrafficSimulator(config)
        
        # Generate some packets
        benign_count = 0
        malicious_count = 0
        
        for i in range(100):
            packet, is_benign = simulator.generate_packet()
            
            if is_benign:
                benign_count += 1
            else:
                malicious_count += 1
        
        print(f"✓ Generated 100 packets: {benign_count} benign, {malicious_count} malicious")
        print(f"✓ Benign ratio: {benign_count / 100:.2f} (expected: {config['benign_traffic_ratio']})")
        
        return True
        
    except Exception as e:
        print(f"✗ Traffic simulation test failed: {e}")
        return False


def test_feature_extraction():
    """Test feature extraction"""
    print("\nTesting Feature Extraction...")
    
    try:
        from packet_capture.features import FeatureExtractor, FeatureVector
        from packet_capture.capture import PacketInfo
        
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
        print(f"✓ Feature extractor created with {len(extractor.feature_names)} features")
        
        # Create sample packet
        packet_info = PacketInfo(
            timestamp=time.time(),
            src_ip="192.168.1.100",
            dst_ip="8.8.8.8",
            src_port=12345,
            dst_port=53,
            protocol="UDP",
            packet_size=64,
            flags="",
            flow_id="test_flow_1",
            is_inbound=False
        )
        
        # Sample flow features
        flow_features = {
            'duration': 1.5,
            'packet_count': 3,
            'bytes_total': 192,
            'packet_rate': 2.0,
            'byte_rate': 128.0,
            'avg_packet_size': 64.0,
            'direction_changes': 1
        }
        
        # Extract features
        feature_vector = extractor.extract_features(packet_info, flow_features)
        print(f"✓ Extracted feature vector with {len(feature_vector.features)} features")
        
        # Test normalization
        normalized_vector = extractor.normalize_features(feature_vector)
        print(f"✓ Normalized feature vector")
        
        return True
        
    except Exception as e:
        print(f"✗ Feature extraction test failed: {e}")
        return False


def test_basic_training():
    """Test basic RL training setup"""
    print("\nTesting Basic Training Setup...")
    
    try:
        from rl_agent.agent import FirewallAgent
        
        config = {
            'algorithm': 'DQN',
            'state_size': 20,
            'total_timesteps': 1000,  # Small for testing
            'learning_rate': 3e-4,
            'gamma': 0.99,
            'epsilon_start': 1.0,
            'epsilon_end': 0.01,
            'replay_buffer_size': 1000,
            'batch_size': 32,
            'target_update_freq': 100,
            'eval_freq': 500,
            'save_freq': 1000,
            'model_save_path': 'test_models/',
            'max_episode_steps': 50,
            'benign_traffic_ratio': 0.7,
            'attack_types': ['port_scan'],
            'rewards': {
                'correct_allow': 1.0,
                'correct_block': 1.0,
                'false_positive': -2.0,
                'false_negative': -5.0
            }
        }
        
        agent = FirewallAgent(config)
        print(f"✓ FirewallAgent created with {agent.algorithm} algorithm")
        
        # Test environment creation
        env = agent.create_environment()
        print(f"✓ Environment created")
        
        # Test model creation
        model = agent.create_model(env)
        print(f"✓ Model created")
        
        # Test a few prediction steps
        state = env.reset()
        for i in range(5):
            action = model.predict(state, deterministic=True)[0]
            state, reward, done, info = env.step(action)
            if done:
                state = env.reset()
        
        print(f"✓ Model prediction working")
        
        return True
        
    except Exception as e:
        print(f"✗ Training setup test failed: {e}")
        return False


def main():
    """Run all tests"""
    print("=" * 60)
    print("Dynamic RL Firewall - Component Tests")
    print("=" * 60)
    
    tests = [
        test_traffic_simulation,
        test_feature_extraction,
        test_environment,
        test_basic_training
    ]
    
    passed = 0
    total = len(tests)
    
    for test in tests:
        if test():
            passed += 1
        else:
            print("Stopping tests due to failure")
            break
    
    print("\n" + "=" * 60)
    print(f"Test Results: {passed}/{total} tests passed")
    
    if passed == total:
        print("✓ All core components working correctly!")
        print("\nNext steps:")
        print("1. Install required dependencies: pip install -r requirements.txt")
        print("2. Train a model: python main.py train --timesteps 50000")
        print("3. Run evaluation: python main.py evaluate --model-path models/best_model")
        print("4. Launch dashboard: python main.py dashboard")
    else:
        print("✗ Some tests failed. Please check the implementation.")
    
    print("=" * 60)


if __name__ == "__main__":
    main()