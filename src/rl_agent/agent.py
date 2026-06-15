"""
Reinforcement Learning Agent
DQN and PPO implementations for firewall policy learning
"""

import os
import time
from typing import Dict, List, Tuple, Optional, Union, Callable
import numpy as np
import torch
import torch.nn as nn
import torch.optim as optim
from collections import deque
import pickle

from stable_baselines3 import DQN, PPO
from stable_baselines3.common.env_util import make_vec_env
from stable_baselines3.common.vec_env import DummyVecEnv, SubprocVecEnv
from stable_baselines3.common.callbacks import BaseCallback, EvalCallback
from stable_baselines3.common.logger import configure
from stable_baselines3.common.monitor import Monitor
from stable_baselines3.common.noise import NormalActionNoise
from stable_baselines3.common.utils import set_random_seed

from .environment import FirewallEnv, make_firewall_env
from loguru import logger


class FirewallCallback(BaseCallback):
    """Custom callback for tracking firewall training progress"""
    
    def __init__(self, eval_freq: int = 1000, verbose: int = 1):
        super(FirewallCallback, self).__init__(verbose)
        self.eval_freq = eval_freq
        self.best_mean_reward = -np.inf
        self.episode_rewards = deque(maxlen=100)
        self.episode_accuracies = deque(maxlen=100)
        
    def _on_step(self) -> bool:
        # Log episode statistics
        if len(self.locals.get('infos', [])) > 0:
            info = self.locals['infos'][0]
            if 'episode' in info:
                episode_reward = info['episode']['r']
                self.episode_rewards.append(episode_reward)
                
                # Extract performance metrics if available
                if 'performance' in info:
                    perf = info['performance']
                    if 'accuracy' in perf:
                        self.episode_accuracies.append(perf['accuracy'])
        
        # Periodic evaluation
        if self.n_calls % self.eval_freq == 0:
            if len(self.episode_rewards) > 0:
                mean_reward = np.mean(self.episode_rewards)
                mean_accuracy = np.mean(self.episode_accuracies) if self.episode_accuracies else 0.0
                
                self.logger.record("eval/mean_reward", mean_reward)
                self.logger.record("eval/mean_accuracy", mean_accuracy)
                
                if mean_reward > self.best_mean_reward:
                    self.best_mean_reward = mean_reward
                    if self.verbose > 0:
                        logger.info(f"New best mean reward: {mean_reward:.2f}")
        
        return True


class FirewallDQNNetwork(nn.Module):
    """Custom DQN network for firewall decisions"""
    
    def __init__(self, input_size: int, output_size: int, hidden_sizes: List[int] = [256, 128]):
        super(FirewallDQNNetwork, self).__init__()
        
        layers = []
        prev_size = input_size
        
        # Hidden layers
        for hidden_size in hidden_sizes:
            layers.extend([
                nn.Linear(prev_size, hidden_size),
                nn.ReLU(),
                nn.Dropout(0.2)
            ])
            prev_size = hidden_size
        
        # Output layer
        layers.append(nn.Linear(prev_size, output_size))
        
        self.network = nn.Sequential(*layers)
        
    def forward(self, x):
        return self.network(x)


class FirewallAgent:
    """Main reinforcement learning agent for firewall policy"""
    
    def __init__(self, config: Dict):
        self.config = config
        self.algorithm = config.get('algorithm', 'DQN')
        self.model_save_path = config.get('model_save_path', 'models/')
        
        # Training parameters
        self.total_timesteps = config.get('total_timesteps', 100000)
        self.eval_freq = config.get('eval_freq', 5000)
        self.save_freq = config.get('save_freq', 10000)
        
        # Environment configuration
        self.env_config = self._prepare_env_config(config)
        
        # Initialize components
        self.model = None
        self.env = None
        self.eval_env = None
        
        # Training history
        self.training_history = {
            'rewards': [],
            'accuracies': [],
            'losses': [],
            'timesteps': []
        }
        
        logger.info(f"FirewallAgent initialized with {self.algorithm} algorithm")
    
    def _prepare_env_config(self, config: Dict) -> Dict:
        """Prepare environment configuration"""
        env_config = {
            'state_size': config.get('state_size', 20),
            'max_episode_steps': config.get('max_episode_steps', 1000),
            'benign_traffic_ratio': config.get('benign_traffic_ratio', 0.8),
            'attack_types': config.get('attack_types', ['port_scan', 'ddos', 'brute_force']),
            'rewards': config.get('rewards', {
                'correct_allow': 1.0,
                'correct_block': 1.0,
                'false_positive': -2.0,
                'false_negative': -5.0
            })
        }
        
        # Add feature extraction config
        feature_config = {
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
        
        env_config.update(feature_config)
        return env_config
    
    def create_environment(self, n_envs: int = 1) -> Union[FirewallEnv, DummyVecEnv]:
        """Create training environment(s)"""
        if n_envs == 1:
            env = make_firewall_env(self.env_config)
            env = Monitor(env)
            return env
        else:
            # Multiple environments for parallel training
            env_fns = [lambda: Monitor(make_firewall_env(self.env_config)) for _ in range(n_envs)]
            return DummyVecEnv(env_fns)
    
    def create_model(self, env) -> Union[DQN, PPO]:
        """Create RL model based on configuration"""
        
        if self.algorithm == 'DQN':
            model = DQN(
                policy='MlpPolicy',
                env=env,
                learning_rate=self.config.get('learning_rate', 3e-4),
                buffer_size=self.config.get('replay_buffer_size', 100000),
                batch_size=self.config.get('batch_size', 32),
                gamma=self.config.get('gamma', 0.99),
                exploration_initial_eps=self.config.get('epsilon_start', 1.0),
                exploration_final_eps=self.config.get('epsilon_end', 0.01),
                exploration_fraction=0.3,
                target_update_interval=self.config.get('target_update_freq', 1000),
                policy_kwargs={
                    'net_arch': [256, 128],
                    'activation_fn': torch.nn.ReLU
                },
                verbose=1,
                device='auto'
            )
            
        elif self.algorithm == 'PPO':
            model = PPO(
                policy='MlpPolicy',
                env=env,
                learning_rate=self.config.get('learning_rate', 3e-4),
                n_steps=self.config.get('n_steps', 2048),
                batch_size=self.config.get('batch_size', 64),
                n_epochs=self.config.get('n_epochs', 10),
                gamma=self.config.get('gamma', 0.99),
                clip_range=self.config.get('clip_range', 0.2),
                ent_coef=0.01,
                policy_kwargs={
                    'net_arch': [dict(pi=[256, 128], vf=[256, 128])],
                    'activation_fn': torch.nn.ReLU
                },
                verbose=1,
                device='auto'
            )
        
        else:
            raise ValueError(f"Unsupported algorithm: {self.algorithm}")
        
        return model
    
    def train(self, resume_training: bool = False) -> None:
        """Train the firewall agent"""
        logger.info("Starting firewall agent training...")
        
        # Create environments
        self.env = self.create_environment(n_envs=4)  # Parallel training
        self.eval_env = self.create_environment(n_envs=1)
        
        # Create or load model
        if resume_training and self._model_exists():
            self.model = self.load_model()
            self.model.set_env(self.env)
            logger.info("Resumed training from saved model")
        else:
            self.model = self.create_model(self.env)
            logger.info("Created new model for training")
        
        # Setup callbacks
        callback = FirewallCallback(eval_freq=self.eval_freq)
        eval_callback = EvalCallback(
            self.eval_env,
            best_model_save_path=os.path.join(self.model_save_path, 'best_model'),
            log_path=os.path.join(self.model_save_path, 'logs'),
            eval_freq=self.eval_freq,
            n_eval_episodes=10,
            deterministic=True
        )
        
        # Configure logging
        log_path = os.path.join(self.model_save_path, 'logs')
        os.makedirs(log_path, exist_ok=True)
        self.model.set_logger(configure(log_path, ["csv", "tensorboard"]))
        
        try:
            # Train the model
            start_time = time.time()
            self.model.learn(
                total_timesteps=self.total_timesteps,
                callback=[callback, eval_callback],
                log_interval=100,
                progress_bar=True
            )
            
            training_time = time.time() - start_time
            logger.info(f"Training completed in {training_time:.2f} seconds")
            
            # Save final model
            self.save_model()
            
        except KeyboardInterrupt:
            logger.info("Training interrupted by user")
            self.save_model()
        
        except Exception as e:
            logger.error(f"Training failed: {e}")
            raise
    
    def evaluate(self, n_episodes: int = 100) -> Dict:
        """Evaluate the trained agent"""
        if self.model is None:
            if self._model_exists():
                self.model = self.load_model()
            else:
                raise ValueError("No trained model available for evaluation")
        
        logger.info(f"Evaluating agent for {n_episodes} episodes...")
        
        # Create evaluation environment
        eval_env = self.create_environment(n_envs=1)
        
        # Run evaluation episodes
        episode_rewards = []
        episode_accuracies = []
        episode_metrics = []
        
        for episode in range(n_episodes):
            state = eval_env.reset()
            episode_reward = 0
            done = False
            step = 0
            
            while not done:
                action, _ = self.model.predict(state, deterministic=True)
                state, reward, done, info = eval_env.step(action)
                episode_reward += reward
                step += 1
            
            episode_rewards.append(episode_reward)
            
            # Extract performance metrics
            if 'performance' in info:
                perf = info['performance']
                episode_accuracies.append(perf.get('accuracy', 0.0))
                episode_metrics.append(perf)
        
        # Calculate summary statistics
        eval_results = {
            'mean_reward': np.mean(episode_rewards),
            'std_reward': np.std(episode_rewards),
            'mean_accuracy': np.mean(episode_accuracies),
            'std_accuracy': np.std(episode_accuracies),
            'episodes_evaluated': n_episodes
        }
        
        # Calculate aggregate metrics
        if episode_metrics:
            total_tp = sum(m.get('true_positives', 0) for m in episode_metrics)
            total_tn = sum(m.get('true_negatives', 0) for m in episode_metrics)
            total_fp = sum(m.get('false_positives', 0) for m in episode_metrics)
            total_fn = sum(m.get('false_negatives', 0) for m in episode_metrics)
            total_packets = total_tp + total_tn + total_fp + total_fn
            
            if total_packets > 0:
                eval_results.update({
                    'overall_accuracy': (total_tp + total_tn) / total_packets,
                    'overall_precision': total_tp / max(total_tp + total_fp, 1),
                    'overall_recall': total_tp / max(total_tp + total_fn, 1),
                    'false_positive_rate': total_fp / max(total_fp + total_tn, 1),
                    'false_negative_rate': total_fn / max(total_fn + total_tp, 1)
                })
        
        logger.info(f"Evaluation results: {eval_results}")
        return eval_results
    
    def predict(self, state: np.ndarray) -> Tuple[int, float]:
        """Make prediction for a single state"""
        if self.model is None:
            raise ValueError("No trained model available for prediction")
        
        action, _ = self.model.predict(state, deterministic=True)
        
        # Get action probabilities if available
        if hasattr(self.model, 'predict_proba'):
            proba = self.model.predict_proba(state)
            confidence = np.max(proba)
        else:
            confidence = 1.0  # Default confidence
        
        return action, confidence
    
    def save_model(self, filename: Optional[str] = None) -> None:
        """Save the trained model"""
        if self.model is None:
            raise ValueError("No model to save")
        
        os.makedirs(self.model_save_path, exist_ok=True)
        
        if filename is None:
            filename = f"firewall_{self.algorithm.lower()}_{int(time.time())}"
        
        model_path = os.path.join(self.model_save_path, filename)
        self.model.save(model_path)
        
        # Save training history
        history_path = os.path.join(self.model_save_path, f"{filename}_history.pkl")
        with open(history_path, 'wb') as f:
            pickle.dump(self.training_history, f)
        
        # Save configuration
        config_path = os.path.join(self.model_save_path, f"{filename}_config.pkl")
        with open(config_path, 'wb') as f:
            pickle.dump(self.config, f)
        
        logger.info(f"Model saved to {model_path}")
    
    def load_model(self, filename: Optional[str] = None) -> Union[DQN, PPO]:
        """Load a trained model"""
        if filename is None:
            # Find the most recent model
            model_files = [f for f in os.listdir(self.model_save_path) if f.endswith('.zip')]
            if not model_files:
                raise ValueError("No saved models found")
            filename = max(model_files, key=lambda x: os.path.getctime(os.path.join(self.model_save_path, x)))
            filename = filename[:-4]  # Remove .zip extension
        
        model_path = os.path.join(self.model_save_path, filename)
        
        if self.algorithm == 'DQN':
            model = DQN.load(model_path)
        elif self.algorithm == 'PPO':
            model = PPO.load(model_path)
        else:
            raise ValueError(f"Unsupported algorithm: {self.algorithm}")
        
        logger.info(f"Model loaded from {model_path}")
        return model
    
    def _model_exists(self) -> bool:
        """Check if a saved model exists"""
        if not os.path.exists(self.model_save_path):
            return False
        model_files = [f for f in os.listdir(self.model_save_path) if f.endswith('.zip')]
        return len(model_files) > 0


# Example usage
def main():
    """Example usage of FirewallAgent"""
    config = {
        'algorithm': 'DQN',
        'state_size': 20,
        'total_timesteps': 50000,
        'learning_rate': 3e-4,
        'gamma': 0.99,
        'epsilon_start': 1.0,
        'epsilon_end': 0.01,
        'replay_buffer_size': 50000,
        'batch_size': 32,
        'target_update_freq': 1000,
        'eval_freq': 5000,
        'save_freq': 10000,
        'model_save_path': 'models/',
        'max_episode_steps': 500,
        'benign_traffic_ratio': 0.7,
        'attack_types': ['port_scan', 'ddos', 'brute_force'],
        'rewards': {
            'correct_allow': 1.0,
            'correct_block': 1.0,
            'false_positive': -2.0,
            'false_negative': -5.0
        }
    }
    
    # Create agent
    agent = FirewallAgent(config)
    
    try:
        # Train the agent
        agent.train()
        
        # Evaluate the trained agent
        results = agent.evaluate(n_episodes=50)
        logger.info(f"Final evaluation results: {results}")
        
    except Exception as e:
        logger.error(f"Training failed: {e}")


if __name__ == "__main__":
    main()