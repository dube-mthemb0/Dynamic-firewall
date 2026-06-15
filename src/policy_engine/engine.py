"""
Main Policy Engine for the RL Firewall

This module coordinates between the RL agent decisions and the actual
firewall rule enforcement.
"""

import json
import time
import threading
from typing import Dict, Any, List, Optional, Callable
from pathlib import Path
import logging

from .rules import Rule, RuleSet, RuleAction, RuleCondition, Protocol
from .enforcer import PolicyEnforcer, EnforcementResult


class PolicyEngine:
    """Main policy engine that manages rules and enforcement"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.logger = logging.getLogger(__name__)
        
        # Initialize components
        self.rule_set = RuleSet()
        self.enforcer = PolicyEnforcer(config)
        
        # State management
        self.is_running = False
        self._lock = threading.Lock()
        
        # Callbacks
        self.on_rule_applied: Optional[Callable] = None
        self.on_packet_processed: Optional[Callable] = None
        
        # Load default rules
        self._load_default_rules()
        
        # Statistics
        self.stats = {
            'packets_processed': 0,
            'rules_applied': 0,
            'start_time': None
        }
    
    def start(self) -> None:
        """Start the policy engine"""
        with self._lock:
            if self.is_running:
                self.logger.warning("Policy engine is already running")
                return
            
            self.is_running = True
            self.stats['start_time'] = time.time()
            self.logger.info("Policy engine started")
    
    def stop(self) -> None:
        """Stop the policy engine"""
        with self._lock:
            if not self.is_running:
                self.logger.warning("Policy engine is not running")
                return
            
            self.is_running = False
            self.logger.info("Policy engine stopped")
    
    def process_packet(self, packet_info: Dict[str, Any]) -> Dict[str, Any]:
        """
        Process a packet through the policy engine
        
        Args:
            packet_info: Dictionary containing packet information
            
        Returns:
            Dictionary with processing result
        """
        if not self.is_running:
            return {
                'action': 'allow',
                'reason': 'Policy engine not running',
                'rule_id': None
            }
        
        self.stats['packets_processed'] += 1
        
        # Find matching rule
        matching_rule = self.rule_set.find_matching_rule(packet_info)
        
        if matching_rule is None:
            # No rule matches - apply default action
            default_action = self.config.get('default_action', 'allow')
            result = {
                'action': default_action,
                'reason': 'No matching rule found',
                'rule_id': None,
                'enforcement_result': None
            }
        else:
            # Apply the matching rule
            enforcement_result = self.enforcer.enforce_policy(matching_rule, packet_info)
            self.stats['rules_applied'] += 1
            
            result = {
                'action': matching_rule.action.value.lower(),
                'reason': f'Matched rule: {matching_rule.name}',
                'rule_id': matching_rule.id,
                'rule_priority': matching_rule.priority,
                'enforcement_result': enforcement_result
            }
            
            # Call callback if set
            if self.on_rule_applied:
                try:
                    self.on_rule_applied(matching_rule, packet_info, enforcement_result)
                except Exception as e:
                    self.logger.error(f"Error in rule applied callback: {e}")
        
        # Call packet processed callback
        if self.on_packet_processed:
            try:
                self.on_packet_processed(packet_info, result)
            except Exception as e:
                self.logger.error(f"Error in packet processed callback: {e}")
        
        return result
    
    def add_rule_from_rl_decision(self, action: int, packet_info: Dict[str, Any], 
                                  confidence: float = 1.0) -> str:
        """
        Add a rule based on RL agent decision
        
        Args:
            action: Action from RL agent (0=ALLOW, 1=DROP, 2=LOG, 3=QUARANTINE)
            packet_info: Packet information that triggered the decision
            confidence: Confidence level of the decision
            
        Returns:
            Rule ID of the created rule
        """
        
        # Map RL actions to rule actions
        action_map = {
            0: RuleAction.ALLOW,
            1: RuleAction.DROP,
            2: RuleAction.LOG,
            3: RuleAction.QUARANTINE
        }
        
        rule_action = action_map.get(action, RuleAction.LOG)
        
        # Create rule condition based on packet info
        condition = RuleCondition(
            src_ip=packet_info.get('src_ip'),
            dst_ip=packet_info.get('dst_ip'),
            src_port=packet_info.get('src_port'),
            dst_port=packet_info.get('dst_port'),
            protocol=self._get_protocol_enum(packet_info.get('protocol'))
        )
        
        # Create rule
        rule = Rule(
            id=f"rl_rule_{int(time.time() * 1000)}",
            name=f"RL Decision Rule ({rule_action.value})",
            condition=condition,
            action=rule_action,
            priority=int(confidence * 100),  # Higher confidence = higher priority
            created_by="rl_agent",
            description=f"Rule created by RL agent with {confidence:.2f} confidence"
        )
        
        self.rule_set.add_rule(rule)
        self.logger.info(f"Added RL rule {rule.id}: {rule.name}")
        
        return rule.id
    
    def add_manual_rule(self, rule_data: Dict[str, Any]) -> str:
        """Add a manually created rule"""
        rule = Rule.from_dict(rule_data)
        if not rule.created_by:
            rule.created_by = "manual"
        
        self.rule_set.add_rule(rule)
        self.logger.info(f"Added manual rule {rule.id}: {rule.name}")
        
        return rule.id
    
    def remove_rule(self, rule_id: str) -> bool:
        """Remove a rule"""
        # Remove from enforcement
        self.enforcer.remove_policy(rule_id)
        
        # Remove from rule set
        success = self.rule_set.remove_rule(rule_id)
        
        if success:
            self.logger.info(f"Removed rule {rule_id}")
        else:
            self.logger.warning(f"Rule {rule_id} not found")
        
        return success
    
    def get_rule(self, rule_id: str) -> Optional[Rule]:
        """Get a rule by ID"""
        return self.rule_set.get_rule(rule_id)
    
    def list_rules(self, enabled_only: bool = False) -> List[Rule]:
        """List all rules"""
        rules = self.rule_set.rules
        if enabled_only:
            rules = [r for r in rules if r.enabled]
        return rules
    
    def enable_rule(self, rule_id: str) -> bool:
        """Enable a rule"""
        rule = self.rule_set.get_rule(rule_id)
        if rule:
            rule.enabled = True
            self.logger.info(f"Enabled rule {rule_id}")
            return True
        return False
    
    def disable_rule(self, rule_id: str) -> bool:
        """Disable a rule"""
        rule = self.rule_set.get_rule(rule_id)
        if rule:
            rule.enabled = False
            # Remove from enforcement
            self.enforcer.remove_policy(rule_id)
            self.logger.info(f"Disabled rule {rule_id}")
            return True
        return False
    
    def save_rules(self, filepath: str) -> bool:
        """Save rules to file"""
        try:
            data = self.rule_set.to_dict()
            with open(filepath, 'w') as f:
                json.dump(data, f, indent=2)
            self.logger.info(f"Saved rules to {filepath}")
            return True
        except Exception as e:
            self.logger.error(f"Error saving rules to {filepath}: {e}")
            return False
    
    def load_rules(self, filepath: str) -> bool:
        """Load rules from file"""
        try:
            with open(filepath, 'r') as f:
                data = json.load(f)
            
            self.rule_set = RuleSet.from_dict(data)
            self.logger.info(f"Loaded rules from {filepath}")
            return True
        except Exception as e:
            self.logger.error(f"Error loading rules from {filepath}: {e}")
            return False
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get policy engine statistics"""
        enforcement_stats = self.enforcer.get_enforcement_stats()
        
        # Calculate uptime
        uptime = 0
        if self.stats['start_time']:
            uptime = time.time() - self.stats['start_time']
        
        return {
            'engine_stats': {
                'is_running': self.is_running,
                'uptime_seconds': uptime,
                'packets_processed': self.stats['packets_processed'],
                'rules_applied': self.stats['rules_applied'],
                'total_rules': len(self.rule_set.rules),
                'enabled_rules': len([r for r in self.rule_set.rules if r.enabled])
            },
            'enforcement_stats': enforcement_stats,
            'rule_hit_counts': {rule.id: rule.hit_count for rule in self.rule_set.rules}
        }
    
    def _load_default_rules(self) -> None:
        """Load default security rules"""
        default_rules_config = self.config.get('default_rules', [])
        
        for rule_config in default_rules_config:
            try:
                rule = Rule.from_dict(rule_config)
                self.rule_set.add_rule(rule)
                self.logger.info(f"Loaded default rule: {rule.name}")
            except Exception as e:
                self.logger.error(f"Error loading default rule {rule_config}: {e}")
        
        # If no default rules configured, add basic security rules
        if not default_rules_config:
            self._add_basic_security_rules()
    
    def _add_basic_security_rules(self) -> None:
        """Add basic security rules"""
        
        # Allow loopback traffic
        loopback_rule = Rule(
            id="default_loopback",
            name="Allow Loopback Traffic",
            condition=RuleCondition(src_ip="127.0.0.1"),
            action=RuleAction.ALLOW,
            priority=1000,
            created_by="system",
            description="Allow loopback traffic"
        )
        self.rule_set.add_rule(loopback_rule)
        
        # Log suspicious traffic (high ports)
        suspicious_rule = Rule(
            id="default_suspicious",
            name="Log High Port Traffic",
            condition=RuleCondition(
                dst_port=None,  # Will be checked in custom logic
                protocol=Protocol.TCP
            ),
            action=RuleAction.LOG,
            priority=50,
            created_by="system",
            description="Log traffic to high ports"
        )
        self.rule_set.add_rule(suspicious_rule)
        
        self.logger.info("Added basic security rules")
    
    def _get_protocol_enum(self, protocol_str: str) -> Optional[Protocol]:
        """Convert protocol string to Protocol enum"""
        if not protocol_str:
            return None
        
        protocol_map = {
            'tcp': Protocol.TCP,
            'udp': Protocol.UDP,
            'icmp': Protocol.ICMP
        }
        
        return protocol_map.get(protocol_str.lower())
    
    def cleanup(self) -> None:
        """Cleanup resources"""
        self.stop()
        
        # Remove all enforced rules
        try:
            self.enforcer.rule_enforcer.flush_all_rules()
            self.logger.info("Cleaned up enforced rules")
        except Exception as e:
            self.logger.error(f"Error during cleanup: {e}")