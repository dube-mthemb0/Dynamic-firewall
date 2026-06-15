"""
Rule enforcement implementation using iptables and system-level controls
"""

import subprocess
import logging
import platform
import time
from typing import Dict, Any, List, Optional
from dataclasses import dataclass

from .rules import Rule, RuleAction, Protocol


@dataclass
class EnforcementResult:
    """Result of rule enforcement action"""
    success: bool
    message: str
    rule_id: str
    action_taken: str


class RuleEnforcer:
    """Enforces firewall rules at the system level"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.logger = logging.getLogger(__name__)
        self.is_linux = platform.system().lower() == 'linux'
        self.test_mode = config.get('test_mode', True)  # Safe default for development
        self.applied_rules: Dict[str, str] = {}  # rule_id -> iptables rule
        
        if not self.test_mode and not self.is_linux:
            self.logger.warning("Rule enforcement only supported on Linux systems")
    
    def enforce_rule(self, rule: Rule, packet_info: Dict[str, Any]) -> EnforcementResult:
        """Enforce a specific rule for a packet"""
        
        if self.test_mode:
            return self._simulate_enforcement(rule, packet_info)
        
        if not self.is_linux:
            return EnforcementResult(
                success=False,
                message="Rule enforcement only supported on Linux",
                rule_id=rule.id,
                action_taken="none"
            )
        
        try:
            if rule.action == RuleAction.ALLOW:
                return self._allow_traffic(rule, packet_info)
            elif rule.action == RuleAction.DROP:
                return self._drop_traffic(rule, packet_info)
            elif rule.action == RuleAction.LOG:
                return self._log_traffic(rule, packet_info)
            elif rule.action == RuleAction.QUARANTINE:
                return self._quarantine_traffic(rule, packet_info)
            else:
                return EnforcementResult(
                    success=False,
                    message=f"Unknown action: {rule.action}",
                    rule_id=rule.id,
                    action_taken="none"
                )
                
        except Exception as e:
            self.logger.error(f"Error enforcing rule {rule.id}: {e}")
            return EnforcementResult(
                success=False,
                message=f"Enforcement error: {e}",
                rule_id=rule.id,
                action_taken="error"
            )
    
    def _simulate_enforcement(self, rule: Rule, packet_info: Dict[str, Any]) -> EnforcementResult:
        """Simulate rule enforcement for testing"""
        action_map = {
            RuleAction.ALLOW: "allowed",
            RuleAction.DROP: "dropped",
            RuleAction.LOG: "logged",
            RuleAction.QUARANTINE: "quarantined"
        }
        
        action_taken = action_map.get(rule.action, "unknown")
        message = f"SIMULATION: {action_taken} packet {packet_info.get('src_ip', 'unknown')} -> {packet_info.get('dst_ip', 'unknown')}"
        
        self.logger.info(message)
        
        return EnforcementResult(
            success=True,
            message=message,
            rule_id=rule.id,
            action_taken=action_taken
        )
    
    def _allow_traffic(self, rule: Rule, packet_info: Dict[str, Any]) -> EnforcementResult:
        """Allow traffic by adding ACCEPT rule"""
        iptables_rule = self._build_iptables_rule(rule, "ACCEPT")
        
        if self._execute_iptables(iptables_rule):
            self.applied_rules[rule.id] = iptables_rule
            return EnforcementResult(
                success=True,
                message=f"Traffic allowed for rule {rule.id}",
                rule_id=rule.id,
                action_taken="allow"
            )
        else:
            return EnforcementResult(
                success=False,
                message=f"Failed to apply ALLOW rule {rule.id}",
                rule_id=rule.id,
                action_taken="error"
            )
    
    def _drop_traffic(self, rule: Rule, packet_info: Dict[str, Any]) -> EnforcementResult:
        """Drop traffic by adding DROP rule"""
        iptables_rule = self._build_iptables_rule(rule, "DROP")
        
        if self._execute_iptables(iptables_rule):
            self.applied_rules[rule.id] = iptables_rule
            return EnforcementResult(
                success=True,
                message=f"Traffic dropped for rule {rule.id}",
                rule_id=rule.id,
                action_taken="drop"
            )
        else:
            return EnforcementResult(
                success=False,
                message=f"Failed to apply DROP rule {rule.id}",
                rule_id=rule.id,
                action_taken="error"
            )
    
    def _log_traffic(self, rule: Rule, packet_info: Dict[str, Any]) -> EnforcementResult:
        """Log traffic by adding LOG rule"""
        iptables_rule = self._build_iptables_rule(rule, "LOG", log_prefix=f"FIREWALL_LOG_{rule.id}: ")
        
        if self._execute_iptables(iptables_rule):
            self.applied_rules[rule.id] = iptables_rule
            self.logger.info(f"Traffic logged for rule {rule.id}: {packet_info}")
            return EnforcementResult(
                success=True,
                message=f"Traffic logged for rule {rule.id}",
                rule_id=rule.id,
                action_taken="log"
            )
        else:
            return EnforcementResult(
                success=False,
                message=f"Failed to apply LOG rule {rule.id}",
                rule_id=rule.id,
                action_taken="error"
            )
    
    def _quarantine_traffic(self, rule: Rule, packet_info: Dict[str, Any]) -> EnforcementResult:
        """Quarantine traffic by redirecting to quarantine network"""
        # For simplicity, quarantine = DROP + LOG
        log_result = self._log_traffic(rule, packet_info)
        drop_result = self._drop_traffic(rule, packet_info)
        
        if log_result.success and drop_result.success:
            return EnforcementResult(
                success=True,
                message=f"Traffic quarantined for rule {rule.id}",
                rule_id=rule.id,
                action_taken="quarantine"
            )
        else:
            return EnforcementResult(
                success=False,
                message=f"Failed to quarantine traffic for rule {rule.id}",
                rule_id=rule.id,
                action_taken="error"
            )
    
    def _build_iptables_rule(self, rule: Rule, target: str, log_prefix: str = "") -> str:
        """Build iptables command from rule"""
        cmd_parts = ["iptables", "-A", "INPUT"]
        
        # Add conditions
        if rule.condition.src_ip:
            cmd_parts.extend(["-s", rule.condition.src_ip])
        
        if rule.condition.dst_ip:
            cmd_parts.extend(["-d", rule.condition.dst_ip])
        
        if rule.condition.protocol and rule.condition.protocol != Protocol.ALL:
            cmd_parts.extend(["-p", rule.condition.protocol.value])
            
            # Add port conditions for TCP/UDP
            if rule.condition.protocol in [Protocol.TCP, Protocol.UDP]:
                if rule.condition.src_port:
                    cmd_parts.extend(["--sport", str(rule.condition.src_port)])
                if rule.condition.dst_port:
                    cmd_parts.extend(["--dport", str(rule.condition.dst_port)])
        
        # Add target
        if target == "LOG" and log_prefix:
            cmd_parts.extend(["-j", "LOG", "--log-prefix", f'"{log_prefix}"'])
        else:
            cmd_parts.extend(["-j", target])
        
        return " ".join(cmd_parts)
    
    def _execute_iptables(self, command: str) -> bool:
        """Execute iptables command"""
        try:
            result = subprocess.run(
                command.split(),
                capture_output=True,
                text=True,
                check=True,
                timeout=30
            )
            self.logger.debug(f"iptables command executed: {command}")
            return True
            
        except subprocess.CalledProcessError as e:
            self.logger.error(f"iptables command failed: {command}, error: {e.stderr}")
            return False
        except subprocess.TimeoutExpired:
            self.logger.error(f"iptables command timeout: {command}")
            return False
        except Exception as e:
            self.logger.error(f"iptables execution error: {e}")
            return False
    
    def remove_rule(self, rule_id: str) -> bool:
        """Remove a previously applied rule"""
        if rule_id not in self.applied_rules:
            return False
        
        # Convert INSERT to DELETE
        iptables_rule = self.applied_rules[rule_id]
        delete_rule = iptables_rule.replace("-A INPUT", "-D INPUT")
        
        if self._execute_iptables(delete_rule):
            del self.applied_rules[rule_id]
            self.logger.info(f"Removed rule {rule_id}")
            return True
        else:
            self.logger.error(f"Failed to remove rule {rule_id}")
            return False
    
    def flush_all_rules(self) -> bool:
        """Remove all applied rules"""
        success = True
        for rule_id in list(self.applied_rules.keys()):
            if not self.remove_rule(rule_id):
                success = False
        return success
    
    def get_system_stats(self) -> Dict[str, Any]:
        """Get system firewall statistics"""
        try:
            if self.test_mode:
                return {
                    "mode": "test_mode",
                    "applied_rules": len(self.applied_rules),
                    "system": platform.system(),
                    "status": "simulated"
                }
            
            # Get iptables stats
            result = subprocess.run(
                ["iptables", "-L", "-n", "-v"],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            return {
                "applied_rules": len(self.applied_rules),
                "system": platform.system(),
                "iptables_output": result.stdout if result.returncode == 0 else "error",
                "status": "active" if result.returncode == 0 else "error"
            }
            
        except Exception as e:
            self.logger.error(f"Error getting system stats: {e}")
            return {
                "applied_rules": len(self.applied_rules),
                "system": platform.system(),
                "status": "error",
                "error": str(e)
            }


class PolicyEnforcer:
    """High-level policy enforcement coordinator"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.logger = logging.getLogger(__name__)
        self.rule_enforcer = RuleEnforcer(config)
        self.enforcement_history: List[Dict[str, Any]] = []
        self.active_policies: Dict[str, Rule] = {}
    
    def enforce_policy(self, rule: Rule, packet_info: Dict[str, Any]) -> EnforcementResult:
        """Enforce a policy rule"""
        result = self.rule_enforcer.enforce_rule(rule, packet_info)
        
        # Record enforcement action
        self.enforcement_history.append({
            'timestamp': time.time(),
            'rule_id': rule.id,
            'rule_name': rule.name,
            'action': rule.action.value,
            'success': result.success,
            'message': result.message,
            'packet_info': packet_info
        })
        
        # Track active policies
        if result.success and rule.action in [RuleAction.ALLOW, RuleAction.DROP]:
            self.active_policies[rule.id] = rule
        
        return result
    
    def remove_policy(self, rule_id: str) -> bool:
        """Remove an active policy"""
        success = self.rule_enforcer.remove_rule(rule_id)
        if success and rule_id in self.active_policies:
            del self.active_policies[rule_id]
        return success
    
    def get_enforcement_stats(self) -> Dict[str, Any]:
        """Get enforcement statistics"""
        total_enforcements = len(self.enforcement_history)
        successful_enforcements = sum(1 for h in self.enforcement_history if h['success'])
        
        # Count by action type
        action_counts = {}
        for history in self.enforcement_history:
            action = history['action']
            action_counts[action] = action_counts.get(action, 0) + 1
        
        return {
            'total_enforcements': total_enforcements,
            'successful_enforcements': successful_enforcements,
            'success_rate': successful_enforcements / total_enforcements if total_enforcements > 0 else 0,
            'active_policies': len(self.active_policies),
            'action_counts': action_counts,
            'system_stats': self.rule_enforcer.get_system_stats()
        }