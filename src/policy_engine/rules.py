"""
Rule definitions for the policy engine
"""

from enum import Enum
from dataclasses import dataclass
from typing import Dict, Any, Optional, List
import ipaddress
import re


class RuleAction(Enum):
    """Actions that can be taken on network traffic"""
    ALLOW = "ALLOW"
    DROP = "DROP"
    LOG = "LOG"
    QUARANTINE = "QUARANTINE"


class Protocol(Enum):
    """Network protocols"""
    TCP = "tcp"
    UDP = "udp"
    ICMP = "icmp"
    ALL = "all"


@dataclass
class RuleCondition:
    """Represents a condition for applying a firewall rule"""
    
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    protocol: Optional[Protocol] = None
    packet_size: Optional[tuple] = None  # (min, max)
    time_window: Optional[tuple] = None  # (start_hour, end_hour)
    
    def matches(self, packet_info: Dict[str, Any]) -> bool:
        """Check if packet matches this condition"""
        
        # Check source IP
        if self.src_ip and not self._ip_matches(packet_info.get('src_ip'), self.src_ip):
            return False
            
        # Check destination IP
        if self.dst_ip and not self._ip_matches(packet_info.get('dst_ip'), self.dst_ip):
            return False
            
        # Check source port
        if self.src_port and packet_info.get('src_port') != self.src_port:
            return False
            
        # Check destination port
        if self.dst_port and packet_info.get('dst_port') != self.dst_port:
            return False
            
        # Check protocol
        if self.protocol and self.protocol != Protocol.ALL:
            if packet_info.get('protocol', '').lower() != self.protocol.value:
                return False
                
        # Check packet size
        if self.packet_size:
            size = packet_info.get('packet_size', 0)
            min_size, max_size = self.packet_size
            if size < min_size or size > max_size:
                return False
                
        # Check time window
        if self.time_window:
            from datetime import datetime
            current_hour = datetime.now().hour
            start_hour, end_hour = self.time_window
            if start_hour <= end_hour:
                if not (start_hour <= current_hour <= end_hour):
                    return False
            else:  # Crosses midnight
                if not (current_hour >= start_hour or current_hour <= end_hour):
                    return False
                    
        return True
    
    def _ip_matches(self, packet_ip: str, rule_ip: str) -> bool:
        """Check if packet IP matches rule IP (supports CIDR notation)"""
        try:
            if '/' in rule_ip:
                # CIDR notation
                network = ipaddress.ip_network(rule_ip, strict=False)
                return ipaddress.ip_address(packet_ip) in network
            else:
                # Exact match or wildcard
                if rule_ip == "*":
                    return True
                return packet_ip == rule_ip
        except Exception:
            return False


@dataclass
class Rule:
    """Represents a firewall rule"""
    
    id: str
    name: str
    condition: RuleCondition
    action: RuleAction
    priority: int = 100
    enabled: bool = True
    created_by: str = "system"
    description: str = ""
    hit_count: int = 0
    
    def matches(self, packet_info: Dict[str, Any]) -> bool:
        """Check if this rule matches the given packet"""
        if not self.enabled:
            return False
        return self.condition.matches(packet_info)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert rule to dictionary for serialization"""
        return {
            'id': self.id,
            'name': self.name,
            'condition': {
                'src_ip': self.condition.src_ip,
                'dst_ip': self.condition.dst_ip,
                'src_port': self.condition.src_port,
                'dst_port': self.condition.dst_port,
                'protocol': self.condition.protocol.value if self.condition.protocol else None,
                'packet_size': self.condition.packet_size,
                'time_window': self.condition.time_window,
            },
            'action': self.action.value,
            'priority': self.priority,
            'enabled': self.enabled,
            'created_by': self.created_by,
            'description': self.description,
            'hit_count': self.hit_count
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Rule':
        """Create rule from dictionary"""
        condition_data = data['condition']
        protocol = None
        if condition_data.get('protocol'):
            protocol = Protocol(condition_data['protocol'])
            
        condition = RuleCondition(
            src_ip=condition_data.get('src_ip'),
            dst_ip=condition_data.get('dst_ip'),
            src_port=condition_data.get('src_port'),
            dst_port=condition_data.get('dst_port'),
            protocol=protocol,
            packet_size=tuple(condition_data['packet_size']) if condition_data.get('packet_size') else None,
            time_window=tuple(condition_data['time_window']) if condition_data.get('time_window') else None,
        )
        
        return cls(
            id=data['id'],
            name=data['name'],
            condition=condition,
            action=RuleAction(data['action']),
            priority=data.get('priority', 100),
            enabled=data.get('enabled', True),
            created_by=data.get('created_by', 'system'),
            description=data.get('description', ''),
            hit_count=data.get('hit_count', 0)
        )


class RuleSet:
    """Collection of firewall rules with management capabilities"""
    
    def __init__(self):
        self.rules: List[Rule] = []
        self._id_counter = 0
    
    def add_rule(self, rule: Rule) -> None:
        """Add a rule to the rule set"""
        if not rule.id:
            rule.id = f"rule_{self._id_counter:04d}"
            self._id_counter += 1
        self.rules.append(rule)
        self._sort_by_priority()
    
    def remove_rule(self, rule_id: str) -> bool:
        """Remove a rule by ID"""
        for i, rule in enumerate(self.rules):
            if rule.id == rule_id:
                del self.rules[i]
                return True
        return False
    
    def get_rule(self, rule_id: str) -> Optional[Rule]:
        """Get a rule by ID"""
        for rule in self.rules:
            if rule.id == rule_id:
                return rule
        return None
    
    def find_matching_rule(self, packet_info: Dict[str, Any]) -> Optional[Rule]:
        """Find the first matching rule for a packet"""
        for rule in self.rules:
            if rule.matches(packet_info):
                rule.hit_count += 1
                return rule
        return None
    
    def _sort_by_priority(self) -> None:
        """Sort rules by priority (higher priority first)"""
        self.rules.sort(key=lambda r: r.priority, reverse=True)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert rule set to dictionary"""
        return {
            'rules': [rule.to_dict() for rule in self.rules],
            'id_counter': self._id_counter
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'RuleSet':
        """Create rule set from dictionary"""
        ruleset = cls()
        ruleset._id_counter = data.get('id_counter', 0)
        for rule_data in data.get('rules', []):
            ruleset.rules.append(Rule.from_dict(rule_data))
        return ruleset