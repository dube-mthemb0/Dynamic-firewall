"""
Packet Capture Module
Real-time network packet capture and analysis using Scapy
"""

import time
import threading
import queue
from typing import Dict, List, Optional, Callable, Tuple
from dataclasses import dataclass
from collections import defaultdict, deque
import numpy as np

from scapy.all import (
    sniff, IP, TCP, UDP, ICMP, 
    get_if_list, get_if_addr,
    wrpcap, rdpcap
)
from loguru import logger
import yaml


@dataclass
class PacketInfo:
    """Structure to hold extracted packet information"""
    timestamp: float
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    packet_size: int
    flags: str
    flow_id: str
    is_inbound: bool
    raw_packet: Optional[object] = None


class FlowTracker:
    """Track network flows for feature extraction"""
    
    def __init__(self, timeout: int = 300):
        self.flows = defaultdict(lambda: {
            'start_time': 0,
            'last_seen': 0,
            'packet_count': 0,
            'bytes_total': 0,
            'packets': deque(maxlen=100),  # Keep recent packets for analysis
            'directions': deque(maxlen=100)
        })
        self.timeout = timeout
        
    def update_flow(self, packet_info: PacketInfo) -> Dict:
        """Update flow statistics with new packet"""
        flow_id = packet_info.flow_id
        flow = self.flows[flow_id]
        
        current_time = packet_info.timestamp
        
        # Initialize flow if first packet
        if flow['start_time'] == 0:
            flow['start_time'] = current_time
            
        # Update flow statistics
        flow['last_seen'] = current_time
        flow['packet_count'] += 1
        flow['bytes_total'] += packet_info.packet_size
        flow['packets'].append(packet_info.packet_size)
        flow['directions'].append(packet_info.is_inbound)
        
        # Calculate derived features
        duration = current_time - flow['start_time']
        packet_rate = flow['packet_count'] / max(duration, 0.001)
        byte_rate = flow['bytes_total'] / max(duration, 0.001)
        
        return {
            'flow_id': flow_id,
            'duration': duration,
            'packet_count': flow['packet_count'],
            'bytes_total': flow['bytes_total'],
            'packet_rate': packet_rate,
            'byte_rate': byte_rate,
            'avg_packet_size': flow['bytes_total'] / flow['packet_count'],
            'direction_changes': self._count_direction_changes(flow['directions'])
        }
    
    def _count_direction_changes(self, directions: deque) -> int:
        """Count how many times flow direction changes"""
        if len(directions) < 2:
            return 0
        
        changes = 0
        for i in range(1, len(directions)):
            if directions[i] != directions[i-1]:
                changes += 1
        return changes
    
    def cleanup_expired_flows(self) -> None:
        """Remove flows that have timed out"""
        current_time = time.time()
        expired = [
            flow_id for flow_id, flow in self.flows.items()
            if current_time - flow['last_seen'] > self.timeout
        ]
        
        for flow_id in expired:
            del self.flows[flow_id]
            
        if expired:
            logger.info(f"Cleaned up {len(expired)} expired flows")


class PacketCapture:
    """Main packet capture class with real-time processing"""
    
    def __init__(self, config: Dict):
        self.config = config
        self.interface = config.get('interface', 'eth0')
        self.capture_filter = config.get('capture_filter', '')
        self.batch_size = config.get('batch_size', 1000)
        self.buffer_size = config.get('buffer_size', 100000)
        
        # Threading and queue management
        self.packet_queue = queue.Queue(maxsize=self.buffer_size)
        self.is_capturing = False
        self.capture_thread = None
        self.process_thread = None
        
        # Flow tracking and statistics
        self.flow_tracker = FlowTracker(config.get('flow_timeout', 300))
        self.packet_count = 0
        self.start_time = None
        
        # Callbacks for packet processing
        self.packet_callbacks: List[Callable] = []
        
        # Network interface information
        self.local_ips = self._get_local_ips()
        
        logger.info(f"PacketCapture initialized for interface: {self.interface}")
        
    def _get_local_ips(self) -> List[str]:
        """Get local IP addresses for determining packet direction"""
        local_ips = []
        try:
            for iface in get_if_list():
                try:
                    ip = get_if_addr(iface)
                    if ip and ip != '0.0.0.0':
                        local_ips.append(ip)
                except:
                    pass
        except Exception as e:
            logger.warning(f"Could not get local IPs: {e}")
            
        return local_ips
    
    def _create_flow_id(self, src_ip: str, dst_ip: str, src_port: int, dst_port: int, protocol: str) -> str:
        """Create unique flow identifier"""
        # Normalize flow ID to be bidirectional
        if src_ip < dst_ip:
            return f"{src_ip}:{src_port}-{dst_ip}:{dst_port}-{protocol}"
        else:
            return f"{dst_ip}:{dst_port}-{src_ip}:{src_port}-{protocol}"
    
    def _extract_packet_info(self, packet) -> Optional[PacketInfo]:
        """Extract relevant information from captured packet"""
        try:
            if not packet.haslayer(IP):
                return None
                
            ip_layer = packet[IP]
            timestamp = time.time()
            
            # Basic IP information
            src_ip = ip_layer.src
            dst_ip = ip_layer.dst
            packet_size = len(packet)
            
            # Initialize port and protocol information
            src_port = 0
            dst_port = 0
            flags = ""
            protocol = "OTHER"
            
            # Extract transport layer information
            if packet.haslayer(TCP):
                tcp_layer = packet[TCP]
                src_port = tcp_layer.sport
                dst_port = tcp_layer.dport
                protocol = "TCP"
                flags = self._get_tcp_flags(tcp_layer)
                
            elif packet.haslayer(UDP):
                udp_layer = packet[UDP]
                src_port = udp_layer.sport
                dst_port = udp_layer.dport
                protocol = "UDP"
                
            elif packet.haslayer(ICMP):
                protocol = "ICMP"
                
            # Create flow identifier
            flow_id = self._create_flow_id(src_ip, dst_ip, src_port, dst_port, protocol)
            
            # Determine packet direction
            is_inbound = dst_ip in self.local_ips
            
            return PacketInfo(
                timestamp=timestamp,
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                protocol=protocol,
                packet_size=packet_size,
                flags=flags,
                flow_id=flow_id,
                is_inbound=is_inbound,
                raw_packet=packet if self.config.get('keep_raw', False) else None
            )
            
        except Exception as e:
            logger.error(f"Error extracting packet info: {e}")
            return None
    
    def _get_tcp_flags(self, tcp_layer) -> str:
        """Extract TCP flags as string"""
        flags = []
        if tcp_layer.flags & 0x01: flags.append('FIN')
        if tcp_layer.flags & 0x02: flags.append('SYN')
        if tcp_layer.flags & 0x04: flags.append('RST')
        if tcp_layer.flags & 0x08: flags.append('PSH')
        if tcp_layer.flags & 0x10: flags.append('ACK')
        if tcp_layer.flags & 0x20: flags.append('URG')
        return ','.join(flags)
    
    def _packet_handler(self, packet) -> None:
        """Handler called for each captured packet"""
        try:
            packet_info = self._extract_packet_info(packet)
            if packet_info:
                # Add to processing queue
                if not self.packet_queue.full():
                    self.packet_queue.put(packet_info)
                else:
                    logger.warning("Packet queue full, dropping packet")
                    
                self.packet_count += 1
                
        except Exception as e:
            logger.error(f"Error in packet handler: {e}")
    
    def _capture_worker(self) -> None:
        """Worker thread for packet capture"""
        logger.info(f"Starting packet capture on {self.interface}")
        
        try:
            sniff(
                iface=self.interface,
                filter=self.capture_filter,
                prn=self._packet_handler,
                stop_filter=lambda x: not self.is_capturing,
                store=False
            )
        except Exception as e:
            logger.error(f"Error in capture worker: {e}")
            
    def _process_worker(self) -> None:
        """Worker thread for packet processing"""
        logger.info("Starting packet processing worker")
        
        while self.is_capturing or not self.packet_queue.empty():
            try:
                # Get packet from queue with timeout
                packet_info = self.packet_queue.get(timeout=1.0)
                
                # Update flow tracker
                flow_features = self.flow_tracker.update_flow(packet_info)
                
                # Call registered callbacks
                for callback in self.packet_callbacks:
                    try:
                        callback(packet_info, flow_features)
                    except Exception as e:
                        logger.error(f"Error in packet callback: {e}")
                
                # Periodic cleanup of expired flows
                if self.packet_count % 1000 == 0:
                    self.flow_tracker.cleanup_expired_flows()
                    
            except queue.Empty:
                continue
            except Exception as e:
                logger.error(f"Error in process worker: {e}")
    
    def add_packet_callback(self, callback: Callable) -> None:
        """Register callback function for packet processing"""
        self.packet_callbacks.append(callback)
        logger.info(f"Added packet callback: {callback.__name__}")
    
    def start_capture(self) -> None:
        """Start packet capture and processing"""
        if self.is_capturing:
            logger.warning("Capture already running")
            return
            
        self.is_capturing = True
        self.start_time = time.time()
        self.packet_count = 0
        
        # Start worker threads
        self.capture_thread = threading.Thread(target=self._capture_worker, daemon=True)
        self.process_thread = threading.Thread(target=self._process_worker, daemon=True)
        
        self.capture_thread.start()
        self.process_thread.start()
        
        logger.info("Packet capture started")
    
    def stop_capture(self) -> None:
        """Stop packet capture and processing"""
        if not self.is_capturing:
            logger.warning("Capture not running")
            return
            
        logger.info("Stopping packet capture...")
        self.is_capturing = False
        
        # Wait for threads to finish
        if self.capture_thread:
            self.capture_thread.join(timeout=5.0)
        if self.process_thread:
            self.process_thread.join(timeout=5.0)
            
        # Final statistics
        duration = time.time() - self.start_time if self.start_time else 0
        rate = self.packet_count / max(duration, 0.001)
        
        logger.info(f"Capture stopped. Processed {self.packet_count} packets in {duration:.2f}s ({rate:.2f} pps)")
    
    def get_statistics(self) -> Dict:
        """Get current capture statistics"""
        duration = time.time() - self.start_time if self.start_time else 0
        rate = self.packet_count / max(duration, 0.001)
        
        return {
            'packet_count': self.packet_count,
            'capture_duration': duration,
            'packet_rate': rate,
            'queue_size': self.packet_queue.qsize(),
            'active_flows': len(self.flow_tracker.flows),
            'is_capturing': self.is_capturing
        }


# Example usage and testing functions
def example_packet_callback(packet_info: PacketInfo, flow_features: Dict) -> None:
    """Example callback function for packet processing"""
    logger.info(f"Packet: {packet_info.src_ip}:{packet_info.src_port} -> {packet_info.dst_ip}:{packet_info.dst_port} "
                f"({packet_info.protocol}, {packet_info.packet_size} bytes)")


def main():
    """Example usage of PacketCapture"""
    # Load configuration
    config = {
        'interface': 'eth0',
        'capture_filter': 'ip',
        'batch_size': 100,
        'buffer_size': 10000,
        'flow_timeout': 300
    }
    
    # Create and configure packet capture
    capture = PacketCapture(config)
    capture.add_packet_callback(example_packet_callback)
    
    try:
        # Start capture
        capture.start_capture()
        
        # Run for specified duration
        logger.info("Capturing packets for 60 seconds...")
        time.sleep(60)
        
        # Display statistics
        stats = capture.get_statistics()
        logger.info(f"Capture statistics: {stats}")
        
    except KeyboardInterrupt:
        logger.info("Capture interrupted by user")
    finally:
        capture.stop_capture()


if __name__ == "__main__":
    main()