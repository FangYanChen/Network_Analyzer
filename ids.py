from collections import defaultdict
from datetime import datetime, timedelta

class IntrusionDetectionSystem:

    def __init__(self):
        # Track connection attempts per IP
        self.connection_tracker = defaultdict(list)
        
        # Track port scan attempts
        self.port_scan_tracker = defaultdict(set)
        
        # Track failed connections
        self.failed_connections = defaultdict(int)
        
        # Thresholds
        self.PORT_SCAN_THRESHOLD = 10  # ports per minute
        self.CONNECTION_THRESHOLD = 50  # connections per minute
        self.SUSPICIOUS_PORTS = [23, 3389, 1433, 3306, 5432]  # Telnet, RDP, databases
        


    def check_packet(self, packet_info):
        """Check packet for suspicious activity"""
        source_ip = packet_info['source_ip']
        dest_port = packet_info.get('dest_port')
        
        # Check for port scanning
        port_scan_alert = self._check_port_scan(source_ip, dest_port)
        if port_scan_alert:
            return port_scan_alert
        
        # Check for connection flooding
        flood_alert = self._check_connection_flood(source_ip)
        if flood_alert:
            return flood_alert
        
        # Check for suspicious port access
        suspicious_port_alert = self._check_suspicious_port(source_ip, dest_port)
        if suspicious_port_alert:
            return suspicious_port_alert
        
        return {'alert': False}
    


    def _check_port_scan(self, source_ip, dest_port):
        """Detect port scanning activity"""
        if dest_port is None:
            return {'alert': False}
        
        # Add port to tracker
        self.port_scan_tracker[source_ip].add(dest_port)
        
        # Clean old entries (keep only last minute)
        current_time = datetime.now()
        
        # Check if too many different ports accessed
        if len(self.port_scan_tracker[source_ip]) > self.PORT_SCAN_THRESHOLD:
            ports = self.port_scan_tracker[source_ip]
            self.port_scan_tracker[source_ip] = set()  # Reset
            
            return {
                'alert': True,
                'type': 'Port Scan Detected',
                'severity': 'HIGH',
                'source': source_ip,
                'description': f'Scanned {len(ports)} different ports: {list(ports)[:10]}'
            }
        
        return {'alert': False}
    


    def _check_connection_flood(self, source_ip):
        """Detect connection flooding (potential DDoS)"""
        current_time = datetime.now()
        
        # Add current connection
        self.connection_tracker[source_ip].append(current_time)
        
        # Remove old connections (older than 1 minute)
        self.connection_tracker[source_ip] = [
            t for t in self.connection_tracker[source_ip]
            if current_time - t < timedelta(minutes=1)
        ]
        
        # Check threshold
        connection_count = len(self.connection_tracker[source_ip])
        if connection_count > self.CONNECTION_THRESHOLD:
            return {
                'alert': True,
                'type': 'Connection Flood',
                'severity': 'MEDIUM',
                'source': source_ip,
                'description': f'{connection_count} connections in last minute'
            }
        
        return {'alert': False}
    


    def _check_suspicious_port(self, source_ip, dest_port):
        """Check for access to suspicious ports"""
        if dest_port in self.SUSPICIOUS_PORTS:
            port_names = {
                23: 'Telnet (unencrypted)',
                3389: 'RDP (Remote Desktop)',
                1433: 'MS SQL Server',
                3306: 'MySQL',
                5432: 'PostgreSQL'
            }
            
            return {
                'alert': True,
                'type': 'Suspicious Port Access',
                'severity': 'LOW',
                'source': source_ip,
                'description': f'Access to {port_names.get(dest_port, "unknown")} port {dest_port}'
            }
        
        return {'alert': False}
    

    
    def get_statistics(self):
        """Get IDS statistics"""
        return {
            'monitored_ips': len(self.connection_tracker),
            'potential_scanners': len([ip for ip, ports in self.port_scan_tracker.items() 
                                      if len(ports) > 5]),
            'active_connections': sum(len(conns) for conns in self.connection_tracker.values())
        }