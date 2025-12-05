from scapy.all import sniff, IP, TCP, UDP, ICMP, DNS, Raw
from datetime import datetime
import threading
import json

class PacketSniffer:
    def __init__(self, database, ids_system):
        self.database = database
        self.ids = ids_system
        self.is_running = False
        self.packet_count = 0
        
    def analyze_packet(self, packet):
        """Analyze packet and extract useful information"""
        if not packet.haslayer(IP):
            return None
            
        packet_info = {
            'timestamp': datetime.now().isoformat(),
            'source_ip': packet[IP].src,
            'dest_ip': packet[IP].dst,
            'protocol': 'Unknown',
            'size': len(packet),
            'service': 'Unknown',
            'dest_port': None
        }
        
        # Determine protocol and service
        if packet.haslayer(TCP):
            packet_info['protocol'] = 'TCP'
            packet_info['dest_port'] = packet[TCP].dport
            
            # Common services
            if packet[TCP].dport == 80 or packet[TCP].sport == 80:
                packet_info['service'] = 'HTTP'
            elif packet[TCP].dport == 443 or packet[TCP].sport == 443:
                packet_info['service'] = 'HTTPS'
            elif packet[TCP].dport == 22 or packet[TCP].sport == 22:
                packet_info['service'] = 'SSH'
            elif packet[TCP].dport == 21 or packet[TCP].sport == 21:
                packet_info['service'] = 'FTP'
            elif packet[TCP].dport == 25 or packet[TCP].sport == 25:
                packet_info['service'] = 'SMTP'
                
        elif packet.haslayer(UDP):
            packet_info['protocol'] = 'UDP'
            packet_info['dest_port'] = packet[UDP].dport
            
            if packet.haslayer(DNS):
                packet_info['service'] = 'DNS'
            elif packet[UDP].dport == 67 or packet[UDP].dport == 68:
                packet_info['service'] = 'DHCP'
            elif packet[UDP].dport == 123:
                packet_info['service'] = 'NTP'
                
        elif packet.haslayer(ICMP):
            packet_info['protocol'] = 'ICMP'
            packet_info['service'] = 'Ping/Traceroute'
        
        return packet_info
    
    def packet_callback(self, packet):
        """Callback function for each captured packet"""
        packet_info = self.analyze_packet(packet)
        
        if packet_info:
            self.packet_count += 1
            
            # Save to database
            self.database.add_packet(packet_info)
            
            # Check for threats
            alert = self.ids.check_packet(packet_info)
            if alert['alert']:
                self.database.add_alert(alert)
                print(f"ALERT: {alert['type']} from {alert['source']}")
            
            # Print summary every 100 packets
            if self.packet_count % 100 == 0:
                print(f"Captured {self.packet_count} packets")
    
    def start(self, interface=None):
        """Start packet capture"""
        self.is_running = True
        print("Starting packet capture...")
        print("Note: You may need to run this with administrator/root privileges")
        
        try:
            sniff(prn=self.packet_callback, 
                  store=False, 
                  iface=interface,
                  stop_filter=lambda x: not self.is_running)
        except PermissionError:
            print("Permission denied. Please run with sudo/administrator privileges")
        except Exception as e:
            print(f"Error: {e}")
    
    def stop(self):
        """Stop packet capture"""
        self.is_running = False
        print(f"Stopped. Total packets captured: {self.packet_count}")