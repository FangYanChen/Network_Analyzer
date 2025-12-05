import sqlite3
from datetime import datetime, timedelta
import json

class PacketDatabase:

    def __init__(self, db_name='network_data.db'):
        self.db_name = db_name
        self.conn = sqlite3.connect(db_name, check_same_thread=False)
        self.create_tables()

    
    def create_tables(self):
        """Create necessary database tables"""
        # Packets table
        self.conn.execute('''
            CREATE TABLE IF NOT EXISTS packets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                source_ip TEXT NOT NULL,
                dest_ip TEXT NOT NULL,
                protocol TEXT,
                service TEXT,
                dest_port INTEGER,
                size INTEGER
            )
        ''')

        
        # Alerts table
        self.conn.execute('''
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                alert_type TEXT NOT NULL,
                severity TEXT,
                source_ip TEXT,
                description TEXT
            )
        ''')
        self.conn.commit()
        print("Database initialized")



    
    def add_packet(self, packet_info):
        """Add packet information to database"""
        self.conn.execute('''
            INSERT INTO packets (timestamp, source_ip, dest_ip, protocol, service, dest_port, size)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (
            packet_info['timestamp'],
            packet_info['source_ip'],
            packet_info['dest_ip'],
            packet_info['protocol'],
            packet_info['service'],
            packet_info['dest_port'],
            packet_info['size']
        ))
        self.conn.commit()
    

    def add_alert(self, alert_info):
        """Add security alert to database"""
        self.conn.execute('''
            INSERT INTO alerts (timestamp, alert_type, severity, source_ip, description)
            VALUES (?, ?, ?, ?, ?)
        ''', (
            datetime.now().isoformat(),
            alert_info['type'],
            alert_info['severity'],
            alert_info['source'],
            alert_info.get('description', '')
        ))
        self.conn.commit()
    


    def get_protocol_stats(self):
        """Get statistics by protocol"""
        cursor = self.conn.execute('''
            SELECT protocol, COUNT(*) as count, SUM(size) as total_size
            FROM packets
            GROUP BY protocol
            ORDER BY count DESC
        ''')
        return [{'protocol': row[0], 'count': row[1], 'size': row[2]} 
                for row in cursor.fetchall()]
    


    def get_service_stats(self):
        """Get statistics by service"""
        cursor = self.conn.execute('''
            SELECT service, COUNT(*) as count
            FROM packets
            WHERE service != 'Unknown'
            GROUP BY service
            ORDER BY count DESC
            LIMIT 10
        ''')
        return [{'service': row[0], 'count': row[1]} 
                for row in cursor.fetchall()]
    


    def get_top_talkers(self, limit=10):
        """Get most active IP addresses"""
        cursor = self.conn.execute('''
            SELECT source_ip, COUNT(*) as count, SUM(size) as total_size
            FROM packets
            GROUP BY source_ip
            ORDER BY count DESC
            LIMIT ?
        ''', (limit,))
        return [{'ip': row[0], 'packets': row[1], 'bytes': row[2]} 
                for row in cursor.fetchall()]
    


    def get_recent_packets(self, limit=50):
        """Get most recent packets"""
        cursor = self.conn.execute('''
            SELECT timestamp, source_ip, dest_ip, protocol, service, size
            FROM packets
            ORDER BY id DESC
            LIMIT ?
        ''', (limit,))
        return [{'timestamp': row[0], 'source': row[1], 'dest': row[2],
                'protocol': row[3], 'service': row[4], 'size': row[5]}
                for row in cursor.fetchall()]
    


    def get_alerts(self, limit=20):
        """Get recent security alerts"""
        cursor = self.conn.execute('''
            SELECT timestamp, alert_type, severity, source_ip, description
            FROM alerts
            ORDER BY id DESC
            LIMIT ?
        ''', (limit,))
        return [{'timestamp': row[0], 'type': row[1], 'severity': row[2],
                'source': row[3], 'description': row[4]}
                for row in cursor.fetchall()]
    

    
    def get_traffic_timeline(self, minutes=60):
        """Get traffic over time"""
        cursor = self.conn.execute('''
            SELECT 
                strftime('%Y-%m-%d %H:%M', timestamp) as time_bucket,
                COUNT(*) as packet_count,
                SUM(size) as bytes
            FROM packets
            WHERE timestamp >= datetime('now', '-' || ? || ' minutes')
            GROUP BY time_bucket
            ORDER BY time_bucket
        ''', (minutes,))
        return [{'time': row[0], 'packets': row[1], 'bytes': row[2]}
                for row in cursor.fetchall()]
    


    
    def get_total_stats(self):
        """Get overall statistics"""
        cursor = self.conn.execute('''
            SELECT 
                COUNT(*) as total_packets,
                COUNT(DISTINCT source_ip) as unique_ips,
                SUM(size) as total_bytes
            FROM packets
        ''')
        row = cursor.fetchone()
        return {
            'total_packets': row[0] or 0,
            'unique_ips': row[1] or 0,
            'total_bytes': row[2] or 0
        }
    

    
    def clear_old_data(self, days=7):
        """Clear data older than specified days"""
        self.conn.execute('''
            DELETE FROM packets 
            WHERE timestamp < datetime('now', '-' || ? || ' days')
        ''', (days,))
        self.conn.commit()
        
    
    def close(self):
        """Close database connection"""
        self.conn.close()