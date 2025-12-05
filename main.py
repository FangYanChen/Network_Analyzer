import threading
import time
import sys
from sniffer import PacketSniffer
from data_base import PacketDatabase
from ids import IntrusionDetectionSystem
from app import init_app, run_server

def print_banner():
      """Print application banner"""
      print("=" * 60)
      print("     NETWORK TRAFFIC ANALYZER & INTRUSION DETECTION")
      print("=" * 60)
      print()

def main():
      print_banner()

      # Initialize components
      print("Initializing components...")
      database = PacketDatabase()
      ids_system = IntrusionDetectionSystem()
      sniffer = PacketSniffer(database, ids_system)

      # Initialize web app
      init_app(database)

      # Start web server in separate thread
      print("Starting web dashboard...")
      web_thread = threading.Thread(target=run_server, daemon=True)
      web_thread.start()

      # Wait a moment for server to start
      time.sleep(2)

      print("\n" + "=" * 60)
      print("System Ready!")
      print("=" * 60)
      print("\n Dashboard: http://localhost:5000")
      print("Note: Packet capture requires administrator/root privileges")
      print("\n Starting packet capture...")
      print("Press Ctrl+C to stop\n")
      print("=" * 60 + "\n")

      try:
            # Start packet capture (blocking)
            sniffer.start()
      except KeyboardInterrupt:
            print("\n\n Stopping capture...")
            sniffer.stop()
            print("\n Final Statistics:")
            print(f"   Total packets captured: {sniffer.packet_count}")
            total_stats = database.get_total_stats()
            print(f"   Unique IP addresses: {total_stats['unique_ips']}")
            print(f"   Total data: {total_stats['total_bytes'] / 1024:.2f} KB")
            print("\n Database saved to: network_data.db")
            print("Goodbye!\n")
            database.close()

if __name__ == "__main__":
      main()