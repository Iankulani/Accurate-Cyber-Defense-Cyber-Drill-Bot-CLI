import threading
import time
import subprocess
import socket
import json
import os
import sys
import select
import logging
from datetime import datetime
from collections import deque
import requests
import ping3
import scapy.all as scapy
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.sendrecv import sr1, send
import readline  # For command history and better input handling

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("cyber_tool.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("CyberSecurityTool")

class CyberSecurityTool:
    def __init__(self):
        # Initialize variables
        self.monitored_ips = set()
        self.monitoring_active = False
        self.telegram_token = None
        self.telegram_chat_id = None
        self.command_history = deque(maxlen=100)
        self.ping_results = {}
        self.monitoring_thread = None
        self.stop_monitoring = threading.Event()
        
        # Load configuration if exists
        self.load_config()
        
        # Welcome message
        self.display_output("Accurate Cyber Defense security Tool initialized. Type 'help' for available commands.")
    
    def display_output(self, message):
        """Display message in the output"""
        print(f"{datetime.now().strftime('%H:%M:%S')} - {message}")
    
    def run(self):
        """Main CLI loop"""
        try:
            while True:
                try:
                    cmd = input("cyber-tool> ").strip()
                    
                    if not cmd:
                        continue
                    
                    # Add to command history
                    self.command_history.append(cmd)
                    
                    # Process command
                    if cmd.lower() == "exit":
                        self.exit_tool()
                        break
                    
                    self.process_command(cmd)
                    
                except KeyboardInterrupt:
                    print("\nUse 'exit' to quit the tool")
                except EOFError:
                    self.exit_tool()
                    break
        except Exception as e:
            self.display_output(f"Error in main loop: {str(e)}")
    
    def process_command(self, cmd):
        """Process user command"""
        parts = cmd.split()
        command = parts[0].lower()
        args = parts[1:] if len(parts) > 1 else []
        
        try:
            if command == "help":
                self.show_help()
            elif command == "ping":
                if len(args) < 1:
                    self.display_output("Usage: ping <ip_address>")
                else:
                    self.ping_ip(args[0])
            elif command == "start":
                if len(args) < 1:
                    self.display_output("Usage: start monitoring <ip_address> or start monitoring all")
                elif args[0] == "monitoring":
                    if len(args) < 2:
                        self.display_output("Usage: start monitoring <ip_address> or start monitoring all")
                    else:
                        if args[1] == "all":
                            self.start_monitoring_all()
                        else:
                            self.start_monitoring_ip(args[1])
                else:
                    self.display_output("Unknown command. Type 'help' for available commands.")
            elif command == "stop":
                self.stop_monitoring_cmd()
            elif command == "view":
                self.view_monitored_ips()
            elif command == "status":
                self.show_status()
            elif command == "clear":
                self.clear_output()
            elif command == "config":
                if len(args) < 2:
                    self.display_output("Usage: config telegram token <token> or config telegram chat_id <chat_id>")
                elif args[0] == "telegram":
                    if args[1] == "token":
                        if len(args) < 3:
                            self.display_output("Usage: config telegram token <your_telegram_token>")
                        else:
                            self.config_telegram_token(args[2])
                    elif args[1] == "chat_id":
                        if len(args) < 3:
                            self.display_output("Usage: config telegram chat_id <your_chat_id>")
                        else:
                            self.config_telegram_chat_id(args[2])
                    else:
                        self.display_output("Unknown config option. Type 'help' for available commands.")
                else:
                    self.display_output("Unknown config option. Type 'help' for available commands.")
            elif command == "test":
                if len(args) < 1:
                    self.display_output("Usage: test telegram connection")
                elif args[0] == "telegram" and len(args) > 1 and args[1] == "connection":
                    self.test_telegram_connection()
                else:
                    self.display_output("Unknown test option. Type 'help' for available commands.")
            elif command == "history":
                self.show_command_history()
            elif command == "add":
                if len(args) < 1:
                    self.display_output("Usage: add ip <ip_address>")
                elif args[0] == "ip":
                    if len(args) < 2:
                        self.display_output("Usage: add ip <ip_address>")
                    else:
                        self.add_ip(args[1])
                else:
                    self.display_output("Unknown add option. Type 'help' for available commands.")
            elif command == "remove":
                if len(args) < 1:
                    self.display_output("Usage: remove ip <ip_address>")
                elif args[0] == "ip":
                    if len(args) < 2:
                        self.display_output("Usage: remove ip <ip_address>")
                    else:
                        self.remove_ip(args[1])
                else:
                    self.display_output("Unknown remove option. Type 'help' for available commands.")
            elif command == "udptraceroute":
                if len(args) < 1:
                    self.display_output("Usage: udptraceroute <ip_address>")
                else:
                    self.udp_traceroute(args[0])
            elif command == "tcptraceroute":
                if len(args) < 1:
                    self.display_output("Usage: tcptraceroute <ip_address>")
                else:
                    self.tcp_traceroute(args[0])
            else:
                self.display_output("Unknown command. Type 'help' for available commands.")
        except Exception as e:
            self.display_output(f"Error executing command: {str(e)}")
    
    def show_help(self):
        """Display help information"""
        help_text = """
Available commands:
- help: Show this help message
- ping <ip_address>: Ping an IP address
- start monitoring <ip_address>: Start monitoring a specific IP
- start monitoring all: Start monitoring all IPs in the list
- stop: Stop monitoring
- view: View all monitored IP addresses
- status: Show current monitoring status
- exit: Exit the tool
- clear: Clear the screen
- config telegram token <token>: Set Telegram bot token
- config telegram chat_id <chat_id>: Set Telegram chat ID
- test telegram connection: Test Telegram connection
- history: Show command history
- add ip <ip_address>: Add an IP address to monitor
- remove ip <ip_address>: Remove an IP address from monitoring
- udptraceroute <ip_address>: Perform UDP traceroute to an IP
- tcptraceroute <ip_address>: Perform TCP traceroute to an IP
"""
        self.display_output(help_text)
    
    def ping_ip(self, ip):
        """Ping an IP address"""
        self.display_output(f"Pinging {ip}...")
        
        try:
            # Use ping3 library for cross-platform ping
            response_time = ping3.ping(ip, timeout=2)
            
            if response_time is not False and response_time is not None:
                self.display_output(f"Reply from {ip}: time={round(response_time * 1000)}ms")
                self.ping_results[ip] = f"{round(response_time * 1000)}ms"
            else:
                self.display_output(f"Request timed out for {ip}")
                self.ping_results[ip] = "Timeout"
        except Exception as e:
            self.display_output(f"Error pinging {ip}: {str(e)}")
            self.ping_results[ip] = f"Error: {str(e)}"
    
    def start_monitoring_ip(self, ip):
        """Start monitoring a specific IP address"""
        if ip not in self.monitored_ips:
            self.display_output(f"IP {ip} is not in the monitored list. Use 'add ip {ip}' first.")
            return
        
        if self.monitoring_active:
            self.display_output("Monitoring is already active.")
            return
        
        self.monitoring_active = True
        self.stop_monitoring.clear()
        
        # Start monitoring thread
        self.monitoring_thread = threading.Thread(target=self.monitor_ips, args=([ip],))
        self.monitoring_thread.daemon = True
        self.monitoring_thread.start()
        
        self.display_output(f"Started monitoring IP: {ip}")
    
    def start_monitoring_all(self):
        """Start monitoring all IP addresses"""
        if not self.monitored_ips:
            self.display_output("No IP addresses to monitor. Use 'add ip <ip_address>' first.")
            return
        
        if self.monitoring_active:
            self.display_output("Monitoring is already active.")
            return
        
        self.monitoring_active = True
        self.stop_monitoring.clear()
        
        # Start monitoring thread
        self.monitoring_thread = threading.Thread(target=self.monitor_ips, args=(self.monitored_ips,))
        self.monitoring_thread.daemon = True
        self.monitoring_thread.start()
        
        self.display_output(f"Started monitoring all IPs: {len(self.monitored_ips)} addresses")
    
    def stop_monitoring_cmd(self):
        """Stop monitoring"""
        if not self.monitoring_active:
            self.display_output("Monitoring is not active.")
            return
        
        self.monitoring_active = False
        self.stop_monitoring.set()
        
        if self.monitoring_thread and self.monitoring_thread.is_alive():
            self.monitoring_thread.join(timeout=5)
        
        self.display_output("Monitoring stopped.")
    
    def view_monitored_ips(self):
        """View all monitored IP addresses"""
        if not self.monitored_ips:
            self.display_output("No IP addresses being monitored.")
            return
        
        self.display_output("Monitored IP addresses:")
        for ip in sorted(self.monitored_ips):
            self.display_output(f"  {ip}")
    
    def show_status(self):
        """Show current monitoring status"""
        status = "Monitoring: " + ("Active" if self.monitoring_active else "Inactive")
        status += f"\nMonitored IPs: {len(self.monitored_ips)}"
        status += f"\nTelegram configured: {'Yes' if self.telegram_token and self.telegram_chat_id else 'No'}"
        
        self.display_output(status)
    
    def exit_tool(self):
        """Exit the tool"""
        if self.monitoring_active:
            self.stop_monitoring_cmd()
        
        self.save_config()
        self.display_output("Exiting tool. Goodbye!")
        sys.exit(0)
    
    def clear_output(self):
        """Clear the screen"""
        os.system('cls' if os.name == 'nt' else 'clear')
        self.display_output("Cyber Security Monitoring Tool. Type 'help' for available commands.")
    
    def config_telegram_token(self, token):
        """Configure Telegram bot token"""
        self.telegram_token = token
        self.display_output("Telegram token configured.")
        self.save_config()
    
    def config_telegram_chat_id(self, chat_id):
        """Configure Telegram chat ID"""
        self.telegram_chat_id = chat_id
        self.display_output("Telegram chat ID configured.")
        self.save_config()
    
    def test_telegram_connection(self):
        """Test Telegram connection"""
        if not self.telegram_token or not self.telegram_chat_id:
            self.display_output("Telegram not configured. Set token and chat ID first.")
            return
        
        try:
            url = f"https://api.telegram.org/bot{self.telegram_token}/getMe"
            response = requests.get(url, timeout=10)
            
            if response.status_code == 200:
                self.display_output("Telegram connection test successful.")
                
                # Send a test message
                message = "Cyber Security Tool: Telegram connection test successful!"
                self.send_telegram_message(message)
            else:
                self.display_output(f"Telegram connection test failed: {response.text}")
        except Exception as e:
            self.display_output(f"Telegram connection test failed: {str(e)}")
    
    def send_telegram_message(self, message):
        """Send a message via Telegram"""
        if not self.telegram_token or not self.telegram_chat_id:
            return False
        
        try:
            url = f"https://api.telegram.org/bot{self.telegram_token}/sendMessage"
            data = {
                "chat_id": self.telegram_chat_id,
                "text": message
            }
            response = requests.post(url, data=data, timeout=10)
            return response.status_code == 200
        except Exception as e:
            self.display_output(f"Failed to send Telegram message: {str(e)}")
            return False
    
    def show_command_history(self):
        """Show command history"""
        if not self.command_history:
            self.display_output("No command history.")
            return
        
        self.display_output("Command history:")
        for i, cmd in enumerate(self.command_history, 1):
            self.display_output(f"{i}. {cmd}")
    
    def add_ip(self, ip):
        """Add an IP address to monitor"""
        # Validate IP address
        try:
            socket.inet_aton(ip)
            self.monitored_ips.add(ip)
            self.display_output(f"Added IP: {ip}")
            self.save_config()
        except socket.error:
            self.display_output(f"Invalid IP address: {ip}")
    
    def remove_ip(self, ip):
        """Remove an IP address from monitoring"""
        if ip in self.monitored_ips:
            self.monitored_ips.remove(ip)
            self.display_output(f"Removed IP: {ip}")
            self.save_config()
        else:
            self.display_output(f"IP {ip} is not in the monitored list.")
    
    def udp_traceroute(self, ip):
        """Perform UDP traceroute to an IP"""
        self.display_output(f"Performing UDP traceroute to {ip}...")
        
        try:
            # Create a UDP packet
            port = 33434  # Standard traceroute port
            ttl = 1
            max_hops = 30
            timeout = 2
            
            while ttl <= max_hops:
                # Create a UDP packet with increasing TTL
                packet = IP(dst=ip, ttl=ttl) / UDP(dport=port)
                
                # Send the packet and wait for a response
                start_time = time.time()
                reply = sr1(packet, verbose=0, timeout=timeout)
                elapsed_time = (time.time() - start_time) * 1000
                
                if reply is None:
                    self.display_output(f"{ttl}\t*\t*\t*")
                elif reply.type == 3:  # Destination unreachable
                    self.display_output(f"{ttl}\t{reply.src}\t{elapsed_time:.2f} ms\tDestination reached")
                    break
                else:
                    self.display_output(f"{ttl}\t{reply.src}\t{elapsed_time:.2f} ms")
                
                ttl += 1
                
                # Check if we've reached the destination
                if reply is not None and reply.src == ip:
                    break
                    
        except Exception as e:
            self.display_output(f"Error performing UDP traceroute: {str(e)}")
    
    def tcp_traceroute(self, ip):
        """Perform TCP traceroute to an IP"""
        self.display_output(f"Performing TCP traceroute to {ip}...")
        
        try:
            port = 80  # HTTP port
            ttl = 1
            max_hops = 30
            timeout = 2
            
            while ttl <= max_hops:
                # Create a TCP SYN packet with increasing TTL
                packet = IP(dst=ip, ttl=ttl) / TCP(dport=port, flags="S")
                
                # Send the packet and wait for a response
                start_time = time.time()
                reply = sr1(packet, verbose=0, timeout=timeout)
                elapsed_time = (time.time() - start_time) * 1000
                
                if reply is None:
                    self.display_output(f"{ttl}\t*\t*\t*")
                elif reply.haslayer(TCP) and reply.getlayer(TCP).flags == 0x12:  # SYN-ACK
                    self.display_output(f"{ttl}\t{reply.src}\t{elapsed_time:.2f} ms\tDestination reached")
                    # Send RST to close the connection
                    rst_packet = IP(dst=ip) / TCP(dport=port, flags="R")
                    send(rst_packet, verbose=0)
                    break
                elif reply.haslayer(ICMP):
                    self.display_output(f"{ttl}\t{reply.src}\t{elapsed_time:.2f} ms")
                else:
                    self.display_output(f"{ttl}\t{reply.src}\t{elapsed_time:.2f} ms")
                
                ttl += 1
                
                # Check if we've reached the destination
                if reply is not None and reply.src == ip:
                    break
                    
        except Exception as e:
            self.display_output(f"Error performing TCP traceroute: {str(e)}")
    
    def monitor_ips(self, ips_to_monitor):
        """Monitor IP addresses for availability"""
        check_interval = 60  # Check every 60 seconds
        
        self.display_output(f"Monitoring started for {len(ips_to_monitor)} IP addresses")
        
        # Initial status check
        ip_status = {}
        for ip in ips_to_monitor:
            ip_status[ip] = self.check_ip_status(ip)
        
        # Continuous monitoring
        while not self.stop_monitoring.is_set():
            try:
                for ip in ips_to_monitor:
                    if self.stop_monitoring.is_set():
                        break
                    
                    current_status = self.check_ip_status(ip)
                    
                    # Check if status changed
                    if ip in ip_status and ip_status[ip] != current_status:
                        message = f"Status change for {ip}: {ip_status[ip]} -> {current_status}"
                        self.display_output(message)
                        
                        # Send Telegram notification if configured
                        if self.telegram_token and self.telegram_chat_id:
                            self.send_telegram_message(message)
                    
                    ip_status[ip] = current_status
                
                # Wait for next check
                time.sleep(check_interval)
                
            except Exception as e:
                self.display_output(f"Error in monitoring thread: {str(e)}")
                time.sleep(check_interval)
        
        self.display_output("Monitoring stopped")
    
    def check_ip_status(self, ip):
        """Check the status of an IP address"""
        try:
            # Try to ping the IP
            response = ping3.ping(ip, timeout=2)
            
            if response is not False and response is not None:
                return "Online"
            else:
                return "Offline"
        except Exception as e:
            return f"Error: {str(e)}"
    
    def load_config(self):
        """Load configuration from file"""
        try:
            if os.path.exists("cyber_tool_config.json"):
                with open("cyber_tool_config.json", "r") as f:
                    config = json.load(f)
                
                self.monitored_ips = set(config.get("monitored_ips", []))
                self.telegram_token = config.get("telegram_token")
                self.telegram_chat_id = config.get("telegram_chat_id")
                
                self.display_output("Configuration loaded successfully.")
        except Exception as e:
            self.display_output(f"Error loading configuration: {str(e)}")
    
    def save_config(self):
        """Save configuration to file"""
        try:
            config = {
                "monitored_ips": list(self.monitored_ips),
                "telegram_token": self.telegram_token,
                "telegram_chat_id": self.telegram_chat_id
            }
            
            with open("cyber_tool_config.json", "w") as f:
                json.dump(config, f, indent=2)
            
            self.display_output("Configuration saved successfully.")
        except Exception as e:
            self.display_output(f"Error saving configuration: {str(e)}")

# Main function
def main():
    tool = CyberSecurityTool()
    tool.run()

if __name__ == "__main__":
    main()