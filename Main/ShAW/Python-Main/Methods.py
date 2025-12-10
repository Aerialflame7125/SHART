#Literally the old ShAW methods without all the nasty stuff
import time
import json
import socket
import asyncio
import threading
import base64
import sys
import uuid

# Constants
BUFFER_SIZE = 4096
SERVER_ADDRESS = 'relay.amretar.com'
SERVER_PORT = 6742
TCP_PORT = 6741

def generate_hash(input_data):
    import random
    import hashlib
    random.seed(input_data)
    random_number = random.randint(0, 1000000)
    hash_object = hashlib.sha256(f"{input_data}{random_number}".encode())
    return hash_object.hexdigest()

def upgrade_connection(sock):
    """Upgrade the connection from HTTP to TCP"""
    upgrade_request = f"GET /upgrade HTTP/1.1\r\nHost: {SERVER_ADDRESS}\r\n\r\n"
    sock.sendall(upgrade_request.encode())
    response = sock.recv(1024)
    if b'101 Switching Protocols' in response:
        try:
            data = response.decode().split('\r\n')
            for line in data:
                if line.startswith('Upgrade-Port:'):
                    new_port = int(line.split(':')[1].strip())
                    return new_port
        except Exception as e:
            print(f"[Client] Failed to parse upgrade response: {e}")
            sock.close()
            sys.exit(1)
    else:
        print("[Client] Failed to upgrade connection")
        sock.close()
        sys.exit(1)

def receive_json_response(sock, timeout=30.0):
    """Receive and parse a JSON response from the server"""
    response_data = b''
    start_time = time.time()
    
    while time.time() - start_time < timeout:
        try:
            sock.settimeout(1.0)
            chunk = sock.recv(1024)
            if chunk:
                response_data += chunk
                if b'\n' in response_data:
                    # Extract the first complete JSON message
                    json_data, remaining = response_data.split(b'\n', 1)
                    try:
                        response = json.loads(json_data.decode().strip())
                        return response
                    except json.JSONDecodeError:
                        # Continue accumulating if JSON is incomplete
                        response_data = remaining
                        continue
            else:
                # No data received, connection might be closed
                break
        except socket.timeout:
            # Check if we have a complete JSON message already
            if b'\n' in response_data:
                json_data, remaining = response_data.split(b'\n', 1)
                try:
                    return json.loads(json_data.decode().strip())
                except json.JSONDecodeError:
                    pass
            continue
        except Exception as e:
            print(f"Error receiving response: {e}")
            break
    
    # If we have data but no newline, try to parse it anyway
    if response_data:
        try:
            return json.loads(response_data.decode().strip())
        except json.JSONDecodeError:
            pass
    
    return None

def extract_json_objects_from_line(line: str) -> list:
    """Return a list of JSON objects found in a string.

    Accepts a single JSON object, newline-delimited JSON, or multiple JSON
    objects concatenated together (no delimiter). This is defensive parsing
    to handle noisy or mis-terminated streams.
    """
    if not line:
        return []

    s = line.strip()
    if not s:
        return []

    # Fast-path: single object
    try:
        return [json.loads(s)]
    except json.JSONDecodeError:
        pass

    objs = []
    dec = json.JSONDecoder()
    idx = 0
    length = len(s)
    while idx < length:
        try:
            obj, consumed = dec.raw_decode(s[idx:])
        except json.JSONDecodeError:
            break
        objs.append(obj)
        idx += consumed
        # skip whitespace/newlines
        while idx < length and s[idx] in '\r\n \t':
            idx += 1

    return objs

def enable_long_lived_keepalive(sock):
    """Enable keepalive for long-lived connections"""
    try:
        # Enable keepalive
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        
        # Platform-specific keepalive settings - longer timeouts
        if hasattr(socket, 'TCP_KEEPIDLE'):
            # Linux: 5 minutes idle, 1 minute interval, 5 retries
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 300)
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 60)
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, 5)
        elif hasattr(socket, 'TCP_KEEPALIVE'):
            # macOS
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPALIVE, 300)
        
        # Disable Nagle's algorithm for immediate sending
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        
    except Exception as e:
        print(f"Warning: Could not set keepalive: {e}")

async def pipe(src_reader: asyncio.StreamReader,
               dst_writer: asyncio.StreamWriter):
    """Read from src and write to dst until EOF."""
    try:
        while True:
            data = await src_reader.read(4096)
            if not data:          # peer closed
                break
            dst_writer.write(data)
            await dst_writer.drain()
    finally:
        # Make sure the other side knows weâ€™re done.
        try:
            dst_writer.close()
            await dst_writer.wait_closed()
        except Exception:
            pass

def parse_target(tgt: str):
    """Parse a CONNECT/target string and return (host, port).

    Accepts forms like:
      - host:port
      - host:port/path
      - http://host:port/path
      - https://host:port/path
      - [::1]:port  (bracketed IPv6)

    Raises ValueError on invalid format.
    """
    try:
        from urllib.parse import urlsplit
    except Exception:
        urlsplit = None

    if tgt.startswith(('http://', 'https://')) and urlsplit:
        u = urlsplit(tgt)
        if not u.hostname:
            raise ValueError(f"Invalid URL target: {tgt}")
        host = u.hostname
        port = u.port or (80 if u.scheme == 'http' else 443)
        return host, int(port)

    # Strip incidental leading // used in some proxies
    if tgt.startswith('//'):
        tgt = tgt[2:]

    # Bracketed IPv6 form [::1]:8080
    if tgt.startswith('['):
        closing = tgt.find(']')
        if closing == -1:
            raise ValueError('Invalid bracketed IPv6 target')
        host = tgt[1:closing]
        rest = tgt[closing+1:]
        if rest.startswith(':'):
            port_str = rest[1:]
        else:
            raise ValueError('Missing port for bracketed IPv6 target')
    else:
        # Split on the last colon so IPv6-like values keep host portion
        if ':' in tgt:
            host, port_str = tgt.rsplit(':', 1)
        else:
            raise ValueError('Missing port in target')

    # strip any path accidentally included in the port portion
    if '/' in port_str:
        port_str = port_str.split('/', 1)[0]

    host = host.lstrip('/')

    if not port_str or not port_str.isdigit():
        raise ValueError(f'Invalid port: {port_str}')

    return host, int(port_str)

async def handle_client(client_reader: asyncio.StreamReader,
                        client_writer: asyncio.StreamWriter):
    peername = client_writer.get_extra_info("peername")
    print(f"[{peername}] new connection")

    # ----- 1. Read the CONNECT request -----
    raw_req = b""
    while b"\r\n\r\n" not in raw_req:
        chunk = await client_reader.read(4096)
        if not chunk:          # client closed before finishing
            print(f"[{peername}] closed before request")
            return
        raw_req += chunk

    first_line = raw_req.split(b"\r\n", 1)[0].decode()
    method, target, _httpver = first_line.split()

    # Use module-level parse_target helper
    try:
        host, port = parse_target(target)
    except Exception as exc:
        err_msg = f"HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\nBad target: {exc}\r\n"
        client_writer.write(err_msg.encode())
        await client_writer.drain()
        return

    print(f"[{peername}] Proxy request to {host}:{port} (method={method})")

    # ----- 2. Open a socket to the real destination -----
    try:
        remote_reader, remote_writer = await asyncio.open_connection(host, port)
    except Exception as exc:
        err_msg = f"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n{exc}\r\n"
        client_writer.write(err_msg.encode())
        await client_writer.drain()
        return

    # If this is a CONNECT request we should create a raw TCP tunnel.
    if method.upper() == 'CONNECT':
        # tell the client we are ready and start piping raw bytes
        client_writer.write(b"HTTP/1.1 200 Connection established\r\n\r\n")
        await client_writer.drain()
        await asyncio.gather(
            pipe(client_reader, remote_writer),
            pipe(remote_reader, client_writer)
        )
        print(f"[{peername}] closed tunnel")
        return

    # Otherwise, treat as a regular HTTP proxy: forward the original HTTP request
    # We must rewrite the request-line if it contains an absolute-URL (origin servers expect origin-form)
    try:
        # raw_req currently holds up to the end of headers (we read until \r\n\r\n)
        # split into first line and the rest
        if b"\r\n" in raw_req:
            _, rest = raw_req.split(b"\r\n", 1)
        else:
            rest = b""

        # compute path to use in the origin-form request line
        path = target
        if target.startswith(('http://', 'https://')):
            from urllib.parse import urlsplit
            u = urlsplit(target)
            p = u.path or '/'
            if u.query:
                p = p + ('?' + u.query)
            path = p

        new_first_line = f"{method} {path} {_httpver}\r\n".encode()
        new_req = new_first_line + rest

        # send the rewritten request to the remote server
        remote_writer.write(new_req)
        await remote_writer.drain()

        # now start piping for the rest of the connection (handle persistent connections / bodies)
        await asyncio.gather(
            pipe(client_reader, remote_writer),
            pipe(remote_reader, client_writer)
        )
        print(f"[{peername}] proxied request to {host}:{port}")

    except Exception as e:
        print(f"[{peername}] Error forwarding request: {e}")

def run_async_in_thread(coro):
    """Run an async coroutine in a new thread with its own event loop"""
    def run_in_thread():
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            loop.run_until_complete(coro)
        finally:
            loop.close()
    
    thread = threading.Thread(target=run_in_thread, daemon=True)
    thread.start()
    return thread

async def openproxy(port):
    if not port:
        print("No port recieved, method ending prematurely.")
        return
    try:
        server = await asyncio.start_server(handle_client, "localhost", port)
    except Exception as e:
        if e is PermissionError:
            print(f"Permission denied for port {port}, trying again..")
            await asyncio.sleep(2)
            await openproxy(port)
        else:
            print("Failed to start")
    addrs = ", ".join(str(sock.getsockname()) for sock in server.sockets)
    print(f"Proxy listening on {addrs}")
    async with server:
        await server.serve_forever()

class ChannelManager:
    """Manages multiplexed channels over a single TCP connection"""
    def __init__(self, tcp_sock, node_id):
        self.tcp_sock = tcp_sock
        self.node_id = node_id
        self.channels = {}  # channel_id -> {'socket': local_sock, 'active': bool, 'last_activity': timestamp}
        self.lock = threading.Lock()
        self.send_lock = threading.Lock()
        
    def send_message(self, msg):
        """Send a JSON message over the main connection (thread-safe)"""
        try:
            with self.send_lock:
                self.tcp_sock.sendall((json.dumps(msg) + '\n').encode())
        except Exception as e:
            print(f"[Client] Error sending message: {e}")

    def start_channel_heartbeat(self, channel_id):
        """Send periodic heartbeat messages to keep channel alive"""
        def heartbeat_loop():
            last_heartbeat = time.time()
            while True:
                time.sleep(30)  # Reduced frequency to 30 seconds
                
                with self.lock:
                    if channel_id not in self.channels:
                        break
                    channel = self.channels[channel_id]
                    if not channel.get('active', False):
                        continue
                
                # Only send heartbeat if no recent activity
                current_time = time.time()
                if current_time - channel.get('last_activity', 0) > 25:
                    try:
                        self.send_message({
                            'type': 'channel_heartbeat',
                            'channel_id': channel_id,
                            'node_id': self.node_id,
                            'timestamp': current_time
                        })
                        last_heartbeat = current_time
                    except Exception as e:
                        print(f"[Client] Channel {channel_id} heartbeat failed: {e}")
                        break
    
        threading.Thread(target=heartbeat_loop, daemon=True).start()

    def handle_open_channel(self, channel_id, client_port):
        """Open a channel to a local port"""
        try:
            # Connect to local service
            local_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            local_sock.settimeout(300.0)  # Increased timeout to 5 minutes

            enable_long_lived_keepalive(local_sock)
            local_sock.connect(("127.0.0.1", client_port))
            print(f"[Client] Channel {channel_id}: Connected to local port {client_port}")
            
            with self.lock:
                self.channels[channel_id] = {
                    'socket': local_sock,
                    'active': True,
                    'last_activity': time.time(),
                    'client_port': client_port
                }
            
            # Send acknowledgment
            self.send_message({
                'type': 'channel_ack',
                'channel_id': channel_id,
                'node_id': self.node_id
            })

            self.start_channel_heartbeat(channel_id)
            
            # Start reading from local socket and forwarding to server
            def forward_to_server():
                try:
                    while True:
                        try:
                            data = local_sock.recv(BUFFER_SIZE)
                            if not data:
                                break
                            
                            # Update activity timestamp
                            with self.lock:
                                if channel_id in self.channels:
                                    self.channels[channel_id]['last_activity'] = time.time()
                            
                            # Send data over main connection with channel ID
                            self.send_message({
                                'type': 'channel_data',
                                'channel_id': channel_id,
                                'data': base64.b64encode(data).decode('utf-8'),
                                'node_id': self.node_id
                            })
                        except socket.timeout:
                            # Check if channel is still active
                            with self.lock:
                                if channel_id not in self.channels:
                                    break
                            continue
                        except ConnectionAbortedError:
                            break
                        except ConnectionResetError:
                            break
                except Exception as e:
                    if "10038" not in str(e) and "10054" not in str(e):
                        print(f"[Client] Channel {channel_id} forward error: {e}")
                finally:
                    # Send close message only if channel still exists
                    with self.lock:
                        channel_exists = channel_id in self.channels
                    
                    if channel_exists:
                        self.send_message({
                            'type': 'channel_close',
                            'channel_id': channel_id,
                            'node_id': self.node_id
                        })
                    
                    try:
                        local_sock.close()
                    except:
                        pass
                    
                    with self.lock:
                        if channel_id in self.channels:
                            del self.channels[channel_id]
                    
                    print(f"[Client] Channel {channel_id}: Closed")
            
            threading.Thread(target=forward_to_server, daemon=True).start()
            
        except ConnectionRefusedError:
            print(f"[Client] Channel {channel_id}: Local port {client_port} is not open")
            self.send_message({
                'type': 'channel_error',
                'channel_id': channel_id,
                'error': 'Connection refused',
                'node_id': self.node_id
            })
        except socket.timeout:
            print(f"[Client] Channel {channel_id}: Timeout connecting to local port {client_port}")
            self.send_message({
                'type': 'channel_error',
                'channel_id': channel_id,
                'error': 'Connection timeout',
                'node_id': self.node_id
            })
        except Exception as e:
            print(f"[Client] Channel {channel_id}: Error opening channel: {e}")
            self.send_message({
                'type': 'channel_error',
                'channel_id': channel_id,
                'error': str(e),
                'node_id': self.node_id
            })
    
    def handle_channel_data(self, channel_id, data):
        """Handle incoming data for a channel"""
        with self.lock:
            channel = self.channels.get(channel_id)
            if channel:
                channel['last_activity'] = time.time()
        
        if channel:
            try:
                decoded_data = base64.b64decode(data)
                channel['socket'].sendall(decoded_data)
            except Exception as e:
                if "10038" not in str(e) and "10054" not in str(e):
                    print(f"[Client] Error forwarding data on channel {channel_id}: {e}")
    
    def handle_channel_close(self, channel_id):
        """Handle channel close from server"""
        print(f"[Client] Channel {channel_id}: Closing due to server request")
        with self.lock:
            channel = self.channels.get(channel_id)
            if channel:
                try:
                    channel['socket'].close()
                except:
                    pass
                del self.channels[channel_id]

def checkForOthers():
    global version
    #Attempt local connection to check if already existing client
    tsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # Use a short timeout for local socket checks so we don't block the client
    try:
        tsock.settimeout(2.0)
        tsock.connect(("localhost", 9942))
    except socket.timeout:
        print("Connection timeout.")
        try:
            tsock.close()
        except Exception:
            pass
        return
    except ConnectionRefusedError:
        print("Connection Refused")
        try:
            tsock.close()
        except Exception:
            pass
        return
    except Exception as e:
        # Unexpected error — log and abort the quick-check
        print(f"Unexpected connection error: {e}")
        try:
            tsock.close()
        except Exception:
            pass
        return

    # Connected — receive data in a safe try/except
    try:
        a = tsock.recv(4096)
    except Exception as e:
        print(f"Error receiving from local socket: {e}")
        try:
            tsock.close()
        except Exception:
            pass
        return
    a = a.decode()
    j = json.loads(a)
    if j.get('ShAW') == "client":
        if int(j.get('version')) < int(version):
            tsock.sendall("{'message': '2o1', 'action': 'ewm', 'reason': 'Upgrading ShAW version'}".encode())
        elif int(j.get('version')) == int(version):
            tsock.sendall("{'message': '2o1', 'action': 'e', 'reason': 'Conflicting ShAW processes'}".encode())
        else:
            tsock.close()
            sys.exit(0)

async def localsrv(tcpsock, nodeid):
    """Start a small local asyncio TCP server to handle local discovery/conflict checks.

    The server will reply with a short JSON hello and accept simple commands from
    local clients. Any 'quitting' requests are forwarded to the main TCP control
    socket via tcpsock.sendall(...).
    """
    global version

    async def handle_local(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        peer = writer.get_extra_info('peername')
        try:
            print(f"Connected to localhost {peer}")
            hello = json.dumps({'ShAW': 'client', 'version': version}) + '\n'
            writer.write(hello.encode())
            await writer.drain()

            while True:
                data = await reader.readline()
                if not data:
                    break
                try:
                    j = json.loads(data.decode())
                except Exception:
                    continue

                msg = j.get('message')
                action = j.get('action')
                reason = j.get('reason')

                if msg == '2o1':
                    if action == 'e':
                        out = json.dumps({'msg': 'quitting', 'node_id': nodeid, 'reason': '2 processes on 1 node'}) + '\n'
                        try:
                            tcpsock.sendall(out.encode())
                        except Exception as e:
                            print(f"Failed to notify controller about quitting: {e}")
                    elif action == 'ewm':
                        out = json.dumps({'msg': 'quitting', 'node_id': nodeid, 'reason': reason}) + '\n'
                        try:
                            tcpsock.sendall(out.encode())
                        except Exception as e:
                            print(f"Failed to notify controller about quitting: {e}")

        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    # Try to bind to the well-known local-check port. If another instance
    # already has that port open, we should not crash the background thread —
    # simply log and return so the main client keeps running.
    tried = 0
    max_retries = 4
    while True:
        try:
            server = await asyncio.start_server(handle_local, '127.0.0.1', 9942)
            break
        except OSError as e:
            # EADDRINUSE on Linux, 10048 on Windows -> address already in use
            import errno
            if getattr(e, 'errno', None) in (errno.EADDRINUSE, 10048):
                # Attempt to contact the existing process and ask it to quit so
                # this instance can take the port. We will try a few times and
                # then give up.
                tried += 1
                try:
                    print("Local check server port 9942 already in use — attempting to ask existing process to quit (try %d/%d)" % (tried, max_retries))
                    with socket.create_connection(('127.0.0.1', 9942), timeout=2) as s:
                        # read the hello line
                        s.settimeout(2.0)
                        data = b""
                        while b"\n" not in data:
                            chunk = s.recv(1024)
                            if not chunk:
                                break
                            data += chunk
                        try:
                            hello = json.loads(data.decode().strip())
                        except Exception:
                            hello = None

                        # If the remote claims to be a ShAW client, request it quits
                        if hello and hello.get('ShAW') == 'client':
                            # Send a JSON kill request (2o1/e) newline-terminated
                            msg = json.dumps({'message': '2o1', 'action': 'e', 'reason': 'Conflicting ShAW processes - please exit'}) + '\n'
                            try:
                                s.sendall(msg.encode())
                            except Exception:
                                pass
                        else:
                            # If no structured hello, still try a generic quit request
                            try:
                                s.sendall((json.dumps({'message': '2o1', 'action': 'e', 'reason': 'Conflicting ShAW processes'}) + '\n').encode())
                            except Exception:
                                pass

                except Exception as e2:
                    # Could not contact the existing process – nothing else to do here
                    print(f"Failed to contact local process on 9942: {e2}")

                # Wait a short while for the other process to exit and release the port
                await asyncio.sleep(1.0)

                if tried >= max_retries:
                    print("Giving up trying to bind local check server on port 9942; another instance remains.")
                    return
                # Try again to bind
                continue
            raise
    addrs = ','.join(str(sock.getsockname()) for sock in server.sockets)
    print(f"Local check server listening on {addrs}")
    async with server:
        await server.serve_forever()
                
def main():
    NODE_ID = str(uuid.uuid4())
    hashed_id = generate_hash(NODE_ID)
    print(f"[Client] Starting with Node ID: {NODE_ID}")

    while True:  # main reconnect loop
        try:
            checkForOthers()
            
            # Initial HTTP connection
            print(f"[Client] Connecting to {SERVER_ADDRESS}:{SERVER_PORT}")
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((SERVER_ADDRESS, SERVER_PORT))
            new_port = upgrade_connection(sock)
            sock.close()

            # TCP connection
            print(f"[Client] Upgrading to TCP on port {new_port}")
            tcp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            tcp_sock.connect((SERVER_ADDRESS, new_port))

            # Start local tcp server (run in background so main loop continues)
            print(f"[Client] Starting local TCP server.")
            # Run the local server in a background thread so it doesn't block main
            run_async_in_thread(localsrv(tcp_sock, NODE_ID))
            
            # CRITICAL: Disable Nagle's algorithm on main connection
            try:
                tcp_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            except:
                pass

            enable_long_lived_keepalive(tcp_sock)
            # Register node
            if sys.platform == 'Windows' or sys.platform == 'win32' or sys.platform == "windows":
                registration = json.dumps({'node_id': NODE_ID, 'hash': hashed_id, 'client_type': "Windows"}) + '\n'
            else:
                registration = json.dumps({'node_id': NODE_ID, 'hash': hashed_id, 'client_type': "Python"}) + '\n'
            tcp_sock.sendall(registration.encode())
            print(f"[Client] Registered with server")

            # Create channel manager
            channel_mgr = ChannelManager(tcp_sock, NODE_ID)
            
            buffer = ""
            last_health = time.time()
            
            while True:  # main command/health loop
                # Send health update every 5 seconds
                if time.time() - last_health >= 5:
                    health = {
                        'node_id': NODE_ID,
                        'hostname': socket.gethostname(),
                        'status': 'healthy',
                        'uptime': time.time(),
                        'RAM_usage': subprocess.getoutput("free -m") if sys.platform == 'linux' else 'N/A',
                        'CPU_usage': subprocess.getoutput("top -bn1 | grep 'Cpu(s)'") if sys.platform == 'linux' else 'N/A'
                    }
                    tcp_sock.sendall((json.dumps(health) + '\n').encode())
                    last_health = time.time()

                current_time = time.time()
                if not hasattr(main, 'last_heartbeat'):
                    main.last_heartbeat = current_time
                
                if current_time - main.last_heartbeat >= 15:
                    try:
                        heartbeat = json.dumps({'type': 'heartbeat', 'timestamp': current_time}) + '\n'
                        tcp_sock.sendall(heartbeat.encode())
                        main.last_heartbeat = current_time
                    except:
                        print("[Client] Heartbeat send failed, connection may be dead")
                        break

                # Listen for commands with short timeout
                tcp_sock.settimeout(300.0)
                try:
                    data = tcp_sock.recv(4096)
                    if not data:
                        print("[Client] Connection closed by server")
                        break
                        
                    buffer += data.decode()
                    
                    # Process complete JSON messages (delimited by newlines)
                    while '\n' in buffer:
                        line, buffer = buffer.split('\n', 1)
                        if not line.strip():
                            continue
                        
                        try:
                            # Extract one or more JSON objects from the line (robust to concatenated JSON)
                            messages = extract_json_objects_from_line(line)
                            for message in messages:
                                msg_type = message.get('type') or message.get('action')

                            if msg_type == 'open_channel':
                                # Open a multiplexed channel
                                channel_id = message['channel_id']
                                client_port = message['client_port']
                                print(f"[Client] Opening channel {channel_id} to local port {client_port}")
                                # Handle in separate thread to avoid blocking
                                threading.Thread(
                                    target=channel_mgr.handle_open_channel,
                                    args=(channel_id, client_port),
                                    daemon=True
                                ).start()
                                
                            elif msg_type == 'channel_data':
                                # Receive data for a channel
                                channel_id = message['channel_id']
                                data = message['data']
                                channel_mgr.handle_channel_data(channel_id, data)
                                
                            elif msg_type == 'channel_close':
                                # Close a channel
                                channel_id = message['channel_id']
                                channel_mgr.handle_channel_close(channel_id)

                            elif msg_type == 'channel_heartbeat':
                                pass
                                
                            elif msg_type == 'opennet':
                                print("Received opennet")
                                port = message.get('port')
                                if isinstance(port, int) and 0 < port < 65536:
                                    print(f"Starting proxy server on port {port} in background...")
                                    run_async_in_thread(openproxy(port))
                                    print(f"Proxy server started on port {port}")
                                else:
                                    print(f"Invalid port: {port}")
                        except json.JSONDecodeError as e:
                            print(f"[Client] Error parsing message: {e}")
                        except Exception as e:
                            print(f"[Client] Error handling message: {e}")

                except socket.timeout:
                    pass  # no data received, continue
                except Exception as e:
                    print(f"[Client] Error receiving data: {e}")
                    break

        except ConnectionRefusedError:
            print(f"[Client] Connection refused, retrying in 5s")
            time.sleep(5)
        except Exception as e:
            print(f"[Client] Connection error: {e}, retrying in 5s")
            time.sleep(5)
