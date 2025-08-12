import json
import socket
import time
import traceback
import types
import uuid
import os
import asyncio
import pickle
from pathlib import Path

import threading
import time

import tornado
import tornado.web
import tornado.websocket

from urllib.parse import urlencode
from tornado.httpclient import AsyncHTTPClient, HTTPRequest

# This brakes ROS1 support
from rosboard.topics import get_all_topics, update_all_topics_with_typedef
from rosboard.ros_init import rospy

# Config stuff for auth
from rosboard.config import GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, DEVICE_CODE_URL, TOKEN_URL
from rosboard.config import PERSISTENT_SESSION_FILE, PERSISTENT_SESSION_TIMEOUT
from rosboard.config import is_email_domain_allowed

from . import __version__

def current_user_from_cookie(handler):
    """Extract user data from secure cookie"""
    data = handler.get_secure_cookie("session")
    if not data:
        return None
    try:
        return json.loads(data.decode("utf-8"))
    except Exception:
        return None

class AuthStartHandler(tornado.web.RequestHandler):
    """Handler to start Google OAuth device flow"""
    
    def set_default_headers(self):
        self.set_header("Access-Control-Allow-Origin", "*")
        self.set_header("Access-Control-Allow-Headers", "content-type")
        self.set_header("Access-Control-Allow-Methods", "POST, OPTIONS")

    def options(self):
        self.set_status(204)
        self.finish()

    def write_json(self, obj, status=200):
        self.set_status(status)
        self.set_header("Content-Type", "application/json")
        self.finish(json.dumps(obj))

    async def post(self):
        if not GOOGLE_CLIENT_ID:
            return self.write_json({"error": "server_not_configured", "detail": "Missing GOOGLE_CLIENT_ID"}, 500)


        body = urlencode({
            "client_id": GOOGLE_CLIENT_ID,
            "scope": "openid email profile"
        })
        req = HTTPRequest(
            DEVICE_CODE_URL,
            method="POST",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            body=body,
        )
        http = AsyncHTTPClient()
        resp = await http.fetch(req, raise_error=False)

        if resp.code != 200:
            return self.write_json({"error": "google_device_code_failed", "detail": resp.body.decode()}, 502)

        data = json.loads(resp.body.decode())
        self.write_json({
            "device_code": data["device_code"],
            "user_code": data["user_code"],
            "verification_url": data["verification_url"],
            "interval": data.get("interval", 2.5),
            "expires_in": data.get("expires_in", 600)
        })

class AuthPollHandler(tornado.web.RequestHandler):
    """Handler to poll for OAuth completion"""
    
    def set_default_headers(self):
        self.set_header("Access-Control-Allow-Origin", "*")
        self.set_header("Access-Control-Allow-Headers", "content-type")
        self.set_header("Access-Control-Allow-Methods", "POST, OPTIONS")

    def options(self):
        self.set_status(204)
        self.finish()

    def write_json(self, obj, status=200):
        self.set_status(status)
        self.set_header("Content-Type", "application/json")
        self.finish(json.dumps(obj))

    async def post(self):
        try:
            payload = json.loads(self.request.body.decode() or "{}")
        except Exception:
            payload = {}

        device_code = payload.get("device_code")
        if not device_code:
            return self.write_json({"error": "missing_device_code"}, 400)

        body = urlencode({
            "client_id": GOOGLE_CLIENT_ID,
            "client_secret": GOOGLE_CLIENT_SECRET,
            "device_code": device_code,
            "grant_type": "urn:ietf:params:oauth:grant-type:device_code"
        })
        req = HTTPRequest(
            TOKEN_URL,
            method="POST",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            body=body,
        )
        http = AsyncHTTPClient()
        resp = await http.fetch(req, raise_error=False)
        data = json.loads(resp.body.decode())

        # If authorization is not complete yet, Google returns an error
        if "error" in data:
            return self.write_json(data, 202)

        # We should have id_token
        id_tok = data.get("id_token")
        if not id_tok:
            return self.write_json({"error": "no_id_token", "detail": data}, 502)

        # Verify the id_token
        loop = asyncio.get_running_loop()
        def _verify():
            from google.oauth2 import id_token
            from google.auth.transport import requests as grequests
            req = grequests.Request()
            return id_token.verify_oauth2_token(id_tok, req, GOOGLE_CLIENT_ID)

        try:
            claims = await loop.run_in_executor(None, _verify)
        except Exception as e:
            return self.write_json({"error": "id_token_verification_failed", "detail": str(e)}, 401)

        result = {
            "email": claims.get("email"),
            "email_verified": claims.get("email_verified"),
            "sub": claims.get("sub"),
            "name": claims.get("name"),
            "picture": claims.get("picture"),
        }

        # Check domain restrictions
        if not is_email_domain_allowed(result["email"]):
            return self.write_json({
                "error": "domain_not_allowed", 
                "detail": f"Email domain not in allowed list. Contact administrator for access."
            }, 403)

        # Persist a session for ~30 days
        self.set_secure_cookie(
            "session",
            json.dumps({"email": result["email"], "sub": result["sub"]}),
            expires_days=60,
            httponly=True,
            samesite="Lax",
            secure=True  # serve over HTTPS
        )

        return self.write_json(result, 200)

class MeHandler(tornado.web.RequestHandler):
    """Handler to check current user status"""
    
    def get(self):
        user = current_user_from_cookie(self)
        self.set_header("Content-Type", "application/json")
        if user:
            self.finish(json.dumps({"authenticated": True, "email": user.get("email"), "sub": user.get("sub")}))
        else:
            # Check if authentication is enabled
            if GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET:
                self.finish(json.dumps({"authenticated": False, "auth_required": True}))
            else:
                self.finish(json.dumps({"authenticated": False, "auth_required": False}))

class LogoutHandler(tornado.web.RequestHandler):
    """Handler to logout user"""
    
    def post(self):
        self.clear_cookie("session")
        self.set_header("Content-Type", "application/json")
        self.finish(json.dumps({"ok": True}))

class AdminHandler(tornado.web.RequestHandler):
    """Admin endpoint to monitor WebSocket connections"""
    
    def get(self):
        # Get connection statistics
        stats = ROSBoardSocketHandler.get_connection_stats()
        
        # Add additional system info
        stats['system'] = {
            'hostname': socket.gethostname(),
            'version': __version__,
            'uptime': time.time() - getattr(self, '_start_time', time.time())
        }
        
        self.set_header("Content-Type", "application/json")
        self.finish(json.dumps(stats, indent=2))

class AdminPageHandler(tornado.web.RequestHandler):
    """Handler for the admin page"""
    
    def get(self):
        self.set_header("Content-Type", "text/html")
        static_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'html')
        admin_file = os.path.join(static_path, 'admin.html')
        
        try:
            with open(admin_file, "r", encoding="utf-8") as f:
                self.write(f.read())
        except FileNotFoundError:
            self.set_status(404)
            self.write("Admin page not found")

class LoginPageHandler(tornado.web.RequestHandler):
    """Handler for the login page"""
    
    def get(self):
        self.set_header("Content-Type", "text/html")
        static_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'html')
        login_file = os.path.join(static_path, 'login.html')
        
        try:
            with open(login_file, "r", encoding="utf-8") as f:
                self.write(f.read())
        except FileNotFoundError:
            self.set_status(404)
            self.write("Login page not found")

class AuthenticatedHandler(tornado.web.RequestHandler):
    """Base handler that requires authentication (if enabled)"""
    
    def prepare(self):
        # Check if authentication is enabled        
        if not GOOGLE_CLIENT_ID or not GOOGLE_CLIENT_SECRET:
            # Authentication disabled, allow access
            return
            
        user = current_user_from_cookie(self)
        if not user:
            # Redirect to login page instead of returning JSON error
            self.redirect('/login.html')
            return
        self.current_user = user


class MainPageHandler(AuthenticatedHandler):
    """Handler for the main page - requires authentication"""

    def get(self, path=None):
        self.render(self.default_filename, foxglove_uri=self.foxglove_uri, foxglove_layout_uri=self.foxglove_layout_uri)

    def set_extra_headers(self, path):
        # Disable cache
        self.set_header('Cache-Control', 'no-store, no-cache, must-revalidate, max-age=0')

    def initialize(self, default_filename, foxglove_uri, foxglove_layout_uri):
        self.default_filename = default_filename
        self.foxglove_uri = foxglove_uri
        self.foxglove_layout_uri = foxglove_layout_uri


class ROSBoardSocketHandler(tornado.websocket.WebSocketHandler):
    sockets = set()  # All sockets
    users = {}       # Track users by email -> list of their sockets
    dropped_users = {}  # Track recently dropped users with timestamps for Foxglove association

    # Time window (secs) for dropped user association with Foxglove since we don't have a way 
    # to detect the user from the Foxglove connection
    dropped_association_timeout: int = 5
    
    @classmethod
    def load_persistent_sessions(cls):
        """Load persistent Foxglove sessions from file"""
        try:
            if os.path.exists(PERSISTENT_SESSION_FILE):
                with open(PERSISTENT_SESSION_FILE, 'rb') as f:
                    sessions = pickle.load(f)
                    return sessions
        except Exception as e:
            print(f"Failed to load persistent sessions: {e}")
        return {}
    
    @classmethod
    def save_persistent_sessions(cls):
        """Save current Foxglove sessions to file"""
        try:
            # Get current Foxglove connections with timestamps
            foxglove_sessions = {}
            current_time = time.time()
            
            for email, connections in cls.users.items():
                foxglove_connections = []
                for conn in connections:
                    if getattr(conn, 'client_type', '') == 'foxglove':
                        foxglove_connections.append(conn)
                
                # If user has Foxglove connections, save the connection info
                if foxglove_connections:
                    # Store the current time as the session timestamp
                    # This represents when the session was last active
                    foxglove_sessions[email] = current_time
            
            # Save to file
            with open(PERSISTENT_SESSION_FILE, 'wb') as f:
                pickle.dump(foxglove_sessions, f)
        except Exception as e:
            print(f"Failed to save persistent sessions: {e}")
    
    @classmethod
    def force_save_persistent_sessions(cls):
        """Force save persistent sessions immediately (useful for debugging)"""
        cls.save_persistent_sessions()
    
    @classmethod
    def cleanup_expired_sessions(cls):
        """Remove expired sessions (older than configured timeout) from persistent storage"""
        try:
            sessions = cls.load_persistent_sessions()
            
            current_time = time.time()
            expired_sessions = []
            
            for email, timestamp in sessions.items():
                if current_time - timestamp > PERSISTENT_SESSION_TIMEOUT:
                    expired_sessions.append(email)
            
            for email in expired_sessions:
                del sessions[email]
            
            # Save cleaned up sessions
            with open(PERSISTENT_SESSION_FILE, 'wb') as f:
                pickle.dump(sessions, f)
            
            if expired_sessions:
                print(f"Cleaned up {len(expired_sessions)} expired sessions (timeout: {PERSISTENT_SESSION_TIMEOUT}s)")
        except Exception as e:
            print(f"Failed to cleanup expired sessions: {e}")
    
    @classmethod
    def find_persistent_foxglove_user(cls):
        """Find a persistent Foxglove user based on recent activity"""
        cls.cleanup_expired_sessions()
        
        try:
            sessions = cls.load_persistent_sessions()
            # Find the most recent session
            if sessions:
                most_recent_email = max(sessions.keys(), key=lambda email: sessions[email])
                most_recent_time = sessions[email]
                
                # Check if it's within configured timeout
                if time.time() - most_recent_time <= PERSISTENT_SESSION_TIMEOUT:
                    return most_recent_email
        except Exception as e:
            print(f"Failed to find persistent Foxglove user: {e}")
        
        return None
    
    @classmethod
    def initialize_persistent_sessions(cls):
        """Initialize persistent sessions on startup"""
        cls.load_persistent_sessions()
        cls.cleanup_expired_sessions()
        
        # Start periodic session saving (every 30 seconds)
        cls.start_periodic_session_saving()
    
    @classmethod
    def start_periodic_session_saving(cls):
        """Start periodic saving of persistent sessions to handle runtime crashes"""
        def periodic_save():
            while True:
                try:
                    time.sleep(15)  # Save every 15 seconds
                    if cls.sockets:  # Only save if there are active connections
                        cls.save_persistent_sessions()
                except Exception as e:
                    print(f"Periodic session save failed: {e}")
        
        # Start periodic saving in background thread
        save_thread = threading.Thread(target=periodic_save, daemon=True)
        save_thread.start()

    def check_origin(self, origin):
        # Allow connections from any origin so we can connect from other pages
        return True

    def initialize(self, node, max_allowed_latency, full_topics, allow_external_clients):
        # store the instance of the ROS node that created this WebSocketHandler so we can access it later
        self.node = node
        self.max_allowed_latency = max_allowed_latency
        self.allow_external_clients = allow_external_clients

        # Cache the topics and their typedefs since this can be slow
        # This is a dict by reference, so it will be updated by the rosboard node
        self.full_topics = full_topics

    def get_compression_options(self):
        # Non-None enables compression with default options.
        return {}

    def handle_auth(self):
        if GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET:
            # First, try to get user from cookie (regardless of connection source)
            user = current_user_from_cookie(self)
            if user:
                # User is authenticated via cookie - use their real identity
                self.user = user
                self.auth_method = "cookie"
                # Determine if this is coming from Foxglove or main interface
                if self._is_foxglove_connection():
                    self.client_type = "foxglove"
                else:
                    self.client_type = "rosboard"
            else:
                # No valid session - check if external clients are allowed
                if self.allow_external_clients:
                    # Check if this might be a Foxglove connection from a recently dropped user
                    if self._is_foxglove_connection():
                        recently_dropped_user = ROSBoardSocketHandler.find_recently_dropped_user()
                        if recently_dropped_user:
                            # Associate this connection with the recently dropped user
                            self.user = {"email": recently_dropped_user, "sub": "from_dropped"}
                            self.auth_method = "dropped_association"
                            self.client_type = "foxglove"
                        else:
                            # Check for persistent Foxglove sessions (for restarts)
                            persistent_user = ROSBoardSocketHandler.find_persistent_foxglove_user()
                            if persistent_user:
                                # Associate with persistent user from file
                                self.user = {"email": persistent_user, "sub": "from_persistent"}
                                self.auth_method = "persistent_association"
                                self.client_type = "foxglove"
                            else:
                                # No persistent user, treat as external client
                                self.user = {"email": "external_client", "sub": "external"}
                                self.auth_method = "external"
                                self.client_type = "foxglove"
                    else:
                        # Not Foxglove, treat as regular external client
                        self.user = {"email": "external_client", "sub": "external"}
                        self.auth_method = "external"
                        self.client_type = "external"
                    
                    print(f"External client connected from {self.request.remote_ip} - allowing anonymous access")
                else:
                    # External clients not allowed, close connection
                    self.close(1008, "Authentication required")
                    return False
        else:
            # Authentication disabled
            self.user = {"email": "anonymous", "sub": "anonymous"}
            self.auth_method = "no-auth"
            self.client_type = "foxglove" if self._is_foxglove_connection() else "rosboard"
        
        return True

    def open(self):
        # Initialize persistent sessions on first connection (before processing anything)
        if len(ROSBoardSocketHandler.sockets) == 0:
            ROSBoardSocketHandler.initialize_persistent_sessions()
                
        if not self.handle_auth():
            return

        # Initialize WebSocket connection
        self.id = uuid.uuid4()    # unique socket id
        self.latency = 0          # latency measurement
        self.last_ping_times = [0] * 1024
        self.ping_seq = 0

        self.set_nodelay(True)

        # polyfill of is_closing() method for older versions of tornado
        if not hasattr(self.ws_connection, "is_closing"):
            self.ws_connection.is_closing = types.MethodType(
                lambda self_: self_.stream.closed() or self_.client_terminated or self_.server_terminated,
                self.ws_connection
            )

        self.update_intervals_by_topic = {}  # this socket's throttle rate on each topic
        self.last_data_times_by_topic = {}   # last time this socket received data on each topic

        # Add to global tracking
        ROSBoardSocketHandler.sockets.add(self)
        
        # Track user-specific connections
        user_email = self.user.get('email', 'anonymous')
        if user_email not in ROSBoardSocketHandler.users:
            ROSBoardSocketHandler.users[user_email] = []
        ROSBoardSocketHandler.users[user_email].append(self)
        
        # Log connection with enhanced information
        print(f"User {user_email} connected (via {self.auth_method} from {self.client_type}). Total connections: {len(ROSBoardSocketHandler.sockets)}")

        # Save persistent sessions if this is a Foxglove connection (capture current state)
        if getattr(self, 'client_type', '') == 'foxglove' and user_email != 'external_client':
            ROSBoardSocketHandler.save_persistent_sessions()

        self.write_message(json.dumps([ROSBoardSocketHandler.MSG_SYSTEM, {
            "hostname": socket.gethostname(),
            "version": __version__,
            "user": self.user.get("email", "unknown")
        }], separators=(',', ':')))

    def _is_foxglove_connection(self):
        """Detect if this WebSocket connection is coming from Foxglove"""
        # Since the user is redirecting within the same browser session,
        # we only need to check for obvious Foxglove identifiers
        
        # Check User-Agent for Foxglove identifiers
        user_agent = self.request.headers.get("User-Agent", "").lower()
        if "foxglove" in user_agent:
            return True
            
        # Check Origin header for Foxglove domains
        origin = self.request.headers.get("Origin", "")
        if origin and "foxglove" in origin.lower():
            return True
            
        # For redirects within the same session, we'll be more conservative
        # Only classify as Foxglove if we're very sure
        return False

    def on_close(self):
        # Remove from global tracking
        ROSBoardSocketHandler.sockets.remove(self)
        
        # Remove from user-specific tracking
        user_email = self.user.get('email', 'anonymous')
        if user_email in ROSBoardSocketHandler.users:
            ROSBoardSocketHandler.users[user_email].remove(self)
            if not ROSBoardSocketHandler.users[user_email]:  # No more connections for this user
                del ROSBoardSocketHandler.users[user_email]
        
        # Track this user as recently dropped for potential Foxglove association
        if user_email != 'anonymous' and user_email != 'external_client':
            ROSBoardSocketHandler.dropped_users[user_email] = time.time()
        
        # Save persistent sessions if this was a Foxglove connection
        if getattr(self, 'client_type', '') == 'foxglove' and user_email != 'external_client':
            ROSBoardSocketHandler.save_persistent_sessions()
        
        # Log disconnection
        print(f"User {user_email} disconnected (via {getattr(self, 'auth_method', 'unknown')} from {getattr(self, 'client_type', 'unknown')}). Total connections: {len(ROSBoardSocketHandler.sockets)}")

        # when socket closes, remove ourselves from all subscriptions
        for topic_name in self.node.remote_subs:
            if self.id in self.node.remote_subs[topic_name]:
                self.node.remote_subs[topic_name].remove(self.id)

    @classmethod
    def get_connected_users(cls):
        """Get list of all connected users"""
        return list(cls.users.keys())
    
    @classmethod
    def get_user_connections(cls, user_email):
        """Get all connections for a specific user"""
        return cls.users.get(user_email, [])
    
    @classmethod
    def get_connection_stats(cls):
        """Get connection statistics"""
        total_connections = len(cls.sockets)
        unique_users = len(cls.users)
        
        user_connection_counts = {}
        user_client_details = {}
        
        for user_email, connections in cls.users.items():
            user_connection_counts[user_email] = len(connections)
            
            # Get client type breakdown for this user
            client_types = {}
            for conn in connections:
                client_type = getattr(conn, 'client_type', 'unknown')
                client_types[client_type] = client_types.get(client_type, 0) + 1
            
            user_client_details[user_email] = {
                'total_connections': len(connections),
                'client_breakdown': client_types
            }
        
        return {
            'total_connections': total_connections,
            'unique_users': unique_users,
            'users': user_connection_counts,
            'user_details': user_client_details,
            'timestamp': time.time()
        }
    
    @classmethod
    def cleanup_dropped_users(cls):
        """Clean up old dropped user entries (older than 5 seconds)"""
        current_time = time.time()
        expired_users = []
        
        for email, drop_time in cls.dropped_users.items():
            if current_time - drop_time > cls.dropped_association_timeout:
                expired_users.append(email)
        
        for email in expired_users:
            del cls.dropped_users[email]
    
    @classmethod
    def find_recently_dropped_user(cls):
        """Find a recently dropped user (within 5 seconds) and remove them from tracking"""
        cls.cleanup_dropped_users()  # Clean up old entries first
        
        if cls.dropped_users:
            # Return the most recently dropped user
            most_recent_email = max(cls.dropped_users.keys(), 
                                  key=lambda email: cls.dropped_users[email])
            most_recent_time = cls.dropped_users[most_recent_email]
            
            # Remove from tracking and return
            del cls.dropped_users[most_recent_email]
            return most_recent_email
        
        return None

    @classmethod
    def send_pings(cls):
        """
        Send pings to all sockets. When pongs are received they will be used for measuring
        latency and clock differences.
        """

        for curr_socket in cls.sockets:
            try:
                curr_socket.last_ping_times[curr_socket.ping_seq % 1024] = time.time() * 1000
                if curr_socket.ws_connection and not curr_socket.ws_connection.is_closing():
                    curr_socket.write_message(json.dumps([ROSBoardSocketHandler.MSG_PING, {
                        ROSBoardSocketHandler.PING_SEQ: curr_socket.ping_seq,
                    }], separators=(',', ':')))
                curr_socket.ping_seq += 1
            except Exception as e:
                print("Error sending message: %s" % str(e))

    @classmethod
    def broadcast(cls, message):
        """
        Broadcasts a dict-ified ROS message (message) to all sockets that care about that topic.
        The dict message should contain metadata about what topic it was
        being sent on: message["_topic_name"], message["_topic_type"].
        """

        try:
            if message[0] in [ROSBoardSocketHandler.MSG_TOPICS, ROSBoardSocketHandler.MSG_TOPICS_FULL]:
                json_msg = json.dumps(message, separators=(',', ':'))
                for curr_socket in cls.sockets:
                    if curr_socket.ws_connection and not curr_socket.ws_connection.is_closing():
                        curr_socket.write_message(json_msg)
            elif message[0] == ROSBoardSocketHandler.MSG_MSG:
                topic_name = message[1]["_topic_name"]
                json_msg = None
                for curr_socket in cls.sockets:
                    if topic_name not in curr_socket.node.remote_subs:
                        continue
                    if curr_socket.id not in curr_socket.node.remote_subs[topic_name]:
                        continue
                    t = time.time()
                    if t - curr_socket.last_data_times_by_topic.get(topic_name, 0.0) < \
                            curr_socket.update_intervals_by_topic.get(topic_name) - 2e-4:
                        continue
                    if curr_socket.ws_connection and not curr_socket.ws_connection.is_closing():
                        if json_msg is None:
                            json_msg = json.dumps(message, separators=(',', ':'))
                        curr_socket.write_message(json_msg)
                    curr_socket.last_data_times_by_topic[topic_name] = t
        except Exception as e:
            print("Error sending message: %s" % str(e))
            traceback.print_exc()

    def on_message(self, message):
        """
        Message received from the client.
        """

        if self.ws_connection is None or self.ws_connection.is_closing():
            return

        # JSON decode it, give up if it isn't valid JSON
        try:
            argv = json.loads(message)
        except (ValueError, TypeError):
            print("error: bad: %s" % message)
            return

        # make sure the received argv is a list and the first element is a string and indicates the type of command
        if type(argv) is not list or len(argv) < 1 or type(argv[0]) is not str:
            print("error: bad: %s" % message)
            return

        # if we got a pong for our own ping, compute latency and clock difference
        elif argv[0] == ROSBoardSocketHandler.MSG_PONG:
            if len(argv) != 2 or type(argv[1]) is not dict:
                print("error: pong: bad: %s" % message)
                return

            received_pong_time = time.time() * 1000
            self.latency = (received_pong_time - self.last_ping_times[argv[1].get(ROSBoardSocketHandler.PONG_SEQ, 0) % 1024]) / 2
            if self.latency > 1000.0:
                self.node.logwarn("socket %s has high latency of %.2f ms" % (str(self.id), self.latency))
            
            if self.latency > self.max_allowed_latency:
                self.node.logerr("socket %s has excessive latency of %.2f ms; closing connection" % (str(self.id), self.latency))
                self.node.logerr("max allowed latency is %.2f ms" % self.max_allowed_latency)
                self.close()

        # client wants to subscribe to topic
        elif argv[0] == ROSBoardSocketHandler.MSG_SUB:
            if len(argv) != 2 or type(argv[1]) is not dict:
                print("error: sub: bad: %s" % message)
                return

            topic_name = argv[1].get("topicName")
            max_update_rate = float(argv[1].get("maxUpdateRate", 24.0))

            # Check if the rosboard node was launched with a this topic type as 
            # as a parameter which indicates its max rate to be streamed
            topic_type = get_all_topics().get(topic_name)
            topic_type_max_rate = rospy.get_param(topic_type)
            set_topic_type_max_rate = topic_type is not None and topic_type_max_rate is not None
            if set_topic_type_max_rate:
                max_update_rate = topic_type_max_rate
                print(f"info: param for topic type {topic_type} set, " 
                    f"setting {topic_name} to max rate of {topic_type_max_rate}")
             
            # Check if the rosboard node was lunched with this topic name as
            # a parameter which indicates its max rate to be streamed
            param_name = f"topic.{topic_name}" # must be like this because otherwise it thinks it is a param of another node
            topic_name_max_rate = rospy.get_param(param_name)
            if topic_name_max_rate is not None:
                max_update_rate = topic_name_max_rate
                if set_topic_type_max_rate:
                    print("info: overriding topic type max rate because specific topic name has prevalence")
                print(f"info: param for topic name {topic_name} set, " 
                    f"setting {topic_name} to max rate of {topic_name_max_rate}") 

            self.update_intervals_by_topic[topic_name] = 1.0 / max_update_rate
            self.node.update_intervals_by_topic[topic_name] = min(
                self.node.update_intervals_by_topic.get(topic_name, 1.),
                self.update_intervals_by_topic[topic_name]
            )

            if topic_name is None:
                print("error: no topic specified")
                return

            if topic_name not in self.node.remote_subs:
                self.node.remote_subs[topic_name] = set()

            self.node.remote_subs[topic_name].add(self.id)
            self.node.sync_subs()

        # client wants to unsubscribe from topic
        elif argv[0] == ROSBoardSocketHandler.MSG_UNSUB:
            if len(argv) != 2 or type(argv[1]) is not dict:
                print("error: unsub: bad: %s" % message)
                return
            topic_name = argv[1].get("topicName")

            if topic_name not in self.node.remote_subs:
                self.node.remote_subs[topic_name] = set()

            try:
                self.node.remote_subs[topic_name].remove(self.id)
            except KeyError:
                print("KeyError trying to remove sub")

        # Client wants to stop publishing a topic
        elif argv[0] == ROSBoardSocketHandler.MSG_UNPUB:
            if len(argv) != 2 or type(argv[1]) is not dict:
                print("error: unpub: bad %s" % message)
                return
            topic_name = argv[1].get("topicName")

            try:
                if topic_name not in self.node.local_pubs:
                    print("WARN: Attempted to remove unavailable topic.")
                else:
                    self.node.local_pubs[topic_name].unregister()
                    self.node.local_pubs.pop(topic_name)
            
            except KeyError:
                print("KeyError trying to remove publisher")

        # client sent a ROS message
        elif argv[0] == ROSBoardSocketHandler.MSG_MSG:
            self.node.create_publisher_if_not_exists(argv[1]["_topic_name"], argv[1]["_topic_type"])
            self.node.publish_remote_message(argv)

        # client asked for a list of topics
        elif argv[0] == ROSBoardSocketHandler.MSG_TOPICS:
            topics = get_all_topics()
            self.broadcast([ROSBoardSocketHandler.MSG_TOPICS, topics])

        # client asked for a list of topics and full descriptions
        elif argv[0] == ROSBoardSocketHandler.MSG_TOPICS_FULL:
            # Copy to avoid thread safety issues, since main thread can update the topics
            full_topics = self.full_topics.copy()
            update_all_topics_with_typedef(full_topics)
            self.broadcast([ROSBoardSocketHandler.MSG_TOPICS_FULL, full_topics])



ROSBoardSocketHandler.MSG_PING = "p"
ROSBoardSocketHandler.MSG_PONG = "q"
ROSBoardSocketHandler.MSG_MSG = "m"
ROSBoardSocketHandler.MSG_TOPICS = "t"
ROSBoardSocketHandler.MSG_TOPICS_FULL = "f"
ROSBoardSocketHandler.MSG_SUB = "s"
ROSBoardSocketHandler.MSG_SYSTEM = "y"
ROSBoardSocketHandler.MSG_UNSUB = "u"
ROSBoardSocketHandler.MSG_UNPUB = "n"

ROSBoardSocketHandler.PING_SEQ = "s"
ROSBoardSocketHandler.PONG_SEQ = "s"
ROSBoardSocketHandler.PONG_TIME = "t"
