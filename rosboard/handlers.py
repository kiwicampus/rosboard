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

import jwt

# This brakes ROS1 support
from rosboard.topics import get_all_topics, update_all_topics_with_typedef
from rosboard.ros_init import rospy

# Config stuff for auth
from rosboard.config import GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, DEVICE_CODE_URL, TOKEN_URL
from rosboard.config import is_email_domain_allowed, COOKIE_SECRET

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
            "interval": 2.5, # Hardcoded to 2.5 for better UX # data.get("interval", 2.5),
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

        # Generate JWT token for Foxglove authentication        
        token_payload = {
            "email": result["email"],
            "sub": result["sub"],
            "exp": time.time() + (60 * 60 * 24 * 7),  # 7 days expiration
            "iat": time.time()
        }
        
        foxglove_token = jwt.encode(token_payload, COOKIE_SECRET, algorithm='HS256')

        # Set secure cookie with user info
        self.set_secure_cookie(
            "session",
            json.dumps({"email": result["email"], "sub": result["sub"]}),
            expires_days=60,
            httponly=True,
            samesite="Lax",
            secure=True  # serve over HTTPS
        )

        # Return user info plus the Foxglove token
        result["foxglove_token"] = foxglove_token
        return self.write_json(result, 200)

class MeHandler(tornado.web.RequestHandler):
    """Handler to check current user status"""
    
    def initialize(self, google_auth_enabled):
        self.google_auth_enabled = google_auth_enabled
    
    def get(self):
        user = current_user_from_cookie(self)
        self.set_header("Content-Type", "application/json")
        if user:
            self.finish(json.dumps({"authenticated": True, "email": user.get("email"), "sub": user.get("sub")}))
        else:
            # Check if authentication is enabled
            if GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET and self.google_auth_enabled:
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
    
    def initialize(self, google_auth_enabled):
        self.google_auth_enabled = google_auth_enabled

    def prepare(self):
        # Check if authentication is enabled        
        if not GOOGLE_CLIENT_ID or not GOOGLE_CLIENT_SECRET or not self.google_auth_enabled:
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

    def initialize(self, default_filename, foxglove_uri, foxglove_layout_uri, google_auth_enabled):
        super().initialize(google_auth_enabled)
        self.default_filename = default_filename
        self.foxglove_uri = foxglove_uri
        self.foxglove_layout_uri = foxglove_layout_uri


class ROSBoardSocketHandler(tornado.websocket.WebSocketHandler):
    """WebSocket handler for ROSboard connections"""
    
    # Class-level tracking for all connections
    sockets = set()
    users = {} # Track users by email -> list of their sockets
    
    def check_origin(self, origin):
        """Allow connections from any origin (needed for Foxglove)"""
        return True

    def initialize(self, node, max_allowed_latency, full_topics, allow_external_clients, google_auth_enabled):
        # store the instance of the ROS node that created this WebSocketHandler so we can access it later
        self.node = node
        self.max_allowed_latency = max_allowed_latency
        self.allow_external_clients = allow_external_clients
        self.google_auth_enabled = google_auth_enabled

        # Cache the topics and their typedefs since this can be slow
        # This is a dict by reference, so it will be updated by the rosboard node
        self.full_topics = full_topics

    def get_compression_options(self):
        # Non-None enables compression with default options.
        return {}

    def handle_auth(self):
        # Check authentication before allowing WebSocket connection (if enabled)        
        if GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET and self.google_auth_enabled:
            # Check if this is a Foxglove connection with a token
            if self._is_foxglove_connection():
                # Extract token from query parameters
                token = self._extract_token_from_query()
                if token and self._validate_token(token):
                    # Token is valid, get user info
                    user_info = self._get_user_from_token(token)
                    self.user = user_info
                    self.auth_method = "token"
                    self.client_type = "foxglove"
                else:
                    # No valid token, check if external clients are allowed
                    if self.allow_external_clients:
                        self.user = {"email": "external_client", "sub": "external"}
                        self.auth_method = "external"
                        self.client_type = "foxglove"
                    else:
                        self.close(1008, "Authentication required")
                        return False
            else:
                # Regular ROSboard connection, check cookies
                user = current_user_from_cookie(self)
                if user:
                    self.user = user
                    self.auth_method = "cookie"
                    self.client_type = "rosboard"
                else:
                    # No valid session, check if external clients are allowed
                    if self.allow_external_clients:
                        self.user = {"email": "external_client", "sub": "external"}
                        self.auth_method = "external"
                        self.client_type = "external"
                    else:
                        self.close(1008, "Authentication required")
                        return False
        else:
            # Authentication disabled
            self.user = {"email": "anonymous", "sub": "anonymous"}
            self.auth_method = "disabled"
            self.client_type = "rosboard" if not self._is_foxglove_connection() else "foxglove"
        
        return True

    def open(self):
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
        print(f"User {user_email} connected via {self.auth_method} from {self.client_type}. Total connections: {len(ROSBoardSocketHandler.sockets)}")
    
        self.write_message(json.dumps([ROSBoardSocketHandler.MSG_SYSTEM, {
            "hostname": socket.gethostname(),
            "version": __version__,
            "user": self.user.get("email", "unknown")
        }], separators=(',', ':')))

    def _is_foxglove_connection(self):
        """Detect if this WebSocket connection is coming from Foxglove"""
        # Check User-Agent for Foxglove identifiers
        user_agent = self.request.headers.get("User-Agent", "").lower()
        if "foxglove" in user_agent:
            return True
            
        # Check Origin header for Foxglove domains
        origin = self.request.headers.get("Origin", "")
        if origin and "foxglove" in origin.lower():
            return True
            
        return False

    def _extract_token_from_query(self):
        """Extract authentication token from WebSocket query parameters"""
        # WebSocket connections can have query parameters in the URL
        # Example: ws://localhost:8888/rosboard/v1?token=abc123
        query_string = self.request.uri.split('?')[1] if '?' in self.request.uri else ""
        if not query_string:
            return None
            
        # Parse query parameters
        params = {}
        for param in query_string.split('&'):
            if '=' in param:
                key, value = param.split('=', 1)
                params[key] = value
        
        return params.get('token')

    def _validate_token(self, token):
        """Validate the authentication token"""
        try:
            # Decode and verify the JWT token            
            # Verify the token using the same secret as cookies
            payload = jwt.decode(token, COOKIE_SECRET, algorithms=['HS256'])
            
            # Check if token is expired
            if 'exp' in payload and payload['exp'] < time.time():
                return False
                
            return True
        except Exception as e:
            print(f"Token validation failed: {e}")
            return False

    def _get_user_from_token(self, token):
        """Extract user information from the validated token"""
        try:            
            payload = jwt.decode(token, COOKIE_SECRET, algorithms=['HS256'])
            return {
                "email": payload.get('email'),
                "sub": payload.get('sub')
            }
        except Exception as e:
            print(f"Failed to extract user from token: {e}")
            return {"email": "unknown", "sub": "unknown"}

    def on_close(self):
        # Remove from global tracking
        ROSBoardSocketHandler.sockets.remove(self)
        
        # Remove from user-specific tracking
        user_email = self.user.get('email', 'anonymous')
        if user_email in ROSBoardSocketHandler.users:
            ROSBoardSocketHandler.users[user_email].remove(self)
            if not ROSBoardSocketHandler.users[user_email]:  # No more connections for this user
                del ROSBoardSocketHandler.users[user_email]
        
        # Log disconnection
        print(f"User {user_email} disconnected via {getattr(self, 'auth_method', 'unknown')} from {getattr(self, 'client_type', 'unknown')}. Total connections: {len(ROSBoardSocketHandler.sockets)}")

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

    def check_origin(self, origin):
        """Allow connections from any origin (needed for Foxglove)"""
        return True

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
            topic_type_max_rate = rospy.get_param(topic_type, 0)
            set_topic_type_max_rate = topic_type is not None and topic_type_max_rate is not None and topic_type_max_rate > 0
            if set_topic_type_max_rate:
                max_update_rate = topic_type_max_rate
                print(f"info: param for topic type {topic_type} set, " 
                    f"setting {topic_name} to max rate of {topic_type_max_rate}")
             
            # Check if the rosboard node was launched with this topic name as
            # a parameter which indicates its max rate to be streamed
            param_name = f"topic.{topic_name}" # must be like this because otherwise it thinks it is a param of another node
            topic_name_max_rate = rospy.get_param(param_name, 0)
            if topic_name_max_rate is not None and topic_name_max_rate > 0:
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
                    # print("WARN: Attempted to remove unavailable topic.")
                    pass
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
