# -*- coding: utf-8 -*-
# Copyright 2025(C) CryptoChat Dinnerb0ne<tomma_2022@outlook.com>

#    Copyright 2025 [Dinnberb0ne & T0ast101]

#    Licensed under the Apache License, Version 2.0 (the "License");
#    you may not use this file except in compliance with the License.
#    You may obtain a copy of the License at

#        http://www.apache.org/licenses/LICENSE-2.0

#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS,
#    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#    See the License for the specific language governing permissions and
#    limitations under the License.

# date: 2025-05-14
# version: 1.1.2
# description: A simple chat application with encryption and room features.
# LICENSE: Apache-2.0


import os
import sys
import json
import time
import socket
import threading
from datetime import datetime, UTC
from Crypto.PublicKey import RSA, DSA, ECC
import hashlib

class ChatApplication:
    def __init__(self):
        self.server_alive = None
        self.check_eula()
        self.load_config()
        self.setup_crypto()
        
        # Initialize Ban System
        self.bans_file = 'bans.json'
        self.banned_ips = set()
        self.banned_users = set()
        self.load_bans()
        
        # Room System
        self.rooms = {}
        self.current_room = None
        self.room_config_dir = self.config.get('room_config', './room_config/')
        self.load_rooms()
        
        # Chat History System
        self.chat_history = []
        
        if self.config['mode'] == 'server':
            self.admin_commands = {
                'kick': self.kick_user,
                'ban': self.ban_user,
                'unban': self.unban_user,
                'check': self.check_user,
                'listbans': self.list_bans,
                'rooms': self.list_rooms,
                'stop': self.stop_server,
                'help': self.show_admin_help,
                'setpassword': self.set_password,
                'hashpassword': self.hash_password,
                'roompassword': self.set_room_password,
                'save': self.save_chat_history
            }
            self.run_server()
            self.start_admin_console()
        else:
            self.chat_history = []  # Ensure chat history is initialized for the client
            self.run_client()

    def list_rooms(self, args):
        """List Available Rooms"""
        if self.config['enable_rooms']:
            print("Available rooms:")
            for room_name in self.rooms.keys():
                print(f"  {room_name}")
        else:
            print("Room feature is disabled")

    def stop_server(self, args):
        """Stop Server"""
        print("The server is shutting down...")

        self.broadcast({
            'type': 'system',
            'message': f"Server shutting down...",
            'timestamp': time.time()
        })
        self.server_alive = False
        if self.config['enable_autosave']:
            self.save_chat_history()
        self.save_bans()
        for room_name in self.rooms.keys():
            self.save_room_bans(room_name)
        for addr, client in list(self.clients.items()):
            try:
                del self.clients[addr]
            except:
                pass
        #try:
        #    self.server_socket.close()
        #    self.server_socket.shutdown(socket.SHUT_RDWR)
        #except Exception as e:
        #    print(f"Error shutting down server socket: {e}")
        #finally:
        print("Server stopped")
        sys.exit(0)

    def load_config(self):
        """Load Configuration File"""
        default_config = {
            'mode': 'server',
            'ip': 'localhost',
            'port': '25566',
            'encrypt_algorithm': 'RSA',
            'key_length': '2048',
            'nickname': '',
            'motd': '',
            'max_users': '20',
            'pubkey_file': 'public_key.pem',
            'key_file': 'private_key.pem',
            'enable_rooms': 'false',
            'room_config': './room_config/',
            'enable_hash': 'false',
            'hash_type': 'sha256',
            'enable_password': 'false',
            'enable_autosave': 'false',
            'autosave_delay': '500'  # 默认自动保存延迟为500秒
        }
        
        if not os.path.exists('chat.properties'):
            with open('chat.properties', 'w', encoding='utf-8') as f:
                for key, value in default_config.items():
                    f.write(f"{key}={value}\n")

        self.config = {}
        with open('chat.properties', 'r', encoding='utf-8') as f:
            for line in f:
                if '=' in line:
                    key, value = line.strip().split('=', 1)
                    self.config[key] = value
        
        # Ensure room_config is not empty
        if not self.config.get('room_config', '').strip():
            self.config['room_config'] = './room_config/'
        
        # Set default value for max_users if it's empty
        if not self.config.get('max_users', '').strip():
            self.config['max_users'] = default_config['max_users']
        
        self.config['port'] = int(self.config['port'])
        self.config['key_length'] = int(self.config['key_length'])
        self.config['enable_rooms'] = self.config['enable_rooms'].lower() == 'true'
        self.config['max_users'] = int(self.config['max_users'])
        self.config['enable_hash'] = self.config['enable_hash'].lower() == 'true'
        self.config['enable_password'] = self.config['enable_password'].lower() == 'true'
        self.config['enable_autosave'] = self.config['enable_autosave'].lower() == 'true'
        self.config['autosave_delay'] = int(self.config.get('autosave_delay', default_config['autosave_delay']))

    def load_rooms(self):
        """Load Room Configurations"""
        if not os.path.exists(self.room_config_dir):
            os.makedirs(self.room_config_dir)
            print(f"Created room configuration directory: {self.room_config_dir}")
        
        if self.config['enable_rooms']:
            self.rooms = {}
            for filename in os.listdir(self.room_config_dir):
                if filename.endswith('.cfg'):
                    room_path = os.path.join(self.room_config_dir, filename)
                    try:
                        room_config = {}
                        with open(room_path, 'r', encoding='utf-8') as f:
                            for line in f:
                                if '=' in line:
                                    key, value = line.strip().split('=', 1)
                                    room_config[key] = value
                        room_name = room_config['name']
                        bans_json_dir = os.path.join(self.room_config_dir, f"{room_name}_bans.json")
                        password_hash_file = os.path.join(self.room_config_dir, f"{room_name}.hash")
                        if not os.path.exists(bans_json_dir):
                            with open(bans_json_dir, 'w', encoding='utf-8') as f:
                                json.dump({'ips': [], 'users': []}, f)
                        self.rooms[room_name] = {
                            'motd': room_config.get('motd', ''),
                            'members': set(),
                            'bans': {
                                'ips': [],
                                'users': []
                            },
                            'bans_file': bans_json_dir,
                            'password': room_config.get('password', ''),
                            'password_hash_file': password_hash_file,
                            'password_hash': ''
                        }
                        self.load_room_bans(room_name)
                        self.load_room_password_hash(room_name)
                    except Exception as e:
                        print(f"Failed to load room configuration: {filename} - {e}")
            
            print(f"Loaded rooms: {list(self.rooms.keys())}")
        else:
            print("Room feature is disabled")

    def load_room_password_hash(self, room_name):
        """Load Room Password Hash"""
        if os.path.exists(self.rooms[room_name]['password_hash_file']):
            try:
                with open(self.rooms[room_name]['password_hash_file'], 'r', encoding='utf-8') as f:
                    self.rooms[room_name]['password_hash'] = f.read().strip()
            except Exception as e:
                print(f"Failed to load room password hash for {room_name}: {e}")

    def save_room_password_hash(self, room_name, password_hash):
        """Save Room Password Hash"""
        try:
            with open(self.rooms[room_name]['password_hash_file'], 'w', encoding='utf-8') as f:
                f.write(password_hash)
        except Exception as e:
            print(f"Failed to save room password hash for {room_name}: {e}")

    def load_room_bans(self, room_name):
        """Load Bans for a specific room"""
        try:
            with open(self.rooms[room_name]['bans_file'], 'r', encoding='utf-8') as f:
                bans = json.load(f)
                self.rooms[room_name]['bans']['ips'] = bans.get('ips', [])
                self.rooms[room_name]['bans']['users'] = bans.get('users', [])
                print(f"Loaded room bans for {room_name}")
        except Exception as e:
            print(f"Failed to load room bans for {room_name}: {e}")

    def save_room_bans(self, room_name):
        """Save Bans for a specific room"""
        try:
            with open(self.rooms[room_name]['bans_file'], 'w', encoding='utf-8') as f:
                json.dump(
                    {
                        'ips': self.rooms[room_name]['bans']['ips'],
                        'users': self.rooms[room_name]['bans']['users']
                    },
                    f,
                    indent=2
                )
        except Exception as e:
            print(f"Failed to save room bans for {room_name}: {e}")

    def run_server(self):
        """Run the Server"""
        self.server_alive = True
        self.clients = {}
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.bind((self.config['ip'], self.config['port']))
        self.server_socket.listen(5)
        
        print(f"Chat server started: {self.config['ip']}:{self.config['port']}")
        print(f"Maximum users allowed: {self.config['max_users']}")
        
        server_thread = threading.Thread(target=self.server_input_loop, daemon=True)
        server_thread.start()
        
        # 启动自动保存聊天记录的线程
        if self.config['enable_autosave']:
            autosave_thread = threading.Thread(target=self.auto_save_chat_history, daemon=True)
            autosave_thread.start()
        
        while self.server_alive:
            try:
                client_socket, addr = self.server_socket.accept()
                if len(self.clients) >= self.config['max_users']:
                    try:
                        client_socket.send(json.dumps({
                            'type': 'system',
                            'message': 'Server is full. Please try again later.',
                            'timestamp': time.time()
                        }).encode())
                        client_socket.close()
                        print(f"Rejected connection from {addr[0]}: Server is full")
                        continue
                    except:
                        client_socket.close()
                        continue

                client_thread = threading.Thread(target=self.handle_client, args=(client_socket, addr))
                client_thread.daemon = True
                client_thread.start()
            except OSError as e:
                if not self.server_alive:
                    print("Server socket closed")
                    break
                else:
                    raise e

    def handle_client(self, client_socket, addr):
        """Handle Client Connection"""
        try:
            data = client_socket.recv(4096)
            client_info = json.loads(data.decode())
            nickname = client_info.get('nickname', 'Unknown').strip()
            if not nickname:
                nickname = 'Unknown'
            room_name = client_info.get('room', None) if self.config['enable_rooms'] else None
            
            # Check if username is globally banned
            if nickname.lower() in self.banned_users:
                try:
                    client_socket.send(json.dumps({
                        'type': 'system',
                        'message': 'Your username has been globally banned',
                        'timestamp': time.time()
                    }).encode())
                    client_socket.close()
                except:
                    pass
                print(f"Blocked globally banned user connection: {nickname}")
                return
            
            # Check if user is banned in the specific room (if rooms are enabled)
            if self.config['enable_rooms'] and room_name and room_name in self.rooms:
                if nickname.lower() in self.rooms[room_name]['bans']['users'] or addr[0] in self.rooms[room_name]['bans']['ips']:
                    try:
                        client_socket.send(json.dumps({
                            'type': 'system',
                            'message': f'You have been banned from room {room_name}',
                            'timestamp': time.time()
                        }).encode())
                        client_socket.close()
                    except:
                        pass
                    print(f"Blocked banned user in room {room_name}: {nickname}")
                    return
            
            public_key = client_info['public_key']
            
            # Handle password verification
            if self.config['enable_password']:
                password = client_info.get('password', '')
                if not self.verify_password(password):
                    try:
                        client_socket.send(json.dumps({
                            'type': 'system',
                            'message': 'Incorrect password',
                            'timestamp': time.time()
                        }).encode())
                        client_socket.close()
                    except:
                        pass
                    print(f"Password verification failed for {nickname}")
                    return
                
                # Verify room password if room is enabled and specified
                if self.config['enable_rooms'] and room_name and room_name in self.rooms:
                    room_password = client_info.get('room_password', '')
                    if not self.verify_room_password(room_name, room_password):
                        try:
                            client_socket.send(json.dumps({
                                'type': 'system',
                                'message': f'Incorrect password for room {room_name}',
                                'timestamp': time.time()
                            }).encode())
                            client_socket.close()
                        except:
                            pass
                        print(f"Room password verification failed for {nickname} in room {room_name}")
                        return
            
            self.clients[addr] = {
                'socket': client_socket,
                'nickname': nickname,
                'public_key': public_key,
                'last_seen': time.time(),
                'room': room_name
            }
            
            print(f"{nickname} connected ({addr[0]}) - Room: {room_name}")
            
            welcome_msg = {
                'type': 'system',
                'message': self.get_motd(room_name),
                'timestamp': time.time()
            }
            client_socket.send(json.dumps(welcome_msg).encode())
            
            # Update room members
            if self.config['enable_rooms'] and room_name and room_name in self.rooms:
                self.rooms[room_name]['members'].add(nickname)
                self.broadcast({
                    'type': 'system',
                    'message': f"{nickname} joined {room_name}",
                    'timestamp': time.time()
                }, room=room_name)
            else:
                self.broadcast({
                    'type': 'system',
                    'message': f"{nickname} joined the chat",
                    'timestamp': time.time()
                }, exclude=addr)
            
            while self.server_alive:
                data = client_socket.recv(4096)
                if not data:
                    break

                message_data = json.loads(data.decode())

                if 'message' not in message_data or 'timestamp' not in message_data:
                    print("Invalid message format: missing fields")
                    return

                if message_data['type'] == 'message':
                    broadcast_msg = {
                        'type': 'message',
                        'nickname': nickname,
                        'message': message_data['message'],
                        'timestamp': time.time(),
                        'room': message_data.get('room', room_name)
                    }
                    
                    # Add message to chat history
                    self.chat_history.append({
                        #'timestamp': datetime.utcfromtimestamp(message_data['timestamp']).isoformat(), #DEPRECATED
                        'timestamp': datetime.fromtimestamp(message_data['timestamp'], UTC).isoformat(),
                        'local_time': datetime.fromtimestamp(message_data['timestamp']).strftime("%m/%d %H:%M:%S"),
                        'user': nickname,
                        'message': message_data['message'],
                        'room': message_data.get('room', room_name)
                    })
                    
                    formatted_msg = self.format_message(broadcast_msg)
                    print(formatted_msg)  # 打印消息到服务器终端
                    self.broadcast({'type': 'message', 'formatted_message': formatted_msg}, room=message_data.get('room', room_name))
                elif message_data['type'] == 'ping':
                    client_socket.send(json.dumps({
                        'type': 'pong',
                        'timestamp': message_data['timestamp']
                    }).encode())
                elif message_data['type'] == 'online':
                    client_socket.send(json.dumps({
                        'type': 'online',
                        'count': len(self.clients),
                        'nicknames': [client['nickname'] for client in self.clients.values()],
                        'timestamp': time.time()
                    }).encode())
        
        except (ConnectionResetError, json.JSONDecodeError) as e:
            print(f"Connection error: {e}")
        finally:
            if addr in self.clients:
                disconnected_nick = self.clients[addr]['nickname']
                room_name = self.clients[addr]['room']
                del self.clients[addr]
                
                # Update room members
                if self.config['enable_rooms'] and room_name and room_name in self.rooms:
                    if disconnected_nick in self.rooms[room_name]['members']:
                        self.rooms[room_name]['members'].remove(disconnected_nick)
                        self.broadcast({
                            'type': 'system',
                            'message': f"{disconnected_nick} left {room_name}",
                            'timestamp': time.time()
                        }, room=room_name)
                else:
                    self.broadcast({
                        'type': 'system',
                        'message': f"{disconnected_nick} left",
                        'timestamp': time.time()
                    })
                
                print(f"{disconnected_nick} disconnected - Room: {room_name}")
            client_socket.close()

    def broadcast(self, message, exclude=None, room=None):
        """Broadcast Message"""
        message_json = json.dumps(message)
        for addr, client in self.clients.items():
            if exclude and addr == exclude:
                continue
            
            # If room is specified, broadcast only to that room
            if room is not None:
                if room == client['room']:
                    try:
                        client['socket'].send(message_json.encode())
                    except ConnectionError:
                        del self.clients[addr]
            else:
                # Broadcast to all
                try:
                    client['socket'].send(message_json.encode())
                except ConnectionError:
                    del self.clients[addr]

    def auto_save_chat_history(self):
        """Automatically save chat history at regular intervals"""
        save_interval = self.config['autosave_delay']
        while True:
            time.sleep(save_interval)
            self.save_chat_history()

    def save_chat_history(self):
        """Save Chat History"""
        if not self.chat_history:
            print("No chat history to save")
            return
        
        now = datetime.now()
        formatted_time = now.strftime("%Y%m%d%H%M%S")
        filename = f"chat_history_{formatted_time}.txt"
        
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                for entry in self.chat_history:
                    f.write(f"[{entry['timestamp']}] {entry['user']}: {entry['message']}\n")
            print(f"Chat history saved to {filename}")
        except Exception as e:
            print(f"Failed to save chat history: {e}")

    def run_client(self):
        """Run Client"""
        print(f"Connecting to server {self.config['ip']}:{self.config['port']}")
        
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            self.client_socket.connect((self.config['ip'], self.config['port']))
            
            # Collect password if enabled
            password = ''
            room_password = ''
            if self.config['enable_password']:
                password = input("Enter server password (leave blank if none): ")
                if self.current_room and self.config['enable_rooms']:
                    room_password = input(f"Enter password for room {self.current_room} (leave blank if none): ")
            
            # Send client info to server
            client_info = {
                'nickname': self.config['nickname'],
                'public_key': self.public_key.decode(),
                'room': self.current_room,
                'password': password,
                'room_password': room_password
            }
            self.client_socket.send(json.dumps(client_info).encode())
            
            receive_thread = threading.Thread(target=self.receive_messages)
            receive_thread.daemon = True
            receive_thread.start()
            
            while True:
                message = input()
                if message.startswith('/'):
                    self.handle_command(message[1:])
                else:
                    self.send_message(message)
        
        except ConnectionRefusedError:
            print("Failed to connect to server")
            sys.exit(1)

    def handle_command(self, command):
        """Handle Client Commands"""
        parts = command.split()
        cmd = parts[0].lower()
        
        if cmd == 'ping':
            self.client_socket.send(json.dumps({
                'type': 'ping',
                'timestamp': time.time()
            }).encode())
        elif cmd == 'online':
            self.client_socket.send(json.dumps({
                'type': 'online'
            }).encode())
        elif cmd == 'exit':
            print("Exiting chat")
            self.client_socket.close()
            sys.exit(0)
        elif cmd == 'help':
            print("Available commands:")
            print("/ping - Test server latency")
            print("/online - Show online users")
            print("/join <room_name> - Join a room")
            print("/rooms - Show available rooms")
            print("/exit - Exit chat")  
            print("/help - Show help information")
            print("/save - Save chat history")
        elif cmd == 'join' and len(parts) > 1:
            room_name = ' '.join(parts[1:])
            if self.config['enable_rooms']:
                if room_name in self.rooms:
                    self.current_room = room_name
                    password = input(f"Enter password for room {room_name} (leave blank if none): ")
                    self.client_socket.send(json.dumps({
                        'type': 'join',
                        'room': room_name,
                        'room_password': password
                    }).encode())
                    print(f"Joined room: {room_name}")
                else:
                    print(f"Room does not exist: {room_name}")
            else:
                print("Room feature is disabled")
        elif cmd == 'rooms':
            if self.config['enable_rooms']:
                print(f"Available rooms: {', '.join(self.rooms.keys())}")
            else:
                print("Room feature is disabled")
        elif cmd == 'save':
            self.client_socket.send(json.dumps({
                'type': 'save'
            }).encode())
            print("Saving chat history...")
        else:
            print(f"Unknown command: {cmd}")


    def send_message(self, message):
        """Send Message"""
        message_data = {
            'type': 'message',
            'message': message,
            'timestamp': time.time(),
            'room': self.current_room
        }
        self.client_socket.send(json.dumps(message_data).encode())


    def receive_messages(self):
        """Receive Messages"""
        while True:
            try:
                data = self.client_socket.recv(4096)
                if not data:
                    print("Disconnected from server")
                    sys.exit(0)
                
                message_data = json.loads(data.decode())

                if message_data['type'] == 'message':
                    timestamp = message_data.get('timestamp', time.time())
                    nickname = message_data.get('nickname', 'Unknown')
                    fetched_message = message_data.get('message', '')
                    local_time = datetime.fromtimestamp(timestamp).strftime("%m/%d %H:%M:%S")
                    room_name = message_data.get('room', 'public')
                    if 'formatted_message' in message_data:
                        print(message_data['formatted_message'])
                    else:
                        formatted_msg = self.format_message({
                            'timestamp': timestamp,
                            'nickname': nickname,
                            'message': fetched_message
                        })
                        print(formatted_msg)
                    self.chat_history.append({
                        'timestamp': timestamp,
                        'local_time': local_time,
                        'user': nickname,
                        'message': fetched_message,
                        'room': message_data.get('room', 'public')
                    })
                elif message_data['type'] == 'system':
                    room_name = message_data.get('room', 'public')
                    print(f"[{room_name}] [System] {message_data['message']}")
                elif message_data['type'] == 'pong':
                    print(f"Server latency: {(time.time() - message_data['timestamp']) * 1000:.2f}ms")
                elif message_data['type'] == 'online':
                    nicknames = ', '.join(message_data['nicknames'])
                    print(f"Online users: {nicknames} (Total: {message_data['count']} people)")
                elif message_data['type'] == 'join':
                    self.current_room = message_data['room']
                    print(f"Joined room: {self.current_room}")
                elif message_data['type'] == 'save':
                    self.save_chat_history()
                    print("Chat history saved")
            
            except (ConnectionResetError, json.JSONDecodeError) as e:
                print(f"Connection error: {e}")
                sys.exit(1)


    def get_motd(self, room_name=None):
        """Get MOTD"""
        if self.config['enable_rooms'] and room_name and room_name in self.rooms:
            return self.rooms[room_name]['motd']
        else:
            return self.config['motd']


    def check_eula(self):
        """Check User License Agreement"""
        if not os.path.exists('eula.txt'):
            with open('eula.txt', 'w', encoding='utf-8') as f:
                f.write(f"{datetime.now().isoformat()}\neula=false\n"
                        "本软件按 “现状” 提供，不提供任何形式的明示或暗示的保证，\n"
                        "包括但不限于对软件的适销性、特定用途适用性、准确性、完整性以及不侵犯第三方权利的保证。软件开发者、提供者\n"
                        "及所有相关方均不对因软件使用或无法使用而导致的任何直接、间接、偶然、特殊及后续的损害承担责任，无论这些损\n"
                        "害是否基于合同、侵权或任何其他法律理论，也不论是否已被告知发生此类损害的可能性。\n"
                        "对于使用者因不当使用本软件而产生的一切法律后果，包括但不限于民事纠纷、行政处罚、刑事犯罪等，均由使用者自\n"
                        "行承担全部责任，软件开发者、提供者及所有相关方概不负责。即使使用者的不当行为是基于软件存在的漏洞、缺陷或\n"
                        "设计瑕疵，使用者仍需对其自身行为负责，但软件方将尽力及时修复漏洞、完善软件以降低风险。软件开发者、提供者\n"
                        "及所有相关方不对任何第三方利用本软件从事违法犯罪活动或其他不当行为所产生的后果承担责任。使用者应自行判断\n"
                        "聊天内容及其他用户行为的合法性与适当性，对于因信赖或使用其他用户提供的信息而遭受的损失，由使用者自行\n"
                        "承担风险。\n"
                        "\n"
                        "This software is provided \"as is\" without any form of express or implied warranty,\n"
                        "including but not limited to warranties of merchantability, fitness for a particular purpose, \n"
                        "accuracy, completeness, and non-infringement of third-party rights of the software. Software \n"
                        "developers and providers\n"
                        "all parties involved shall not be liable for any direct, indirect, incidental, special, or \n"
                        "consequential damages arising from the use or inability to use the software, regardless of \n"
                        "the nature of such damages\n"
                        "whether the harm is based on contract, tort or any other legal theory, and regardless of \n"
                        "whether the possibility of such harm has been notified.\n"
                        "\n"
                        "All legal consequences arising from the improper use of this software by users, including but \n"
                        "not limited to civil disputes, administrative penalties, criminal offenses, etc., shall be \n"
                        "borne by the users themselves, and software developers, providers, and all related \n"
                        "parties are not responsible. Even if the user's inappropriate behavior is based on software \n"
                        "vulnerabilities, defects, or\n"
                        "design flaws still require users to take responsibility for their own actions, but the software \n"
                        "provider will make every effort to promptly fix vulnerabilities and improve the software to reduce \n"
                        "risks. Software developers and providers\n"
                        "all relevant parties shall not be held responsible for any consequences arising from any \n"
                        "third party's use of this software for illegal or criminal activities or other improper behavior. \n"
                        "Users should make their own judgments\n"
                        "the legality and appropriateness of chat content and other user behaviors, as well as any losses \n"
                        "incurred due to reliance on or use of information provided by other users, shall be borne by the \n"
                        "users themselves to take on risks.\n")
                

            print("Please open eula.txt and change 'eula=false' to 'eula=true' to accept the user agreement")
            sys.exit(0)
        
        with open('eula.txt', 'r', encoding='utf-8') as f:
            lines = f.readlines()
            if len(lines) < 2 or 'eula=true' not in lines[1]:
                print("Please accept the user agreement: Open eula.txt and change 'eula=false' to 'eula=true'")
                sys.exit(0)


    def setup_crypto(self):
        """Setup Encryption System"""
        algo = self.config['encrypt_algorithm'].upper()
        key_length = int(self.config['key_length'])
        
        if not os.path.exists(self.config['key_file']) or not os.path.exists(self.config['pubkey_file']):
            print(f"Generating new {algo} key pair...")
            
            if algo == 'RSA':
                key = RSA.generate(key_length)
                private_key = key.export_key()
                public_key = key.publickey().export_key()
            elif algo == 'DSA':
                key = DSA.generate(key_length)
                private_key = key.export_key()
                public_key = key.public_key().export_key()
            elif algo == 'ECDSA':
                curve = 'p256'
                key = ECC.generate(curve=curve)
                private_key = key.export_key(format='PEM')
                public_key = key.public_key().export_key(format='PEM')
            else:
                raise ValueError(f"Unsupported encryption algorithm: {algo}")
            
            with open(self.config['key_file'], 'wb') as f:
                f.write(private_key)
            with open(self.config['pubkey_file'], 'wb') as f:
                f.write(public_key)
        
        with open(self.config['key_file'], 'rb') as f:
            self.private_key = f.read()
        
        with open(self.config['pubkey_file'], 'rb') as f:
            self.public_key = f.read()


    def load_bans(self):
        """Load Bans from JSON File"""
        if os.path.exists(self.bans_file):
            try:
                with open(self.bans_file, 'r', encoding='utf-8') as f:
                    bans = json.load(f)
                    self.banned_ips = set(bans.get('ips', []))
                    self.banned_users = set(bans.get('users', []))
            except Exception as e:
                print(f"Failed to load ban list: {e}")


    def save_bans(self):
        """Save Bans to JSON File"""
        try:
            with open(self.bans_file, 'w', encoding='utf-8') as f:
                json.dump({
                    'ips': list(self.banned_ips),
                    'users': list(self.banned_users)
                }, f, indent=2)
        except Exception as e:
            print(f"Failed to save ban list: {e}")


    def start_admin_console(self):
        """Start Admin Console"""
        def admin_input_loop():
            print("=== Admin Console ===")
            print("Enter /help to view available commands\n")
            while True:
                try:
                    cmd = input("admin> ").strip()
                    if cmd.startswith('/'):
                        self.handle_admin_command(cmd[1:])
                    else:
                        # Send chat message to all clients and print on server
                        if cmd:
                            message_data = {
                                'type': 'message',
                                'nickname': 'Admin',
                                'message': cmd,
                                'timestamp': time.time(),
                                'room': None  # Send to all rooms
                            }
                            formatted_msg = self.format_message(message_data)
                            print(formatted_msg)  # Print on server terminal
                            self.broadcast({'type': 'message', 'formatted_message': formatted_msg})
                except (EOFError, KeyboardInterrupt):
                    print("\nExiting admin console")
                    os._exit(0)
                except Exception as e:
                    print(f"Error: {e}")

        if threading.current_thread() is threading.main_thread():
            admin_thread = threading.Thread(target=admin_input_loop, daemon=True)
            admin_thread.start()
        else:
            admin_input_loop()  


    def server_input_loop(self):
        """Server Input Loop for Admin Commands and Chat"""
        print("=== Admin Console ===")
        print("Enter /help to view available commands\n")
        while True:
            try:
                cmd = input("admin> ").strip()
                if cmd.startswith('/'):
                    self.handle_admin_command(cmd[1:])
                else:
                    # Send chat message to all clients and print on server
                    if cmd:
                        message_data = {
                            'type': 'message',
                            'nickname': 'Admin',
                            'message': cmd,
                            'timestamp': time.time(),
                            'room': None  # Send to all rooms
                        }
                        formatted_msg = self.format_message(message_data)
                        print(formatted_msg)  # Print on server terminal
                        self.broadcast({'type': 'message', 'formatted_message': formatted_msg})
            except (EOFError, KeyboardInterrupt):
                print("\nExiting admin console")
                sys.exit(0)
            except Exception as e:
                print(f"Error: {e}")


    def handle_admin_command(self, command):
        """Handle Admin Commands"""
        parts = command.split()
        if not parts:
            return
            
        cmd = parts[0].lower()
        args = parts[1:]
        
        if cmd in self.admin_commands:
            self.admin_commands[cmd](args)
        else:
            print(f"Unknown command: {cmd}")


    def kick_user(self, args):
        """Kick User /kick <Nickname>"""
        if not args:
            print("Usage: /kick <Nickname>")
            return
            
        nickname = ' '.join(args)
        found = False
        
        for addr, client in list(self.clients.items()):
            if client['nickname'].lower() == nickname.lower():
                try:
                    client['socket'].send(json.dumps({
                        'type': 'system',
                        'message': 'You have been kicked by the administrator',
                        'timestamp': time.time()
                    }).encode())
                    client['socket'].close()
                except:
                    pass
                del self.clients[addr]
                print(f"Kicked user: {nickname}")
                found = True
                break
        if not found:
            print(f"User not found: {nickname}")


    def ban_user(self, args):
        """Ban User or IP /ban <RoomName> <Nickname|IP>"""
        if not args or len(args) < 2:
            print("Usage: /ban <RoomName> <Nickname|IP>")
            return
            
        room_name = args[0]
        target = ' '.join(args[1:])
        found = False
        
        if room_name.lower() == 'global':
            # Global ban
            if self.is_valid_ip(target.split(':')[0]):
                ip = target.split(':')[0]
                self.banned_ips.add(ip)
                self.save_bans()
                print(f"Globally banned IP: {ip}")
                found = True
                
                # Disconnect all connections from this IP
                for addr, client in list(self.clients.items()):
                    if addr[0] == ip:
                        try:
                            client['socket'].send(json.dumps({
                                'type': 'system',
                                'message': 'Your IP has been globally banned by the administrator',
                                'timestamp': time.time()
                            }).encode())
                            client['socket'].close()
                        except:
                            pass
                        del self.clients[addr]
            else:
                # Global ban by nickname
                for addr, client in list(self.clients.items()):
                    if client['nickname'].lower() == target.lower():
                        self.banned_users.add(client['nickname'].lower())
                        self.save_bans()
                        try:
                            client['socket'].send(json.dumps({
                                'type': 'system',
                                'message': 'You have been globally banned by the administrator',
                                'timestamp': time.time()
                            }).encode())
                            client['socket'].close()
                        except:
                            pass
                        del self.clients[addr]
                        print(f"Globally banned user: {client['nickname']}")
                        found = True
                        break
                if not found and target.lower() in self.banned_users:
                    print(f"User {target} is already globally banned")
                    found = True
        else:
            # Room-specific ban
            if room_name not in self.rooms:
                print(f"Room does not exist: {room_name}")
                return
            
            # Check if it's an IP
            if self.is_valid_ip(target.split(':')[0]):
                ip = target.split(':')[0]
                if ip not in self.rooms[room_name]['bans']['ips']:
                    self.rooms[room_name]['bans']['ips'].append(ip)
                    self.save_room_bans(room_name)
                    print(f"Banned IP {ip} from room {room_name}")
                    found = True
                    
                    # Disconnect users from this IP in the room
                    for addr, client in list(self.clients.items()):
                        if addr[0] == ip and client['room'] == room_name:
                            try:
                                client['socket'].send(json.dumps({
                                    'type': 'system',
                                    'message': f'You have been banned from room {room_name} by the administrator',
                                    'timestamp': time.time()
                                }).encode())
                                client['socket'].close()
                            except:
                                pass
                            del self.clients[addr]
            else:
                # Ban by nickname in the room
                for addr, client in list(self.clients.items()):
                    if client['nickname'].lower() == target.lower() and client['room'] == room_name:
                        if target.lower() not in self.rooms[room_name]['bans']['users']:
                            self.rooms[room_name]['bans']['users'].append(target.lower())
                            self.save_room_bans(room_name)
                            try:
                                client['socket'].send(json.dumps({
                                    'type': 'system',
                                    'message': f'You have been banned from room {room_name} by the administrator',
                                    'timestamp': time.time()
                                }).encode())
                                client['socket'].close()
                            except:
                                pass
                            del self.clients[addr]
                            print(f"Banned user {target} from room {room_name}")
                            found = True
                            break
                if not found and target.lower() in self.rooms[room_name]['bans']['users']:
                    print(f"User {target} is already banned in room {room_name}")
                    found = True
        if not found:
            print(f"User not found or invalid IP: {target}")


    def unban_user(self, args):
        """Unban /unban <RoomName> <Nickname|IP>"""
        if not args or len(args) < 2:
            print("Usage: /unban <RoomName> <Nickname|IP>")
            return
            
        room_name = args[0]
        target = ' '.join(args[1:])
        found = False
        
        if room_name.lower() == 'global':
            # Global unban
            if self.is_valid_ip(target):
                if target in self.banned_ips:
                    self.banned_ips.remove(target)
                    self.save_bans()
                    print(f"Globally unbanned IP: {target}")
                    found = True
            else:
                target_lower = target.lower()
                if target_lower in self.banned_users:
                    self.banned_users.remove(target_lower)
                    self.save_bans()
                    print(f"Globally unbanned user: {target}")
                    found = True
        else:
            # Room-specific unban
            if room_name not in self.rooms:
                print(f"Room does not exist: {room_name}")
                return
            
            if self.is_valid_ip(target):
                if target in self.rooms[room_name]['bans']['ips']:
                    self.rooms[room_name]['bans']['ips'].remove(target)
                    self.save_room_bans(room_name)
                    print(f"Unbanned IP {target} from room {room_name}")
                    found = True
            else:
                target_lower = target.lower()
                if target_lower in self.rooms[room_name]['bans']['users']:
                    self.rooms[room_name]['bans']['users'].remove(target_lower)
                    self.save_room_bans(room_name)
                    print(f"Unbanned user {target} from room {room_name}")
                    found = True
        if not found:
            print(f"No ban record found: {target}")

    def check_user(self, args):
        """Check User Information /check <Nickname>"""
        if not args:
            print("Usage: /check <Nickname>")
            return
            
        nickname = ' '.join(args)
        found = False
        
        for addr, client in self.clients.items():
            if client['nickname'].lower() == nickname.lower():
                print(f"User Information:")
                print(f"  Nickname: {client['nickname']}")
                print(f"  IP: {addr[0]}")
                print(f"  Port: {addr[1]}")
                print(f"  Connection Time: {time.ctime(client['last_seen'])}")
                found = True
        if not found:
            print(f"User not found: {nickname}")

    def list_bans(self, args):
        """List All Bans /listbans <RoomName>"""
        if not args:
            print("Usage: /listbans [RoomName]")
            return
            
        room_name = args[0] if args else 'global'
        
        print("\n=== Ban List ===")
        if room_name.lower() == 'global':
            print("Global Bans:")
            print("IP Addresses:")
            for ip in sorted(self.banned_ips):
                print(f"  {ip}")
            
            print("\nUsernames:")
            for user in sorted(self.banned_users):
                print(f"  {user}")
            
            print(f"\nTotal: {len(self.banned_ips)} IPs, {len(self.banned_users)} users")
        else:
            if room_name not in self.rooms:
                print(f"Room does not exist: {room_name}")
                return
            
            print(f"Bans for room {room_name}:")
            print("IP Addresses:")
            for ip in sorted(self.rooms[room_name]['bans']['ips']):
                print(f"  {ip}")
            
            print("\nUsernames:")
            for user in sorted(self.rooms[room_name]['bans']['users']):
                print(f"  {user}")
            
            print(f"\nTotal: {len(self.rooms[room_name]['bans']['ips'])} IPs, {len(self.rooms[room_name]['bans']['users'])} users")

    def show_admin_help(self, args):
        """Show Help /help"""
        print("\nAvailable Admin Commands:")
        print("/kick <Nickname>        - Kick a user")
        print("/ban <RoomName> <Nickname|IP> \n                        - Ban a user or IP (use 'global' for global ban)")
        print("/unban <RoomName> <Nickname|IP> \n                        - Unban a user or IP")
        print("/check <Nickname>       - Check user information")
        print("/listbans [RoomName]    - List all bans (global if no room specified)")
        print("/stop                   - Stop the server")
        print("/help                   - Show this help")
        print("/setpassword <password> - Set server password")
        print("/hashpassword           - Hash server password")
        print("/roompassword <room> <password> - Set room password")
        print("/save                   - Save chat history")

    def is_valid_ip(self, ip):
        """Check if IP address is valid"""
        try:
            socket.inet_pton(socket.AF_INET, ip)
            return True
        except socket.error:
            try:
                socket.inet_pton(socket.AF_INET6, ip)
                return True
            except socket.error:
                return False

    def set_password(self, args):
        """Set Server Password"""
        if not args:
            print("Usage: /setpassword <password>")
            return
        
        password = ' '.join(args)
        if self.config['enable_hash']:
            hashed_password = self.hash_password_value(password)
            with open('password.hash', 'w', encoding='utf-8') as f:
                f.write(hashed_password)
            print("Password updated and hashed")
        else:
            with open('password.txt', 'w', encoding='utf-8') as f:
                f.write(password)
            print("Password updated")

    def hash_password_value(self, password):
        """Hash a password"""
        if self.config['hash_type'] == 'md5':
            return hashlib.md5(password.encode()).hexdigest()
        elif self.config['hash_type'] == 'sha1':
            return hashlib.sha1(password.encode()).hexdigest()
        elif self.config['hash_type'] == 'sha256':
            return hashlib.sha256(password.encode()).hexdigest()
        elif self.config['hash_type'] == 'sha512':
            return hashlib.sha512(password.encode()).hexdigest()
        else:
            print(f"Unsupported hash type: {self.config['hash_type']}")
            return password

    def hash_password(self, args):
        """Hash Server Password"""
        if not args:
            print("Usage: /hashpassword")
            return
        
        if os.path.exists('password.txt'):
            with open('password.txt', 'r', encoding='utf-8') as f:
                password = f.read().strip()
            hashed_password = self.hash_password_value(password)
            with open('password.hash', 'w', encoding='utf-8') as f:
                f.write(hashed_password)
            print("Password hashed")
        else:
            print("No password set. Use /setpassword first.")

    def verify_password(self, password):
        """Verify Server Password"""
        if not self.config['enable_password']:
            return True
        
        if self.config['enable_hash'] and os.path.exists('password.hash'):
            with open('password.hash', 'r', encoding='utf-8') as f:
                hashed_password = f.read().strip()
            return self.hash_password_value(password) == hashed_password
        elif os.path.exists('password.txt'):
            with open('password.txt', 'r', encoding='utf-8') as f:
                stored_password = f.read().strip()
            return password == stored_password
        else:
            return False

    def set_room_password(self, args):
        """Set Room Password"""
        if len(args) < 2:
            print("Usage: /roompassword <room_name> <password>")
            return
        
        room_name = args[0]
        password = ' '.join(args[1:])
        
        if room_name not in self.rooms:
            print(f"Room does not exist: {room_name}")
            return
        
        if self.config['enable_hash']:
            hashed_password = self.hash_password_value(password)
            self.rooms[room_name]['password_hash'] = hashed_password
            self.save_room_password_hash(room_name, hashed_password)
            print(f"Password for room {room_name} updated and hashed")
        else:
            self.rooms[room_name]['password'] = password
            with open(os.path.join(self.room_config_dir, f"{room_name}.cfg"), 'a', encoding='utf-8') as f:
                f.write(f"password={password}\n")
            print(f"Password for room {room_name} updated")

    def verify_room_password(self, room_name, password):
        """Verify Room Password"""
        if not self.config['enable_password']:
            return True
        
        if room_name not in self.rooms:
            return False
        
        if self.config['enable_hash'] and self.rooms[room_name]['password_hash']:
            return self.hash_password_value(password) == self.rooms[room_name]['password_hash']
        else:
            return password == self.rooms[room_name]['password']

    def format_message(self, message_data):
        """Format message with timestamp"""
        timestamp = datetime.fromtimestamp(message_data['timestamp'])
        formatted_time = timestamp.strftime("%m/%d %H:%M:%S")
        return f"{formatted_time} {message_data['nickname']}\n    {message_data['message']}"

    def save_chat_history(self):
        """Save Chat History"""
        if not self.chat_history:
            print("No chat history to save")
            return
        
        now = datetime.now()
        formatted_time = now.strftime("%Y%m%d%H%M%S")
        filename = f"chat_history_{formatted_time}.txt"
        
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                for entry in self.chat_history:
                    f.write(f"[{entry['timestamp']}] {entry['user']}: {entry['message']}\n")
            print(f"Chat history saved to {filename}")
        except Exception as e:
            print(f"Failed to save chat history: {e}")

if __name__ == '__main__':
    ChatApplication()