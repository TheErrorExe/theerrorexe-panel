from flask import Flask, render_template, request, redirect, url_for, send_from_directory, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
import os
import subprocess
import threading
from werkzeug.security import generate_password_hash, check_password_hash
import yaml
from queue import Queue, Empty
import time
from collections import deque
import uuid
import json

app = Flask(__name__)
app.config['SECRET_KEY'] = 'super-secret-key'
app.config['JWT_SECRET_KEY'] = 'another-super-secret-key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///panel.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
jwt = JWTManager(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)

class Server(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    uuid = db.Column(db.String(36), unique=True, nullable=False)
    name = db.Column(db.String(150), nullable=False)
    config = db.Column(db.Text, nullable=False)
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'))
    is_default = db.Column(db.Boolean, default=False)

class ServerUser(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    server_id = db.Column(db.Integer, db.ForeignKey('server.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    can_manage = db.Column(db.Boolean, default=False)

with app.app_context():
    db.create_all()
    if not User.query.filter_by(username='admin').first():
        admin = User(
            username='admin',
            password=generate_password_hash('admin'),
            is_admin=True
        )
        db.session.add(admin)
        db.session.commit()

class MinecraftServer:
    def __init__(self, server_id):
        self.server_id = server_id
        self.process = None
        self.thread = None
        self.output_queue = Queue()
        self.command_queue = Queue()
        self.running = False
        self.last_lines = deque(maxlen=100)
        self.server_data = Server.query.get(server_id)
        self.config = json.loads(self.server_data.config)
        
    def start(self):
        if self.thread is None or not self.thread.is_alive():
            self.thread = threading.Thread(target=self._runner)
            self.thread.daemon = True
            self.thread.start()
            return True
        return False
    
    def stop(self):
        if self.process and self.process.poll() is None:
            self.command_queue.put("stop")
            time.sleep(1)
            if self.thread and self.thread.is_alive():
                self.thread.join(timeout=5)
            return True
        return False
    
    def send_command(self, command):
        if self.process and self.process.poll() is None:
            self.command_queue.put(command)
            return True
        return False
    
    def _runner(self):
        try:
            os.chdir(self.config['directory'])
            java_args = self.config['java_args'].split()
            self.process = subprocess.Popen(
                ['java'] + java_args + ['-jar', self.config['jar_file'], 'nogui'],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                universal_newlines=True
            )
            self.running = True
            
            def command_sender():
                while self.running:
                    try:
                        command = self.command_queue.get(timeout=0.1)
                        if self.process.poll() is None:
                            self.process.stdin.write(command + "\n")
                            self.process.stdin.flush()
                    except (Empty, BrokenPipeError):
                        continue
            
            threading.Thread(target=command_sender, daemon=True).start()
            
            while True:
                output = self.process.stdout.readline()
                if output == '' and self.process.poll() is not None:
                    break
                if output:
                    stripped_output = output.strip()
                    self.last_lines.append(stripped_output)
                    self.output_queue.put(stripped_output)
        except Exception as e:
            error_msg = f"Server error: {str(e)}"
            self.last_lines.append(error_msg)
            self.output_queue.put(error_msg)
        finally:
            self.running = False
            if self.process:
                try:
                    self.process.stdin.close()
                    self.process.terminate()
                    try:
                        self.process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        self.process.kill()
                except:
                    pass

servers = {}
active_server_id = None

def get_active_server():
    global active_server_id
    current_user = get_jwt_identity()
    if not current_user:
        return None
        
    if active_server_id is None:
        server_user = ServerUser.query.filter_by(user_id=current_user['id']).first()
        if server_user:
            active_server_id = server_user.server_id
        else:
            if current_user.get('is_admin'):
                first_server = Server.query.first()
                if first_server:
                    active_server_id = first_server.id
    return servers.get(active_server_id)

def user_has_access(user_id, server_id):
    if User.query.get(user_id).is_admin:
        return True
    return ServerUser.query.filter_by(user_id=user_id, server_id=server_id).first() is not None

def initialize_servers():
    global servers
    with app.app_context():
        for server in Server.query.all():
            if server.id not in servers:
                servers[server.id] = MinecraftServer(server.id)

initialize_servers()

@app.route('/')
def index():
    return redirect(url_for('dashboard'))

@app.route('/dashboard')
@jwt_required()
def dashboard():
    current_user = get_jwt_identity()
    user_servers = []
    
    if current_user.get('is_admin'):
        user_servers = Server.query.all()
    else:
        server_users = ServerUser.query.filter_by(user_id=current_user['id']).all()
        user_servers = [su.server for su in server_users]
    
    active_server = get_active_server()
    return render_template('dashboard.html', 
                         servers=user_servers,
                         active_server_id=active_server.server_id if active_server else None,
                         is_admin=current_user.get('is_admin', False))

@app.route('/server/select/<int:server_id>', methods=['POST'])
@jwt_required()
def select_server(server_id):
    global active_server_id
    current_user = get_jwt_identity()
    
    if not user_has_access(current_user['id'], server_id):
        return jsonify(success=False, error="Unauthorized"), 403
        
    active_server_id = server_id
    return jsonify(success=True)

@app.route('/server/create', methods=['POST'])
@jwt_required()
def create_server():
    current_user = get_jwt_identity()
    if not current_user.get('is_admin'):
        return jsonify(success=False, error="Unauthorized"), 403
    
    data = request.get_json()
    if not data or 'name' not in data or 'directory' not in data or 'jar_file' not in data:
        return jsonify(success=False, error="Missing required fields"), 400
    
    if Server.query.filter_by(name=data['name']).first():
        return jsonify(success=False, error="Server with this name already exists"), 400
    
    config = {
        'directory': data['directory'],
        'jar_file': data['jar_file'],
        'java_args': data.get('java_args', '-Xmx1024M -Xms1024M'),
        'auto_start': data.get('auto_start', False)
    }
    
    server = Server(
        uuid=str(uuid.uuid4()),
        name=data['name'],
        config=json.dumps(config),
        created_by=current_user['id']
    )
    
    db.session.add(server)
    db.session.commit()
    
    servers[server.id] = MinecraftServer(server.id)
    if config['auto_start']:
        servers[server.id].start()
    
    return jsonify(success=True, server_id=server.id)

@app.route('/admin/users', methods=['GET'])
@jwt_required()
def admin_users():
    current_user = get_jwt_identity()
    if not current_user.get('is_admin'):
        return jsonify(success=False, error="Unauthorized"), 403
    
    users = User.query.all()
    return jsonify(users=[{'id': u.id, 'username': u.username, 'is_admin': u.is_admin} for u in users])

@app.route('/admin/users/add', methods=['POST'])
@jwt_required()
def admin_add_user():
    current_user = get_jwt_identity()
    if not current_user.get('is_admin'):
        return jsonify(success=False, error="Unauthorized"), 403
    
    data = request.get_json()
    if not data or 'username' not in data or 'password' not in data:
        return jsonify(success=False, error="Missing required fields"), 400
    
    if User.query.filter_by(username=data['username']).first():
        return jsonify(success=False, error="User already exists"), 400
    
    user = User(
        username=data['username'],
        password=generate_password_hash(data['password']),
        is_admin=data.get('is_admin', False)
    )
    
    db.session.add(user)
    db.session.commit()
    return jsonify(success=True)

@app.route('/auth')
def auth():
    return redirect(url_for('login'))

@app.route('/favicon.ico')
def favicon():
    return send_from_directory(os.path.join(app.root_path, 'static'),
                             'favicon.ico', mimetype='image/vnd.microsoft.icon')
    
@app.route('/admin/server/<int:server_id>/users', methods=['GET'])
@jwt_required()
def server_users(server_id):
    current_user = get_jwt_identity()
    if not current_user.get('is_admin'):
        return jsonify(success=False, error="Unauthorized"), 403
    
    server_users = ServerUser.query.filter_by(server_id=server_id).all()
    users = []
    for su in server_users:
        user = User.query.get(su.user_id)
        users.append({
            'id': user.id,
            'username': user.username,
            'can_manage': su.can_manage
        })
    
    return jsonify(users=users)

@app.route('/admin/server/<int:server_id>/users/add', methods=['POST'])
@jwt_required()
def server_add_user(server_id):
    current_user = get_jwt_identity()
    if not current_user.get('is_admin'):
        return jsonify(success=False, error="Unauthorized"), 403
    
    data = request.get_json()
    if not data or 'user_id' not in data:
        return jsonify(success=False, error="Missing user_id"), 400
    
    if ServerUser.query.filter_by(server_id=server_id, user_id=data['user_id']).first():
        return jsonify(success=False, error="User already has access to this server"), 400
    
    server_user = ServerUser(
        server_id=server_id,
        user_id=data['user_id'],
        can_manage=data.get('can_manage', False)
    )
    
    db.session.add(server_user)
    db.session.commit()
    return jsonify(success=True)

@app.route('/mc_console/last_lines')
@jwt_required()
def get_last_lines():
    server = get_active_server()
    if server:
        return jsonify(lines=list(server.last_lines))
    return jsonify(lines=[])

@app.route('/mc_console/stream')
def mc_console_stream():
    server = get_active_server()
    
    def generate():
        try:
            while True:
                try:
                    if server:
                        output = server.output_queue.get(timeout=1)
                        yield f"data: {output}\n\n"
                    else:
                        yield ":keepalive\n\n"
                except Empty:
                    yield ":keepalive\n\n"
        except GeneratorExit:
            pass
    
    return app.response_class(generate(), mimetype='text/event-stream')

@app.route('/mc_console/command', methods=['POST'])
@jwt_required()
def mc_console_command():
    server = get_active_server()
    if not server:
        return jsonify(success=False, error="No active server"), 400
    
    command = request.json.get('command')
    if command:
        if server.send_command(command):
            return jsonify(success=True)
    return jsonify(success=False)

@app.route('/mc_server/start', methods=['POST'])
@jwt_required()
def mc_server_start():
    server = get_active_server()
    if not server:
        return jsonify(success=False, error="No active server"), 400
    
    if server.start():
        return jsonify(success=True, message="Server started")
    return jsonify(success=False, message="Server is already running or an error occurred")

@app.route('/mc_server/stop', methods=['POST'])
@jwt_required()
def mc_server_stop():
    server = get_active_server()
    if not server:
        return jsonify(success=False, error="No active server"), 400
    
    if server.stop():
        return jsonify(success=True, message="Stopping server")
    return jsonify(success=False, message="Server is not running or an error occurred")

@app.route('/mc_server/status')
@jwt_required()
def mc_server_status():
    server = get_active_server()
    if server:
        return jsonify(running=server.running)
    return jsonify(running=False)

@app.route('/files')
@jwt_required()
def file_manager():
    server = get_active_server()
    if not server:
        return "No active server selected", 400
    
    base_dir = server.config['directory']
    subpath = request.args.get('path', '')
    current_path = os.path.abspath(os.path.join(base_dir, subpath))
    
    if not current_path.startswith(base_dir):
        return "Access denied", 403
    
    if not os.path.exists(current_path):
        return "Path does not exist", 404
        
    if not os.path.isdir(current_path):
        return send_from_directory(
            os.path.dirname(current_path),
            os.path.basename(current_path),
            as_attachment=False
        )
        
    items = os.listdir(current_path)
    entries = []
    for item in items:
        item_path = os.path.join(current_path, item)
        entries.append({
            'name': item,
            'is_file': os.path.isfile(item_path),
            'rel_path': os.path.relpath(item_path, base_dir).replace('\\', '/')
        })
    
    parent_path = os.path.relpath(os.path.join(current_path, '..'), base_dir).replace('\\', '/')
    if parent_path == '.':
        parent_path = ''
        
    return render_template('file_manager.html', 
                         entries=entries, 
                         current=subpath, 
                         parent_path=parent_path,
                         server_name=server.server_data.name)

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    if not data or 'username' not in data or 'password' not in data:
        return jsonify(msg='Invalid request'), 400
        
    user = User.query.filter_by(username=data.get('username')).first()
    if user and check_password_hash(user.password, data.get('password')):
        token = create_access_token(identity={'id': user.id, 'username': user.username, 'is_admin': user.is_admin})
        return jsonify(token=token)
    return jsonify(msg='Invalid credentials'), 401

@app.route('/browse/', defaults={'subpath': ''})
@app.route('/browse/<path:subpath>')
def browse(subpath):
    return redirect(url_for('file_manager', subpath=subpath))
    
if __name__ == '__main__':
    with app.app_context():
        initialize_servers()
    app.run(host='0.0.0.0', port=5656, debug=True)
