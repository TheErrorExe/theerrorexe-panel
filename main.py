from flask import Flask, render_template, request, redirect, url_for, send_from_directory, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
import os
import subprocess
import threading
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy import inspect
from queue import Queue, Empty
import time
from collections import deque

app = Flask(__name__)
app.config['SECRET_KEY'] = 'super-secret-key' # Change this to something different
app.config['JWT_SECRET_KEY'] = 'another-super-secret-key' # Also change this
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///accs.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
jwt = JWTManager(app)
last_lines = deque(maxlen=100)

BASE_DIR = 'your_server_directory' # IMPORTANT -  Change this to your directory where server.jar and the panel files are located
MC_SERVER_DIR = os.path.join(BASE_DIR) # optional: make the panel and sevrer files different
MC_SERVER_JAR = 'server.jar' # change this to your JAR

mc_process = None
mc_thread = None
mc_output_queue = Queue()
mc_command_queue = Queue()
mc_server_running = False

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)

with app.app_context():
    db.create_all()
    if not User.query.filter_by(username='root').first():
        root = User(
            username='root',
            password=generate_password_hash('25565'), # Change the Password to something secret
            is_admin=True
        )
        db.session.add(root)
        db.session.commit()

def mc_server_runner():
    global mc_process, mc_server_running, last_lines
    try:
        os.chdir(MC_SERVER_DIR)
        mc_process = subprocess.Popen(
            ['java', '-Xmx1024M', '-Xms1024M', '-jar', MC_SERVER_JAR, 'nogui'], # Change this to your RAM
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            universal_newlines=True
        )
        mc_server_running = True
        
        def command_sender():
            while mc_server_running:
                try:
                    command = mc_command_queue.get(timeout=0.1)
                    if mc_process.poll() is None:
                        mc_process.stdin.write(command + "\n")
                        mc_process.stdin.flush()
                except (Empty, BrokenPipeError):
                    continue
        
        threading.Thread(target=command_sender, daemon=True).start()
        
        while True:
            output = mc_process.stdout.readline()
            if output == '' and mc_process.poll() is not None:
                break
            if output:
                stripped_output = output.strip()
                last_lines.append(stripped_output)
                mc_output_queue.put(stripped_output)
    except Exception as e:
        error_msg = f"Server error: {str(e)}"
        last_lines.append(error_msg)
        mc_output_queue.put(error_msg)
    finally:
        mc_server_running = False
        if mc_process:
            try:
                mc_process.stdin.close()
                mc_process.terminate()
                try:
                    mc_process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    mc_process.kill()
            except:
                pass

def start_mc_server():
    global mc_thread
    if mc_thread is None or not mc_thread.is_alive():
        mc_thread = threading.Thread(target=mc_server_runner)
        mc_thread.daemon = True
        mc_thread.start()
        return True
    return False

def stop_mc_server():
    global mc_process, mc_thread
    if mc_process and mc_process.poll() is None:
        mc_command_queue.put("stop")
        time.sleep(1)
        if mc_thread and mc_thread.is_alive():
            mc_thread.join(timeout=5)
        return True
    return False

def send_mc_command(command):
    if mc_process and mc_process.poll() is None:
        mc_command_queue.put(command)
        return True
    return False

@app.route('/mc_console/last_lines')
@jwt_required()
def get_last_lines():
    return jsonify(lines=list(last_lines))

@app.route('/favicon.ico')
def get_favicon():
    return send_from_directory('.', 'favicon.ico', mimetype='image/vnd.microsoft.icon')
    

@app.route('/mc_console/stream')
def mc_console_stream():
    def generate():
        try:
            while True:
                try:
                    output = mc_output_queue.get(timeout=1)
                    yield f"data: {output}\n\n"
                except Empty:
                    yield ":keepalive\n\n"
        except GeneratorExit:
            pass
    
    return app.response_class(generate(), mimetype='text/event-stream')

@app.route('/mc_console/command', methods=['POST'])
@jwt_required()
def mc_console_command():
    command = request.json.get('command')
    if command:
        if send_mc_command(command):
            return jsonify(success=True)
    return jsonify(success=False)

@app.route('/mc_server/start', methods=['POST'])
@jwt_required()
def mc_server_start():
    if start_mc_server():
        return jsonify(success=True, message="Server started")
    return jsonify(success=False, message="Server is already running or an error occurred")

@app.route('/mc_server/stop', methods=['POST'])
@jwt_required()
def mc_server_stop():
    if stop_mc_server():
        return jsonify(success=True, message="Stopping server")
    return jsonify(success=False, message="Server is not running or an error occurred")

@app.route('/mc_server/status')
@jwt_required()
def mc_server_status():
    return jsonify(running=mc_server_running)

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    if not data or 'username' not in data or 'password' not in data:
        return jsonify(msg='Ungültige Anfrage'), 400
        
    user = User.query.filter_by(username=data.get('username')).first()
    if user and check_password_hash(user.password, data.get('password')):
        token = create_access_token(identity={'username': user.username, 'is_admin': user.is_admin})
        return jsonify(token=token)
    return jsonify(msg='Invalid Credentials'), 401

@app.route('/create_user', methods=['POST'])
@jwt_required()
def create_user():
    current_user = get_jwt_identity()
    if not current_user.get('is_admin'):
        return jsonify(msg='No Permissions'), 403
        
    data = request.get_json()
    if not data or 'username' not in data or 'password' not in data:
        return jsonify(msg='Invalid Request'), 400
        
    if User.query.filter_by(username=data.get('username')).first():
        return jsonify(msg='User already exists'), 400
        
    user = User(
        username=data.get('username'),
        password=generate_password_hash(data.get('password')),
        is_admin=data.get('is_admin', False)
    )
    db.session.add(user)
    db.session.commit()
    return jsonify(msg='Benutzer erstellt')


def get_safe_path(subpath=""):
    full_path = os.path.abspath(os.path.join(BASE_DIR, subpath))
    if not full_path.startswith(BASE_DIR):
        return BASE_DIR
    return full_path

@app.route('/', defaults={'subpath': ''})
@app.route('/browse/', defaults={'subpath': ''})
@app.route('/browse/<path:subpath>')
def index(subpath):
    current_path = get_safe_path(subpath)
    
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
            'rel_path': os.path.relpath(item_path, BASE_DIR).replace('\\', '/')
        })
    
    parent_path = os.path.relpath(os.path.join(current_path, '..'), BASE_DIR).replace('\\', '/')
    if parent_path == '.':
        parent_path = ''
        
    return render_template('index.html', entries=entries, current=subpath, parent_path=parent_path)

@app.route('/download/<path:filepath>')
@jwt_required()
def download_file(filepath):
    safe_path = get_safe_path(filepath)
    if not os.path.exists(safe_path):
        return "File not found", 404
    return send_from_directory(
        os.path.dirname(safe_path), 
        os.path.basename(safe_path), 
        as_attachment=True
    )

@app.route('/delete/<path:filepath>', methods=['POST'])
@jwt_required()
def delete_file(filepath):
    safe_path = get_safe_path(filepath)
    if not os.path.exists(safe_path):
        return "File not found", 404
        
    try:
        if os.path.isfile(safe_path):
            os.remove(safe_path)
        else:
            os.rmdir(safe_path)
        return redirect(url_for('index', subpath=os.path.dirname(filepath)))
    except Exception as e:
        return str(e), 500

@app.route('/upload/<path:subpath>', methods=['POST'])
@jwt_required()
def upload_file(subpath):
    if 'file' not in request.files:
        return "No File selected", 400
        
    file = request.files['file']
    if file.filename == '':
        return "No File selected", 400
        
    upload_path = get_safe_path(subpath)
    try:
        file.save(os.path.join(upload_path, file.filename))
        return redirect(url_for('index', subpath=subpath))
    except Exception as e:
        return str(e), 500

@app.route('/create_folder/<path:subpath>', methods=['POST'])
@jwt_required()
def create_folder(subpath):
    folder_name = request.form.get('folder_name')
    if not folder_name:
        return "Folder name missing", 400
        
    full_path = get_safe_path(os.path.join(subpath, folder_name))
    try:
        os.makedirs(full_path, exist_ok=True)
        return redirect(url_for('index', subpath=subpath))
    except Exception as e:
        return str(e), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5656, debug=True)
