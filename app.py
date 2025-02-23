from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, make_response
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_sqlalchemy import SQLAlchemy
import subprocess
import os
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import glob

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-here'  # Change this to a secure secret key
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

class VPS(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), nullable=False)
    vmx_path = db.Column(db.String(200), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    status = db.Column(db.String(20), default='stopped')
    rdp_host = db.Column(db.String(100))
    rdp_port = db.Column(db.Integer, default=3389)
    rdp_username = db.Column(db.String(100))
    rdp_password = db.Column(db.String(100))

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    vps_list = db.relationship('VPS', backref='owner', lazy=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            flash('You need admin privileges to access this page.')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

def vmware_control(action, vmx_path):
    vmware_path = r"C:\Program Files (x86)\VMware\VMware Workstation\vmrun.exe"
    
    try:
        if action == "start":
            subprocess.run([vmware_path, "start", vmx_path])
            return "running"
        elif action == "stop":
            subprocess.run([vmware_path, "stop", vmx_path])
            return "stopped"
        elif action == "restart":
            subprocess.run([vmware_path, "reset", vmx_path])
            return "running"
        elif action == "status":
            result = subprocess.run([vmware_path, "list"], capture_output=True, text=True)
            return "running" if vmx_path in result.stdout else "stopped"
    except Exception as e:
        return "error"

def get_vm_status(vmx_path):
    try:
        # Use vmrun list to get list of running VMs
        result = subprocess.run(['vmrun', 'list'], capture_output=True, text=True)
        running_vms = result.stdout.splitlines()
        
        # Skip the first line which is just a header
        running_vms = running_vms[1:] if running_vms else []
        
        # Check if this VM's vmx path is in the list of running VMs
        vmx_path = os.path.normpath(vmx_path)
        for vm in running_vms:
            if os.path.normpath(vm.strip()) == vmx_path:
                return "running"
        return "stopped"
    except Exception as e:
        app.logger.error(f"Error checking VM status: {e}")
        return "unknown"

@app.route('/')
def home():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        
        if user and user.check_password(password):
            login_user(user)
            return redirect(url_for('dashboard'))
        flash('Invalid username or password')
    return render_template('login.html')

@app.route('/dashboard')
@login_required
def dashboard():
    try:
        if current_user.is_admin:
            vps_list = VPS.query.all()
        else:
            vps_list = VPS.query.filter_by(user_id=current_user.id).all()
        
        # Update status for each VPS
        for vps in vps_list:
            vps.status = get_vm_status(vps.vmx_path)
        
        return render_template('dashboard.html', user=current_user, vps_list=vps_list)
    except Exception as e:
        app.logger.error(f"Dashboard error: {e}")
        flash('Error loading dashboard', 'error')
        return redirect(url_for('login'))

@app.route('/control/<int:vps_id>/<action>', methods=['POST'])
@login_required
def control(vps_id, action):
    vps = VPS.query.get_or_404(vps_id)
    
    if not current_user.is_admin and vps.user_id != current_user.id:
        return jsonify({'success': False, 'message': 'You do not have permission to control this VPS'})
    
    try:
        if action in ['start', 'stop', 'restart', 'status']:
            new_status = vmware_control(action, vps.vmx_path)
            vps.status = new_status
            db.session.commit()
            return jsonify({'success': True, 'message': f'VPS {action} command executed successfully', 'status': new_status})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})
    
    return jsonify({'success': False, 'message': 'Invalid action'})

@app.route('/admin_panel')
@login_required
def admin_panel():
    if not current_user.is_admin:
        flash('Admin access required', 'error')
        return redirect(url_for('dashboard'))
        
    users = User.query.all()
    vps_list = VPS.query.all()
    return render_template('admin_panel.html', users=users, vps_list=vps_list)

@app.route('/manage-users')
@login_required
@admin_required
def manage_users():
    users = User.query.all()
    return render_template('manage_users.html', users=users)

@app.route('/manage-vps')
@login_required
@admin_required
def manage_vps():
    vps_list = VPS.query.all()
    users = User.query.all()
    return render_template('manage_vps.html', vps_list=vps_list, users=users)

@app.route('/scan-vmx-files', methods=['POST'])
@login_required
@admin_required
def scan_vmx_files():
    base_path = request.form.get('base_path', '')
    if not base_path or not os.path.exists(base_path):
        return jsonify({'error': 'Invalid path'}), 400

    # Search for .vmx files recursively
    vmx_files = []
    try:
        for root, dirs, files in os.walk(base_path):
            for file in files:
                if file.endswith('.vmx'):
                    full_path = os.path.join(root, file)
                    vmx_files.append({
                        'path': full_path,
                        'name': os.path.splitext(file)[0]
                    })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

    return jsonify({'vmx_files': vmx_files})

@app.route('/add-vps', methods=['POST'])
@login_required
@admin_required
def add_vps():
    name = request.form['name']
    vmx_path = request.form['vmx_path']
    user_id = request.form.get('user_id')
    
    # Validate VMX file exists
    if not os.path.exists(vmx_path) or not vmx_path.endswith('.vmx'):
        flash('Invalid VMX file path. Please provide a valid .vmx file path.')
        return redirect(url_for('manage_vps'))
    
    if user_id:
        user_id = int(user_id)
    
    vps = VPS(name=name, vmx_path=vmx_path, user_id=user_id)
    db.session.add(vps)
    db.session.commit()
    
    flash('VPS added successfully')
    return redirect(url_for('manage_vps'))

@app.route('/assign-vps/<int:vps_id>', methods=['POST'])
@login_required
@admin_required
def assign_vps(vps_id):
    vps = VPS.query.get_or_404(vps_id)
    user_id = request.form.get('user_id')
    
    if user_id:
        vps.user_id = int(user_id)
    else:
        vps.user_id = None
        
    db.session.commit()
    flash('VPS assigned successfully')
    return redirect(url_for('manage_vps'))

@app.route('/delete-vps/<int:vps_id>', methods=['POST'])
@login_required
@admin_required
def delete_vps(vps_id):
    vps = VPS.query.get_or_404(vps_id)
    db.session.delete(vps)
    db.session.commit()
    flash('VPS deleted successfully')
    return redirect(url_for('manage_vps'))

@app.route('/add-user', methods=['POST'])
@login_required
@admin_required
def add_user():
    username = request.form['username']
    password = request.form['password']
    is_admin = 'is_admin' in request.form
    
    if User.query.filter_by(username=username).first():
        flash('Username already exists')
        return redirect(url_for('manage_users'))
    
    user = User(
        username=username,
        is_admin=is_admin
    )
    user.set_password(password)
    db.session.add(user)
    db.session.commit()
    
    flash('User added successfully')
    return redirect(url_for('manage_users'))

@app.route('/delete-user/<int:user_id>', methods=['POST'])
@login_required
@admin_required
def delete_user(user_id):
    user = User.query.get_or_404(user_id)
    if user.username == current_user.username:
        flash('You cannot delete your own account')
        return redirect(url_for('manage_users'))
    
    db.session.delete(user)
    db.session.commit()
    flash('User deleted successfully')
    return redirect(url_for('manage_users'))

@app.route('/toggle-admin/<int:user_id>', methods=['POST'])
@login_required
@admin_required
def toggle_admin(user_id):
    user = User.query.get_or_404(user_id)
    if user.username == current_user.username:
        flash('You cannot modify your own admin status')
        return redirect(url_for('manage_users'))
    
    user.is_admin = not user.is_admin
    db.session.commit()
    flash(f'Admin status updated for {user.username}')
    return redirect(url_for('manage_users'))

@app.route('/rdp_settings/<int:vps_id>', methods=['GET', 'POST'])
@login_required
def rdp_settings(vps_id):
    vps = VPS.query.get_or_404(vps_id)
    
    # Check if user has permission to access this VPS
    if not current_user.is_admin and vps.user_id != current_user.id:
        flash('Unauthorized access', 'error')
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        vps.rdp_host = request.form.get('rdp_host')
        vps.rdp_port = request.form.get('rdp_port')
        vps.rdp_username = request.form.get('rdp_username')
        
        # Only update password if provided
        new_password = request.form.get('rdp_password')
        if new_password:
            vps.rdp_password = new_password
            
        db.session.commit()
        flash('RDP settings updated successfully', 'success')
        return redirect(url_for('dashboard'))
        
    return render_template('rdp_settings.html', vps=vps)

@app.route('/download_rdp/<int:vps_id>')
@login_required
def download_rdp(vps_id):
    vps = VPS.query.get_or_404(vps_id)
    
    # Check if user owns this VPS or is admin
    if not current_user.is_admin and vps.user_id != current_user.id:
        flash('Access denied')
        return redirect(url_for('dashboard'))
    
    # Generate RDP file content
    rdp_content = f"""screen mode id:i:2
use multimon:i:0
desktopwidth:i:1920
desktopheight:i:1080
session bpp:i:32
winposstr:s:0,1,0,0,800,600
compression:i:1
keyboardhook:i:2
audiocapturemode:i:0
videoplaybackmode:i:1
connection type:i:7
networkautodetect:i:1
bandwidthautodetect:i:1
displayconnectionbar:i:1
enableworkspacereconnect:i:0
disable wallpaper:i:0
allow font smoothing:i:0
allow desktop composition:i:0
disable full window drag:i:1
disable menu anims:i:1
disable themes:i:0
disable cursor setting:i:0
bitmapcachepersistenable:i:1
full address:s:{vps.rdp_host}:{vps.rdp_port}
audiomode:i:0
redirectprinters:i:1
redirectcomports:i:0
redirectsmartcards:i:1
redirectclipboard:i:1
redirectposdevices:i:0
autoreconnection enabled:i:1
authentication level:i:2
prompt for credentials:i:0
negotiate security layer:i:1
remoteapplicationmode:i:0
alternate shell:s:
shell working directory:s:
gatewayhostname:s:
gatewayusagemethod:i:4
gatewaycredentialssource:i:4
gatewayprofileusagemethod:i:0
promptcredentialonce:i:0
use redirection server name:i:0
rdgiskdcproxy:i:0
kdcproxyname:s:
username:s:{vps.rdp_username}"""
    
    # Create response with RDP file
    response = make_response(rdp_content)
    response.headers['Content-Type'] = 'application/x-rdp'
    response.headers['Content-Disposition'] = f'attachment; filename={vps.name}.rdp'
    return response

@app.route('/api/status/<int:vps_id>')
@login_required
def get_status(vps_id):
    vps = VPS.query.get_or_404(vps_id)
    if not current_user.is_admin and vps.user_id != current_user.id:
        return jsonify({'error': 'Unauthorized'}), 403
    
    status = get_vm_status(vps.vmx_path)
    return jsonify({'status': status})

@app.route('/change_password/<username>', methods=['POST'])
@login_required
def change_password(username):
    user = User.query.filter_by(username=username).first()
    if user:
        user.set_password('admin')
        db.session.commit()
        return jsonify({'success': True, 'message': f'Password changed successfully for user {username}'})
    return jsonify({'success': False, 'message': 'User not found'})

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True, port=5001, host='0.0.0.0', use_reloader=False)
