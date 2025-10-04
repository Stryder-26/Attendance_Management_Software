"""
AMS Flask Starter - app.py (Production-Ready for PostgreSQL)
"""
import os
import csv
from io import StringIO, BytesIO
from datetime import date
import pandas as pd
from flask import (Flask, render_template, request, redirect, url_for, flash, abort, send_file)
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import (LoginManager, UserMixin, login_user, logout_user,
                         login_required, current_user)

# --- App Setup ---
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'a-very-secret-key-that-is-long-and-secure')

# --- Database Configuration ---
DATABASE_URL = os.environ.get('DATABASE_URL')
if DATABASE_URL and DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

app.config['SQLALCHEMY_DATABASE_URI'] = DATABASE_URL or 'sqlite:///' + os.path.join(BASE_DIR, 'ams.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# --- Login Manager Setup ---
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

# ----------------------
# Database models
# ----------------------
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    role = db.Column(db.String(20), nullable=False, default='teacher')
    college_id = db.Column(db.Integer, db.ForeignKey('college.id'), nullable=True)
    department_id = db.Column(db.Integer, db.ForeignKey('department.id'), nullable=True)
    classes_taught = db.relationship('ClassRoom', backref='teacher', lazy=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class College(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False, unique=True)
    departments = db.relationship('Department', backref='college', cascade='all, delete-orphan')
    admins = db.relationship('User', foreign_keys=[User.college_id], backref='college', lazy=True)

class Department(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    college_id = db.Column(db.Integer, db.ForeignKey('college.id'), nullable=False)
    classes = db.relationship('ClassRoom', backref='department', cascade='all, delete-orphan')
    teachers = db.relationship('User', backref='department', lazy=True)

class ClassRoom(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    department_id = db.Column(db.Integer, db.ForeignKey('department.id'))
    students = db.relationship('Student', backref='classroom', cascade='all, delete-orphan')
    teacher_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)

class Student(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    enrollment_no = db.Column(db.String(120), nullable=True)
    class_id = db.Column(db.Integer, db.ForeignKey('class_room.id'))
    attendance_records = db.relationship('Attendance', backref='student', cascade='all, delete-orphan')

class Attendance(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    student_id = db.Column(db.Integer, db.ForeignKey('student.id'), nullable=False)
    date = db.Column(db.Date, nullable=False)
    status = db.Column(db.String(10), nullable=False)

# ----------------------
# Helpers & Template Generation
# ----------------------
def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in {'csv', 'xlsx', 'xls'}

def ensure_templates():
    TEMPLATES_FOLDER = os.path.join(BASE_DIR, 'templates')
    os.makedirs(TEMPLATES_FOLDER, exist_ok=True)
    files = {
        'base.html': """<!doctype html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>AMS</title><link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet"></head><body class="p-3 bg-light"><div class="container"><nav class="navbar navbar-expand-lg navbar-light bg-white rounded mb-3 shadow-sm"><div class="container-fluid"><a class="navbar-brand" href="{{ url_for('index') }}">AMS Portal</a><div class="collapse navbar-collapse"><ul class="navbar-nav ms-auto">{% if current_user.is_authenticated %}<li class="nav-item"><span class="navbar-text me-3">Welcome, {{ current_user.name }} ({{ current_user.role.replace('_', ' ')|title }})!</span></li><li class="nav-item"><a class="btn btn-outline-danger" href="{{ url_for('logout') }}">Logout</a></li>{% else %}<li class="nav-item"><a class="btn btn-outline-primary" href="{{ url_for('login') }}">Login</a></li>{% endif %}</ul></div></div></nav>{% with messages = get_flashed_messages(with_categories=true) %}{% if messages %}{% for category, message in messages %}<div class="alert alert-{{ category or 'info' }}">{{ message }}</div>{% endfor %}{% endif %}{% endwith %}{% block content %}{% endblock %}</div></body></html>""",
        'login.html': """{% extends 'base.html' %}{% block content %}<div class="row justify-content-center"><div class="col-md-6 col-lg-4"><div class="card shadow"><div class="card-body"><h3 class="card-title text-center mb-4">Login</h3><form method="post"><div class="mb-3"><label for="email" class="form-label">Email address</label><input type="email" class="form-control" name="email" id="email" required></div><div class="mb-3"><label for="password" class="form-label">Password</label><input type="password" class="form-control" name="password" id="password" required></div><div class="d-grid"><button type="submit" class="btn btn-primary">Login</button></div></form></div></div></div></div>{% endblock %}""",
        'force_credential_change.html': """{% extends 'base.html' %}{% block content %}<div class="row justify-content-center"><div class="col-md-6"><div class="card shadow-sm"><div class="card-body"><h3>Mandatory Credential Change</h3><p class="text-muted">For security, you must change the default administrator login ID and password before you can proceed.</p><form method="post"><div class="mb-3"><label class="form-label">New Email (Login ID)</label><input type="email" name="new_email" class="form-control" required></div><div class="mb-3"><label class="form-label">New Password</label><input type="password" name="new_password" class="form-control" required></div><div class="mb-3"><label class="form-label">Confirm New Password</label><input type="password" name="confirm_password" class="form-control" required></div><button type="submit" class="btn btn-primary">Set New Credentials</button></form></div></div></div></div>{% endblock %}""",
        'index.html': """{% extends 'base.html' %}{% block content %}{% if current_user.role == 'admin' %}<h2>Super Admin Dashboard</h2><a class="btn btn-primary mb-3" href="{{ url_for('create_college') }}">Create College</a> <a class="btn btn-success mb-3" href="{{ url_for('register_college_admin') }}">Register College Admin</a><h4>Colleges</h4><ul class="list-group">{% for c in colleges %}<li class="list-group-item d-flex justify-content-between align-items-center">{{ c.name }}<form method="post" action="{{ url_for('delete_college', college_id=c.id) }}" onsubmit="return confirm('DELETE COLLEGE? This is irreversible.');"><button type="submit" class="btn btn-sm btn-danger">Remove</button></form></li>{% else %}<li class="list-group-item">No colleges created yet.</li>{% endfor %}</ul>{% elif current_user.role == 'college_admin' %}<h2>{{ current_user.college.name }} Admin Dashboard</h2><a class="btn btn-primary mb-3" href="{{ url_for('create_department') }}">Add Department</a> <a class="btn btn-success mb-3" href="{{ url_for('register_teacher') }}">Register Teacher</a><h4>Departments</h4><ul class="list-group">{% for dept in departments %}<li class="list-group-item d-flex justify-content-between align-items-center">{{ dept.name }}<a class="btn btn-sm btn-outline-secondary" href="{{ url_for('manage_department', department_id=dept.id) }}">Manage</a></li>{% else %}<li class="list-group-item">No departments in your college.</li>{% endfor %}</ul>{% elif current_user.role == 'teacher' %}<h2>{{ current_user.college.name }} Teacher Dashboard</h2><p>You are assigned to the <strong>{{ current_user.department.name }}</strong> department.</p><p>Select a class below to manage.</p><ul class="list-group">{% for cl in classes %}<li class="list-group-item d-flex justify-content-between align-items-center">{{ cl.name }}<a class="btn btn-sm btn-outline-secondary" href="{{ url_for('manage_class', class_id=cl.id) }}">Open</a></li>{% else %}<li class="list-group-item">You are not assigned to any classes yet.</li>{% endfor %}</ul>{% endif %}{% endblock %}""",
        'create_college.html': """{% extends 'base.html' %}{% block content %}<h3>Create College</h3><form method="post"><div class="mb-3"><input class="form-control" name="name" placeholder="College name" required></div><button class="btn btn-success">Create</button></form>{% endblock %}""",
        'register_college_admin.html': """{% extends 'base.html' %}{% block content %}<h3>Register New College Admin</h3><form method="post"><div class="mb-3"><label class="form-label">Admin's Name</label><input class="form-control" name="name" required></div><div class="mb-3"><label class="form-label">Admin's Email</label><input type="email" class="form-control" name="email" required></div><div class="mb-3"><label class="form-label">Password</label><input type="password" class="form-control" name="password" required></div><div class="mb-3"><label class="form-label">Assign to College</label><select name="college_id" class="form-select" required><option value="">-- Select College --</option>{% for college in colleges %}<option value="{{ college.id }}">{{ college.name }}</option>{% endfor %}</select></div><button type="submit" class="btn btn-success">Register Admin</button></form>{% endblock %}""",
        'register_teacher.html': """{% extends 'base.html' %}{% block content %}<h3>Register New Teacher in {{ current_user.college.name }}</h3><form method="post"><div class="mb-3"><label class="form-label">Teacher's Name</label><input class="form-control" name="name" required></div><div class="mb-3"><label class="form-label">Teacher's Email</label><input type="email" class="form-control" name="email" required></div><div class="mb-3"><label class="form-label">Password</label><input type="password" class="form-control" name="password" required></div><div class="mb-3"><label class="form-label">Assign to Department</label><select name="department_id" class="form-select" required><option value="">-- Select Department --</option>{% for dept in departments %}<option value="{{ dept.id }}">{{ dept.name }}</option>{% endfor %}</select></div><button type="submit" class="btn btn-success">Register Teacher</button></form>{% endblock %}""",
        'create_department.html': """{% extends 'base.html' %}{% block content %}<h3>Create Department in {{ current_user.college.name }}</h3><form method="post"><div class="mb-3"><input class="form-control" name="name" placeholder="Department name" required></div><button type="submit" class="btn btn-success">Create</button></form>{% endblock %}""",
        'manage_department.html': """{% extends 'base.html' %}{% block content %}<h3>Department: {{ department.name }}</h3><a class="btn btn-primary mb-2" href="{{ url_for('create_class', department_id=department.id) }}">Add Class</a><ul class="list-group">{% for cl in department.classes %}<li class="list-group-item d-flex justify-content-between align-items-center">{{ cl.name }} <small class="text-muted">— Teacher: {{ cl.teacher.name if cl.teacher else 'N/A' }}</small><div><a class="btn btn-sm btn-outline-secondary" href="{{ url_for('manage_class', class_id=cl.id) }}">Open</a></div></li>{% else %}<li class="list-group-item">No classes yet.</li>{% endfor %}</ul>{% endblock %}""",
        'create_class.html': """{% extends 'base.html' %}{% block content %}<h3>Create Class in {{ department.name }}</h3><form method="post"><div class="mb-3"><input class="form-control" name="name" placeholder="Class name" required></div><div class="mb-3"><label class="form-label">Assign Teacher</label><select name="teacher_id" class="form-select"><option value="">-- Unassigned --</option>{% for teacher in teachers %}<option value="{{ teacher.id }}">{{ teacher.name }}</option>{% endfor %}</select></div><button type="submit" class="btn btn-success">Create</button></form>{% endblock %}""",
        'manage_class.html': """{% extends 'base.html' %}{% block content %}<h3>Class: {{ cl.name }}</h3>{% if cl.teacher %}<p>Teacher: <strong>{{ cl.teacher.name }}</strong></p>{% endif %}<a class="btn btn-primary mb-2" href="{{ url_for('add_student', class_id=cl.id) }}">Add Students</a> <a class="btn btn-secondary mb-2" href="{{ url_for('attendance_panel', class_id=cl.id) }}">Open Attendance Panel</a> <a class="btn btn-info mb-2" href="{{ url_for('class_report', class_id=cl.id) }}">View Report</a><h5>Students</h5><ul class="list-group">{% for s in cl.students %}<li class="list-group-item d-flex justify-content-between align-items-center">{{ s.name }}<form method="post" action="{{ url_for('delete_student', student_id=s.id) }}" onsubmit="return confirm('Remove student?');"><button type="submit" class="btn btn-sm btn-outline-danger">Remove</button></form></li>{% else %}<li class="list-group-item">No students yet.</li>{% endfor %}</ul>{% endblock %}""",
        'add_student.html': """{% extends 'base.html' %}{% block content %}<h3>Add Students to {{ cl.name }}</h3><form method="post"><div class="mb-3"><input class="form-control" name="name" placeholder="Student full name"></div><div class="mb-3"><input class="form-control" name="enroll" placeholder="Enrollment no (optional)"></div><button type="submit" name="submit_manual" class="btn btn-success">Add Manually</button></form><hr><h5>Or Upload a File</h5><p>Upload a CSV or Excel file with columns: <code>name, enrollment_no</code></p><form method="post" enctype="multipart/form-data"><input type="file" name="file" class="form-control"><button type="submit" name="submit_file" class="btn btn-primary mt-2">Upload File</button></form>{% endblock %}""",
        'attendance_panel.html': """{% extends 'base.html' %}{% block content %}<h3>Attendance — {{ cl.name }} — {{ date }}</h3><form method="post"><table class="table"><thead><tr><th>Name</th><th>Present</th></tr></thead><tbody>{% for s in cl.students %}<tr><td>{{ s.name }}</td><td><input type="checkbox" name="present_{{ s.id }}" value="1" class="form-check-input" checked></td></tr>{% endfor %}</tbody></table><button class="btn btn-success">Save Attendance</button></form>{% endblock %}""",
        'class_report.html': """{% extends 'base.html' %}{% block content %}<h3>Attendance Report for {{ cl.name }}</h3><p>Total attendance days recorded: <strong>{{ report.total_days }}</strong></p><a class="btn btn-success mb-3" href="{{ url_for('export_class_report', class_id=cl.id) }}">Export Full Report (CSV)</a><table class="table table-striped"><thead><tr><th>Student Name</th><th>Enrollment No.</th><th>Days Attended</th><th>Attendance %%</th></tr></thead><tbody>{% for student_stat in report.student_stats %}<tr><td>{{ student_stat.name }}</td><td>{{ student_stat.enrollment_no or 'N/A' }}</td><td>{{ student_stat.days_attended }}</td><td>{{ "%.2f"|format(student_stat.percentage) }}%%</td></tr>{% else %}<tr><td colspan="4" class="text-center">No attendance records found for this class.</td></tr>{% endfor %}</tbody></table>{% endblock %}"""
    }
    for fname, content in files.items():
        path = os.path.join(BASE_DIR, 'templates', fname)
        if not os.path.exists(path):
            with open(path, 'w', encoding='utf-8') as f: f.write(content)

# --- App Initialization Block ---
# This block runs when the app is imported by Gunicorn on the server
with app.app_context():
    ensure_templates()
    db.create_all()
    # Create a default admin user if one doesn't exist
    if not User.query.filter_by(email='admin@example.com').first():
        print("Creating default admin user...")
        admin = User(name="Super Admin", email="admin@example.com", role='admin')
        admin.set_password("admin123")
        db.session.add(admin)
        db.session.commit()
        print("--- Default Admin Credentials ---")
        print("  Email: admin@example.com")
        print("  Password: admin123")
        print("---------------------------------")

# ----------------------
# Auth & Registration Routes
# ----------------------
@app.before_request
def check_force_credential_change():
    if (current_user.is_authenticated and
            current_user.role == 'admin' and
            current_user.email == 'admin@example.com' and
            current_user.check_password('admin123') and
            request.endpoint not in ('force_credential_change', 'logout', 'static')):
        return redirect(url_for('force_credential_change'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated: return redirect(url_for('index'))
    if request.method == 'POST':
        user = User.query.filter_by(email=request.form['email']).first()
        if user is None or not user.check_password(request.form['password']):
            flash('Invalid email or password', 'danger')
            return redirect(url_for('login'))
        login_user(user, remember=True)
        if user.role == 'admin' and user.email == 'admin@example.com' and user.check_password('admin123'):
            flash('For security, you must change the default administrator credentials.', 'warning')
            return redirect(url_for('force_credential_change'))
        return redirect(url_for('index'))
    return render_template('login.html')

@app.route('/force-credential-change', methods=['GET', 'POST'])
@login_required
def force_credential_change():
    if request.method == 'POST':
        new_email = request.form.get('new_email').strip()
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')
        if new_password != confirm_password:
            flash('New passwords do not match.', 'danger')
            return redirect(url_for('force_credential_change'))
        existing_user = User.query.filter(User.email == new_email, User.id != current_user.id).first()
        if existing_user:
            flash('That email address is already in use by another account.', 'danger')
            return redirect(url_for('force_credential_change'))
        current_user.email = new_email
        current_user.set_password(new_password)
        db.session.commit()
        flash('Credentials updated successfully! You can now use the system.', 'success')
        return redirect(url_for('index'))
    return render_template('force_credential_change.html')

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/register-college-admin', methods=['GET', 'POST'])
@login_required
def register_college_admin():
    if current_user.role != 'admin': abort(403)
    if request.method == 'POST':
        if User.query.filter_by(email=request.form['email']).first():
            flash('Email address already registered.', 'warning')
            return redirect(request.url)
        new_admin = User(name=request.form['name'], email=request.form['email'], college_id=request.form['college_id'], role='college_admin')
        new_admin.set_password(request.form['password'])
        db.session.add(new_admin)
        db.session.commit()
        flash('College Admin registered successfully!', 'success')
        return redirect(url_for('index'))
    return render_template('register_college_admin.html', colleges=College.query.all())

@app.route('/register-teacher', methods=['GET', 'POST'])
@login_required
def register_teacher():
    if current_user.role != 'college_admin': abort(403)
    if request.method == 'POST':
        if User.query.filter_by(email=request.form['email']).first():
            flash('Email address already registered.', 'warning')
            return redirect(request.url)
        new_teacher = User(name=request.form.get('name'), email=request.form.get('email'), college_id=current_user.college_id, department_id=request.form.get('department_id'), role='teacher')
        new_teacher.set_password(request.form.get('password'))
        db.session.add(new_teacher)
        db.session.commit()
        flash('Teacher registered successfully!', 'success')
        return redirect(url_for('index'))
    departments = Department.query.filter_by(college_id=current_user.college_id).all()
    return render_template('register_teacher.html', departments=departments)

# ----------------------
# Main App Routes
# ----------------------
@app.route('/')
@login_required
def index():
    if current_user.role == 'admin':
        return render_template('index.html', colleges=College.query.order_by(College.name).all())
    if current_user.role == 'college_admin':
        return render_template('index.html', departments=Department.query.filter_by(college_id=current_user.college_id).all())
    if current_user.role == 'teacher':
        return render_template('index.html', classes=ClassRoom.query.filter_by(teacher_id=current_user.id).all())
    return "Invalid Role", 403

@app.route('/college/create', methods=['GET', 'POST'])
@login_required
def create_college():
    if current_user.role != 'admin': abort(403)
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        if not College.query.filter_by(name=name).first():
            db.session.add(College(name=name))
            db.session.commit()
            flash('College created', 'success')
        else: flash('College already exists', 'warning')
        return redirect(url_for('index'))
    return render_template('create_college.html')

@app.route('/college/<int:college_id>/delete', methods=['POST'])
@login_required
def delete_college(college_id):
    if current_user.role != 'admin': abort(403)
    db.session.delete(db.session.get(College, college_id))
    db.session.commit()
    flash('College removed.', 'success')
    return redirect(url_for('index'))

@app.route('/department/create', methods=['GET', 'POST'])
@login_required
def create_department():
    if current_user.role != 'college_admin': abort(403)
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        db.session.add(Department(name=name, college_id=current_user.college_id))
        db.session.commit()
        flash('Department created', 'success')
        return redirect(url_for('index'))
    return render_template('create_department.html')

@app.route('/department/<int:department_id>/manage')
@login_required
def manage_department(department_id):
    department = db.session.get(Department, department_id)
    if current_user.college_id != department.college_id: abort(403)
    return render_template('manage_department.html', department=department)

@app.route('/department/<int:department_id>/class/create', methods=['GET', 'POST'])
@login_required
def create_class(department_id):
    department = db.session.get(Department, department_id)
    if current_user.college_id != department.college_id: abort(403)
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        cl = ClassRoom(name=name, department=department, teacher_id=request.form.get('teacher_id'))
        db.session.add(cl)
        db.session.commit()
        flash('Class created', 'success')
        return redirect(url_for('manage_department', department_id=department_id))
    teachers = User.query.filter_by(department_id=department.id, role='teacher').all()
    return render_template('create_class.html', department=department, teachers=teachers)

@app.route('/class/<int:class_id>/manage')
@login_required
def manage_class(class_id):
    cl = db.session.get(ClassRoom, class_id)
    if current_user.college_id != cl.department.college_id: abort(403)
    return render_template('manage_class.html', cl=cl)

@app.route('/class/<int:class_id>/students/add', methods=['GET', 'POST'])
@login_required
def add_student(class_id):
    cl = db.session.get(ClassRoom, class_id)
    if current_user.college_id != cl.department.college_id: abort(403)
    if request.method == 'POST':
        if 'submit_file' in request.form:
            if 'file' not in request.files or request.files['file'].filename == '':
                flash('No file selected for upload.', 'warning')
                return redirect(request.url)
            file = request.files['file']
            if file and allowed_file(file.filename):
                try:
                    if file.filename.endswith('.csv'):
                        df = pd.read_csv(file.stream)
                    else:
                        df = pd.read_excel(file.stream)
                    df.columns = [c.lower().strip().replace(' ', '_') for c in df.columns]
                    added_count = 0
                    for index, row in df.iterrows():
                        name = row.get('name')
                        enroll = row.get('enrollment_no')
                        if pd.notna(name):
                            student = Student(name=str(name), enrollment_no=str(enroll) if pd.notna(enroll) else None, classroom=cl)
                            db.session.add(student)
                            added_count += 1
                    db.session.commit()
                    flash(f'Successfully added {added_count} students from file.', 'success')
                except Exception as e:
                    db.session.rollback()
                    flash(f'Error processing file: {e}', 'danger')
                return redirect(url_for('manage_class', class_id=class_id))
            else:
                flash('Invalid file type. Please upload a CSV or Excel file.', 'danger')
                return redirect(request.url)
        elif 'submit_manual' in request.form:
            name = request.form.get('name', '').strip()
            if name:
                enroll = request.form.get('enroll', '').strip() or None
                db.session.add(Student(name=name, enrollment_no=enroll, classroom=cl))
                db.session.commit()
                flash('Student added manually.', 'success')
            else:
                flash('Please enter a name for the student.', 'warning')
            return redirect(url_for('manage_class', class_id=class_id))
    return render_template('add_student.html', cl=cl)

@app.route('/student/<int:student_id>/delete', methods=['POST'])
@login_required
def delete_student(student_id):
    student = db.session.get(Student, student_id)
    class_id = student.class_id
    cl = db.session.get(ClassRoom, class_id)
    if current_user.college_id != cl.department.college_id: abort(403)
    db.session.delete(student)
    db.session.commit()
    flash(f'Student "{student.name}" removed.', 'success')
    return redirect(url_for('manage_class', class_id=class_id))

@app.route('/class/<int:class_id>/attendance', methods=['GET', 'POST'])
@login_required
def attendance_panel(class_id):
    cl = db.session.get(ClassRoom, class_id)
    if current_user.college_id != cl.department.college_id: abort(403)
    attendance_date = date.today()
    if request.method == 'POST':
        for s in cl.students:
            status = 'present' if request.form.get(f'present_{s.id}') else 'absent'
            existing = Attendance.query.filter_by(student_id=s.id, date=attendance_date).first()
            if existing: existing.status = status
            else: db.session.add(Attendance(student_id=s.id, date=attendance_date, status=status))
        db.session.commit()
        flash('Attendance saved for today!', 'success')
        return redirect(url_for('manage_class', class_id=class_id))
    return render_template('attendance_panel.html', cl=cl, date=attendance_date.isoformat())

# --- Reporting Routes ---
def calculate_class_report(class_id):
    total_days = db.session.query(Attendance.date).join(Student).filter(Student.class_id == class_id).distinct().count()
    student_stats = []
    cl = db.session.get(ClassRoom, class_id)
    for student in cl.students:
        days_attended = Attendance.query.filter_by(student_id=student.id, status='present').count()
        percentage = (days_attended / total_days * 100) if total_days > 0 else 0
        student_stats.append({
            'name': student.name,
            'enrollment_no': student.enrollment_no,
            'days_attended': days_attended,
            'percentage': percentage
        })
    sorted_stats = sorted(student_stats, key=lambda x: x['name'])
    return {'total_days': total_days, 'student_stats': sorted_stats}

@app.route('/class/<int:class_id>/report')
@login_required
def class_report(class_id):
    cl = db.session.get(ClassRoom, class_id)
    if current_user.college_id != cl.department.college_id: abort(403)
    report_data = calculate_class_report(class_id)
    return render_template('class_report.html', cl=cl, report=report_data)

@app.route('/class/<int:class_id>/report/export')
@login_required
def export_class_report(class_id):
    cl = db.session.get(ClassRoom, class_id)
    if current_user.college_id != cl.department.college_id: abort(403)
    report_data = calculate_class_report(class_id)
    si = StringIO()
    writer = csv.writer(si)
    writer.writerow(['Student Name', 'Enrollment No', 'Total Attendance Days', 'Days Attended', 'Attendance Percentage'])
    for stat in report_data['student_stats']:
        writer.writerow([
            stat['name'],
            stat['enrollment_no'],
            report_data['total_days'],
            stat['days_attended'],
            f"{stat['percentage']:.2f}%"
        ])
    output = si.getvalue().encode('utf-8')
    return send_file(
        BytesIO(output),
        mimetype='text/csv',
        as_attachment=True,
        download_name=f'attendance_report_{cl.name}.csv'
    )
    
# ----------------------
# Run (for local development only)
# ----------------------
if __name__ == '__main__':
    app.run(debug=True)

