"""
AMS Flask Starter - app.py (Final Version for Packaged Executable)
"""
import os
import sys
import csv
import webbrowser
from threading import Timer
from io import StringIO, BytesIO
from datetime import date
import pandas as pd
from flask import (Flask, render_template, request, redirect, url_for, flash, abort, send_file)
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import (LoginManager, UserMixin, login_user, logout_user,
                         login_required, current_user)

# --- App Setup ---
# This smart path detection is crucial for the packaged executable
if getattr(sys, 'frozen', False):
    # If running as a bundled executable, the base is a temporary folder
    # Flask needs to know where to find the templates, which PyInstaller will unpack.
    template_folder = os.path.join(sys._MEIPASS, 'templates')
    app = Flask(__name__, template_folder=template_folder)
    BASE_DIR = os.path.dirname(sys.executable) # For the database file
else:
    # If running as a normal script, use the script's directory
    BASE_DIR = os.path.abspath(os.path.dirname(__file__))
    app = Flask(__name__)

app.config['SECRET_KEY'] = 'a-very-secret-key-that-is-long-and-secure-for-offline'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(BASE_DIR, 'ams.db')
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
# Helpers
# ----------------------
def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in {'csv', 'xlsx', 'xls'}

# --- App Initialization Block ---
with app.app_context():
    db.create_all()
    if not User.query.filter_by(email='admin@example.com').first():
        print("Creating default admin user...")
        admin = User(name="Super Admin", email="admin@example.com", role='admin')
        admin.set_password("admin123")
        db.session.add(admin)
        db.session.commit()

# --- All Routes ---
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
    return render_template('manage_class.html', cl=cl, today=date.today().isoformat())

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
    
    date_str = request.args.get('date', date.today().isoformat())
    try:
        attendance_date = date.fromisoformat(date_str)
    except ValueError:
        flash('Invalid date format.', 'danger')
        return redirect(url_for('manage_class', class_id=class_id))

    if request.method == 'POST':
        for s in cl.students:
            status = 'present' if request.form.get(f'present_{s.id}') else 'absent'
            existing = Attendance.query.filter_by(student_id=s.id, date=attendance_date).first()
            if existing: existing.status = status
            else: db.session.add(Attendance(student_id=s.id, date=attendance_date, status=status))
        db.session.commit()
        flash(f'Attendance for {attendance_date.isoformat()} saved successfully!', 'success')
        return redirect(url_for('manage_class', class_id=class_id))

    students_with_status = []
    for student in cl.students:
        record = Attendance.query.filter_by(student_id=student.id, date=attendance_date).first()
        is_present = record and record.status == 'present'
        students_with_status.append((student, is_present))
        
    return render_template('attendance_panel.html', cl=cl, date=attendance_date.isoformat(), students_with_status=students_with_status)

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
    
# --- Run (for local development and executable) ---
def open_browser():
    webbrowser.open_new("http://127.0.0.1:5000")

if __name__ == '__main__':
    if getattr(sys, 'frozen', False):
        Timer(1, open_browser).start()
    
    app.run(host='0.0.0.0', port=5000)

