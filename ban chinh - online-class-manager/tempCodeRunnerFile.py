from flask import Flask, render_template, request, jsonify, redirect, url_for, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from flask_bcrypt import Bcrypt
from flask_cors import CORS
from datetime import datetime, timedelta
import os
import json

app = Flask(__name__)
app.config['SECRET_KEY'] = 'online-class-manager-secret-key-2025'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///online_class_manager.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = 'jwt-secret-key-2025'
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=24)
app.config['UPLOAD_FOLDER'] = 'uploads'

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)
CORS(app)

# Tạo thư mục upload nếu chưa tồn tại
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# ==================== DATABASE MODELS ====================

class User(db.Model):
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), nullable=False)
    full_name = db.Column(db.String(100), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def to_dict(self):
        return {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            'role': self.role,
            'full_name': self.full_name,
            'created_at': self.created_at.isoformat()
        }

class Class(db.Model):
    __tablename__ = 'classes'
    
    id = db.Column(db.Integer, primary_key=True)
    class_name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    schedule = db.Column(db.String(100))
    teacher_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    teacher = db.relationship('User', backref=db.backref('classes_taught', lazy=True))

    def to_dict(self):
        return {
            'id': self.id,
            'class_name': self.class_name,
            'description': self.description,
            'schedule': self.schedule,
            'teacher_id': self.teacher_id,
            'teacher_name': self.teacher.full_name,
            'created_at': self.created_at.isoformat()
        }

class ClassMember(db.Model):
    __tablename__ = 'class_members'
    
    id = db.Column(db.Integer, primary_key=True)
    class_id = db.Column(db.Integer, db.ForeignKey('classes.id'), nullable=False)
    student_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    joined_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    class_rel = db.relationship('Class', backref=db.backref('members', lazy=True))
    student = db.relationship('User', backref=db.backref('classes_joined', lazy=True))

class Assignment(db.Model):
    __tablename__ = 'assignments'
    
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    due_date = db.Column(db.DateTime)
    class_id = db.Column(db.Integer, db.ForeignKey('classes.id'), nullable=False)
    teacher_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    class_rel = db.relationship('Class', backref=db.backref('assignments', lazy=True))
    teacher = db.relationship('User', backref=db.backref('assignments_created', lazy=True))

    def to_dict(self):
        return {
            'id': self.id,
            'title': self.title,
            'description': self.description,
            'due_date': self.due_date.isoformat() if self.due_date else None,
            'class_id': self.class_id,
            'teacher_id': self.teacher_id,
            'created_at': self.created_at.isoformat()
        }

class Attendance(db.Model):
    """Model đại diện cho điểm danh"""
    __tablename__ = 'attendances'
    
    id = db.Column(db.Integer, primary_key=True)
    class_id = db.Column(db.Integer, db.ForeignKey('classes.id'), nullable=False)
    student_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    date = db.Column(db.Date, nullable=False)
    status = db.Column(db.String(20), default='present')  # present, absent, late
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    class_rel = db.relationship('Class', backref=db.backref('attendances', lazy=True))
    student = db.relationship('User', backref=db.backref('attendances', lazy=True))

    def to_dict(self):
        return {
            'id': self.id,
            'class_id': self.class_id,
            'student_id': self.student_id,
            'student_name': self.student.full_name,
            'date': self.date.isoformat(),
            'status': self.status,
            'created_at': self.created_at.isoformat()
        }

# ==================== ROUTES ====================

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user = User.query.filter_by(username=username).first()
        
        if user and bcrypt.check_password_hash(user.password, password):
            # Create JWT token
            access_token = create_access_token(
                identity={
                    'user_id': user.id,
                    'username': user.username, 
                    'role': user.role
                }
            )
            
            # Store token in localStorage via JavaScript
            response = redirect(url_for('dashboard'))
            return response
        else:
            return render_template('login.html', error='Tên đăng nhập hoặc mật khẩu không đúng')
    
    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    return render_template('dashboard.html')

@app.route('/classes')
def classes_page():
    return render_template('classes.html')

@app.route('/class_detail')
def class_detail():
    return render_template('class_detail.html')

@app.route('/logout')
def logout():
    response = redirect(url_for('login'))
    response.set_cookie('access_token', '', expires=0)
    return response

# ==================== API ROUTES ====================

@app.route('/api/auth/login', methods=['POST'])
def api_login():
    try:
        data = request.get_json()
        
        if not data or 'username' not in data or 'password' not in data:
            return jsonify({'error': 'Username and password are required'}), 400
        
        user = User.query.filter_by(username=data['username']).first()
        
        if user and bcrypt.check_password_hash(user.password, data['password']):
            access_token = create_access_token(
                identity={
                    'user_id': user.id,
                    'username': user.username,
                    'role': user.role
                }
            )
            return jsonify({
                'message': 'Login successful',
                'token': access_token,
                'user': user.to_dict()
            })
        
        return jsonify({'error': 'Invalid credentials'}), 401
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/auth/register', methods=['POST'])
def register():
    try:
        data = request.get_json()
        
        required_fields = ['username', 'email', 'password', 'role', 'full_name']
        for field in required_fields:
            if field not in data or not data[field].strip():
                return jsonify({'error': f'Field {field} is required'}), 400
        
        if User.query.filter_by(username=data['username']).first():
            return jsonify({'error': 'Username already exists'}), 400
        
        if User.query.filter_by(email=data['email']).first():
            return jsonify({'error': 'Email already exists'}), 400
        
        if data['role'] not in ['teacher', 'student']:
            return jsonify({'error': 'Role must be either teacher or student'}), 400
        
        hashed_password = bcrypt.generate_password_hash(data['password']).decode('utf-8')
        user = User(
            username=data['username'],
            email=data['email'],
            password=hashed_password,
            role=data['role'],
            full_name=data['full_name']
        )
        
        db.session.add(user)
        db.session.commit()
        
        return jsonify({
            'message': 'User created successfully',
            'user': user.to_dict()
        }), 201
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/classes', methods=['GET'])
@jwt_required()
def get_classes():
    try:
        current_user = get_jwt_identity()
        user_id = current_user['user_id']
        role = current_user['role']
        
        if role == 'teacher':
            classes = Class.query.filter_by(teacher_id=user_id).all()
        else:
            class_memberships = ClassMember.query.filter_by(student_id=user_id).all()
            classes = [cm.class_rel for cm in class_memberships]
        
        return jsonify([class_obj.to_dict() for class_obj in classes])
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/classes', methods=['POST'])
@jwt_required()
def create_class():
    try:
        current_user = get_jwt_identity()
        
        if current_user['role'] != 'teacher':
            return jsonify({'error': 'Only teachers can create classes'}), 403
        
        data = request.get_json()
        
        if not data.get('class_name'):
            return jsonify({'error': 'Class name is required'}), 400
        
        new_class = Class(
            class_name=data['class_name'],
            description=data.get('description', ''),
            schedule=data.get('schedule', ''),
            teacher_id=current_user['user_id']
        )
        
        db.session.add(new_class)
        db.session.commit()
        
        return jsonify({
            'message': 'Class created successfully',
            'class': new_class.to_dict()
        }), 201
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/classes/<int:class_id>', methods=['GET'])
@jwt_required()
def get_class_detail(class_id):
    """Lấy thông tin chi tiết lớp học"""
    try:
        class_obj = Class.query.get_or_404(class_id)
        
        # Lấy danh sách học sinh trong lớp
        members = ClassMember.query.filter_by(class_id=class_id).all()
        students = [{
            'id': member.student.id,
            'username': member.student.username,
            'full_name': member.student.full_name,
            'email': member.student.email
        } for member in members]
        
        # Lấy số lượng bài tập
        assignments_count = Assignment.query.filter_by(class_id=class_id).count()
        
        class_data = class_obj.to_dict()
        class_data['students'] = students
        class_data['assignments_count'] = assignments_count
        class_data['students_count'] = len(students)
        
        return jsonify(class_data)
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/classes/<int:class_id>/students', methods=['POST'])
@jwt_required()
def add_student_to_class(class_id):
    """Thêm học sinh vào lớp học"""
    try:
        current_user = get_jwt_identity()
        
        # Chỉ giáo viên mới được thêm học sinh
        if current_user['role'] != 'teacher':
            return jsonify({'error': 'Only teachers can add students'}), 403
        
        data = request.get_json()
        student_username = data.get('username')
        
        if not student_username:
            return jsonify({'error': 'Student username is required'}), 400
        
        # Tìm học sinh
        student = User.query.filter_by(username=student_username, role='student').first()
        if not student:
            return jsonify({'error': 'Student not found'}), 404
        
        # Kiểm tra học sinh đã trong lớp chưa
        existing_member = ClassMember.query.filter_by(
            class_id=class_id, 
            student_id=student.id
        ).first()
        
        if existing_member:
            return jsonify({'error': 'Student already in class'}), 400
        
        # Thêm học sinh vào lớp
        new_member = ClassMember(
            class_id=class_id,
            student_id=student.id
        )
        
        db.session.add(new_member)
        db.session.commit()
        
        return jsonify({
            'message': 'Student added to class successfully',
            'student': {
                'id': student.id,
                'username': student.username,
                'full_name': student.full_name
            }
        }), 201
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/classes/<int:class_id>/students/<int:student_id>', methods=['DELETE'])
@jwt_required()
def remove_student_from_class(class_id, student_id):
    """Xóa học sinh khỏi lớp học"""
    try:
        current_user = get_jwt_identity()
        
        if current_user['role'] != 'teacher':
            return jsonify({'error': 'Only teachers can remove students'}), 403
        
        # Tìm và xóa thành viên
        class_member = ClassMember.query.filter_by(
            class_id=class_id, 
            student_id=student_id
        ).first()
        
        if not class_member:
            return jsonify({'error': 'Student not found in class'}), 404
        
        db.session.delete(class_member)
        db.session.commit()
        
        return jsonify({'message': 'Student removed from class successfully'})
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/classes/<int:class_id>/assignments', methods=['GET'])
@jwt_required()
def get_assignments(class_id):
    try:
        assignments = Assignment.query.filter_by(class_id=class_id).all()
        return jsonify([assignment.to_dict() for assignment in assignments])
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/classes/<int:class_id>/assignments', methods=['POST'])
@jwt_required()
def create_assignment(class_id):
    try:
        current_user = get_jwt_identity()
        
        if current_user['role'] != 'teacher':
            return jsonify({'error': 'Only teachers can create assignments'}), 403
        
        class_obj = Class.query.get_or_404(class_id)
        if class_obj.teacher_id != current_user['user_id']:
            return jsonify({'error': 'Unauthorized to create assignments for this class'}), 403
        
        data = request.get_json()
        
        if not data.get('title'):
            return jsonify({'error': 'Assignment title is required'}), 400
        
        due_date = None
        if data.get('due_date'):
            due_date = datetime.fromisoformat(data['due_date'].replace('Z', '+00:00'))
        
        new_assignment = Assignment(
            title=data['title'],
            description=data.get('description', ''),
            due_date=due_date,
            class_id=class_id,
            teacher_id=current_user['user_id']
        )
        
        db.session.add(new_assignment)
        db.session.commit()
        
        return jsonify({
            'message': 'Assignment created successfully',
            'assignment': new_assignment.to_dict()
        }), 201
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/classes/<int:class_id>/attendance', methods=['POST'])
@jwt_required()
def mark_attendance(class_id):
    """Điểm danh học sinh"""
    try:
        current_user = get_jwt_identity()
        
        if current_user['role'] != 'teacher':
            return jsonify({'error': 'Only teachers can mark attendance'}), 403
        
        data = request.get_json()
        date_str = data.get('date')
        attendance_data = data.get('attendance', [])
        
        if not date_str or not attendance_data:
            return jsonify({'error': 'Date and attendance data are required'}), 400
        
        date = datetime.fromisoformat(date_str).date()
        
        # Điểm danh cho từng học sinh
        for record in attendance_data:
            student_id = record.get('student_id')
            status = record.get('status', 'present')
            
            # Kiểm tra xem điểm danh đã tồn tại chưa
            existing_attendance = Attendance.query.filter_by(
                class_id=class_id,
                student_id=student_id,
                date=date
            ).first()
            
            if existing_attendance:
                # Cập nhật điểm danh hiện có
                existing_attendance.status = status
            else:
                # Tạo điểm danh mới
                new_attendance = Attendance(
                    class_id=class_id,
                    student_id=student_id,
                    date=date,
                    status=status
                )
                db.session.add(new_attendance)
        
        db.session.commit()
        
        return jsonify({'message': 'Attendance marked successfully'})
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/classes/<int:class_id>/attendance', methods=['GET'])
@jwt_required()
def get_attendance(class_id):
    """Lấy lịch sử điểm danh của lớp học"""
    try:
        date_str = request.args.get('date')
        
        if date_str:
            # Lấy điểm danh theo ngày cụ thể
            date = datetime.fromisoformat(date_str).date()
            attendances = Attendance.query.filter_by(
                class_id=class_id, 
                date=date
            ).all()
        else:
            # Lấy tất cả điểm danh
            attendances = Attendance.query.filter_by(class_id=class_id).all()
        
        return jsonify([attendance.to_dict() for attendance in attendances])
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/classes/<int:class_id>/attendance/report', methods=['GET'])
@jwt_required()
def get_attendance_report(class_id):
    """Lấy báo cáo điểm danh"""
    try:
        # Lấy tất cả học sinh trong lớp
        members = ClassMember.query.filter_by(class_id=class_id).all()
        students = [member.student for member in members]
        
        # Lấy tất cả điểm danh
        attendances = Attendance.query.filter_by(class_id=class_id).all()
        
        # Tính toán thống kê
        report = []
        for student in students:
            student_attendances = [a for a in attendances if a.student_id == student.id]
            
            present_count = len([a for a in student_attendances if a.status == 'present'])
            absent_count = len([a for a in student_attendances if a.status == 'absent'])
            late_count = len([a for a in student_attendances if a.status == 'late'])
            total_count = len(student_attendances)
            
            attendance_rate = (present_count / total_count * 100) if total_count > 0 else 0
            
            report.append({
                'student_id': student.id,
                'student_name': student.full_name,
                'present_count': present_count,
                'absent_count': absent_count,
                'late_count': late_count,
                'total_count': total_count,
                'attendance_rate': round(attendance_rate, 2)
            })
        
        return jsonify(report)
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/assignments/<int:assignment_id>', methods=['DELETE'])
@jwt_required()
def delete_assignment(assignment_id):
    """Xóa bài tập"""
    try:
        current_user = get_jwt_identity()
        assignment = Assignment.query.get_or_404(assignment_id)
        
        # Chỉ giáo viên tạo bài tập mới được xóa
        if assignment.teacher_id != current_user['user_id']:
            return jsonify({'error': 'Unauthorized to delete this assignment'}), 403
        
        db.session.delete(assignment)
        db.session.commit()
        
        return jsonify({'message': 'Assignment deleted successfully'})
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/students', methods=['GET'])
@jwt_required()
def get_students():
    """Lấy danh sách tất cả học sinh"""
    try:
        students = User.query.filter_by(role='student').all()
        students_data = [{
            'id': student.id,
            'username': student.username,
            'full_name': student.full_name,
            'email': student.email,
            'created_at': student.created_at.isoformat()
        } for student in students]
        
        return jsonify(students_data)
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/user/profile', methods=['GET'])
@jwt_required()
def get_user_profile():
    try:
        current_user = get_jwt_identity()
        user = User.query.get(current_user['user_id'])
        
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        return jsonify(user.to_dict())
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ==================== INITIALIZATION ====================

def create_demo_data():
    """Tạo dữ liệu demo cho ứng dụng"""
    if User.query.filter_by(username='teacher1').first():
        return
    
    # Create demo teacher
    hashed_password = bcrypt.generate_password_hash('password123').decode('utf-8')
    teacher = User(
        username='teacher1',
        email='teacher1@school.edu',
        password=hashed_password,
        role='teacher',
        full_name='Nguyễn Văn A'
    )
    db.session.add(teacher)
    
    # Create demo students
    students = []
    for i in range(1, 6):
        student = User(
            username=f'student{i}',
            email=f'student{i}@school.edu',
            password=hashed_password,
            role='student',
            full_name=f'Học Sinh {i}'
        )
        students.append(student)
        db.session.add(student)
    
    db.session.commit()
    
    # Create demo class
    demo_class = Class(
        class_name='Toán 10',
        description='Lớp Toán lớp 10 cơ bản',
        schedule='T2, T4, T6 - 14:00-16:00',
        teacher_id=teacher.id
    )
    db.session.add(demo_class)
    db.session.commit()
    
    # Add students to class
    for student in students:
        class_member = ClassMember(
            class_id=demo_class.id,
            student_id=student.id
        )
        db.session.add(class_member)
    
    # Create demo assignments
    demo_assignment1 = Assignment(
        title='Bài tập chương 1: Hàm số',
        description='Làm các bài tập từ 1 đến 10 trong sách giáo khoa',
        due_date=datetime.utcnow() + timedelta(days=7),
        class_id=demo_class.id,
        teacher_id=teacher.id
    )
    db.session.add(demo_assignment1)
    
    demo_assignment2 = Assignment(
        title='Bài tập chương 2: Phương trình',
        description='Giải các phương trình trong bài tập 11-20',
        due_date=datetime.utcnow() + timedelta(days=14),
        class_id=demo_class.id,
        teacher_id=teacher.id
    )
    db.session.add(demo_assignment2)
    
    # Create demo attendance records
    today = datetime.utcnow().date()
    for student in students:
        attendance = Attendance(
            class_id=demo_class.id,
            student_id=student.id,
            date=today,
            status='present' if student.id % 3 != 0 else 'absent'
        )
        db.session.add(attendance)
    
    db.session.commit()
    print("✅ Demo data created successfully!")

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        create_demo_data()
    
    app.run(debug=True, host='0.0.0.0', port=5000)