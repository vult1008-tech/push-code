from flask import Flask, render_template, request, jsonify, redirect, url_for, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from flask_bcrypt import Bcrypt
from flask_cors import CORS
from datetime import datetime, timedelta
import os
import json
import random

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

@app.route('/students')
def students_page():
    return render_template('students.html')

@app.route('/attendance')
def attendance_page():
    return render_template('attendance.html')

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

@app.route('/api/students', methods=['POST'])
@jwt_required()
def create_student():
    """API thêm mới học sinh"""
    try:
        current_user = get_jwt_identity()
        
        # Chỉ giáo viên mới được thêm học sinh
        if current_user['role'] != 'teacher':
            return jsonify({'error': 'Only teachers can create students'}), 403
        
        data = request.get_json()
        
        required_fields = ['username', 'email', 'password', 'full_name']
        for field in required_fields:
            if field not in data or not data[field].strip():
                return jsonify({'error': f'Field {field} is required'}), 400
        
        # Kiểm tra username đã tồn tại chưa
        if User.query.filter_by(username=data['username']).first():
            return jsonify({'error': 'Username already exists'}), 400
        
        # Kiểm tra email đã tồn tại chưa
        if User.query.filter_by(email=data['email']).first():
            return jsonify({'error': 'Email already exists'}), 400
        
        hashed_password = bcrypt.generate_password_hash(data['password']).decode('utf-8')
        
        student = User(
            username=data['username'],
            email=data['email'],
            password=hashed_password,
            role='student',
            full_name=data['full_name']
        )
        
        db.session.add(student)
        db.session.commit()
        
        return jsonify({
            'message': 'Student created successfully',
            'student': student.to_dict()
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
        
        # Nếu có danh sách học sinh, thêm vào lớp
        student_ids = data.get('student_ids', [])
        for student_id in student_ids:
            # Kiểm tra xem học sinh đã trong lớp chưa
            existing_member = ClassMember.query.filter_by(
                class_id=new_class.id,
                student_id=student_id
            ).first()
            
            if not existing_member:
                class_member = ClassMember(
                    class_id=new_class.id,
                    student_id=student_id
                )
                db.session.add(class_member)
        
        db.session.commit()
        
        # Lấy thông tin lớp học sau khi tạo
        class_data = new_class.to_dict()
        
        return jsonify({
            'message': 'Class created successfully',
            'class': class_data
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
        student_id = data.get('student_id')
        
        if not student_username and not student_id:
            return jsonify({'error': 'Student username or ID is required'}), 400
        
        # Tìm học sinh
        if student_id:
            student = User.query.filter_by(id=student_id, role='student').first()
        else:
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

# ==================== ATTENDANCE API ROUTES - FIXED VERSION ====================

@app.route('/api/classes/<int:class_id>/attendance', methods=['GET'])
@jwt_required()
def get_class_attendance(class_id):
    """Lấy điểm danh theo lớp và ngày - IMPROVED VERSION"""
    try:
        date_str = request.args.get('date')
        print(f"🎯 Getting attendance for class {class_id}, date: {date_str}")
        
        # Lấy danh sách học sinh trong lớp
        members = ClassMember.query.filter_by(class_id=class_id).all()
        students = [member.student for member in members]
        
        print(f"👥 Found {len(students)} students in class")
        
        if date_str:
            date = datetime.fromisoformat(date_str).date()
            # Lấy điểm danh theo ngày cụ thể
            attendances = Attendance.query.filter_by(
                class_id=class_id, 
                date=date
            ).all()
            
            # Tạo dictionary để tra cứu nhanh
            attendance_dict = {att.student_id: att for att in attendances}
            
            # Tạo response data tương thích với frontend
            result = []
            for student in students:
                student_att = attendance_dict.get(student.id)
                result.append({
                    'id': student_att.id if student_att else None,
                    'class_id': class_id,
                    'student_id': student.id,
                    'student_name': student.full_name,
                    'date': date.isoformat(),
                    'status': student_att.status if student_att else 'absent',
                    'created_at': student_att.created_at.isoformat() if student_att else datetime.utcnow().isoformat()
                })
        else:
            # Lấy tất cả điểm danh
            attendances = Attendance.query.filter_by(class_id=class_id).all()
            result = []
            for att in attendances:
                student = User.query.get(att.student_id)
                result.append({
                    'id': att.id,
                    'class_id': att.class_id,
                    'student_id': att.student_id,
                    'student_name': student.full_name if student else 'Unknown',
                    'date': att.date.isoformat(),
                    'status': att.status,
                    'created_at': att.created_at.isoformat()
                })
        
        print(f"📊 Found {len(result)} attendance records")
        return jsonify(result)
        
    except Exception as e:
        print(f"❌ Error in attendance API: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/classes/<int:class_id>/attendance', methods=['POST'])
@jwt_required()
def mark_class_attendance(class_id):
    """Điểm danh học sinh (API cũ)"""
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
        
        for record in attendance_data:
            student_id = record.get('student_id')
            status = record.get('status', 'present')
            
            existing_attendance = Attendance.query.filter_by(
                class_id=class_id,
                student_id=student_id,
                date=date
            ).first()
            
            if existing_attendance:
                existing_attendance.status = status
            else:
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

@app.route('/api/classes/<int:class_id>/attendance/today', methods=['GET'])
@jwt_required()
def get_today_attendance(class_id):
    """Lấy điểm danh của ngày hiện tại - FIXED VERSION"""
    try:
        current_user = get_jwt_identity()
        
        # Cho phép cả giáo viên và học sinh xem điểm danh
        if current_user['role'] not in ['teacher', 'student']:
            return jsonify({'error': 'Unauthorized'}), 403
        
        today = datetime.now().date()
        print(f"📅 Getting today's attendance for class {class_id}, date: {today}")
        
        # Lấy danh sách học sinh trong lớp
        members = ClassMember.query.filter_by(class_id=class_id).all()
        students = [member.student for member in members]
        
        print(f"👥 Found {len(students)} students in class")
        
        # Lấy điểm danh hiện tại của ngày hôm nay
        today_attendance = Attendance.query.filter_by(
            class_id=class_id,
            date=today
        ).all()
        
        print(f"✅ Found {len(today_attendance)} attendance records for today")
        
        # Tạo dictionary để tra cứu nhanh
        attendance_dict = {att.student_id: att for att in today_attendance}
        
        # Tạo response data
        attendance_data = []
        for student in students:
            student_att = attendance_dict.get(student.id)
            attendance_data.append({
                'student_id': student.id,
                'student_name': student.full_name,
                'status': student_att.status if student_att else 'absent',
                'attendance_id': student_att.id if student_att else None
            })
        
        return jsonify({
            'date': today.isoformat(),
            'attendance': attendance_data,
            'total_students': len(students),
            'marked_count': len(today_attendance)
        })
        
    except Exception as e:
        print(f"❌ Error in get_today_attendance: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/classes/<int:class_id>/attendance/today', methods=['POST'])
@jwt_required()
def mark_today_attendance(class_id):
    """Điểm danh cho ngày hiện tại - FIXED VERSION"""
    try:
        current_user = get_jwt_identity()
        
        if current_user['role'] != 'teacher':
            return jsonify({'error': 'Only teachers can mark attendance'}), 403
        
        data = request.get_json()
        attendance_data = data.get('attendance', [])
        
        if not attendance_data:
            return jsonify({'error': 'Attendance data is required'}), 400
        
        today = datetime.now().date()
        print(f"🎯 Marking attendance for class {class_id}, date: {today}")
        
        updated_count = 0
        created_count = 0
        
        # Điểm danh cho từng học sinh
        for record in attendance_data:
            student_id = record.get('student_id')
            status = record.get('status', 'absent')
            
            if not student_id:
                continue
                
            # Kiểm tra xem điểm danh đã tồn tại chưa
            existing_attendance = Attendance.query.filter_by(
                class_id=class_id,
                student_id=student_id,
                date=today
            ).first()
            
            if existing_attendance:
                # Cập nhật điểm danh hiện có
                existing_attendance.status = status
                updated_count += 1
                print(f"📝 Updated attendance for student {student_id}: {status}")
            else:
                # Tạo điểm danh mới
                new_attendance = Attendance(
                    class_id=class_id,
                    student_id=student_id,
                    date=today,
                    status=status
                )
                db.session.add(new_attendance)
                created_count += 1
                print(f"🆕 Created attendance for student {student_id}: {status}")
        
        db.session.commit()
        
        return jsonify({
            'message': 'Attendance marked successfully for today',
            'created': created_count,
            'updated': updated_count,
            'total': len(attendance_data)
        })
        
    except Exception as e:
        print(f"❌ Error in mark_today_attendance: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/classes/<int:class_id>/attendance/history', methods=['GET'])
@jwt_required()
def get_attendance_history(class_id):
    """Lấy lịch sử điểm danh"""
    try:
        current_user = get_jwt_identity()
        
        # Kiểm tra quyền truy cập
        if current_user['role'] == 'student':
            return jsonify({'error': 'Only teachers can view attendance history'}), 403
        
        # Lấy tất cả các ngày đã điểm danh
        distinct_dates = db.session.query(Attendance.date).filter_by(
            class_id=class_id
        ).distinct().order_by(Attendance.date.desc()).all()
        
        # Lấy tất cả điểm danh
        all_attendances = Attendance.query.filter_by(class_id=class_id).all()
        
        # Lấy danh sách học sinh
        members = ClassMember.query.filter_by(class_id=class_id).all()
        students = {member.student.id: member.student for member in members}
        
        # Tổ chức dữ liệu theo ngày
        history = []
        for date_tuple in distinct_dates:
            date = date_tuple[0]
            date_attendances = [att for att in all_attendances if att.date == date]
            
            date_data = {
                'date': date.isoformat(),
                'total_students': len(students),
                'present_count': len([att for att in date_attendances if att.status == 'present']),
                'absent_count': len([att for att in date_attendances if att.status == 'absent']),
                'late_count': len([att for att in date_attendances if att.status == 'late']),
                'attendance_rate': 0
            }
            
            if date_data['total_students'] > 0:
                present_late_count = date_data['present_count'] + date_data['late_count']
                date_data['attendance_rate'] = round(
                    (present_late_count / date_data['total_students']) * 100, 2
                )
            
            history.append(date_data)
        
        return jsonify(history)
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/classes/<int:class_id>/attendance/date/<string:date_str>', methods=['GET'])
@jwt_required()
def get_attendance_by_date(class_id, date_str):
    """Lấy chi tiết điểm danh theo ngày cụ thể"""
    try:
        current_user = get_jwt_identity()
        
        if current_user['role'] == 'student':
            return jsonify({'error': 'Only teachers can view attendance'}), 403
        
        date = datetime.fromisoformat(date_str).date()
        
        # Lấy điểm danh theo ngày
        attendances = Attendance.query.filter_by(
            class_id=class_id, 
            date=date
        ).all()
        
        # Lấy danh sách tất cả học sinh trong lớp
        members = ClassMember.query.filter_by(class_id=class_id).all()
        all_students = {member.student.id: member.student for member in members}
        
        # Tạo dictionary để tra cứu nhanh
        attendance_dict = {att.student_id: att for att in attendances}
        
        # Tạo response data
        attendance_data = []
        for student_id, student in all_students.items():
            student_att = attendance_dict.get(student_id)
            attendance_data.append({
                'student_id': student.id,
                'student_name': student.full_name,
                'status': student_att.status if student_att else 'absent',
                'attendance_id': student_att.id if student_att else None
            })
        
        return jsonify({
            'date': date.isoformat(),
            'attendance': attendance_data
        })
        
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

# ==================== DEBUG & TESTING ROUTES ====================

@app.route('/api/debug/create-test-attendance', methods=['POST'])
@jwt_required()
def create_test_attendance():
    """Tạo dữ liệu điểm danh test (chỉ cho mục đích debug)"""
    try:
        current_user = get_jwt_identity()
        
        if current_user['role'] != 'teacher':
            return jsonify({'error': 'Only teachers can create test data'}), 403
        
        # Lấy lớp học đầu tiên
        class_obj = Class.query.first()
        if not class_obj:
            return jsonify({'error': 'No classes found'}), 404
        
        # Lấy học sinh trong lớp
        members = ClassMember.query.filter_by(class_id=class_obj.id).all()
        students = [member.student for member in members]
        
        # Tạo điểm danh cho hôm nay và 5 ngày trước
        today = datetime.now().date()
        created_count = 0
        
        for days_ago in range(6):  # 0-5 days ago
            date = today - timedelta(days=days_ago)
            
            for student in students:
                # Kiểm tra xem đã có điểm danh chưa
                existing = Attendance.query.filter_by(
                    class_id=class_obj.id,
                    student_id=student.id,
                    date=date
                ).first()
                
                if not existing:
                    # Tạo điểm danh mới với trạng thái ngẫu nhiên
                    status_options = ['present', 'present', 'present', 'late', 'absent']
                    status = random.choice(status_options)
                    
                    attendance = Attendance(
                        class_id=class_obj.id,
                        student_id=student.id,
                        date=date,
                        status=status
                    )
                    db.session.add(attendance)
                    created_count += 1
        
        db.session.commit()
        
        return jsonify({
            'message': f'Created {created_count} test attendance records',
            'class_id': class_obj.id,
            'class_name': class_obj.class_name,
            'date_range': {
                'from': (today - timedelta(days=5)).isoformat(),
                'to': today.isoformat()
            }
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/debug/fix-attendance-2025-10-28', methods=['POST'])
@jwt_required()
def fix_attendance_2025_10_28():
    """Tạo dữ liệu điểm danh cụ thể cho ngày 28/10/2025"""
    try:
        current_user = get_jwt_identity()
        
        if current_user['role'] != 'teacher':
            return jsonify({'error': 'Only teachers can create test data'}), 403
        
        # Lấy lớp CÔNG NGHỆ PHẦN MỀM (class_id=2)
        class_obj = Class.query.get(2)
        if not class_obj:
            return jsonify({'error': 'Class not found'}), 404
        
        # Lấy học sinh trong lớp
        members = ClassMember.query.filter_by(class_id=2).all()
        students = [member.student for member in members]
        
        # Ngày cụ thể: 28/10/2025
        specific_date = datetime(2025, 10, 28).date()
        created_count = 0
        
        for student in students:
            # Kiểm tra xem đã có điểm danh chưa
            existing = Attendance.query.filter_by(
                class_id=2,
                student_id=student.id,
                date=specific_date
            ).first()
            
            if not existing:
                # Tạo điểm danh mới
                status = 'present'  # Mặc định là có mặt
                
                attendance = Attendance(
                    class_id=2,
                    student_id=student.id,
                    date=specific_date,
                    status=status
                )
                db.session.add(attendance)
                created_count += 1
                print(f"✅ Created attendance for {student.full_name} on 2025-10-28")
        
        db.session.commit()
        
        return jsonify({
            'message': f'Created {created_count} attendance records for 2025-10-28',
            'class_id': 2,
            'class_name': class_obj.class_name,
            'date': '2025-10-28',
            'students_count': len(students)
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/debug/clear-attendance', methods=['POST'])
@jwt_required()
def clear_attendance():
    """Xóa tất cả dữ liệu điểm danh (chỉ cho mục đích debug)"""
    try:
        current_user = get_jwt_identity()
        
        if current_user['role'] != 'teacher':
            return jsonify({'error': 'Only teachers can clear data'}), 403
        
        # Đếm số bản ghi trước khi xóa
        count_before = Attendance.query.count()
        
        # Xóa tất cả điểm danh
        Attendance.query.delete()
        db.session.commit()
        
        count_after = Attendance.query.count()
        
        return jsonify({
            'message': f'Cleared {count_before} attendance records',
            'remaining': count_after
        })
        
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

# API mới để lấy tất cả users (cho việc tạo lớp)
@app.route('/api/users', methods=['GET'])
@jwt_required()
def get_all_users():
    """Lấy danh sách tất cả users (cho dropdown)"""
    try:
        users = User.query.all()
        users_data = [{
            'id': user.id,
            'username': user.username,
            'full_name': user.full_name,
            'email': user.email,
            'role': user.role
        } for user in users]
        
        return jsonify(users_data)
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Debug endpoint để kiểm tra routes
@app.route('/api/debug/routes')
def debug_routes():
    """Debug endpoint để xem tất cả routes"""
    routes = []
    for rule in app.url_map.iter_rules():
        routes.append({
            'endpoint': rule.endpoint,
            'methods': list(rule.methods),
            'path': str(rule)
        })
    return jsonify(routes)

# ==================== INITIALIZATION ====================

def create_demo_data():
    """Tạo dữ liệu demo cho ứng dụng với danh sách học sinh và giáo viên đã cho"""
    if User.query.filter_by(username='lamducduong').first():
        print("✅ Demo data already exists")
        return
    
    print("🔄 Creating demo data...")
    
    # Tạo giáo viên Lâm Đức Dương
    hashed_password = bcrypt.generate_password_hash('password123').decode('utf-8')
    teacher = User(
        username='lamducduong',
        email='lamducduong@school.edu',
        password=hashed_password,
        role='teacher',
        full_name='Lâm Đức Dương'
    )
    db.session.add(teacher)
    
    # Tạo danh sách 5 học sinh
    students_data = [
        {'username': 'phananhngoc', 'email': 'phananhngoc@school.edu', 'full_name': 'Phan Anh Ngọc'},
        {'username': 'nguyenminhthanh', 'email': 'nguyenminhthanh@school.edu', 'full_name': 'Nguyễn Minh Thành'},
        {'username': 'nguyencaoanhhoai', 'email': 'nguyencaoanhhoai@school.edu', 'full_name': 'Nguyễn Cao Anh Hoài'},
        {'username': 'letuanvu', 'email': 'letuanvu@school.edu', 'full_name': 'Lê Tuấn Vũ'},
        {'username': 'haphihung', 'email': 'haphihung@school.edu', 'full_name': 'Hà Phi Hùng'}
    ]
    
    students = []
    for student_data in students_data:
        student = User(
            username=student_data['username'],
            email=student_data['email'],
            password=hashed_password,
            role='student',
            full_name=student_data['full_name']
        )
        students.append(student)
        db.session.add(student)
    
    db.session.commit()
    
    # Tạo lớp học mẫu
    demo_class = Class(
        class_name='Lớp Toán 10A1',
        description='Lớp Toán nâng cao lớp 10',
        schedule='Thứ 2, 4, 6 - 14:00-16:00',
        teacher_id=teacher.id
    )
    db.session.add(demo_class)
    db.session.commit()
    
    # Thêm tất cả học sinh vào lớp
    for student in students:
        class_member = ClassMember(
            class_id=demo_class.id,
            student_id=student.id
        )
        db.session.add(class_member)
    
    # Tạo bài tập mẫu
    demo_assignment1 = Assignment(
        title='Bài tập chương 1: Đại số',
        description='Giải các bài tập từ 1 đến 15 trong sách bài tập',
        due_date=datetime.utcnow() + timedelta(days=7),
        class_id=demo_class.id,
        teacher_id=teacher.id
    )
    db.session.add(demo_assignment1)
    
    demo_assignment2 = Assignment(
        title='Bài tập chương 2: Hình học',
        description='Chứng minh các định lý và giải bài tập hình học',
        due_date=datetime.utcnow() + timedelta(days=14),
        class_id=demo_class.id,
        teacher_id=teacher.id
    )
    db.session.add(demo_assignment2)
    
    # Tạo lớp CÔNG NGHỆ PHẦN MỀM
    software_class = Class(
        class_name='CÔNG NGHỆ PHẦN MỀM',
        description='Lớp học về công nghệ phần mềm và phát triển ứng dụng',
        schedule='Thứ 3, 5, 7 - 08:00-10:00',
        teacher_id=teacher.id
    )
    db.session.add(software_class)
    db.session.commit()

    # Thêm tất cả học sinh vào lớp CÔNG NGHỆ PHẦN MỀM
    for student in students:
        class_member = ClassMember(
            class_id=software_class.id,
            student_id=student.id
        )
        db.session.add(class_member)

    # Tạo bài tập mẫu cho lớp CÔNG NGHỆ PHẦN MỀM
    software_assignment1 = Assignment(
        title='Bài tập: Thiết kế cơ sở dữ liệu',
        description='Thiết kế cơ sở dữ liệu cho hệ thống quản lý trường học',
        due_date=datetime.utcnow() + timedelta(days=5),
        class_id=software_class.id,
        teacher_id=teacher.id
    )
    db.session.add(software_assignment1)

    software_assignment2 = Assignment(
        title='Bài tập: Phát triển API với Flask',
        description='Xây dựng API RESTful cho ứng dụng web sử dụng Flask',
        due_date=datetime.utcnow() + timedelta(days=12),
        class_id=software_class.id,
        teacher_id=teacher.id
    )
    db.session.add(software_assignment2)

    # TẠO DỮ LIỆU ĐIỂM DANH MẪU CHO 5 NGÀY GẦN ĐÂY
    today = datetime.utcnow().date()
    
    for days_ago in range(5):
        date = today - timedelta(days=days_ago)
        
        for i, student in enumerate(students):
            # Tạo điểm danh ngẫu nhiên
            status_options = ['present', 'present', 'present', 'late', 'absent']
            status = random.choice(status_options)
            
            attendance = Attendance(
                class_id=demo_class.id,
                student_id=student.id,
                date=date,
                status=status
            )
            db.session.add(attendance)
            
            # Cũng tạo cho lớp CÔNG NGHỆ PHẦN MỀM
            attendance_software = Attendance(
                class_id=software_class.id,
                student_id=student.id,
                date=date,
                status=status
            )
            db.session.add(attendance_software)

    db.session.commit()
    print("✅ Demo data created successfully with attendance records!")

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        create_demo_data()
    
    print("=" * 60)
    print("🚀 ONLINE CLASS MANAGER SERVER STARTED - FIXED ATTENDANCE")
    print("=" * 60)
    print("📍 Server URL: http://localhost:5000")
    print("📌 Test URLs:")
    print("   • http://localhost:5000/api/classes/2/attendance?date=2025-10-28")
    print("   • http://localhost:5000/api/classes/2/attendance/today")
    print("   • http://localhost:5000/api/debug/fix-attendance-2025-10-28 (POST)")
    print("   • http://localhost:5000/api/debug/create-test-attendance (POST)")
    print("=" * 60)
    print("🎯 ĐÃ SỬA LỖI ĐIỂM DANH:")
    print("   ✅ Fixed get_class_attendance - hiển thị tất cả học sinh kể cả chưa điểm danh")
    print("   ✅ Fixed get_today_attendance - cho phép cả học sinh xem")
    print("   ✅ Fixed mark_today_attendance - thêm logging và xử lý lỗi")
    print("   ✅ Added fix-attendance-2025-10-28 - tạo dữ liệu điểm danh cụ thể")
    print("   ✅ Thêm debug logging để dễ dàng theo dõi")
    print("=" * 60)
    
    app.run(debug=True, host='0.0.0.0', port=5000)