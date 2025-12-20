from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_cors import CORS
from flask_bcrypt import Bcrypt  
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from functools import wraps
from datetime import datetime
import os
import logging
from logging.handlers import RotatingFileHandler

app = Flask(__name__)
CORS(app)


if not os.path.exists('logs'):
    os.mkdir('logs')

file_handler = RotatingFileHandler('logs/school_management.log', maxBytes=10240000, backupCount=10)
file_handler.setFormatter(logging.Formatter(
    '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
))
file_handler.setLevel(logging.INFO)
app.logger.addHandler(file_handler)
app.logger.setLevel(logging.INFO)
app.logger.info('School Management System startup')


basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'app.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config["JWT_SECRET_KEY"] = "super-secret-change-me-later"

db = SQLAlchemy(app)
migrate = Migrate(app, db)
bcrypt = Bcrypt(app)  
jwt = JWTManager(app)


class User(db.Model):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(128), nullable=False)
    role = db.Column(db.String(20), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class Student(db.Model):
    __tablename__ = 'student'
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(100), nullable=False)
    last_name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    
    attendances = db.relationship('Attendance', backref='student', lazy=True, cascade='all, delete-orphan')

    def to_json(self):
        return {
            "id": self.id,
            "firstName": self.first_name,
            "lastName": self.last_name,
            "email": self.email,
            "createdAt": self.created_at.isoformat() if self.created_at else None,
            "updatedAt": self.updated_at.isoformat() if self.updated_at else None
        }

class Teacher(db.Model):
    __tablename__ = 'teacher'
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(100), nullable=False)
    last_name = db.Column(db.String(100), nullable=False)
    subject = db.Column(db.String(100))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    
    timetables = db.relationship('Timetable', backref='teacher', lazy=True)

    def to_json(self):
        return {
            "id": self.id,
            "firstName": self.first_name,
            "lastName": self.last_name,
            "subject": self.subject,
            "createdAt": self.created_at.isoformat() if self.created_at else None,
            "updatedAt": self.updated_at.isoformat() if self.updated_at else None
        }

class Attendance(db.Model):
    __tablename__ = 'attendance'
    id = db.Column(db.Integer, primary_key=True)
    date = db.Column(db.Date, nullable=False, index=True)
    status = db.Column(db.String(20), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    
    student_id = db.Column(db.Integer, db.ForeignKey('student.id'), nullable=False, index=True)
   
    def to_json(self):
        return {
            "id": self.id,
            "date": str(self.date),
            "status": self.status,
            "studentId": self.student_id,
            "studentName": f"{self.student.first_name} {self.student.last_name}" if self.student else None,
            "createdAt": self.created_at.isoformat() if self.created_at else None
        }

class Timetable(db.Model):
    __tablename__ = 'timetable'
    id = db.Column(db.Integer, primary_key=True)
    day_of_week = db.Column(db.String(20), nullable=False, index=True)
    start_time = db.Column(db.Time, nullable=False)
    end_time = db.Column(db.Time, nullable=False)
    subject = db.Column(db.String(100), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    
    teacher_id = db.Column(db.Integer, db.ForeignKey('teacher.id'), nullable=True, index=True)
    
    def to_json(self):
        return {
            "id": self.id,
            "dayOfWeek": self.day_of_week,
            "startTime": str(self.start_time),
            "endTime": str(self.end_time),
            "subject": self.subject,
            "teacherId": self.teacher_id,
            "teacherName": f"{self.teacher.first_name} {self.teacher.last_name}" if self.teacher else None,
            "createdAt": self.created_at.isoformat() if self.created_at else None
        }


def admin_required(fn):
    @wraps(fn)
    @jwt_required()
    def wrapper(*args, **kwargs):
        identity = get_jwt_identity()
        if identity['role'] != 'Admin':
            app.logger.warning(f"Unauthorized admin access attempt by {identity['username']}")
            return jsonify({"error": "Admin access required"}), 403
        return fn(*args, **kwargs)
    return wrapper

def teacher_or_admin_required(fn):
    @wraps(fn)
    @jwt_required()
    def wrapper(*args, **kwargs):
        identity = get_jwt_identity()
        if identity['role'] not in ['Admin', 'Teacher']:
            app.logger.warning(f"Unauthorized access attempt by {identity['username']}")
            return jsonify({"error": "Teacher or Admin access required"}), 403
        return fn(*args, **kwargs)
    return wrapper


def validate_required_fields(data, required_fields):
    """Check if all required fields are present"""
    missing = [field for field in required_fields if field not in data or not data[field]]
    if missing:
        return False, f"Missing required fields: {', '.join(missing)}"
    return True, None

def validate_email(email):
    """Basic email validation"""
    import re
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

def validate_role(role):
    """Validate user role"""
    valid_roles = ['Admin', 'Teacher', 'Student', 'Parent']
    return role in valid_roles


@app.errorhandler(400)
def bad_request(error):
    app.logger.error(f"Bad Request: {error}")
    return jsonify({"error": "Bad request", "message": str(error)}), 400

@app.errorhandler(401)
def unauthorized(error):
    app.logger.error(f"Unauthorized: {error}")
    return jsonify({"error": "Unauthorized", "message": "Authentication required"}), 401

@app.errorhandler(403)
def forbidden(error):
    app.logger.error(f"Forbidden: {error}")
    return jsonify({"error": "Forbidden", "message": "You don't have permission"}), 403

@app.errorhandler(404)
def not_found(error):
    return jsonify({"error": "Not found", "message": "Resource not found"}), 404

@app.errorhandler(500)
def internal_error(error):
    app.logger.error(f"Server Error: {error}")
    db.session.rollback()
    return jsonify({"error": "Internal server error", "message": "Something went wrong"}), 500


@app.route('/register', methods=['POST'])
def register():
    try:
        data = request.get_json()
        
        
        is_valid, error_msg = validate_required_fields(data, ['username', 'password', 'role'])
        if not is_valid:
            app.logger.warning(f"Registration failed: {error_msg}")
            return jsonify({"error": error_msg}), 400
        
        
        if not validate_role(data['role']):
            app.logger.warning(f"Invalid role attempt: {data['role']}")
            return jsonify({"error": "Invalid role. Must be Admin, Teacher, Student, or Parent"}), 400
        
        
        if User.query.filter_by(username=data['username']).first():
            app.logger.warning(f"Registration failed: Username {data['username']} already exists")
            return jsonify({"error": "Username already exists"}), 400
        
        
        hashed_password = bcrypt.generate_password_hash(data['password']).decode('utf-8')
        
        new_user = User(
            username=data['username'], 
            password_hash=hashed_password, 
            role=data['role']
        )
        db.session.add(new_user)
        db.session.commit()
        
        app.logger.info(f"New user registered: {data['username']} as {data['role']}")
        return jsonify({"message": "User created successfully"}), 201
        
    except Exception as e:
        app.logger.error(f"Registration error: {str(e)}")
        db.session.rollback()
        return jsonify({"error": "Registration failed", "details": str(e)}), 500

@app.route('/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
        
        
        is_valid, error_msg = validate_required_fields(data, ['username', 'password'])
        if not is_valid:
            app.logger.warning(f"Login failed: {error_msg}")
            return jsonify({"error": error_msg}), 400
        
        user = User.query.filter_by(username=data['username']).first()
        
        if user and bcrypt.check_password_hash(user.password_hash, data['password']):
            access_token = create_access_token(identity={'username': user.username, 'role': user.role})
            app.logger.info(f"Successful login: {user.username} ({user.role})")
            return jsonify(access_token=access_token, role=user.role), 200
        else:
            app.logger.warning(f"Failed login attempt for username: {data['username']}")
            return jsonify({"error": "Invalid credentials"}), 401
            
    except Exception as e:
        app.logger.error(f"Login error: {str(e)}")
        return jsonify({"error": "Login failed"}), 500

@app.route('/admin-only', methods=['GET'])
@admin_required
def admin_only():
    identity = get_jwt_identity()
    return jsonify({"message": f"Welcome Admin {identity['username']}!"})


@app.route('/student', methods=['POST'])
@admin_required  # Task 6: Only Admin can add
def create_student():
    try:
        data = request.get_json()
        
        
        is_valid, error_msg = validate_required_fields(data, ['firstName', 'lastName', 'email'])
        if not is_valid:
            return jsonify({"error": error_msg}), 400
        
        
        if not validate_email(data['email']):
            return jsonify({"error": "Invalid email format"}), 400
        
        
        if Student.query.filter_by(email=data['email']).first():
            return jsonify({"error": "Email already exists"}), 400
        
        new_student = Student(
            first_name=data['firstName'],
            last_name=data['lastName'],
            email=data['email']
        )
        
        db.session.add(new_student)
        db.session.commit()
        
        app.logger.info(f"Student created: {data['firstName']} {data['lastName']}")
        return jsonify(new_student.to_json()), 201
        
    except Exception as e:
        app.logger.error(f"Create student error: {str(e)}")
        db.session.rollback()
        return jsonify({"error": "Failed to create student"}), 500

@app.route('/students', methods=['GET'])
@jwt_required()
def get_all_students():
    try:
        students = Student.query.all()
        return jsonify([student.to_json() for student in students]), 200
    except Exception as e:
        app.logger.error(f"Get students error: {str(e)}")
        return jsonify({"error": "Failed to fetch students"}), 500

@app.route('/student/<int:student_id>', methods=['GET'])
@jwt_required()
def get_student(student_id):
    try:
        student = Student.query.get(student_id)
        if student:
            return jsonify(student.to_json()), 200
        else:
            return jsonify({"error": "Student not found"}), 404
    except Exception as e:
        app.logger.error(f"Get student error: {str(e)}")
        return jsonify({"error": "Failed to fetch student"}), 500

@app.route('/student/<int:student_id>', methods=['PUT'])
@admin_required
def update_student(student_id):
    try:
        student = Student.query.get(student_id)
        if not student:
            return jsonify({"error": "Student not found"}), 404
        
        data = request.get_json()
        
        
        if 'email' in data and data['email']:
            if not validate_email(data['email']):
                return jsonify({"error": "Invalid email format"}), 400
            # Check if email exists for another student
            existing = Student.query.filter_by(email=data['email']).first()
            if existing and existing.id != student_id:
                return jsonify({"error": "Email already in use"}), 400
        
        student.first_name = data.get('firstName', student.first_name)
        student.last_name = data.get('lastName', student.last_name)
        student.email = data.get('email', student.email)
        student.updated_at = datetime.utcnow()
        
        db.session.commit()
        app.logger.info(f"Student updated: ID {student_id}")
        return jsonify(student.to_json()), 200
        
    except Exception as e:
        app.logger.error(f"Update student error: {str(e)}")
        db.session.rollback()
        return jsonify({"error": "Failed to update student"}), 500

@app.route('/student/<int:student_id>', methods=['DELETE'])
@admin_required  # Task 6: Only Admin can delete
def delete_student(student_id):
    try:
        student = Student.query.get(student_id)
        if not student:
            return jsonify({"error": "Student not found"}), 404
        
        db.session.delete(student)
        db.session.commit()
        
        app.logger.info(f"Student deleted: ID {student_id}")
        return jsonify({"message": "Student deleted successfully"}), 200
        
    except Exception as e:
        app.logger.error(f"Delete student error: {str(e)}")
        db.session.rollback()
        return jsonify({"error": "Failed to delete student"}), 500


@app.route('/teachers', methods=['GET'])
@jwt_required()
def get_teachers():
    try:
        teachers = Teacher.query.all()
        return jsonify([t.to_json() for t in teachers]), 200
    except Exception as e:
        app.logger.error(f"Get teachers error: {str(e)}")
        return jsonify({"error": "Failed to fetch teachers"}), 500

@app.route('/teacher', methods=['POST'])
@admin_required
def add_teacher():
    try:
        data = request.get_json()
        
        is_valid, error_msg = validate_required_fields(data, ['firstName', 'lastName', 'subject'])
        if not is_valid:
            return jsonify({"error": error_msg}), 400
        
        new_teacher = Teacher(
            first_name=data['firstName'], 
            last_name=data['lastName'], 
            subject=data['subject']
        )
        db.session.add(new_teacher)
        db.session.commit()
        
        app.logger.info(f"Teacher created: {data['firstName']} {data['lastName']}")
        return jsonify(new_teacher.to_json()), 201
        
    except Exception as e:
        app.logger.error(f"Create teacher error: {str(e)}")
        db.session.rollback()
        return jsonify({"error": "Failed to create teacher"}), 500

@app.route('/teacher/<int:teacher_id>', methods=['PUT'])
@admin_required
def update_teacher(teacher_id):
    try:
        teacher = Teacher.query.get(teacher_id)
        if not teacher:
            return jsonify({"error": "Teacher not found"}), 404
        
        data = request.get_json()
        teacher.first_name = data.get('firstName', teacher.first_name)
        teacher.last_name = data.get('lastName', teacher.last_name)
        teacher.subject = data.get('subject', teacher.subject)
        teacher.updated_at = datetime.utcnow()
        
        db.session.commit()
        app.logger.info(f"Teacher updated: ID {teacher_id}")
        return jsonify(teacher.to_json()), 200
        
    except Exception as e:
        app.logger.error(f"Update teacher error: {str(e)}")
        db.session.rollback()
        return jsonify({"error": "Failed to update teacher"}), 500

@app.route('/teacher/<int:teacher_id>', methods=['DELETE'])
@admin_required
def delete_teacher(teacher_id):
    try:
        teacher = Teacher.query.get(teacher_id)
        if not teacher:
            return jsonify({"error": "Teacher not found"}), 404
        
        db.session.delete(teacher)
        db.session.commit()
        
        app.logger.info(f"Teacher deleted: ID {teacher_id}")
        return jsonify({"message": "Teacher deleted successfully"}), 200
        
    except Exception as e:
        app.logger.error(f"Delete teacher error: {str(e)}")
        db.session.rollback()
        return jsonify({"error": "Failed to delete teacher"}), 500


@app.route('/timetable', methods=['POST'])
@admin_required
def create_timetable():
    try:
        data = request.get_json()
        
        is_valid, error_msg = validate_required_fields(data, ['dayOfWeek', 'startTime', 'endTime', 'subject'])
        if not is_valid:
            return jsonify({"error": error_msg}), 400
        
        # Validate teacher exists if provided
        if 'teacherId' in data and data['teacherId']:
            teacher = Teacher.query.get(data['teacherId'])
            if not teacher:
                return jsonify({"error": "Teacher not found"}), 404
        
        new_entry = Timetable(
            day_of_week=data['dayOfWeek'],
            start_time=data['startTime'],
            end_time=data['endTime'],
            subject=data['subject'],
            teacher_id=data.get('teacherId')
        )
        db.session.add(new_entry)
        db.session.commit()
        
        app.logger.info(f"Timetable created: {data['subject']} on {data['dayOfWeek']}")
        return jsonify(new_entry.to_json()), 201
        
    except Exception as e:
        app.logger.error(f"Create timetable error: {str(e)}")
        db.session.rollback()
        return jsonify({"error": "Failed to create timetable"}), 500

@app.route('/timetables', methods=['GET'])
@jwt_required()
def get_timetables():
    try:
        timetables = Timetable.query.all()
        return jsonify([t.to_json() for t in timetables]), 200
    except Exception as e:
        app.logger.error(f"Get timetables error: {str(e)}")
        return jsonify({"error": "Failed to fetch timetables"}), 500

@app.route('/timetable/<int:timetable_id>', methods=['PUT'])
@admin_required
def update_timetable(timetable_id):
    try:
        timetable = Timetable.query.get(timetable_id)
        if not timetable:
            return jsonify({"error": "Timetable not found"}), 404
        
        data = request.get_json()
        
        
        if 'teacherId' in data and data['teacherId']:
            teacher = Teacher.query.get(data['teacherId'])
            if not teacher:
                return jsonify({"error": "Teacher not found"}), 404
        
        timetable.day_of_week = data.get('dayOfWeek', timetable.day_of_week)
        timetable.start_time = data.get('startTime', timetable.start_time)
        timetable.end_time = data.get('endTime', timetable.end_time)
        timetable.subject = data.get('subject', timetable.subject)
        timetable.teacher_id = data.get('teacherId', timetable.teacher_id)
        timetable.updated_at = datetime.utcnow()
        
        db.session.commit()
        app.logger.info(f"Timetable updated: ID {timetable_id}")
        return jsonify(timetable.to_json()), 200
        
    except Exception as e:
        app.logger.error(f"Update timetable error: {str(e)}")
        db.session.rollback()
        return jsonify({"error": "Failed to update timetable"}), 500

@app.route('/timetable/<int:timetable_id>', methods=['DELETE'])
@admin_required
def delete_timetable(timetable_id):
    try:
        timetable = Timetable.query.get(timetable_id)
        if not timetable:
            return jsonify({"error": "Timetable not found"}), 404
        
        db.session.delete(timetable)
        db.session.commit()
        
        app.logger.info(f"Timetable deleted: ID {timetable_id}")
        return jsonify({"message": "Timetable deleted successfully"}), 200
        
    except Exception as e:
        app.logger.error(f"Delete timetable error: {str(e)}")
        db.session.rollback()
        return jsonify({"error": "Failed to delete timetable"}), 500


@app.route('/mark-attendance', methods=['POST'])
@teacher_or_admin_required  
def mark_attendance():
    try:
        data = request.get_json()
        identity = get_jwt_identity()
        
        
        is_valid, error_msg = validate_required_fields(data, ['student_id', 'date', 'status'])
        if not is_valid:
            return jsonify({"error": error_msg}), 400
        
        
        student = Student.query.get(data['student_id'])
        if not student:
            return jsonify({"error": "Student not found"}), 404
        
        
        if data['status'] not in ['Present', 'Absent']:
            return jsonify({"error": "Status must be 'Present' or 'Absent'"}), 400
        
        
        try:
            date_obj = datetime.strptime(data['date'], '%Y-%m-%d').date()
        except ValueError:
            return jsonify({"error": "Invalid date format. Use YYYY-MM-DD"}), 400
        
        
        existing = Attendance.query.filter_by(student_id=data['student_id'], date=date_obj).first()
        if existing:
            return jsonify({"error": "Attendance already marked for this date"}), 400
        
        new_entry = Attendance(
            student_id=data['student_id'],
            date=date_obj,
            status=data['status']
        )
        db.session.add(new_entry)
        db.session.commit()
        
        app.logger.info(f"Attendance marked by {identity['username']}: Student {data['student_id']} - {data['status']} on {date_obj}")
        return jsonify(new_entry.to_json()), 201
        
    except Exception as e:
        app.logger.error(f"Mark attendance error: {str(e)}")
        db.session.rollback()
        return jsonify({"error": "Failed to mark attendance"}), 500

@app.route('/get-attendance', methods=['GET'])
@jwt_required()
def get_attendance():
    try:
        date_query = request.args.get('date')
        
        if date_query:
            
            try:
                datetime.strptime(date_query, '%Y-%m-%d')
                records = Attendance.query.filter_by(date=date_query).all()
            except ValueError:
                return jsonify({"error": "Invalid date format. Use YYYY-MM-DD"}), 400
        else:
            records = Attendance.query.all()
        
        return jsonify([r.to_json() for r in records]), 200
        
    except Exception as e:
        app.logger.error(f"Get attendance error: {str(e)}")
        return jsonify({"error": "Failed to fetch attendance"}), 500


@app.route('/')
def index():
    return jsonify({
        "message": "School Management System API",
        "status": "running",
        "version": "2.0"
    })

if __name__ == '__main__':
    app.run(debug=True)
