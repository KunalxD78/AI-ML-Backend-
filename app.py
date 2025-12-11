from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_cors import CORS
from flask_bcrypt import Bcrypt  
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
import os


app = Flask(__name__)


basedir = os.path.abspath(os.path.dirname(__file__))

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'app.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config["JWT_SECRET_KEY"] = "super-secret-change-me-later"

db = SQLAlchemy(app)
migrate = Migrate(app, db)
bcrypt = Bcrypt(app)  
jwt = JWTManager(app)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    role = db.Column(db.String(20), nullable=False)

class Student(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(100), nullable=False)
    last_name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    
    attendances = db.relationship('Attendance', backref='student', lazy=True)

    def to_json(self):
        return {
            "id": self.id,
            "firstName": self.first_name,
            "lastName": self.last_name,
            "email": self.email
        }

class Teacher(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(100), nullable=False)
    last_name = db.Column(db.String(100), nullable=False)
    subject = db.Column(db.String(100))

    def to_json(self):
        return {
            "id": self.id,
            "firstName": self.first_name,
            "lastName": self.last_name,
            "subject": self.subject
        }

class Attendance(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    date = db.Column(db.Date, nullable=False)
    status = db.Column(db.String(20), nullable=False) 
   
    def to_json(self):
        return {
            "id": self.id,
            "date": str(self.date),
            "status": self.status,
            "student_id": self.student_id
        }

    
    student_id = db.Column(db.Integer, db.ForeignKey('student.id'), nullable=False)

class Timetable(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    day_of_week = db.Column(db.String(20), nullable=False) # e.g., 'Monday'
    start_time = db.Column(db.Time, nullable=False)
    end_time = db.Column(db.Time, nullable=False)
    subject = db.Column(db.String(100), nullable=False)
    
    teacher_id = db.Column(db.Integer, db.ForeignKey('teacher.id'), nullable=True)


@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    
    hashed_password = bcrypt.generate_password_hash(data['password']).decode('utf-8')
    
    new_user = User(
        username=data['username'], 
        password_hash=hashed_password, 
        role=data['role']
    )
    db.session.add(new_user)
    db.session.commit()
    return jsonify({"message": "User created successfully"}), 201


@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    user = User.query.filter_by(username=data['username']).first()

    
    if user and bcrypt.check_password_hash(user.password_hash, data['password']):
       
        access_token = create_access_token(identity={'username': user.username, 'role': user.role})
        return jsonify(access_token=access_token, role=user.role), 200
    else:
        return jsonify({"message": "Invalid credentials"}), 401
    

@app.route('/admin-only', methods=['GET'])
@jwt_required()
def admin_only():
    identity = get_jwt_identity()
    if identity['role'] != 'Admin':
        return jsonify({"error": "Admins only"}), 403
    return jsonify({"message": "Welcome Admin!"})



@app.route('/student', methods=['POST'])
def create_student():
    data = request.get_json()
    if not data or not 'firstName' in data or not 'lastName' in data or not 'email' in data:
        return jsonify({"error": "Missing required fields"}), 400
    
    new_student = Student(
        first_name=data['firstName'],
        last_name=data['lastName'],
        email=data['email']
    )
    
    try:
        db.session.add(new_student)
        db.session.commit()
        return jsonify(new_student.to_json()), 201 # 201 = Created
    except Exception as e:
        db.session.rollback()
        return jsonify({"error": "Email may already exist.", "details": str(e)}), 400


@app.route('/students', methods=['GET'])
def get_all_students():
    students = Student.query.all()
    return jsonify([student.to_json() for student in students]), 200


@app.route('/student/<int:student_id>', methods=['GET'])
def get_student(student_id):
    student = Student.query.get(student_id)
    if student:
        return jsonify(student.to_json()), 200
    else:
        return jsonify({"error": "Student not found"}), 404


@app.route('/student/<int:student_id>', methods=['PUT'])
def update_student(student_id):
    student = Student.query.get(student_id)
    if not student:
        return jsonify({"error": "Student not found"}), 404
    
    data = request.get_json()
    student.first_name = data.get('firstName', student.first_name)
    student.last_name = data.get('lastName', student.last_name)
    student.email = data.get('email', student.email)
    
    try:
        db.session.commit()
        return jsonify(student.to_json()), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({"error": "Failed to update.", "details": str(e)}), 400


@app.route('/student/<int:student_id>', methods=['DELETE'])
def delete_student(student_id):
    student = Student.query.get(student_id)
    if not student:
        return jsonify({"error": "Student not found"}), 404
        
    try:
        db.session.delete(student)
        db.session.commit()
        return jsonify({"message": "Student deleted successfully"}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({"error": "Failed to delete.", "details": str(e)}), 500

@app.route('/teachers', methods=['GET'])
def get_teachers():
    teachers = Teacher.query.all()
    return jsonify([t.to_json() for t in teachers]), 200

@app.route('/teacher', methods=['POST'])
def add_teacher():
    data = request.get_json()
    new_teacher = Teacher(first_name=data['firstName'], last_name=data['lastName'], subject=data['subject'])
    db.session.add(new_teacher)
    db.session.commit()
    return jsonify(new_teacher.to_json()), 201


@app.route('/teacher/<int:teacher_id>', methods=['PUT'])
def update_teacher(teacher_id):
    teacher = Teacher.query.get(teacher_id)
    if not teacher:
        return jsonify({"error": "Teacher not found"}), 404
    
    data = request.get_json()
    teacher.first_name = data.get('firstName', teacher.first_name)
    teacher.last_name = data.get('lastName', teacher.last_name)
    teacher.subject = data.get('subject', teacher.subject)
    
    db.session.commit()
    return jsonify(teacher.to_json()), 200


@app.route('/teacher/<int:teacher_id>', methods=['DELETE'])
def delete_teacher(teacher_id):
    teacher = Teacher.query.get(teacher_id)
    if not teacher:
        return jsonify({"error": "Teacher not found"}), 404
    
    db.session.delete(teacher)
    db.session.commit()
    return jsonify({"message": "Teacher deleted successfully"}), 200

@app.route('/timetable', methods=['POST'])
def create_timetable():
    data = request.get_json()
    new_entry = Timetable(
        day_of_week=data['dayOfWeek'],
        start_time=data['startTime'],
        end_time=data['endTime'],
        subject=data['subject'],
        teacher_id=data.get('teacherId')
    )
    db.session.add(new_entry)
    db.session.commit()
    return jsonify({
        "id": new_entry.id,
        "dayOfWeek": new_entry.day_of_week,
        "startTime": str(new_entry.start_time),
        "endTime": str(new_entry.end_time),
        "subject": new_entry.subject,
        "teacherId": new_entry.teacher_id
    }), 201


@app.route('/timetables', methods=['GET'])
def get_timetables():
    timetables = Timetable.query.all()
    return jsonify([{
        "id": t.id,
        "dayOfWeek": t.day_of_week,
        "startTime": str(t.start_time),
        "endTime": str(t.end_time),
        "subject": t.subject,
        "teacherId": t.teacher_id
    } for t in timetables]), 200


@app.route('/timetable/<int:timetable_id>', methods=['PUT'])
def update_timetable(timetable_id):
    timetable = Timetable.query.get(timetable_id)
    if not timetable:
        return jsonify({"error": "Timetable not found"}), 404
    
    data = request.get_json()
    timetable.day_of_week = data.get('dayOfWeek', timetable.day_of_week)
    timetable.start_time = data.get('startTime', timetable.start_time)
    timetable.end_time = data.get('endTime', timetable.end_time)
    timetable.subject = data.get('subject', timetable.subject)
    timetable.teacher_id = data.get('teacherId', timetable.teacher_id)
    
    db.session.commit()
    return jsonify({
        "id": timetable.id,
        "dayOfWeek": timetable.day_of_week,
        "startTime": str(timetable.start_time),
        "endTime": str(timetable.end_time),
        "subject": timetable.subject,
        "teacherId": timetable.teacher_id
    }), 200


@app.route('/timetable/<int:timetable_id>', methods=['DELETE'])
def delete_timetable(timetable_id):
    timetable = Timetable.query.get(timetable_id)
    if not timetable:
        return jsonify({"error": "Timetable not found"}), 404
    
    db.session.delete(timetable)
    db.session.commit()
    return jsonify({"message": "Timetable deleted successfully"}), 200





@app.route('/mark-attendance', methods=['POST'])
@jwt_required() 
def mark_attendance():
    data = request.get_json()
    
    new_entry = Attendance(
        student_id=data['student_id'],
        date=data['date'],
        status=data['status']
    )
    db.session.add(new_entry)
    db.session.commit()
    return jsonify({"message": "Attendance marked"}), 201

@app.route('/get-attendance', methods=['GET'])
def get_attendance():
    
    date_query = request.args.get('date')
    
    if date_query:
        records = Attendance.query.filter_by(date=date_query).all()
    else:
        records = Attendance.query.all()
        
    return jsonify([r.to_json() for r in records]), 200

@app.route('/')
def index():
    return "Your server is running!"

if __name__ == '__main__':
    app.run(debug=True)
