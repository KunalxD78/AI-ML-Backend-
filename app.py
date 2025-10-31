from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
import os


app = Flask(__name__)


basedir = os.path.abspath(os.path.dirname(__file__))

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'app.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False


db = SQLAlchemy(app)

migrate = Migrate(app, db)



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
    
    student_id = db.Column(db.Integer, db.ForeignKey('student.id'), nullable=False)

class Timetable(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    day_of_week = db.Column(db.String(20), nullable=False) # e.g., 'Monday'
    start_time = db.Column(db.Time, nullable=False)
    end_time = db.Column(db.Time, nullable=False)
    subject = db.Column(db.String(100), nullable=False)
    
    teacher_id = db.Column(db.Integer, db.ForeignKey('teacher.id'), nullable=True)









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





@app.route('/')
def index():
    return "Your server is running!"

if __name__ == '__main__':
    app.run(debug=True)
