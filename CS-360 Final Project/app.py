from http import client
from django.http import JsonResponse
from flask import Flask, Request, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
import openai
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import URLSafeTimedSerializer, SignatureExpired
from flask_mail import Mail,Message
from flask import jsonify
from flask_cors import CORS
from sqlalchemy import ForeignKey
from sqlalchemy.exc import SQLAlchemyError 
from sqlalchemy.orm import relationship, aliased
from flask import session
from flask import session, jsonify
from flask import request, jsonify, session
from sqlalchemy.exc import IntegrityError
from flask import Flask, request, jsonify, session, redirect, url_for
from flask import Flask, request, jsonify
from openai import OpenAI
import os 
from flask import Flask
import logging
from sqlalchemy.orm import joinedload
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.dialects.mysql import JSON
from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, Index
from sqlalchemy import LargeBinary
from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
from flask import Flask, request, jsonify
from sqlalchemy.exc import SQLAlchemyError
from flask import request, jsonify
from sqlalchemy.exc import SQLAlchemyError




app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:@localhost/annkit' 
app.config['SQLALCHEMY_POOL_RECYCLE'] = 280
app.config['SQLALCHEMY_POOL_TIMEOUT'] = 20
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'b26a1f26980c137eeafde938f8c06310044aedaf15244ae6'
app.config['SECURITY_PASSWORD_SALT'] = '785aa56dace038190a9baad001443d4c144e16b79b924555'
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
app.config['MAIL_USERNAME'] = 'enserproject@gmail.com'
app.config['MAIL_PASSWORD'] = 'ojll eobw bsbu wfuy'
app.config['MAIL_DEFAULT_SENDER'] = 'enserproject@gmail.com'
db = SQLAlchemy(app)
mail = Mail(app)




openai.api_key = os.getenv("OPENAI_API_KEY")

def create_tables():
    db.create_all()


class User(db.Model):
    __tablename__ = 'Users'
    user_id = db.Column(db.Integer, primary_key=True)
    role = db.Column(db.String(255), nullable=False)
    department = db.Column(db.String(255), nullable=True)
    first_name = db.Column(db.String(255), nullable=False)
    last_name = db.Column(db.String(255), nullable=False)
    username = db.Column(db.String(255), unique=True, nullable=False)
    email = db.Column(db.String(255), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)

s = URLSafeTimedSerializer(app.config['SECRET_KEY'])


class Project(db.Model):
    __tablename__ = 'projects'
    project_id = db.Column(db.Integer, primary_key=True)
    community_member_id = db.Column(db.Integer, db.ForeignKey('Users.user_id'), nullable=False)
    project_department = db.Column(db.String(255), nullable=False)  
    title = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text, nullable=False)
    
    # Relationship
    community_member = db.relationship('User', backref=db.backref('projects', lazy=True))




class Notification(db.Model):
    __tablename__ = 'notifications'
    notification_id = db.Column(db.Integer, primary_key=True)
    project_id = db.Column(db.Integer, db.ForeignKey('projects.project_id'), nullable=False)
    recipient_id = db.Column(db.Integer, db.ForeignKey('Users.user_id'), nullable=False)
    sender_id = db.Column(db.Integer, db.ForeignKey('Users.user_id'), nullable=False)
    notification_type = db.Column(db.String(255), nullable=False)  # Types like 'Project Request', 'Syllabus Submission'
    status = db.Column(db.String(255), default='Pending')  # States like 'Pending', 'Accepted', 'Rejected', 'Viewed'
    message = db.Column(db.Text, nullable=True)  # Optional message from the student
    created_at = db.Column(db.DateTime, default=db.func.current_timestamp())
    updated_at = db.Column(db.DateTime, onupdate=db.func.current_timestamp())

    # Relationships
    project = db.relationship('Project', backref='notifications')
    recipient = db.relationship('User', foreign_keys=[recipient_id], backref=db.backref('received_notifications', lazy=True))
    sender = db.relationship('User', foreign_keys=[sender_id], backref=db.backref('sent_notifications', lazy=True))



class Syllabus(db.Model):
    __tablename__ = 'syllabuses'
    syllabus_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    project_id = db.Column(db.Integer, db.ForeignKey('projects.project_id'), nullable=False)
    auto_syllabus = db.Column(db.Text)
    grading_rubric = db.Column(db.JSON)
    
    notification_id = db.Column(db.Integer, db.ForeignKey('notifications.notification_id'), nullable=True)
    created_at = db.Column(db.DateTime, default=db.func.current_timestamp())
    updated_at = db.Column(db.DateTime, onupdate=db.func.current_timestamp())
    

    # Relationships
    notification = db.relationship('Notification', backref='syllabus', foreign_keys=[notification_id])
    project = db.relationship('Project', backref='syllabus')


class Submission(db.Model):
    __tablename__ = 'submissions'
    __table_args__ = (
        db.Index('ix_submissions_notification_id', 'notification_id'),
        db.Index('ix_submissions_student_id', 'student_id'),
        db.Index('ix_submissions_professor_id', 'professor_id'),
    )

    submission_id = db.Column(db.Integer, primary_key=True)
    notification_id = db.Column(db.Integer, db.ForeignKey('notifications.notification_id'), nullable=False)
    student_id = db.Column(db.Integer, db.ForeignKey('Users.user_id'), nullable=False)
    professor_id = db.Column(db.Integer, db.ForeignKey('Users.user_id'), nullable=False)
    file_data = db.Column(LargeBinary)  
    submitted_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, onupdate=datetime.utcnow)
    status = db.Column(db.String(255), default='Submitted', nullable=False)

    # Relationships
    notification = db.relationship('Notification', backref=db.backref('submissions', lazy='joined'))
    student = db.relationship('User', foreign_keys=[student_id], backref=db.backref('sent_submissions', lazy=True))
    professor = db.relationship('User', foreign_keys=[professor_id], backref=db.backref('received_submissions', lazy=True))





class Grade(db.Model):
    __tablename__ = 'grades'
    grade_id = db.Column(db.Integer, primary_key=True)
    submission_id = db.Column(db.Integer, db.ForeignKey('submissions.submission_id'), nullable=False)
    criterion_name = db.Column(db.String(255), nullable=False)
    percentage = db.Column(db.String(10), nullable=False)
    assigned_score = db.Column(db.Numeric(5, 2), nullable=False)
    total_score = db.Column(db.Float) 
    comments = db.Column(db.Text)
    status = db.Column(db.String(50), default='Pending')


class Feedback(db.Model):
    __tablename__ = 'Feedback'
    
    feedback_id = db.Column(db.Integer, primary_key=True)
    submission_id = db.Column(db.Integer, db.ForeignKey('submissions.submission_id'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    
    submission = db.relationship('Submission', backref=db.backref('feedbacks', lazy=True))

    def __repr__(self):
        return f'<Feedback {self.feedback_id} for Submission {self.submission_id}>'
    



app.config['SECRET_KEY'] = 'your_secret_key'

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/registration', methods=['GET', 'POST'])
def registration():
    if request.method == 'POST':
        
        role = request.form.get('role')
        department = request.form.get('department')
        first_name = request.form.get('first_name')
        last_name = request.form.get('last_name')
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        

        hashed_password = generate_password_hash(password)
        new_user = User(role=role, department=department, first_name=first_name, last_name=last_name, 
                         username=username, email=email, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        flash('Registration successful! You are registered as a {}.'.format(role))
        return redirect(url_for('login'))
    return render_template('registration.html')



@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        role = request.form.get('role')

        user = User.query.filter_by(username=username).first()
        
        if user and check_password_hash(user.password, password) and user.role == role:
            session['role'] = user.role
            session['username'] = user.username
            session['user_id'] = user.user_id
            return redirect(url_for('dashboard', role=user.role))
        flash('Invalid credentials or role mismatch. Please try again.')
        return redirect(url_for('login'))

    return render_template('login.html')

@app.route('/<role>')
def dashboard(role):
    valid_roles = ['Student', 'Professor', 'Community']
    if 'role' not in session or session.get('role') != role or role not in valid_roles:
        flash('Please log in to access this dashboard.')
        return redirect(url_for('login'))
    return render_template(f'{role.lower()}.html')



@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        user = User.query.filter_by(email=email).first()
        if user:
            token = s.dumps(email, salt=app.config['SECURITY_PASSWORD_SALT'])
            reset_url = url_for('reset_password', token=token, _external=True)
            msg = Message("Password Reset Request", recipients=[email])
            msg.html = render_template('reset_email.html', reset_url=reset_url)
            mail.send(msg)
            flash('Check your email for the password reset link')
            return redirect(url_for('login'))
        flash('Email not found!')
    return render_template('forgot_password.html')

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    try:
        email = s.loads(token, salt=app.config['SECURITY_PASSWORD_SALT'], max_age=3600)  # Token expires after 1 hour
    except SignatureExpired:
        flash("The reset link is expired.")
        return redirect(url_for('forgot_password'))

    if request.method == 'POST':
        user = User.query.filter_by(email=email).first()
        if not user:
            flash("No user found with this email address.")
            return redirect(url_for('forgot_password'))
        
        password = request.form['password']
        confirm_password = request.form['confirmPassword']
        if password != confirm_password:
            flash("Passwords do not match!")
            return redirect(url_for('reset_password', token=token))
        
        user.password = generate_password_hash(password)
        db.session.commit()
        flash('Your password has been updated!')
        return redirect(url_for('login'))

    return render_template('reset_password.html', token=token)



@app.route('/logout')
def logout():
    session.clear()
    flash('You have been successfully logged out.')
    return redirect(url_for('login')) 



@app.route('/upload_project', methods=['POST'])
def upload_project():
    if 'user_id' not in session or session.get('role') != 'Community':
        return jsonify({'error': 'Unauthorized access'}), 401

   
    data = request.get_json()

    # Extract data from the JSON payload
    # Extract data from the JSON payload
    title = data.get('title')
    description = data.get('description')
    project_department = data.get('project_department')  # Changed from 'department'

    if not all([title, description, project_department]):
        return jsonify({'error': 'Title, description, and project department are required.'}), 400
    new_project = Project(
        community_member_id=session.get('user_id'),
        project_department=project_department,
        title=title,
        description=description
    )

    try:
        db.session.add(new_project)
        db.session.commit()
        return jsonify({'message': 'Project uploaded successfully'}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': 'Error uploading project: {}'.format(e)}), 500


@app.route('/get_uploaded_projects', methods=['GET'])
def get_my_projects():
    app.logger.debug("Attempting to fetch projects")
    user_id = session.get('user_id')
    if not user_id:
        app.logger.warning("Session user_id not found, sending 403 response")
        return jsonify({'error': 'Authentication required'}), 403

    try:
        app.logger.debug(f"Fetching projects for user_id: {user_id}")
        projects = Project.query.filter_by(community_member_id=user_id).all()
        project_list = [{
            'project_id': project.project_id,
            'title': project.title,
            'department': project.project_department,
            'description': project.description
        } for project in projects]
        app.logger.debug("Projects fetched successfully")
        return jsonify(project_list)
    except Exception as e:
        app.logger.error(f"Failed to fetch projects: {str(e)}")
        return jsonify({'error': str(e)}), 500



@app.route('/api/projects/<department>', methods=['GET'])
def get_projects(department):
    projects = Project.query.filter_by(project_department=department).all()
    professors = User.query.filter_by(department=department).all()

    professor_list = [{"id": prof.user_id, "name": f"{prof.first_name} {prof.last_name}"} for prof in professors]

    results = [
        {
            "project_id": project.project_id,
            "title": project.title,
            "description": project.description,
            "professors": professor_list  # Include all professors in each project
        } for project in projects
    ]
    return jsonify(results)



@app.route('/api/apply/<int:project_id>', methods=['POST'])
def apply_to_project(project_id):
    logging.basicConfig(level=logging.DEBUG)
    if 'user_id' not in session:
        logging.error("User ID not found in session")
        return jsonify({'error': 'Authentication required'}), 401
    
    user_id = session['user_id']
    logging.debug(f"Applying with user ID: {user_id}")
    data = request.get_json()
    professor_id = data.get('professorId')

    try:
        notification = Notification(
            project_id=project_id,
            recipient_id=professor_id,
            sender_id=user_id,
            notification_type='Project Request',
            status='Pending',
            message='Student has applied for a project'
        )
        db.session.add(notification)
        db.session.commit()
        logging.info("Notification created successfully")
        return jsonify({'message': 'Application submitted successfully'}), 200
    except Exception as e:
        db.session.rollback()
        logging.error(f"Failed to submit application: {e}")
        return jsonify({'error': 'Failed to submit application: {}'.format(e)}), 500



@app.route('/api/student/delivered_syllabuses', methods=['GET'])
def get_student_delivered_syllabuses():
    print("Session data:", session)
    if 'user_id' not in session or session['role'] != 'Student':
        return jsonify({'error': 'Unauthorized'}), 401

    student_id = session['user_id']
    print(f"Fetching delivered syllabuses for student ID: {student_id}")
    try:
        delivered_syllabuses = Notification.query\
            .join(Project, Notification.project_id == Project.project_id)\
            .join(User, Notification.recipient_id == User.user_id)\
            .filter(Notification.sender_id == student_id, Notification.status == 'Delivered')\
            .add_columns(
                User.first_name.label("professor_first_name"),
                User.last_name.label("professor_last_name"),
                User.user_id.label("professor_id"),
                Project.title,
                Project.description,
                Project.project_department,
                Notification.notification_id
            ).all()

        formatted_syllabuses = [{
            'notification_id': syllabus.notification_id,
            'professor_first_name': syllabus.professor_first_name,
            'professor_last_name': syllabus.professor_last_name,
            'professor_id': syllabus.professor_id,
            'project_title': syllabus.title,
            'project_description': syllabus.description,
            'project_department': syllabus.project_department 
        } for syllabus in delivered_syllabuses]

        return jsonify(formatted_syllabuses)
    except Exception as e:
        app.logger.error(f'Failed to fetch delivered syllabuses for student ID {student_id}: {str(e)}')
        return jsonify({'error': str(e)}), 500

@app.route('/api/syllabus/<int:notification_id>', methods=['GET'])
def get_syllabus_by_id(notification_id):
    try:
        syllabus = Syllabus.query.filter_by(notification_id=notification_id).first()
        if syllabus:
            return jsonify({
                'syllabus_id': syllabus.syllabus_id,
                'auto_syllabus': syllabus.auto_syllabus 
            }), 200
        else:
            return jsonify({'message': 'Syllabus not found'}), 404
    except Exception as e:
        app.logger.error(f'Error fetching syllabus details for notification ID {notification_id}: {str(e)}')
        return jsonify({'error': 'Internal Server Error'}), 500


@app.route('/api/notifications', methods=['GET'])
def get_notifications():
    if 'user_id' not in session or session['role'] != 'Professor':
        return jsonify({'error': 'Unauthorized'}), 401

    professor_id = session['user_id']
    try:
        # Fetch notifications where the logged-in professor is the recipient
        notifications = Notification.query\
            .join(Project, Notification.project_id == Project.project_id)\
            .join(User, Notification.sender_id == User.user_id)\
            .filter(Notification.recipient_id == professor_id, Notification.status == 'Pending')\
            .add_columns(
                User.first_name,
                User.last_name,
                User.user_id,
                Project.title,
                Project.description,
                Notification.notification_id
            ).all()

        formatted_notifications = [{
            'submission_id': notif.notification_id,
            'student_name': f"{notif.first_name} {notif.last_name}",
            'student_id': notif.user_id,
            'project_title': notif.title,
            'project_description': notif.description
        } for notif in notifications]

        return jsonify(formatted_notifications)
    except Exception as e:
        print(e) 
        return jsonify({'error': str(e)}), 500


@app.route('/api/accepted_notifications', methods=['GET'])
def get_accepted_notifications():
    if 'user_id' not in session or session['role'] != 'Professor':
        return jsonify({'error': 'Unauthorized'}), 401

    professor_id = session['user_id']
    try:
        notifications = Notification.query\
            .join(Project, Notification.project_id == Project.project_id)\
            .join(User, Notification.sender_id == User.user_id)\
            .filter(Notification.recipient_id == professor_id, Notification.status == 'Accepted')\
            .add_columns(
                User.first_name,
                User.last_name,
                User.user_id,
                Project.title,
                Project.description,
                Notification.notification_id
            ).all()

        formatted_notifications = [{
            'notification_id': notif.Notification.notification_id,
            'student_first_name': notif.first_name,
            'student_last_name': notif.last_name,
            'student_id': notif.user_id,
            'project_title': notif.title,
            'project_description': notif.description
        } for notif in notifications]

        return jsonify(formatted_notifications)
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    



@app.route('/api/syllabus/<int:notification_id>', methods=['GET'])
def get_syllabus(notification_id):
    try:
        syllabus = Syllabus.query.filter_by(notification_id=notification_id).first()
        if syllabus:
            
            return jsonify({
                'syllabus_id': syllabus.syllabus_id,
                'auto_syllabus': syllabus.auto_syllabus
            }), 200
        else:
            # If no Syllabus entry is found for the notification_id, return an error message
            return jsonify({'message': 'Syllabus not found'}), 404
    except Exception as e:
        # Log the exception and return an internal server error message
        app.logger.error(f'Failed to fetch syllabus for notification ID {notification_id}: {str(e)}')
        return jsonify({'error': 'Internal Server Error'}), 500



@app.route('/api/delivered_submissions', methods=['GET'])
def get_delivered_submissions():
    if 'user_id' not in session or session['role'] != 'Professor':
        return jsonify({'error': 'Unauthorized'}), 401

    professor_id = session['user_id']
    try:
        submissions = Notification.query\
            .join(Project, Notification.project_id == Project.project_id)\
            .join(User, Notification.sender_id == User.user_id)\
            .filter(Notification.recipient_id == professor_id, Notification.status == 'Delivered')\
            .add_columns(
                User.first_name,
                User.last_name,
                User.user_id,
                Project.title,
                Project.description,
                Notification.notification_id
            ).all()

        formatted_submissions = [{
            'notification_id': sub.Notification.notification_id,
            'student_first_name': sub.first_name,
            'student_last_name': sub.last_name,
            'student_id': sub.user_id,
            'project_title': sub.title,
            'project_description': sub.description
        } for sub in submissions]

        return jsonify(formatted_submissions)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/submission/<int:notification_id>', methods=['GET'])
def get_submission(notification_id):
    try:
        syllabus = Syllabus.query.filter_by(notification_id=notification_id).first()
        if syllabus:
            # If a Syllabus entry is found, return the auto_syllabus content
            return jsonify({
                'syllabus_id': syllabus.syllabus_id,
                'auto_syllabus': syllabus.auto_syllabus
            }), 200
        else:
            # If no Syllabus entry is found for the notification_id, return an error message
            return jsonify({'message': 'Submission not found'}), 404
    except Exception as e:
        # Log the exception and return an internal server error message
        app.logger.error(f'Failed to fetch submission for notification ID {notification_id}: {str(e)}')
        return jsonify({'error': 'Internal Server Error'}), 500






@app.route('/dashboard/professor')
def professor_dashboard():
    if 'user_id' not in session or session['role'] != 'Professor':
        flash('Unauthorized access.')
        return redirect(url_for('login'))

    professor_id = session['user_id']
    # Fetching requests that have been accepted by this professor
    accepted_requests = Request.query.filter_by(professor_id=professor_id, status='accepted').all()
    
    syllabuses = [Syllabus.query.filter_by(project_id=req.project_id).first() for req in accepted_requests]
    
    return render_template('professor_dashboard.html', syllabuses=syllabuses)




@app.route('/dashboard/student')
def student_dashboard():
    if 'user_id' not in session or session['role'] != 'Student':
        flash('Unauthorized access.')
        return redirect(url_for('login'))

    student_id = session['user_id']
    # Fetching requests made by this student that have been accepted
    accepted_requests = Request.query.filter_by(student_id=student_id, status='accepted').all()
    
    syllabuses = []
    for req in accepted_requests:
        syllabus = syllabus.query.filter_by(project_id=req.project_id).first()
        if syllabus:
            syllabuses.append(syllabus)
    
    return render_template('student_dashboard.html', syllabuses=syllabuses)



from flask import jsonify, session

from sqlalchemy.exc import SQLAlchemyError

@app.route('/api/accept_notification/<int:notification_id>', methods=['POST'])
def accept_notification(notification_id):
    if 'user_id' not in session or session['role'] != 'Professor':
        return jsonify({'error': 'Unauthorized'}), 401

    notification = Notification.query.get(notification_id)
    if not notification:
        return jsonify({'error': 'Notification not found'}), 404

    notification.status = 'Accepted'
    db.session.commit()

    project = Project.query.get(notification.project_id)
    if not project:
        return jsonify({'error': 'Project not found'}), 404

    syllabus_content, rubric_json = generate_syllabus(project.description)
    if syllabus_content and rubric_json:
        try:
            new_syllabus = Syllabus(
                project_id=project.project_id,
                auto_syllabus=syllabus_content,
                grading_rubric=rubric_json,  
                notification_id=notification_id
            )
            db.session.add(new_syllabus)
            db.session.commit()
            return jsonify({'message': 'Notification accepted and syllabus generated', 'syllabus': syllabus_content, 'rubric': rubric_json})
        except SQLAlchemyError as e:
            db.session.rollback()
            return jsonify({'error': f'Database error: {str(e)}'}), 500
    else:
        return jsonify({'error': 'Failed to generate syllabus'}), 500





@app.route('/api/rubric/<int:syllabus_id>', methods=['GET', 'POST'])
def handle_rubric(syllabus_id):
    syllabus = Syllabus.query.get(syllabus_id)
    if not syllabus:
        return jsonify({'error': 'Syllabus not found'}), 404

    if request.method == 'GET':
        # Return the rubric as a JSON object
        return jsonify(json.loads(syllabus.grading_rubric))

    if request.method == 'POST':
        # Update the rubric with new data from the request
        data = request.get_json()
        syllabus.grading_rubric = json.dumps(data['rubric'])
        db.session.commit()
        return jsonify({'message': 'Rubric updated successfully'}), 200



import json
import openai



def generate_syllabus(description):
    openai.api_key = os.getenv("OPENAI_API_KEY")

    prompt = (
         f"Generate a syllabus and grading rubric based on the following project description:\n\n"
        f"{description}\n\n"
        "Very strictly provide the grading rubric strictly in two formats with same criteria but with two different names Grading Rubric: and Grading System:"
        "The one most important thing is that you should include both Grading Rubric: and Grading System: "
        "1) strictly  include a clear and structured having topic 'Grading Rubric:' at the end of the syllabus that lists the evaluation criteria with their descriptions and percentage weights formatted as follows: 'Criteria Name: Description - Weight'"
        "2) Strictly add general view of grading rubric that can be included directly in the syllabus text strictly having heading name 'Grading system:'."
        "Generate a syllabus for a 12-week period with little description for each week with 3 credits earned."
        
       
        
    )

    try:
        response = openai.completions.create(
            model="gpt-3.5-turbo-instruct",
            prompt=prompt,
            temperature=0.5,
            max_tokens=3600,
            top_p=1.0,
            frequency_penalty=0.0,
            presence_penalty=0.0
        )
        syllabus_text = response.choices[0].text.strip()

        # Explicitly look for a JSON-like rubric structure in the output
        marker = "Grading Rubric:"
        if marker in syllabus_text:
            rubric_start = syllabus_text.index(marker) + len(marker)
            rubric_text = syllabus_text[rubric_start:].strip()
            syllabus_text = syllabus_text[:rubric_start - len(marker)].strip()

            formatted_rubric = "Grading Rubric:\n" + rubric_text
            syllabus_content = syllabus_text + "\n\n" + formatted_rubric
            rubric_json = parse_rubric_to_json(rubric_text)
            return syllabus_text, json.dumps(rubric_json)
        else:
            # Return the syllabus without rubric if not found
            return syllabus_text, json.dumps({"error": "Rubric section not found in the generated syllabus."})
    except Exception as e:
        print(f"Error generating syllabus: {e}")
        return "", json.dumps({"error": str(e)})


def parse_rubric_to_json(rubric_text):
    """
    Parse a formatted string of rubric details into a JSON-compatible dictionary.

    Expected format for each line in rubric_text:
    "Criterion Name: Description - Weight"

    Args:
    rubric_text (str): Plain text containing rubric information.

    Returns:
    dict: A dictionary with a single key "criteria" that maps to a list of criterion dictionaries.
    """
    criteria = []
    lines = rubric_text.split('\n')
    for line in lines:
        # Split each line into parts by " - ", which divides the name/description from the weight
        parts = line.split(" - ")
        if len(parts) == 2:
            # Further split the first part by ": " to separate the name and description
            name_description = parts[0].split(": ")
            if len(name_description) == 2:
                criterion = {
                    "name": name_description[0].strip(),
                    "description": name_description[1].strip(),
                    "weight": parts[1].strip()
                }
                criteria.append(criterion)

    return {"criteria": criteria}



@app.route('/api/update_syllabus/<int:notification_id>', methods=['POST'])
def update_syllabus(notification_id):
    # Extract the new syllabus content from the request
    data = request.get_json()
    auto_syllabus = data.get('auto_syllabus')

    if not auto_syllabus:
        return jsonify({'error': 'No syllabus content provided'}), 400

    # Retrieve the existing syllabus entry associated with the notification_id
    syllabus = Syllabus.query.filter_by(notification_id=notification_id).first()
    if not syllabus:
        return jsonify({'message': 'Syllabus not found'}), 404

    # Update the syllabus content
    try:
        syllabus.auto_syllabus = auto_syllabus
        db.session.commit()
        return jsonify({'message': 'Syllabus updated successfully'}), 200
    except Exception as e:
        db.session.rollback()
        app.logger.error(f'Error updating syllabus for notification ID {notification_id}: {str(e)}')
        return jsonify({'error': 'Internal Server Error'}), 500



@app.route('/api/change_notification_status/<notification_id>', methods=['POST'])
def change_notification_status(notification_id):
    data = request.get_json()
    notification = Notification.query.get(notification_id)
    if notification:
        notification.status = data.get('status', 'Delivered')  # Default to 'Delivered' if not specified
        db.session.commit()
        return jsonify({'message': 'Notification status updated successfully'}), 200
    else:
        return jsonify({'message': 'Notification not found'}), 404



from flask import Flask, request, jsonify
from werkzeug.utils import secure_filename

def allowed_file(filename):
    ALLOWED_EXTENSIONS = {'pdf'} 
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/api/submit_project', methods=['POST'])
def submit_project():
    notification_id = request.form['notification_id']
    file = request.files['file']
    if file and allowed_file(file.filename):
        try:
            student_id = Notification.query.get(notification_id).sender_id
            professor_id = Notification.query.get(notification_id).recipient_id

            # Read the file's content into memory
            file_content = file.read()

            # Save submission details directly to the database
            new_submission = Submission(
                notification_id=notification_id,
                student_id=student_id,
                professor_id=professor_id,
                file_data=file_content,  # Store the file data directly as binary
                status='Submitted'
            )
            db.session.add(new_submission)
            db.session.commit()

          

            return jsonify({'message': 'File uploaded and submission recorded successfully'}), 200
        except Exception as e:
            db.session.rollback()
            app.logger.error(f'Error during submission: {str(e)}')
            return jsonify({'error': 'Failed to process submission'}), 500

    return jsonify({'error': 'Invalid file'}), 400


from flask import Flask, request, session, send_file, jsonify
from io import BytesIO


@app.route('/api/get_submissions')
def get_submissions():
    professor_id = session.get('user_id')  
    if not professor_id:
        return jsonify({'error': 'User not logged in'}), 401

    submissions = Submission.query.join(
        Notification, Notification.notification_id == Submission.notification_id
    ).join(
        User, User.user_id == Submission.student_id
    ).join(
        Project, Project.project_id == Notification.project_id
    ).filter(
        Submission.professor_id == professor_id
    ).all()

    result = []
    for sub in submissions:
        result.append({
            'student_name': f'{sub.student.first_name} {sub.student.last_name}',
            'student_id': sub.student.user_id,  # Include student ID
            'project_title': sub.notification.project.title,
            'project_description': sub.notification.project.description,
            'submission_id': sub.submission_id
        })

    return jsonify(result)


@app.route('/api/view_pdf/<int:submission_id>')
def view_pdf(submission_id):
    submission = Submission.query.get(submission_id)
    if not submission:
        return jsonify({'error': 'Submission not found'}), 404
#
    file_data = BytesIO(submission.file_data)  
    return send_file(
        file_data,
        mimetype='application/pdf',
        as_attachment=False  
    )






from flask import jsonify
import json

@app.route('/api/get_rubric_by_submission/<int:submission_id>', methods=['GET'])
def get_rubric_by_submission(submission_id):
    try:
        submission = Submission.query.get(submission_id)
        if not submission:
            return jsonify({'error': 'Submission not found'}), 404

        syllabus = Syllabus.query.filter_by(notification_id=submission.notification_id).first()
        if not syllabus:
            return jsonify({'error': 'Syllabus not found'}), 404

        # Check if grading_rubric exists and is a valid JSON string
        if syllabus.grading_rubric:
            # Parse the JSON string in grading_rubric to a Python dictionary
            grading_rubric = json.loads(syllabus.grading_rubric)
            return jsonify(grading_rubric), 200
        else:
            return jsonify({'error': 'Grading rubric not found'}), 404

    except Exception as e:
        app.logger.error(f'Error fetching grading rubric for submission ID {submission_id}: {str(e)}')
        return jsonify({'error': 'Internal Server Error'}), 500







@app.route('/api/process_syllabus', methods=['POST'])
def process_syllabus():
    data = request.get_json()
    syllabus_text = data.get('syllabus_text')

    if not syllabus_text:
        return jsonify({'error': 'Syllabus text is required.'}), 400

    try:
        # Define the start of the rubric section
        rubric_start_keyword = "Grading Rubric:"
        rubric_start_index = syllabus_text.find(rubric_start_keyword)

        if rubric_start_index == -1:
            # Rubric section not found
            return jsonify({
                'error': 'Grading rubric section not found in the syllabus text.'
            }), 404

        # Extract the rubric text
        rubric_text = syllabus_text[rubric_start_index + len(rubric_start_keyword):].strip()

        syllabus_without_rubric = syllabus_text[:rubric_start_index].strip()

        # Parsing the rubric into JSON
        rubric_json_response = parse_rubric_from_text(rubric_text)
        if rubric_json_response.status_code != 200:
            return rubric_json_response

        # Return both the cleaned syllabus and the parsed rubric JSON
        return jsonify({
            'syllabus_text': syllabus_without_rubric,
            'rubric_json': rubric_json_response.json()
        }), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500







@app.route('/api/parse_rubric', methods=['POST'])
def parse_rubric():
    data = request.get_json()
    rubric_text = data.get('rubric_text')

    if not rubric_text:
        return jsonify({'error': 'Rubric text is required.'}), 400

    try:
        # Initialize the JSON structure
        rubric_json = []

        # Split the text into lines assuming each line contains one criterion
        lines = rubric_text.split('\n')
        for line in lines:
            # Trim whitespace and ignore empty lines
            line = line.strip()
            if not line:
                continue
            
            # Assuming each line follows the format: "Criterion: Description - Max Points"
            parts = line.split('-')
            if len(parts) != 2:
                continue  

            criterion_info, max_points = [part.strip() for part in parts]

            # Further split to separate the criterion name and its description
            if ':' not in criterion_info:
                continue  # Skip if no colon is present

            criterion_name, description = [part.strip() for part in criterion_info.split(':', 1)]

            # Try parsing max points as an integer or float, skip if not possible
            try:
                max_points = float(max_points)  # Assuming max points can be a decimal
            except ValueError:
                continue  # Skip if max points is not a number

            # Append the parsed criterion to the rubric list
            rubric_json.append({
                'criteria': criterion_name,
                'description': description,
                'maxScore': max_points
            })

        if not rubric_json:  # Check if any criteria were parsed successfully
            return jsonify({'error': 'No valid rubric entries were found.'}), 400

        return jsonify(rubric_json), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500





@app.route('/api/submit_grades', methods=['POST'])
def submit_grades():
    if 'role' in session and session['role'] != 'Professor':
        return jsonify({'error': 'Unauthorized'}), 403

    data = request.get_json()
    submission_id = data.get('submission_id')
    if not submission_id:
        return jsonify({'error': 'Submission ID is missing'}), 400

    try:
        total_score = sum(float(grade['assigned_score']) for grade in data.get('grades', []) if grade.get('assigned_score'))
        for grade_info in data.get('grades', []):
            grade = Grade(
                submission_id=submission_id,
                criterion_name=grade_info.get('criterion_name'),
                percentage=grade_info.get('percentage'),
                assigned_score=grade_info.get('assigned_score'),
                total_score=total_score,  # Add the total score to each grade
                comments=grade_info.get('feedback', ''),
                status='Pending'
            )
            db.session.add(grade)

        submission = Submission.query.filter_by(submission_id=submission_id).first()
        if submission:
            submission.status = 'Graded'  # Set submission status to 'Graded'
        else:
            db.session.rollback()  # Rollback if no submission found
            return jsonify({'error': 'Submission not found'}), 404

        db.session.commit()
        return jsonify({'message': 'Grades submitted successfully', 'total_score': total_score}), 200
    except Exception as e:  # Use a general exception to catch any errors not just SQLAlchemyError
        db.session.rollback()
        return jsonify({'error': str(e)}), 500
    





@app.route('/api/graded_projects', methods=['GET'])
def get_graded_projects():
    # Check if user is logged in and is a student
    if 'user_id' not in session or session['role'] != 'Student':
        return jsonify({'error': 'Unauthorized'}), 401

    student_id = session['user_id']
    try:
        # Fetch notifications related to the logged-in student where submissions are graded
        graded_submissions = db.session.query(
            Submission.submission_id,  # Include submission_id in the query
            User.first_name.label('professor_first_name'),
            User.last_name.label('professor_last_name'),
            Project.project_department,
            Project.title.label('project_title'),
            Project.description
        ).join(Notification, Notification.notification_id == Submission.notification_id) \
          .join(User, User.user_id == Notification.recipient_id) \
          .join(Project, Project.project_id == Notification.project_id) \
          .filter(Notification.sender_id == student_id, Submission.status == 'Graded') \
          .all()

        # Prepare data for JSON response
        graded_projects = [{
            'submission_id': submission.submission_id,  
            'professor_first_name': submission.professor_first_name,
            'professor_last_name': submission.professor_last_name,
            'project_department': submission.project_department,
            'project_title': submission.project_title,
            'description': submission.description,
            'actions': 'View Result'  # Updated action text to match your frontend requirement
        } for submission in graded_submissions]

        return jsonify(graded_projects)
    except Exception as e:
        app.logger.error(f'Error fetching graded projects for student ID {student_id}: {str(e)}')
        return jsonify({'error': 'Internal Server Error'}), 500




@app.route('/api/grades/<int:submission_id>', methods=['GET'])
def get_grades(submission_id):
    try:
        grades = Grade.query.filter_by(submission_id=submission_id).all()
        if not grades:
            return jsonify({'message': 'No grades found'}), 404

        grades_data = [{
            'criterion_name': grade.criterion_name,
            'percentage': grade.percentage,
            'assigned_score': str(grade.assigned_score),
            'total_score': float(grade.total_score) if grade.total_score is not None else None,
            'comments': grade.comments
        } for grade in grades]

        return jsonify(grades_data), 200
    except Exception as e:
        app.logger.error(f"Error fetching grades for submission ID {submission_id}: {str(e)}")
        return jsonify({'error': 'Internal Server Error'}), 500





@app.route('/api/reject_notification/<int:notification_id>', methods=['POST'])
def reject_notification(notification_id):
    try:
        notification = Notification.query.filter_by(notification_id=notification_id).first()
        if notification:
            notification.status = 'Rejected'
            db.session.commit()
            return jsonify({'message': 'Request rejected'}), 200
        else:
            return jsonify({'message': 'Notification not found'}), 404
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    



@app.route('/api/student/rejected_notifications', methods=['GET'])
def get_rejected_notifications():
    if 'user_id' not in session:
        return jsonify({'error': 'Authentication required'}), 401

    student_id = session['user_id']
    try:
        rejected_notifications = Notification.query.join(Project, Notification.project_id == Project.project_id)\
            .join(User, Notification.recipient_id == User.user_id)\
            .filter(Notification.sender_id == student_id, Notification.status == 'Rejected')\
            .add_columns(
                User.first_name.label("professor_first_name"),
                User.last_name.label("professor_last_name"),
                User.user_id.label("professor_id"),
                Project.title,
              
                Project.project_department,
                Notification.notification_id
            ).all()

        results = [{
            'notification_id': n.Notification.notification_id,
            'professor_first_name': n.professor_first_name,
            'professor_last_name': n.professor_last_name,
            'professor_id': n.professor_id,
            'project_title': n.title,
            
            'project_department': n.project_department,
            'actions': 'Decision'
        } for n in rejected_notifications]

        return jsonify(results)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

    




from sqlalchemy.orm import aliased
Student = aliased(User, name='student')
Professor = aliased(User, name='professor')

@app.route('/get-feedback-data', methods=['GET'])
def get_feedback_data():
    data = db.session.query(
        Submission.submission_id,  # Include submission_id
        Student.first_name.label('student_first_name'),
        Student.last_name.label('student_last_name'),
        Professor.first_name.label('professor_first_name'),
        Professor.last_name.label('professor_last_name'),
        Project.title.label('project_title')
    ).select_from(Submission) \
     .join(Notification, Submission.notification_id == Notification.notification_id) \
     .join(Student, Notification.sender_id == Student.user_id) \
     .join(Professor, Notification.recipient_id == Professor.user_id) \
     .join(Project, Notification.project_id == Project.project_id) \
     .filter(Submission.status == 'graded') \
     .all()

    results = [{
        'submission_id': record.submission_id,  # Pass this to frontend
        'student_name': f"{record.student_first_name} {record.student_last_name}",
        'professor_name': f"{record.professor_first_name} {record.professor_last_name}",
        'project_title': record.project_title
    } for record in data]

    return jsonify(results)


@app.route('/api/serve_pdf/<int:submission_id>')
def serve_pdf(submission_id):
  submission = Submission.query.get(submission_id)
  if not submission:
    return jsonify({'error': 'Submission not found'}), 404

  if not submission.file_data:
    return jsonify({'error': 'No file data available'}), 404

  file_data = BytesIO(submission.file_data)
  return send_file(
      file_data,
      mimetype='application/pdf',
      as_attachment=False  # Allows PDF to be displayed directly
  )


from flask import request, jsonify
from datetime import datetime

@app.route('/submit-feedback', methods=['POST'])
def submit_feedback():
    try:
        submission_id = request.json.get('submission_id')
        content = request.json.get('content')

        # Check if the submission exists
        if not submission_id or not content:
            return jsonify({'error': 'Submission ID and content are required'}), 400

        submission = Submission.query.get(submission_id)
        if not submission:
            return jsonify({'error': 'Invalid submission ID'}), 404

        feedback = Feedback(
            submission_id=submission_id,
            content=content
        )

        db.session.add(feedback)
        db.session.commit()
        return jsonify({'message': 'Feedback submitted successfully'}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500



@app.route('/get-feedback-for-submission/<int:submission_id>', methods=['GET'])
def get_feedback_for_submission(submission_id):
    feedbacks = Feedback.query.filter_by(submission_id=submission_id).all()
    if not feedbacks:
        return jsonify({'message': 'No feedback found'}), 404

    feedback_list = [{
        'content': feedback.content,
        'created_at': feedback.created_at.strftime('%Y-%m-%d %H:%M:%S')
    } for feedback in feedbacks]
    
    return jsonify(feedback_list)




if __name__ == '__main__':
    app.run(debug=True)