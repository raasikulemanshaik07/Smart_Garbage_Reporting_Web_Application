import os
from datetime import datetime, timedelta
from functools import wraps
from flask import Flask, request, jsonify, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_jwt_extended import (
    JWTManager, create_access_token, jwt_required, get_jwt_identity,
    get_jwt
)
from flask_cors import CORS
from werkzeug.utils import secure_filename
from PIL import Image # For image validation
from dotenv import load_dotenv # For environment variables
from google.oauth2 import credentials
from google_auth_oauthlib.flow import Flow

# --- 1. INITIAL APP SETUP ---

# Load environment variables from .env file
load_dotenv()

app = Flask(__name__)
CORS(app) # Allow cross-origin requests from your mobile app

# --- Configuration ---
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')
app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL')
app.config['UPLOAD_FOLDER'] = 'uploads' # Folder to store images
app.config['MAX_CONTENT_LENGTH'] = 10 * 1024 * 1024 # 10 MB file size limit
ALLOWED_EXTENSIONS = {'jpg', 'jpeg', 'png'}

# Ensure the upload folder exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# --- Initialize Extensions ---
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)

# --- 2. DATABASE MODELS (User, Report, Feedback) ---

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=True) # Nullable for Google Sign-in
    role = db.Column(db.String(10), nullable=False, default='user') # 'user', 'worker', 'admin'
    warning_count = db.Column(db.Integer, default=0)
    reports = db.relationship('Report', backref='author', lazy=True)
    feedback = db.relationship('Feedback', backref='author', lazy=True)
    google_id = db.Column(db.String(255), unique=True, nullable=True)

    def set_password(self, password):
        self.password_hash = bcrypt.generate_password_hash(password).decode('utf-8')

    def check_password(self, password):
        return bcrypt.check_password_hash(self.password_hash, password)

class Report(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    description = db.Column(db.Text, nullable=False)
    location_lat = db.Column(db.Float, nullable=False)
    location_lon = db.Column(db.Float, nullable=False)
    image_url = db.Column(db.String(255), nullable=False)
    status = db.Column(db.String(20), nullable=False, default='pending') # pending, approved, in_progress, completed, rejected
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    completed_at = db.Column(db.DateTime, nullable=True)
    completion_image_url = db.Column(db.String(255), nullable=True)
    
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    worker_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True) # Assigned worker
    
    feedback = db.relationship('Feedback', backref='report', uselist=False, lazy=True) # One-to-one

class Feedback(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    rating = db.Column(db.Integer, nullable=False) # 1-5 stars
    suggestion = db.Column(db.Text, nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    report_id = db.Column(db.Integer, db.ForeignKey('report.id'), unique=True, nullable=False)

# --- 3. SECURITY & ROLE-BASED ACCESS ---

# Helper function to check file extensions
def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Verifies that a file is a valid image, not just a renamed file.
# This prevents one of the biggest security loopholes.
def validate_image(file_stream):
    try:
        img = Image.open(file_stream)
        img.verify() # Verify it's an image
        # Re-open after verify to check format (verify() closes file)
        file_stream.seek(0)
        img = Image.open(file_stream)
        if img.format.lower() not in ALLOWED_EXTENSIONS:
            return False
        return True
    except Exception as e:
        print(f"Image validation failed: {e}")
        return False

# Custom decorator to require 'admin' role
def admin_required():
    def wrapper(fn):
        @wraps(fn)
        @jwt_required()
        def decorator(*args, **kwargs):
            claims = get_jwt()
            if claims.get('role') == 'admin':
                return fn(*args, **kwargs)
            else:
                return jsonify(msg="Admins only!"), 403 # Forbidden
        return decorator
    return wrapper

# Custom decorator to require 'worker' role
def worker_required():
    def wrapper(fn):
        @wraps(fn)
        @jwt_required()
        def decorator(*args, **kwargs):
            claims = get_jwt()
            if claims.get('role') in ['worker', 'admin']: # Admins can also do worker tasks
                return fn(*args, **kwargs)
            else:
                return jsonify(msg="Workers only!"), 403
        return decorator
    return wrapper

# Tell JWTManager how to load a user from a token
@jwt.user_lookup_loader
def user_lookup_callback(_jwt_header, jwt_data):
    identity = jwt_data["sub"]
    return User.query.get(identity)

# --- 4. AUTHENTICATION ENDPOINTS (Signup, Login, Google) ---

@app.route('/signup', methods=['POST'])
def signup():
    data = request.get_json()
    email = data.get('email')
    username = data.get('username')
    password = data.get('password')

    if not email or not password or not username:
        return jsonify(msg="Missing email, username, or password"), 400

    if User.query.filter_by(email=email).first() or User.query.filter_by(username=username).first():
        return jsonify(msg="Email or username already exists"), 400

    user = User(email=email, username=username)
    user.set_password(password)
    db.session.add(user)
    db.session.commit()

    return jsonify(msg="User created successfully"), 201

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    # Check that both fields exist
    if not email or not password:
        return jsonify(msg="Email and password are required"), 400

    # Look up user by email
    user = User.query.filter_by(email=email).first()

    # Properly verify user existence and password match
    if user is None:
        return jsonify(msg="User not found. Please sign up first."), 404

    if user.password_hash is None:
        return jsonify(msg="This account uses Google login. Please sign in with Google."), 400

    if not user.check_password(password):
        return jsonify(msg="Incorrect password. Please try again."), 401

    # Everything valid — create token
    additional_claims = {"role": user.role}
    access_token = create_access_token(identity=user.id, additional_claims=additional_claims)

    return jsonify(
        msg="Login successful",
        access_token=access_token,
        username=user.username,
        role=user.role
    ), 200


# --- GOOGLE OAUTH STUBS ---
# NOTE: This requires setup in Google Cloud Console to get client_id/secret.
# The flow is complex and requires redirect handling.
# These are placeholders to show the logic.
@app.route('/google/login')
def google_login():
    # This would redirect the user to Google's login page
    # The Kivy app would need to open this URL in a web browser
    return jsonify(msg="Google Login not fully implemented. Redirect to Google auth URL."), 501

@app.route('/google/callback')
def google_callback():
    # Google redirects here with a code.
    # The backend exchanges the code for a user token.
    # It then finds or creates the user in the DB.
    # Finally, it creates a JWT for our app.
    # ... (Complex OAuth 2.0 flow) ...
    # user = User.query.filter_by(google_id=google_user_id).first()
    # if not user:
    #     user = User(email=google_email, username=google_name, google_id=google_user_id)
    #     db.session.add(user)
    #     db.session.commit()
    # access_token = create_access_token(identity=user.id, additional_claims={"role": user.role})
    # return jsonify(access_token=access_token)
    return jsonify(msg="Google Callback not fully implemented."), 501

# --- 5. USER ENDPOINTS (Report, Track, Feedback) ---

@app.route('/report', methods=['POST'])
@jwt_required()
def create_report():
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    
    if 'image' not in request.files:
        return jsonify(msg="No image file part"), 400
        
    file = request.files['image']
    data = request.form
    
    if file.filename == '':
        return jsonify(msg="No selected file"), 400
    
    if not data.get('location_lat') or not data.get('location_lon'):
        return jsonify(msg="Missing location data"), 400
    
    # Security: Validate file extension
    if not allowed_file(file.filename):
        return jsonify(msg="File type not allowed"), 400
        
    # Security: Validate file content
    if not validate_image(file.stream):
         return jsonify(msg="File is not a valid image"), 400
    file.stream.seek(0) # Reset stream after validation
    
    # Security: Sanitize filename
    filename = secure_filename(f"{user_id}_{datetime.utcnow().timestamp()}_{file.filename}")
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file.save(filepath)

    new_report = Report(
        user_id=user.id,
        description=data.get('description'),
        location_lat=float(data.get('location_lat')),
        location_lon=float(data.get('location_lon')),
        image_url=filename # Store only the filename or relative path
    )
    db.session.add(new_report)
    db.session.commit()
    
    return jsonify(msg="Report created successfully", report_id=new_report.id), 201

@app.route('/reports/user', methods=['GET'])
@jwt_required()
def get_user_reports():
    user_id = get_jwt_identity()
    reports = Report.query.filter_by(user_id=user_id).order_by(Report.created_at.desc()).all()
    
    # Serialize data for JSON
    output = []
    for report in reports:
        output.append({
            "id": report.id,
            "description": report.description,
            "image_url": report.image_url,
            "status": report.status,
            "created_at": report.created_at.isoformat()
        })
    return jsonify(reports=output)

@app.route('/feedback', methods=['POST'])
@jwt_required()
def submit_feedback():
    user_id = get_jwt_identity()
    data = request.get_json()
    
    report_id = data.get('report_id')
    rating = data.get('rating')
    
    if not report_id or not rating:
        return jsonify(msg="Missing report_id or rating"), 400
        
    # Check if user is the author of the report
    report = Report.query.get(report_id)
    if not report or report.user_id != user_id:
        return jsonify(msg="Cannot submit feedback for this report"), 403
        
    # Check if feedback already exists
    if Feedback.query.filter_by(report_id=report_id).first():
        return jsonify(msg="Feedback already submitted for this report"), 400

    new_feedback = Feedback(
        user_id=user_id,
        report_id=report_id,
        rating=int(rating),
        suggestion=data.get('suggestion')
    )
    db.session.add(new_feedback)
    db.session.commit()
    
    return jsonify(msg="Feedback submitted successfully"), 201

# --- 6. ADMIN ENDPOINTS (Verify, Assign, etc.) ---

@app.route('/admin/reports', methods=['GET'])
@admin_required()
def get_admin_reports():
    # Admin can filter reports, e.g., by status
    status_filter = request.args.get('status', 'pending') # Default to pending
    
    reports = Report.query.filter_by(status=status_filter).order_by(Report.created_at.asc()).all()
    # In a real app, add pagination (db.paginate)
    
    output = []
    for report in reports:
        output.append({
            "id": report.id,
            "user_email": report.author.email,
            "description": report.description,
            "location_lat": report.location_lat,
            "location_lon": report.location_lon,
            "image_url": report.image_url,
            "created_at": report.created_at.isoformat()
        })
    
    # Also get a list of available workers
    workers = User.query.filter_by(role='worker').all()
    worker_list = [{"id": w.id, "username": w.username} for w in workers]
    
    return jsonify(reports=output, workers=worker_list)

@app.route('/admin/report/<int:report_id>/approve', methods=['PUT'])
@admin_required()
def approve_report(report_id):
    report = Report.query.get_or_404(report_id)
    report.status = 'approved' # Ready for assignment
    db.session.commit()
    # Here you could trigger a notification
    return jsonify(msg="Report approved")

@app.route('/admin/report/<int:report_id>/reject', methods=['DELETE'])
@admin_required()
def reject_report(report_id):
    report = Report.query.get_or_404(report_id)
    
    # Warn the user
    user = report.author
    user.warning_count += 1
    
    # You could set status to 'rejected' or delete it
    # db.session.delete(report) 
    report.status = 'rejected'
    
    # Here you would trigger a notification to the user
    
    db.session.commit()
    return jsonify(msg=f"Report rejected and user {user.email} warned.")

@app.route('/admin/report/<int:report_id>/assign', methods=['PUT'])
@admin_required()
def assign_worker(report_id):
    data = request.get_json()
    worker_id = data.get('worker_id')
    
    if not worker_id:
        return jsonify(msg="Worker ID is required"), 400
        
    report = Report.query.get_or_404(report_id)
    worker = User.query.get(worker_id)
    
    if not worker or worker.role != 'worker':
        return jsonify(msg="Invalid worker ID"), 404
        
    report.worker_id = worker_id
    report.status = 'in_progress'
    db.session.commit()
    
    # Here you would trigger a notification to the worker
    return jsonify(msg=f"Report {report.id} assigned to worker {worker.username}")

# --- 7. WORKER ENDPOINTS (Get Tasks, Complete Task) ---

@app.route('/worker/tasks', methods=['GET'])
@worker_required()
def get_worker_tasks():
    worker_id = get_jwt_identity() # The logged-in worker
    
    # Get all tasks assigned to this worker that are 'in_progress'
    tasks = Report.query.filter_by(
        worker_id=worker_id, 
        status='in_progress'
    ).order_by(Report.created_at.asc()).all()
    
    output = []
    for task in tasks:
        output.append({
            "id": task.id,
            "description": task.description,
            "location_lat": task.location_lat,
            "location_lon": task.location_lon,
            "image_url": task.image_url,
            "user_email": task.author.email
        })
    return jsonify(tasks=output)

@app.route('/worker/task/<int:report_id>/complete', methods=['POST'])
@worker_required()
def complete_task(report_id):
    worker_id = get_jwt_identity()
    report = Report.query.get_or_404(report_id)
    
    # Security check: Does this task belong to this worker?
    if report.worker_id != worker_id:
        return jsonify(msg="This is not your assigned task"), 403
        
    if 'completion_image' not in request.files:
        return jsonify(msg="Completion image is required"), 400
        
    file = request.files['completion_image']
    
    if file.filename == '' or not allowed_file(file.filename) or not validate_image(file.stream):
        return jsonify(msg="Invalid completion image"), 400
    
    file.stream.seek(0)
    filename = secure_filename(f"comp_{worker_id}_{datetime.utcnow().timestamp()}_{file.filename}")
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file.save(filepath)
    
    report.status = 'completed'
    report.completion_image_url = filename
    report.completed_at = datetime.utcnow()
    db.session.commit()
    
    # Here you would trigger a notification to the admin
    # And the admin would then trigger a notification to the user
    
    return jsonify(msg="Task marked as complete")

# --- 8. MAIN EXECUTION ---
if __name__ == '__main__':
    # Creates the database file and tables if they don't exist
    with app.app_context():
        db.create_all()
        
        # Optional: Create a default admin user on first run
        if not User.query.filter_by(email="raasikuleman5312@gmail.com").first(): #<-- CHANGE THIS
                    print("Creating default admin user...")
                    admin_user = User(
                        email="raasikuleman5312@gmail.com",  #<-- CHANGE THIS
                        username="RaasikAdmin",      #<-- CHANGE THIS
                        role="admin"                 #<-- LEAVE THIS
                    )
                    admin_user.set_password("MySuperStrongPassword123") #<-- CHANGE THIS
                    db.session.add(admin_user)
                    db.session.commit()
                    print("Admin user created with email: raasik@myemail.com")

    # host='0.0.0.0' makes it accessible on your local network
    # Your Kivy app (on your phone) can reach it at http://<your-laptop-ip>:5000
    app.run(debug=True, host='0.0.0.0', port=5000)
