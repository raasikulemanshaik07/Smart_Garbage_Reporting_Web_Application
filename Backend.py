import os
from datetime import datetime, timedelta
from functools import wraps
import random  # --- ADDED for OTP generation ---
from flask import Flask, request, jsonify, redirect, url_for, render_template, session, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import func, distinct
from flask_bcrypt import Bcrypt
from flask_jwt_extended import (
    JWTManager, create_access_token, jwt_required, get_jwt_identity,
    get_jwt
)
from flask_cors import CORS
from werkzeug.utils import secure_filename
from PIL import Image # For image validation
from dotenv import load_dotenv # For environment variables

# --- 1. INITIAL APP SETUP ---
load_dotenv()
app = Flask(__name__, template_folder='templates')
CORS(app) 

# --- Configuration ---
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'default_secret_key_fallback')
app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY', 'default_jwt_key_fallback')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///garbage_app.db')
app.config['UPLOAD_FOLDER'] = 'uploads' 
app.config['MAX_CONTENT_LENGTH'] = 10 * 1024 * 1024 # 10 MB file size limit
ALLOWED_EXTENSIONS = {'jpg', 'jpeg', 'png'}

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# --- Initialize Extensions ---
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)

# --- 2. DATABASE MODELS (User, Report, Feedback) ---

# --- Association Table for Many-to-Many relationship ---
report_assignments = db.Table('report_assignments',
    db.Column('report_id', db.Integer, db.ForeignKey('report.id'), primary_key=True),
    db.Column('worker_id', db.Integer, db.ForeignKey('user.id'), primary_key=True)
)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    # --- MODIFIED: Changed nullable to True ---
    email = db.Column(db.String(120), unique=True, nullable=True)
    username = db.Column(db.String(80), unique=True, nullable=True)
    password_hash = db.Column(db.String(128), nullable=True) 
    role = db.Column(db.String(10), nullable=False, default='user') # 'user', 'worker', 'admin'
    warning_count = db.Column(db.Integer, default=0)
    zone = db.Column(db.String(50), nullable=True) 
    
    # --- ADDED: Gamification Points ---
    points = db.Column(db.Integer, default=0)
    
    # --- ADDED: Phone Verification ---
    phone_number = db.Column(db.String(15), unique=True, nullable=True)
    phone_verified = db.Column(db.Boolean, default=False, nullable=False)
    otp = db.Column(db.String(6), nullable=True)
    otp_expiry = db.Column(db.DateTime, nullable=True)
    
    reports = db.relationship('Report', backref='author', lazy=True, foreign_keys='Report.user_id')
    feedback = db.relationship('Feedback', backref='author', lazy=True, foreign_keys='Feedback.user_id')
    google_id = db.Column(db.String(255), unique=True, nullable=True)

    def set_password(self, password):
        self.password_hash = bcrypt.generate_password_hash(password).decode('utf-8')

    def check_password(self, password):
        if self.password_hash is None:
            return False
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
    zone = db.Column(db.String(50), nullable=True) 
    
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    
    feedback = db.relationship('Feedback', backref='report', uselist=False, lazy=True) 

    assigned_workers = db.relationship('User', secondary=report_assignments, lazy='subquery',
        backref=db.backref('assigned_tasks', lazy='dynamic'))

class Feedback(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    rating = db.Column(db.Integer, nullable=False) # 1-5 stars
    suggestion = db.Column(db.Text, nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    report_id = db.Column(db.Integer, db.ForeignKey('report.id'), unique=True, nullable=False)

# --- 3. SECURITY & HELPER FUNCTIONS ---

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def validate_image(file_stream):
    try:
        img = Image.open(file_stream)
        img.verify() 
        file_stream.seek(0)
        img = Image.open(file_stream) 
        if img.format.lower() not in ALLOWED_EXTENSIONS:
            return False
        return True
    except Exception as e:
        print(f"Image validation failed: {e}")
        return False

def determine_zone(lat, lon):
    if (lat > 9.5 and lat < 9.6) and (lon > 77.6 and lon < 77.7):
        return "City1_Zone" # Krishnankovil
    elif (lat > 12.9 and lat < 13.2) and (lon > 80.1 and lon < 80.3):
        return "City2_Zone" # Chennai
    else:
        return "Default_Zone" 

def admin_required():
    def wrapper(fn):
        @wraps(fn)
        @jwt_required()
        def decorator(*args, **kwargs):
            claims = get_jwt()
            if claims.get('role') == 'admin':
                return fn(*args, **kwargs)
            else:
                return jsonify(msg="Admins only!"), 403
        return decorator
    return wrapper

def worker_required():
    def wrapper(fn):
        @wraps(fn)
        @jwt_required()
        def decorator(*args, **kwargs):
            claims = get_jwt()
            if claims.get('role') in ['worker', 'admin']:
                return fn(*args, **kwargs)
            else:
                return jsonify(msg="Workers only!"), 403
        return decorator
    return wrapper

@jwt.user_lookup_loader
def user_lookup_callback(_jwt_header, jwt_data):
    identity = jwt_data["sub"]
    return User.query.get(int(identity))
    
# --- 4. HTML PAGE SERVING (Frontend Routes) ---

@app.route('/uploads/<filename>')
def get_image(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/')
def index():
    return render_template('login.html')

@app.route('/login')
def login_page():
    return render_template('login.html')

@app.route('/signup')
def signup_page():
    return render_template('signup.html')

@app.route('/dashboard')
def dashboard_page():
    return render_template('dashboard.html')

@app.route('/report')
def report_page():
    return render_template('report.html')

@app.route('/track')
def track_page():
    return render_template('track.html')

@app.route('/feedback')
def feedback_page():
    return render_template('feedback.html')

@app.route('/admin')
def admin_page():
    return render_template('admin.html') 

@app.route('/worker')
def worker_page():
    return render_template('worker.html') 

@app.route('/admin_dashboard')
def admin_dashboard_page():
    return render_template('admin_dashboard.html') 

@app.route('/profile')
def profile_page():
    return render_template('profile.html') 

@app.route('/worker_profile')
def worker_profile_page():
    return render_template('worker_profile.html') 

@app.route('/admin_profile')
def admin_profile_page():
    return render_template('admin_profile.html')

@app.route('/manage_workers')
def manage_workers_page():
    return render_template('manage_workers.html') 

@app.route('/awareness')
def awareness_page():
    return render_template('awareness.html') 

@app.route('/admin_feedback')
def admin_feedback_page():
    return render_template('admin_feedback.html')


# --- 5. API ENDPOINTS (Backend Logic) ---

@app.route('/api/signup', methods=['POST'])
def api_signup():
    data = request.get_json()
    email = data.get('email')
    username = data.get('username')
    password = data.get('password')
    phone_number = data.get('phone_number') # --- ADDED ---

    if not email or not password or not username or not phone_number: # --- MODIFIED ---
        return jsonify(msg="Missing email, username, password, or phone number"), 400

    # --- MODIFIED: Check if email/username are already taken ---
    if User.query.filter_by(email=email).first():
        return jsonify(msg="Email already exists"), 409
    if User.query.filter_by(username=username).first():
        return jsonify(msg="Username already exists"), 409

    # --- MODIFIED: Find user by phone and check verification ---
    user = User.query.filter_by(phone_number=phone_number).first()
    
    if not user:
        return jsonify(msg="Phone number not found. Please send OTP first."), 404
    
    if not user.phone_verified:
        return jsonify(msg="Phone number is not verified. Please verify with OTP."), 403
    
    if user.email is not None: # Check if account is already fully registered
        return jsonify(msg="This phone number is already registered."), 409
    # --- END MODIFIED ---

    # --- MODIFIED: Update the existing user record ---
    user.email = email
    user.username = username
    user.set_password(password)
    # db.session.add(user) # User already exists from phone verification
    db.session.commit()

    return jsonify(msg="User created successfully"), 201

@app.route('/api/login', methods=['POST'])
def api_login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    if not email or not password:
        return jsonify(msg="Email and password are required"), 400

    user = User.query.filter_by(email=email).first()

    if user is None:
        return jsonify(msg="User not found. Please sign up first."), 404

    if user.password_hash is None:
        return jsonify(msg="This account uses Google login. Please sign in with Google."), 400

    if not user.check_password(password):
        return jsonify(msg="Incorrect password. Please try again."), 401

    additional_claims = {"role": user.role, "zone": user.zone}
    access_token = create_access_token(identity=str(user.id), additional_claims=additional_claims)

    redirect_url = '/dashboard' # Default for 'user'
    if user.role == 'admin':
        redirect_url = '/admin_dashboard'
    elif user.role == 'worker':
        redirect_url = '/worker'

    return jsonify(
        msg="Login successful",
        access_token=access_token,
        username=user.username,
        email=user.email, 
        role=user.role,
        redirect=redirect_url
    ), 200

@app.route('/api/change-password', methods=['POST'])
@jwt_required()
def change_password():
    user_id_str = get_jwt_identity()
    user = User.query.get(int(user_id_str))
    
    data = request.get_json()
    current_password = data.get('current_password')
    new_password = data.get('new_password')

    if not user or not user.check_password(current_password):
        return jsonify(msg="Current password is incorrect"), 401
    
    if len(new_password) < 8:
        return jsonify(msg="New password must be at least 8 characters"), 400

    user.set_password(new_password)
    db.session.commit()
    
    return jsonify(msg="Password updated successfully"), 200
    
@app.route('/api/dashboard-stats', methods=['GET'])
@jwt_required() 
def get_dashboard_stats():
    try:
        completed_count = Report.query.filter_by(status='completed').count()
        
        rejected_count = Report.query.filter_by(status='rejected').count()
        total_handled = completed_count + rejected_count
        success_rate = (completed_count / total_handled * 100) if total_handled > 0 else 100 
        
        avg_time_days = db.session.query(
            func.avg(func.julianday(Report.completed_at) - func.julianday(Report.created_at))
        ).filter(Report.status == 'completed', Report.completed_at != None).scalar()
        
        avg_response_hours = (avg_time_days * 24) if avg_time_days else 24 
        
        cities_covered = db.session.query(func.count(Report.zone.distinct())).scalar()

        return jsonify({
            "complaints_resolved": completed_count,
            "success_rate": round(success_rate, 1),
            "avg_response_time": round(avg_response_hours, 1),
            "cities_covered": cities_covered
        }), 200

    except Exception as e:
        print(f"Error getting dashboard stats: {e}")
        return jsonify(msg="Could not load dashboard stats"), 500


# --- USER API ENDPOINTS ---

@app.route('/api/report', methods=['POST'])
@jwt_required()
def create_report():
    user_id = int(get_jwt_identity())
    
    if 'image' not in request.files:
        return jsonify(msg="No image file part"), 400
        
    file = request.files['image']
    data = request.form
    
    if file.filename == '':
        return jsonify(msg="No selected file"), 400
    
    if not data.get('location_lat') or not data.get('location_lon'):
        return jsonify(msg="Missing location data"), 400
    
    if not allowed_file(file.filename):
         return jsonify(msg="File type not allowed"), 400
         
    if not validate_image(file.stream):
         return jsonify(msg="File is not a valid image"), 400
    file.stream.seek(0)
    
    filename = secure_filename(f"{user_id}_{datetime.utcnow().timestamp()}_{file.filename}")
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file.save(filepath)

    lat = float(data.get('location_lat'))
    lon = float(data.get('location_lon'))
    
    report_zone = determine_zone(lat, lon)

    new_report = Report(
        user_id=user_id,
        description=data.get('description'),
        location_lat=lat,
        location_lon=lon,
        image_url=filename,
        zone=report_zone 
    )
    db.session.add(new_report)
    db.session.commit()
    
    return jsonify(msg="Report created successfully", report_id=new_report.id), 201

@app.route('/api/reports/user', methods=['GET'])
@jwt_required()
def get_user_reports():
    user_id = int(get_jwt_identity())
    reports = Report.query.filter_by(user_id=user_id).order_by(Report.created_at.desc()).all()
    
    output = []
    for report in reports:
        output.append({
            "id": report.id,
            "description": report.description,
            "image_url": report.image_url,
            "status": report.status,
            "created_at": report.created_at.isoformat(),
            "has_feedback": report.feedback is not None
        })
    return jsonify(reports=output)

@app.route('/api/feedback', methods=['POST'])
@jwt_required()
def submit_feedback():
    user_id = int(get_jwt_identity())
    data = request.get_json()
    
    report_id = data.get('report_id')
    rating = data.get('rating')
    
    if not report_id or not rating:
        return jsonify(msg="Missing report_id or rating"), 400
        
    report = Report.query.get(report_id)
    if not report or report.user_id != user_id:
        return jsonify(msg="Cannot submit feedback for this report"), 403
        
    if report.status != 'completed':
         return jsonify(msg="Cannot submit feedback for an incomplete report"), 400
         
    if report.feedback:
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

# --- ADDED: API Endpoints for Gamification ---

@app.route('/api/user/stats', methods=['GET'])
@jwt_required()
def get_user_stats():
    """
    Get the current user's points and total reports submitted.
    """
    user_id = int(get_jwt_identity())
    user = User.query.get(user_id)
    
    if not user:
        return jsonify(msg="User not found"), 404
        
    # Get total approved reports
    report_count = Report.query.filter_by(user_id=user_id, status='approved').count()
    completed_count = Report.query.filter_by(user_id=user_id, status='completed').count()
    total_valid_reports = report_count + completed_count

    return jsonify({
        "points": user.points or 0,
        "report_count": total_valid_reports
    }), 200

@app.route('/api/leaderboard', methods=['GET'])
@jwt_required()
def get_leaderboard():
    """
    Get the top 10 users by points and the current user's rank.
    """
    current_user_id = int(get_jwt_identity())
    
    # Get Top 10 users
    top_users = User.query.filter_by(role='user').order_by(User.points.desc()).limit(10).all()
    leaderboard_data = [{"username": u.username, "points": u.points} for u in top_users]
    
    # Get current user's rank
    # Create a subquery that ranks all users
    rank_subquery = db.session.query(
        User.id,
        func.rank().over(order_by=User.points.desc()).label('rank')
    ).filter_by(role='user').subquery()

    # Query the subquery to find the rank for the specific user
    user_rank_result = db.session.query(rank_subquery.c.rank).filter(rank_subquery.c.id == current_user_id).first()
    
    current_user_rank = user_rank_result[0] if user_rank_result else None

    return jsonify({
        "leaderboard": leaderboard_data,
        "user_rank": current_user_rank
    }), 200

# --- ADDED: Phone Verification API Endpoints ---

@app.route('/api/send-otp', methods=['POST'])
def send_otp():
    data = request.get_json()
    phone_number = data.get('phone_number')

    if not phone_number or len(phone_number) != 10 or not phone_number.isdigit():
        return jsonify(msg="Invalid Indian phone number. Must be 10 digits."), 400

    # Check if this phone is already in use by a *fully registered* user
    existing_user = User.query.filter(
        User.phone_number == phone_number,
        User.email != None
    ).first()
    if existing_user:
        return jsonify(msg="This phone number is already registered."), 409

    # Find or create a user record for this phone number
    user = User.query.filter_by(phone_number=phone_number).first()
    if not user:
        user = User(phone_number=phone_number, role='user') # Create a placeholder user
        db.session.add(user)
    
    # Generate and save OTP
    otp_code = str(random.randint(100000, 999999))
    user.otp = otp_code
    user.otp_expiry = datetime.utcnow() + timedelta(minutes=10) # 10 minute expiry
    user.phone_verified = False # Reset verification status
    db.session.commit()
    
    # --- THIS IS THE FAKE SMS "STUB" ---
    # In a real app, you would use Twilio/Msg91 here to send the SMS.
    # For testing, we just print it to the terminal.
    print("------------------------------------------------")
    print(f"OTP for {phone_number}: {otp_code}")
    print("------------------------------------------------")
    # --- END OF FAKE SMS ---
    
    return jsonify(msg=f"OTP sent to {phone_number} (check terminal for test OTP)"), 200

@app.route('/api/verify-otp', methods=['POST'])
def verify_otp():
    data = request.get_json()
    phone_number = data.get('phone_number')
    otp_code = data.get('otp')

    if not phone_number or not otp_code:
        return jsonify(msg="Phone number and OTP are required."), 400
    
    user = User.query.filter_by(phone_number=phone_number).first()
    
    if not user:
        return jsonify(msg="User not found."), 404
    
    if not user.otp:
        return jsonify(msg="No OTP was sent. Please request one."), 400

    if user.otp_expiry < datetime.utcnow():
        return jsonify(msg="OTP has expired. Please request a new one."), 400
        
    if user.otp != otp_code:
        return jsonify(msg="Invalid OTP code."), 400
    
    # Success!
    user.phone_verified = True
    user.otp = None # Clear OTP after use
    user.otp_expiry = None
    db.session.commit()
    
    return jsonify(msg="Phone number verified successfully!"), 200

# --- 6. ADMIN API ENDPOINTS ---

@app.route('/api/admin/reports', methods=['GET'])
@admin_required()
def get_admin_reports():
    admin_id = int(get_jwt_identity())
    admin = User.query.get(admin_id)
    admin_zone = admin.zone
    
    status_filter = request.args.get('status', 'pending')
    
    reports_query = Report.query.filter_by(status=status_filter)
    if admin_zone: 
        reports_query = reports_query.filter_by(zone=admin_zone)
        
    reports = reports_query.order_by(Report.created_at.asc()).all()
    
    output = []
    for report in reports:
        worker_usernames = [w.username for w in report.assigned_workers]
            
        output.append({
            "id": report.id,
            "user_email": report.author.email,
            "description": report.description,
            "location_lat": report.location_lat,
            "location_lon": report.location_lon,
            "image_url": report.image_url,
            "created_at": report.created_at.isoformat(),
            "status": report.status,
            "worker_usernames": worker_usernames,
            "completion_image_url": report.completion_image_url
        })
    
    busy_worker_ids_query = db.session.query(report_assignments.c.worker_id).join(Report).filter(
        Report.status == 'in_progress'
    ).distinct()
    busy_worker_ids = [item[0] for item in busy_worker_ids_query]

    free_workers_query = User.query.filter(
        User.role == 'worker',
        User.id.notin_(busy_worker_ids)
    )
    if admin_zone: 
        free_workers_query = free_workers_query.filter_by(zone=admin_zone)
        
    free_workers = free_workers_query.all()
    
    worker_list = [{"id": w.id, "username": w.username} for w in free_workers]
    
    return jsonify(reports=output, workers=worker_list)

@app.route('/api/admin/report/<int:report_id>/approve', methods=['PUT'])
@admin_required()
def approve_report(report_id):
    report = Report.query.get_or_404(report_id)
    
    # --- ADDED: Award points to the user ---
    if report.status == 'pending': # Only award points once
        user = report.author
        if user and user.role == 'user':
            user.points = (user.points or 0) + 10 # Award 10 points
            
    report.status = 'approved'
    db.session.commit()
    return jsonify(msg="Report approved and 10 points awarded to user")

@app.route('/api/admin/report/<int:report_id>/reject', methods=['DELETE'])
@admin_required()
def reject_report(report_id):
    report = Report.query.get_or_404(report_id)
    
    user = report.author
    user.warning_count += 1
    report.status = 'rejected'
    
    # --- ADDED: Deduct points for false report (optional) ---
    if user and user.role == 'user':
        user.points = max(0, (user.points or 0) - 5) # Deduct 5 points, but not below 0
    
    db.session.commit()
    return jsonify(msg=f"Report rejected, user {user.email} warned, and 5 points deducted.")

@app.route('/api/admin/report/<int:report_id>/assign', methods=['PUT'])
@admin_required()
def assign_worker(report_id):
    data = request.get_json()
    worker_ids = data.get('worker_ids') 
    
    if not worker_ids or not isinstance(worker_ids, list):
        return jsonify(msg="Worker IDs (as a list) are required"), 400
        
    report = Report.query.get_or_404(report_id)
    admin_id = int(get_jwt_identity())
    admin = User.query.get(admin_id)

    busy_worker_ids_query = db.session.query(report_assignments.c.worker_id).join(Report).filter(
        Report.status == 'in_progress'
    ).distinct()
    busy_worker_ids = [item[0] for item in busy_worker_ids_query]

    new_workers_list = []
    worker_usernames = []

    for worker_id in worker_ids:
        worker = User.query.get(worker_id)
        
        if not worker or worker.role != 'worker':
            return jsonify(msg=f"Invalid worker ID: {worker_id}"), 404
            
        if admin.zone and worker.zone != admin.zone:
            return jsonify(msg=f"Cannot assign {worker.username} from a different zone."), 403

        if worker_id in busy_worker_ids:
            return jsonify(msg=f"Worker {worker.username} is already busy."), 400
        
        new_workers_list.append(worker)
        worker_usernames.append(worker.username)
        
    report.assigned_workers = new_workers_list
    report.status = 'in_progress'
    db.session.commit()
    
    return jsonify(msg=f"Report {report.id} assigned to workers: {', '.join(worker_usernames)}")

@app.route('/api/admin/workers', methods=['GET'])
@admin_required()
def get_worker_status():
    admin_id = int(get_jwt_identity())
    admin = User.query.get(admin_id)
    admin_zone = admin.zone

    workers_query = User.query.filter_by(role='worker')
    if admin_zone:
        workers_query = workers_query.filter_by(zone=admin_zone)
        
    workers = workers_query.all()
    
    output = []
    for worker in workers:
        busy_task = worker.assigned_tasks.filter_by(status='in_progress').first()
        status = 'Busy' if busy_task else 'Free'
        
        output.append({
            "id": worker.id,
            "username": worker.username,
            "email": worker.email,
            "status": status,
            "task_id": busy_task.id if busy_task else None
        })
    return jsonify(workers=output)

@app.route('/api/admin/feedback', methods=['GET'])
@admin_required()
def get_admin_feedback():
    admin_id = int(get_jwt_identity())
    admin = User.query.get(admin_id)
    admin_zone = admin.zone

    feedback_query = db.session.query(Feedback).join(Report, Feedback.report_id == Report.id)
    
    if admin_zone:
        feedback_query = feedback_query.filter(Report.zone == admin_zone)
        
    feedbacks = feedback_query.order_by(Feedback.id.desc()).all()
    
    output = []
    for fb in feedbacks:
        output.append({
            "id": fb.id,
            "rating": fb.rating,
            "suggestion": fb.suggestion,
            "report_id": fb.report_id,
            "user_email": fb.author.email
        })
    return jsonify(feedback=output)


# --- 7. WORKER API ENDPOINTS ---

@app.route('/api/worker/tasks', methods=['GET'])
@worker_required()
def get_worker_tasks():
    # --- MODIFIED: Get worker object ---
    worker_id = int(get_jwt_identity()) 
    worker = User.query.get(worker_id)
    
    if not worker:
        return jsonify(msg="Worker not found"), 404

    tasks = worker.assigned_tasks.filter_by(
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

@app.route('/api/worker/task/<int:report_id>/complete', methods=['POST'])
@worker_required()
def complete_task(report_id):
    # --- MODIFIED: Get worker object ---
    worker_id = int(get_jwt_identity())
    worker = User.query.get(worker_id)
    report = Report.query.get_or_404(report_id)
    
    if not worker:
        return jsonify(msg="Worker not found"), 404
    
    if report not in worker.assigned_tasks:
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
    
    return jsonify(msg="Task marked as complete")

# --- 8. MAIN EXECUTION ---
if __name__ == '__main__':
    with app.app_context():
        db.create_all() # This will now create the new 'points', 'phone_number', etc. columns
        
        if not User.query.filter_by(email="admin1@gmail.com").first():
            print("Creating default admin user...")
            admin_user_1 = User(
                email="admin1@gmail.com",
                username="Admin1", 
                role="admin",
                zone="City1_Zone" # Krishnankovil
            )
            admin_user_1.set_password("Admin@1234")
            db.session.add(admin_user_1)
            db.session.commit()
            print("Admin user created with email: admin1@gmail.com in City1_Zone")

        if not User.query.filter_by(email="admin2@gmail.com").first():
            print("Creating default admin user 2...")
            admin_user_2 = User(
                email="admin2@gmail.com",
                username="Admin2", 
                role="admin",
                zone="City2_Zone" # Chennai
            )
            admin_user_2.set_password("Admin@1234") 
            db.session.add(admin_user_2)
            db.session.commit()
            print("Admin user created with email: admin2@gmail.com in City2_Zone")

        if not User.query.filter_by(email="worker1@gmail.com").first():
            print("Creating default worker user...")
            worker_user_1 = User(
                email="worker1@gmail.com",
                username="Worker1",
                role="worker",
                zone="City1_Zone" # Krishnankovil
            )
            worker_user_1.set_password("worker123")
            db.session.add(worker_user_1)
            db.session.commit()
            print("Worker user created with email: worker1@gmail.com in City1_Zone")
            
        if not User.query.filter_by(email="worker2@gmail.com").first():
            print("Creating default worker user 2...")
            worker_user_2 = User(
                email="worker2@gmail.com",
                username="Worker2",
                role="worker",
                zone="City2_Zone" # Chennai
            )
            worker_user_2.set_password("worker456")
            db.session.add(worker_user_2)
            db.session.commit()
            print("Worker user created with email: worker2@gmail.com in City2_Zone")

    app.run(debug=True, host='0.0.0.0', port=5000)