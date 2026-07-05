import os
from datetime import datetime
from flask import Flask, render_react, render_template, redirect, url_for, request, flash, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps

app = Flask(__name__)
app.config['SECRET_KEY'] = 'super-secret-loan-key-12345'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///loans.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# --- DATABASE MODELS ---

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    phone_number = db.Column(db.String(20), nullable=False)
    role = db.Column(db.String(10), default='client') # 'client' or 'admin'
    applications = db.relationship('LoanApplication', backref='applicant', lazy=True)

class LoanApplication(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    full_name = db.Column(db.String(100), nullable=False)
    date_of_birth = db.Column(db.String(20), nullable=False)
    gender = db.Column(db.String(10), nullable=False)
    phone_number = db.Column(db.String(20), nullable=False)
    email = db.Column(db.String(120), nullable=False)
    physical_address = db.Column(db.Text, nullable=False)
    nin_number = db.Column(db.String(14), unique=True, nullable=False)
    monthly_income = db.Column(db.Float, nullable=False)
    employment_status = db.Column(db.String(50), nullable=False)
    loan_amount_requested = db.Column(db.Float, nullable=False)
    loan_amount_approved = db.Column(db.Float, nullable=True)
    loan_purpose = db.Column(db.String(200), nullable=False)
    application_status = db.Column(db.String(20), default='pending') # pending, approved, rejected
    rejection_reason = db.Column(db.Text, nullable=True)
    submitted_at = db.Column(db.DateTime, default=datetime.utcnow)
    reviewed_at = db.Column(db.DateTime, nullable=True)
    reviewed_by = db.Column(db.String(120), nullable=True)
    referrals = db.relationship('Referral', backref='application', cascade="all, delete-orphan", lazy=True)

class Referral(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    loan_application_id = db.Column(db.Integer, db.ForeignKey('loan_application.id'), nullable=False)
    referral_name = db.Column(db.String(100), nullable=False)
    referral_phone = db.Column(db.String(20), nullable=False)
    referral_relationship = db.Column(db.String(50), nullable=False)


# --- ROUTE GUARDS (DECORATORS) ---

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in first.', 'error')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def role_required(role):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if session.get('role') != role:
                flash('Access Denied: Unauthorized Area.', 'error')
                return redirect(url_for('dashboard' if session.get('role') == 'client' else 'admin_dashboard'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator


# --- AUTHENTICATION ROUTES ---

@app.route('/')
def home():
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form.get('email').strip().lower()
        password = request.form.get('password')
        phone = request.form.get('phone_number')
        
        if User.query.filter_by(email=email).first():
            flash('Email already registered.', 'error')
            return redirect(url_for('register'))
            
        # Standard users sign up as client. Specific admin email handled below.
        role = 'admin' if email == 'wambewosamuel2022@gmail.com' else 'client'
        
        hashed_pw = generate_password_hash(password, method='pbkdf2:sha256')
        new_user = User(email=email, password_hash=hashed_pw, phone_number=phone, role=role)
        db.session.add(new_user)
        db.session.commit()
        
        flash('Registration successful! Please login.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email').strip().lower()
        password = request.form.get('password')
        
        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password_hash, password):
            session['user_id'] = user.id
            session['role'] = user.role
            session['email'] = user.email
            
            if user.role == 'admin':
                return redirect(url_for('admin_dashboard'))
            return redirect(url_for('dashboard'))
            
        flash('Invalid email or password.', 'error')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('You have logged out.', 'success')
    return redirect(url_for('login'))


# --- CLIENT DASHBOARD & APPLICATION ---

@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
@role_required('client')
def dashboard():
    user_id = session['user_id']
    existing_apps = LoanApplication.query.filter_by(user_id=user_id).order_by(LoanApplication.submitted_at.desc()).all()
    
    # Check if there's any active application currently pending
    has_pending = any(app.application_status == 'pending' for app in existing_apps)

    if request.method == 'POST':
        if has_pending:
            flash('You already have a pending loan application.', 'error')
            return redirect(url_for('dashboard'))
            
        # Format validation for Uganda's 14-character NIN
        nin = request.form.get('nin_number').strip().upper()
        if len(nin) != 14:
            flash('NIN validation failed! Uganda NIN must be exactly 14 characters.', 'error')
            return redirect(url_for('dashboard'))
            
        if LoanApplication.query.filter_by(nin_number=nin).first():
            flash('This NIN number is already associated with an application.', 'error')
            return redirect(url_for('dashboard'))

        try:
            # Create Loan Application Object
            new_app = LoanApplication(
                user_id=user_id,
                full_name=request.form.get('full_name'),
                date_of_birth=request.form.get('date_of_birth'),
                gender=request.form.get('gender'),
                phone_number=request.form.get('phone_number'),
                email=request.form.get('email'),
                physical_address=request.form.get('physical_address'),
                nin_number=nin,
                monthly_income=float(request.form.get('monthly_income')),
                employment_status=request.form.get('employment_status'),
                loan_amount_requested=float(request.form.get('loan_amount')),
                loan_purpose=request.form.get('loan_purpose'),
                application_status='pending'
            )
            db.session.add(new_app)
            db.session.flush() # Yields new_app.id before commit
            
            # Extract exactly 3 referrals securely
            for i in range(1, 4):
                ref = Referral(
                    loan_application_id=new_app.id,
                    referral_name=request.form.get(f'ref_name_{i}'),
                    referral_phone=request.form.get(f'ref_phone_{i}'),
                    referral_relationship=request.form.get(f'ref_rel_{i}')
                )
                db.session.add(ref)
                
            db.session.commit()
            flash('Application submitted successfully!', 'success')
            return redirect(url_for('dashboard'))
        except Exception as e:
            db.session.rollback()
            flash(f'An error occurred: {str(e)}', 'error')
            
    return render_template('dashboard.html', applications=existing_apps, has_pending=has_pending)


# --- ADMIN DASHBOARD & APPLICATION OPERATIONS ---

@app.route('/admin', methods=['GET'])
@login_required
@role_required('admin')
def admin_dashboard():
    # Filter operations
    status_filter = request.args.get('status', 'all')
    search_query = request.args.get('search', '').strip()
    
    query = LoanApplication.query
    if status_filter != 'all':
        query = query.filter_by(application_status=status_filter)
    if search_query:
        query = query.filter((LoanApplication.full_name.contains(search_query)) | (LoanApplication.nin_number.contains(search_query)))
        
    apps = query.order_by(LoanApplication.submitted_at.desc()).all()
    
    # Calculate System Stats
    total_apps = LoanApplication.query.count()
    pending_count = LoanApplication.query.filter_by(application_status='pending').count()
    approved_apps = LoanApplication.query.filter_by(application_status='approved').all()
    total_approved_amount = sum(app.loan_amount_approved or 0 for app in approved_apps)
    rejected_count = LoanApplication.query.filter_by(application_status='rejected').count()
    
    rejection_rate = round((rejected_count / total_apps * 100), 1) if total_apps > 0 else 0

    return render_template('admin.html', 
                           applications=apps, 
                           total=total_apps, 
                           pending=pending_count, 
                           approved_amt=total_approved_amount, 
                           rej_rate=rejection_rate,
                           status_filter=status_filter,
                           search_query=search_query)

@app.route('/admin/update_status/<int:app_id>', methods=['POST'])
@login_required
@role_required('admin')
def update_status(app_id):
    application = LoanApplication.query.get_or_4000_or_404(app_id)
    new_status = request.form.get('operation_status')
    
    if new_status not in ['pending', 'approved', 'rejected']:
        flash('Invalid operations state.', 'error')
        return redirect(url_for('admin_dashboard'))
        
    application.application_status = new_status
    application.reviewed_by = session['email']
    application.reviewed_at = datetime.utcnow()
    
    if new_status == 'rejected':
        reason = request.form.get('rejection_reason', '').strip()
        if not reason:
            flash('Error: A reason is mandatory for rejections!', 'error')
            return redirect(url_for('admin_dashboard'))
        application.rejection_reason = reason
        application.loan_amount_approved = 0
    elif new_status == 'approved':
        # Admin can optionally alter matching amount
        amt = request.form.get('approved_amount')
        application.loan_amount_approved = float(amt) if amt else application.loan_amount_requested
        application.rejection_reason = None

    db.session.commit()
    flash(f"Application #{app_id} successfully updated to '{new_status}'. Client notified.", 'success')
    return redirect(url_for('admin_dashboard'))


# --- APP SEED INITIALIZATION ---

def seed_admin():
    # Enforces explicit setup requirement for the system admin profile
    admin_email = 'wambewosamuel2022@gmail.com'
    if not User.query.filter_by(email=admin_email).first():
        hashed_pw = generate_password_hash('AdminSecurePass123!', method='pbkdf2:sha256')
        root_admin = User(email=admin_email, password_hash=hashed_pw, phone_number='+256700000000', role='admin')
        db.session.add(root_admin)
        db.session.commit()

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        seed_admin()
    app.run(debug=True)
