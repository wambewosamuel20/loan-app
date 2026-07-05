import os
from datetime import datetime
from flask import Flask, render_template, redirect, url_for, request, flash, session
import psycopg2
from psycopg2.extras import RealDictCursor
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'super-secret-loan-key-12345')

# --- RECOVER DATABASE CONNECTION STRING FROM ENVIRONMENT ---
DATABASE_URL = os.environ.get('DATABASE_URL')

def get_db_connection():
    """Establishes and returns a connection to the Supabase PostgreSQL database."""
    try:
        # Cursor factory allows pulling data out as dictionaries matching column keys
        conn = psycopg2.connect(DATABASE_URL, cursor_factory=RealDictCursor)
        return conn
    except Exception as e:
        print(f"Database Connection Failure: {e}")
        raise e

# --- INITIAL AUTOMATIC DATABASE INITIALIZATION & ROOT SEEDING ---
def init_db():
    """Creates the essential tables on Supabase if they do not exist, and seeds the admin."""
    conn = get_db_connection()
    cur = conn.cursor()
    
    # 1. Users table
    cur.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            email VARCHAR(120) UNIQUE NOT NULL,
            password_hash VARCHAR(256) NOT NULL,
            phone_number VARCHAR(20) NOT NULL,
            role VARCHAR(10) DEFAULT 'client'
        );
    ''')
    
    # 2. Loan Applications table
    cur.execute('''
        CREATE TABLE IF NOT EXISTS loan_applications (
            id SERIAL PRIMARY KEY,
            user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
            full_name VARCHAR(100) NOT NULL,
            date_of_birth VARCHAR(20) NOT NULL,
            gender VARCHAR(10) NOT NULL,
            phone_number VARCHAR(20) NOT NULL,
            email VARCHAR(120) NOT NULL,
            physical_address TEXT NOT NULL,
            nin_number VARCHAR(14) UNIQUE NOT NULL,
            monthly_income REAL NOT NULL,
            employment_status VARCHAR(50) NOT NULL,
            loan_amount_requested REAL NOT NULL,
            loan_amount_approved REAL,
            loan_purpose VARCHAR(200) NOT NULL,
            application_status VARCHAR(20) DEFAULT 'pending',
            rejection_reason TEXT,
            submitted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            reviewed_at TIMESTAMP,
            reviewed_by VARCHAR(120)
        );
    ''')
    
    # 3. Referrals table (strictly managed to take up to 3 elements)
    cur.execute('''
        CREATE TABLE IF NOT EXISTS referrals (
            id SERIAL PRIMARY KEY,
            loan_application_id INTEGER REFERENCES loan_applications(id) ON DELETE CASCADE,
            referral_name VARCHAR(100) NOT NULL,
            referral_phone VARCHAR(20) NOT NULL,
            referral_relationship VARCHAR(50) NOT NULL
        );
    ''')
    
    # 4. Seed unique system admin profile configuration
    admin_email = 'wambewosamuel2022@gmail.com'
    cur.execute("SELECT id FROM users WHERE email = %s;", (admin_email,))
    if not cur.fetchone():
        hashed_pw = generate_password_hash('AdminSecurePass123!', method='pbkdf2:sha256')
        cur.execute(
            "INSERT INTO users (email, password_hash, phone_number, role) VALUES (%s, %s, %s, %s);",
            (admin_email, hashed_pw, '+256700000000', 'admin')
        )
        
    conn.commit()
    cur.close()
    conn.close()


# --- ROUTE GUARDS ---

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
    if 'user_id' in session:
        return redirect(url_for('admin_dashboard' if session.get('role') == 'admin' else 'dashboard'))
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form.get('email').strip().lower()
        password = request.form.get('password')
        phone = request.form.get('phone_number')
        
        conn = get_db_connection()
        cur = conn.cursor()
        
        cur.execute("SELECT id FROM users WHERE email = %s;", (email,))
        if cur.fetchone():
            flash('Email already registered.', 'error')
            cur.close()
            conn.close()
            return redirect(url_for('register'))
            
        role = 'admin' if email == 'wambewosamuel2022@gmail.com' else 'client'
        hashed_pw = generate_password_hash(password, method='pbkdf2:sha256')
        
        cur.execute(
            "INSERT INTO users (email, password_hash, phone_number, role) VALUES (%s, %s, %s, %s);",
            (email, hashed_pw, phone, role)
        )
        conn.commit()
        cur.close()
        conn.close()
        
        flash('Registration successful! Please login.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email').strip().lower()
        password = request.form.get('password')
        
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT * FROM users WHERE email = %s;", (email,))
        user = cur.fetchone()
        cur.close()
        conn.close()
        
        if user and check_password_hash(user['password_hash'], password):
            session['user_id'] = user['id']
            session['role'] = user['role']
            session['email'] = user['email']
            
            if user['role'] == 'admin':
                return redirect(url_for('admin_dashboard'))
            return redirect(url_for('dashboard'))
            
        flash('Invalid email or password.', 'error')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('You have logged out.', 'success')
    return redirect(url_for('login'))


# --- CLIENT DASHBOARD ---

@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
@role_required('client')
def dashboard():
    user_id = session['user_id']
    
    conn = get_db_connection()
    cur = conn.cursor()
    
    # Extract client applications history
    cur.execute("SELECT * FROM loan_applications WHERE user_id = %s ORDER BY submitted_at DESC;", (user_id,))
    existing_apps = cur.fetchall()
    
    has_pending = any(app['application_status'] == 'pending' for app in existing_apps)

    if request.method == 'POST':
        if has_pending:
            flash('You already have a pending loan application.', 'error')
            cur.close()
            conn.close()
            return redirect(url_for('dashboard'))
            
        nin = request.form.get('nin_number').strip().upper()
        if len(nin) != 14:
            flash('NIN validation failed! Uganda NIN must be exactly 14 characters.', 'error')
            cur.close()
            conn.close()
            return redirect(url_for('dashboard'))
            
        cur.execute("SELECT id FROM loan_applications WHERE nin_number = %s;", (nin,))
        if cur.fetchone():
            flash('This NIN number is already associated with an application.', 'error')
            cur.close()
            conn.close()
            return redirect(url_for('dashboard'))

        try:
            # Write new entry and fetch generated ID back safely
            cur.execute('''
                INSERT INTO loan_applications 
                (user_id, full_name, date_of_birth, gender, phone_number, email, physical_address, nin_number, monthly_income, employment_status, loan_amount_requested, loan_purpose, application_status)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, 'pending') RETURNING id;
            ''', (
                user_id, request.form.get('full_name'), request.form.get('date_of_birth'), request.form.get('gender'),
                request.form.get('phone_number'), request.form.get('email'), request.form.get('physical_address'),
                nin, float(request.form.get('monthly_income')), request.form.get('employment_status'),
                float(request.form.get('loan_amount')), request.form.get('loan_purpose')
            ))
            new_app_id = cur.fetchone()['id']
            
            # Map out exactly 3 referrals
            for i in range(1, 4):
                cur.execute('''
                    INSERT INTO referrals (loan_application_id, referral_name, referral_phone, referral_relationship)
                    VALUES (%s, %s, %s, %s);
                ''', (
                    new_app_id, request.form.get(f'ref_name_{i}'), request.form.get(f'ref_phone_{i}'), request.form.get(f'ref_rel_{i}')
                ))
                
            conn.commit()
            flash('Application submitted successfully!', 'success')
            cur.close()
            conn.close()
            return redirect(url_for('dashboard'))
        except Exception as e:
            conn.rollback()
            flash(f'An error occurred: {str(e)}', 'error')
            
    cur.close()
    conn.close()
    return render_template('dashboard.html', applications=existing_apps, has_pending=has_pending)


# --- ADMIN DASHBOARD ---

@app.route('/admin', methods=['GET'])
@login_required
@role_required('admin')
def admin_dashboard():
    status_filter = request.args.get('status', 'all')
    search_query = request.args.get('search', '').strip()
    
    conn = get_db_connection()
    cur = conn.cursor()
    
    # Formulate dynamically parameters using psycopg2 bindings
    query = "SELECT * FROM loan_applications WHERE 1=1"
    params = []
    
    if status_filter != 'all':
        query += " AND application_status = %s"
        params.append(status_filter)
    if search_query:
        query += " AND (full_name ILIKE %s OR nin_number ILIKE %s)"
        search_param = f"%{search_query}%"
        params.extend([search_param, search_param])
        
    query += " ORDER BY submitted_at DESC"
    cur.execute(query, tuple(params))
    apps = cur.fetchall()
    
    # Hydrate each application dictionary object with its exact 3 matched referrals
    for app_obj in apps:
        cur.execute("SELECT * FROM referrals WHERE loan_application_id = %s;", (app_obj['id'],))
        app_obj['referrals'] = cur.fetchall()
        
    # Calculate System Performance Metrics
    cur.execute("SELECT COUNT(*) as total, COUNT(*) FILTER (WHERE application_status = 'pending') as pending, COUNT(*) FILTER (WHERE application_status = 'rejected') as rejected, COALESCE(SUM(loan_amount_approved) FILTER (WHERE application_status = 'approved'), 0) as approved_amt FROM loan_applications;")
    stats = cur.fetchone()
    
    total_apps = stats['total']
    pending_count = stats['pending']
    total_approved_amount = stats['approved_amt']
    rejected_count = stats['rejected']
    
    rejection_rate = round((rejected_count / total_apps * 100), 1) if total_apps > 0 else 0

    cur.close()
    conn.close()

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
    new_status = request.form.get('operation_status')
    if new_status not in ['pending', 'approved', 'rejected']:
        flash('Invalid operations state.', 'error')
        return redirect(url_for('admin_dashboard'))
        
    conn = get_db_connection()
    cur = conn.cursor()
    
    reviewed_by = session['email']
    reviewed_at = datetime.utcnow()
    
    if new_status == 'rejected':
        reason = request.form.get('rejection_reason', '').strip()
        if not reason:
            flash('Error: A reason is mandatory for rejections!', 'error')
            cur.close()
            conn.close()
            return redirect(url_for('admin_dashboard'))
            
        cur.execute('''
            UPDATE loan_applications 
            SET application_status = %s, rejection_reason = %s, loan_amount_approved = 0, reviewed_by = %s, reviewed_at = %s 
            WHERE id = %s;
        ''', (new_status, reason, reviewed_by, reviewed_at, app_id))
        
    elif new_status == 'approved':
        amt = request.form.get('approved_amount')
        if amt:
            approved_amt = float(amt)
            cur.execute('''
                UPDATE loan_applications 
                SET application_status = %s, loan_amount_approved = %s, rejection_reason = NULL, reviewed_by = %s, reviewed_at = %s 
                WHERE id = %s;
            ''', (new_status, approved_amt, reviewed_by, reviewed_at, app_id))
        else:
            # Fall back to matching the original requested budget amount parameters
            cur.execute('''
                UPDATE loan_applications 
                SET application_status = %s, loan_amount_approved = loan_amount_requested, rejection_reason = NULL, reviewed_by = %s, reviewed_at = %s 
                WHERE id = %s;
            ''', (new_status, reviewed_by, reviewed_at, app_id))
            
    else: # Default Reset to Pending
        cur.execute('''
            UPDATE loan_applications 
            SET application_status = 'pending', loan_amount_approved = NULL, rejection_reason = NULL, reviewed_by = %s, reviewed_at = %s 
            WHERE id = %s;
        ''', (reviewed_by, reviewed_at, app_id))

    conn.commit()
    cur.close()
    conn.close()
    
    flash(f"Application #{app_id} successfully updated to '{new_status}'.", 'success')
    return redirect(url_for('admin_dashboard'))


# --- RUN DATABASE INITIALIZATION ON STARTUP ---
try:
    init_db()
except Exception as e:
    print(f"Skipping setup due to initialization constraints: {e}")

if __name__ == '__main__':
    app.run(debug=False)
