from math import ceil
from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from flask_limiter import Limiter
from flask_login import UserMixin, login_required, LoginManager, login_user, logout_user
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from datetime import datetime, timedelta, timezone
from flask_mail import Mail, Message
from werkzeug.utils import secure_filename
from flask_wtf import CSRFProtect, FlaskForm
from wtforms import StringField, PasswordField, SubmitField, HiddenField, TextAreaField
from wtforms.validators import DataRequired
from itsdangerous import URLSafeTimedSerializer
import os
import secrets
import logging
import random
import string
import mimetypes
from logging.handlers import RotatingFileHandler
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
csrf = CSRFProtect(app)
app.config['SECRET_KEY'] = os.getenv("SECRET_KEY") # Replace with a strong secret key
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv("DATABASE_URL")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)
app.config['SESSION_TYPE'] = 'filesystem'
app.config['WTF_CSRF_ENABLED'] = False
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
UPLOAD_FOLDER = 'static/uploads'
ALLOWED_EXTENSIONS = {'mp4', 'mp3', 'jpg', 'jpeg', 'png', 'gif'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024 #limit 16MB

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS



# Configure Flask-Mail
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.getenv("MAIL_USERNAME")
app.config['MAIL_PASSWORD'] = os.getenv("MAIL_PASSWORD")
mail = Mail(app)


logging.basicConfig(level=logging.DEBUG)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))
limiter = Limiter(app)
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

# -------------------------------
# ✅ USER MODEL
# -------------------------------
class User(db.Model, UserMixin):
    __tablename__ = 'user'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    
    referral_code = db.Column(db.String(50), unique=True, nullable=False)
    referred_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    
    is_admin = db.Column(db.Boolean, default=False)
    payment_status = db.Column(db.String(10), default="Unpaid")
    referral_balance = db.Column(db.Float, default=0.0)
    date_joined = db.Column(db.DateTime, default=datetime.utcnow)

    # Relationships
    referrals = db.relationship('Referral', foreign_keys='Referral.referrer_id', backref='referrer', lazy='dynamic')
    transactions = db.relationship('Transaction', backref='user', lazy='dynamic')
    payments = db.relationship('Payment', backref='user', lazy='dynamic')
    referred_by_user = db.relationship('User', remote_side=[id], foreign_keys=[referred_by])

    reset_token = db.Column(db.String(100), nullable=True)
    token_expiration = db.Column(db.DateTime, nullable=True)
    ad_points = db.Column(db.Integer, default=0)    


# -------------------------------
# ✅ REFERRAL MODEL
# -------------------------------
class Referral(db.Model):
    __tablename__ = 'referral'
    
    id = db.Column(db.Integer, primary_key=True)
    referrer_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    referred_user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    referred_username = db.Column(db.String(50), nullable=False)
    status = db.Column(db.String(20), default='Pending')
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    referred_user = db.relationship('User', foreign_keys=[referred_user_id])

# -------------------------------
# ✅ TRANSACTION MODEL
# -------------------------------
class Transaction(db.Model):
    __tablename__ = 'transaction'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    type = db.Column(db.String(50), nullable=False, default="Earning")  # Add this
    date = db.Column(db.DateTime, default=datetime.utcnow)

# -------------------------------
# ✅ PAYMENT MODEL
# -------------------------------
class Payment(db.Model):
    __tablename__ = 'payment'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    payment_method = db.Column(db.String(50), nullable=False)
    transaction_id = db.Column(db.String(100), nullable=False)
    payment_date = db.Column(db.DateTime, nullable=False)
    amount = db.Column(db.Float, nullable=False)
    proof = db.Column(db.String(255), nullable=True)
    status = db.Column(db.String(20), default='Pending')
    admin_comment = db.Column(db.String(255), nullable=True)

# -------------------------------
# ✅ PROFILE UPDATE FORM
# -------------------------------
class UpdateProfileForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired()])
    password = PasswordField('Password')  # Optional to update
    submit = SubmitField('Update Profile')

# -------------------------------
# ✅ ADMIN ACTION FORM
# -------------------------------
class AdminActionForm(FlaskForm):
    payment_id = HiddenField(validators=[DataRequired()])
    comment = TextAreaField('Comment')
    approve = SubmitField('Approve')
    reject = SubmitField('Reject')

# -------------------------------
# ✅ PAYMENT ACTION FORM (Could be same as AdminActionForm)
# -------------------------------
class PaymentActionForm(FlaskForm):
    payment_id = HiddenField(validators=[DataRequired()])
    comment = TextAreaField("Admin Comment")
    approve = SubmitField("Approve")
    reject = SubmitField("Reject")

class CashoutRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    bank_name = db.Column(db.String(100), nullable=False)
    account_number = db.Column(db.String(50), nullable=False)
    status = db.Column(db.String(20), default='Pending')  # Pending, Approved, Rejected
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    user = db.relationship('User', backref='cashout_requests')

class AdSlot(db.Model):
    __table_args__ = (
        db.Index('ix_adslot_expiry_time', 'expiry_time'),
    )
    id = db.Column(db.Integer, primary_key=True)
    ad_title = db.Column(db.String(100), nullable=False)
    ad_url = db.Column(db.String(255), nullable=False)  # video or image
    duration_seconds = db.Column(db.Integer, default=60)  # max 60s
    reward = db.Column(db.Integer, default=1)  # 1 point per 15s
    expiry_time = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

class UserAdWatch(db.Model):
    __table_args__ = (
        db.UniqueConstraint('user_id', 'ad_id', name='uix_user_ad'),
    )

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    ad_id = db.Column(db.Integer, db.ForeignKey('ad_slot.id'))
    reward_earned = db.Column(db.Boolean, default=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)


REWARD_AMOUNT = 1500  


@app.route('/')
def home():
    from datetime import datetime
    return render_template('home.html', current_year=datetime.now().year)

# Initialize Database
@app.before_first_request
def create_tables():
    db.create_all()
    if not os.path.exists(app.config['UPLOAD_FOLDER']):
        os.makedirs(app.config['UPLOAD_FOLDER'])

handler = RotatingFileHandler('app.log', maxBytes=100000, backupCount=3)
app.logger.addHandler(handler)

@app.context_processor
def inject_csrf_token():
    from flask_wtf.csrf import generate_csrf
    return dict(csrf_token=lambda: f'<input type="hidden" name="csrf_token" value="{generate_csrf()}">')

# Helper Function: Send Email
def send_email(to, subject, body):
    try:
        msg = Message(subject, sender=app.config['MAIL_USERNAME'], recipients=[to])
        msg.body = body
        mail.send(msg)
    except Exception as e:
        print(f"Failed to send email: {e}")

def generate_referral_code(username):
    if username:  # Ensure username is not None
        return username[:3].upper() + ''.join(random.choices(string.digits, k=5))
    else:
        return ''.join(random.choices(string.ascii_uppercase + string.digits, k=8))  # Fallback

def allowed_file(filename):
    mime_type, _ = mimetypes.guess_type(filename)
    return mime_type in ['image/jpeg', 'image/png', 'application/pdf']

def is_safe_url(target):
    """
    Helper function to validate redirection URLs.
    Ensures redirection stays within the application.
    """
    from urllib.parse import urlparse, urljoin
    ref_url = urlparse(request.host_url)
    test_url = urlparse(urljoin(request.host_url, target))
    return test_url.scheme in ('http', 'https') and ref_url.netloc == test_url.netloc

    
@login_manager.unauthorized_handler
def unauthorized():
    flash("You need to log in to access this page.", "warning")
    return redirect(url_for('login'))

@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '').strip()
        referred_by_code = request.form.get('referred_by', '').strip()

        if not username or not email or not password:
            flash("Username, email, and password are required.", "danger")
            return redirect(url_for("register"))

        if User.query.filter_by(username=username).first():
            flash("Username already exists. Please choose another one.", "danger")
            return redirect(url_for("register"))

        if User.query.filter_by(email=email).first():
            flash("Email already exists. Please choose another one.", "danger")
            return redirect(url_for("register"))

        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

        referred_by_user = None
        if referred_by_code:
            referred_by_user = User.query.filter_by(referral_code=referred_by_code).first()
            if not referred_by_user:
                flash("Invalid referral code. Please check and try again.", "danger")
                return redirect(url_for("register"))

        referral_code = generate_referral_code(username)

        try:
            new_user = User(
                username=username,
                email=email,
                password=hashed_password,
                referral_code=referral_code,
                payment_status="Unpaid",
                referred_by=referred_by_user.id if referred_by_user else None
            )

            db.session.add(new_user)
            db.session.flush()

            if referred_by_user:
                new_referral = Referral(
                    referrer_id=referred_by_user.id,
                    referred_user_id=new_user.id,
                    referred_username=new_user.username,
                    status="Pending"
                )
                db.session.add(new_referral)

                # ✅ ADD THIS: Record referral bonus as a transaction
                referral_transaction = Transaction(
                    user_id=referred_by_user.id,
                    amount=REWARD_AMOUNT,
                    type="Referral Bonus"
                )
                db.session.add(referral_transaction)

            db.session.commit()
            flash("Registration successful. Please log in and complete your payment.", "success")
            return redirect(url_for('login'))

        except Exception as e:
            db.session.rollback()
            app.logger.error(f"[REGISTRATION ERROR] {str(e)}")
            flash("An error occurred during registration. Please try again.", "danger")
            return redirect(url_for("register"))

    return render_template("register.html")


@app.route('/login', methods=['GET', 'POST'])
def login():
    """
    Handles user login. Validates credentials and redirects users
    based on their payment status or intended next page.
    """
    if request.method == 'POST':
        # Fetch and validate user credentials
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()

        # Ensure fields are filled
        if not username or not password:
            flash("Username and password are required.", "danger")
            return redirect(url_for("login"))

        # Query user and validate password
        user = User.query.filter_by(username=username).first()
        if not user or not bcrypt.check_password_hash(user.password, password):
            flash("Invalid username or password.", "danger")
            return redirect(url_for("login"))

        # Log the user in
        login_user(user)
        session['user_id'] = user.id
        session.permanent = True  # Enable session timeout
        app.permanent_session_lifetime = timedelta(minutes=30)

        # Redirect based on payment status
        if user.payment_status != "Paid":
            flash("Your payment is not complete. Please submit your payment.", "warning")
            return redirect(url_for('submit_payment'))

        # Redirect to the dashboard or intended next page
        flash("Welcome back!", "success")
        next_page = request.args.get('next')
        if next_page and is_safe_url(next_page):  # Ensure redirection URL is safe
            return redirect(next_page)
        return redirect(url_for('dashboard'))

    # Render login template
    return render_template("login.html")


@app.route('/forgot-password', methods=['GET', 'POST'])
@limiter.limit("5 per hour")
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        if not email:
            flash("Please provide a valid email address.", "warning")
            return redirect(url_for('forgot_password'))

        user = User.query.filter_by(email=email).first()

        if user:
            # Generate secure token
            token = secrets.token_urlsafe(32)
            user.reset_token = token
            user.token_expiration = datetime.now(timezone.utc) + timedelta(hours=1)
            db.session.commit()

            # Prepare reset URL
            reset_url = url_for('reset_password', token=token, _external=True)

            # Compose and send email
            msg = Message(
                subject="🔐 Reset Your UNI-REF Password",
                sender=app.config['MAIL_USERNAME'],
                recipients=[email]
            )
            msg.body = f"""Hi {user.username},

We received a request to reset your UNI-REF account password.

Click the link below to reset it:
{reset_url}

This link is valid for 1 hour. If you did not request this, simply ignore this email.

Best,
UNI-REF Team
"""
            try:
                mail.send(msg)
                flash("✅ A password reset link has been sent to your email.", "success")
            except Exception as e:
                print(f"[MAIL ERROR] {e}")
                flash("❌ Failed to send reset email. Please try again later.", "danger")
        else:
            flash("No account found with that email address.", "danger")

        return redirect(url_for('forgot_password'))

    return render_template('forgot_password.html')

@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    user = User.query.filter_by(reset_token=token).first()
    
    if not user or user.token_expiration < datetime.now(timezone.utc):
        flash("This token is invalid or expired.", "danger")
        return redirect(url_for('forgot_password'))
    
    if request.method == 'POST':
        new_password = request.form['password']
        user.password = bcrypt.generate_password_hash(new_password).decode('utf-8')
        user.reset_token = None
        user.token_expiration = None
        s = URLSafeTimedSerializer(app.secret_key)
        token = s.dumps(user.email, salt='password-reset-salt')
        db.session.commit()
        flash("Your password has been updated. You can now log in.", "success")
        return redirect(url_for('login'))
    
    return render_template('reset_password.html', token=token)

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        flash("Please log in to access your dashboard.", "danger")
        return redirect(url_for('login'))

    user = db.session.get(User, session['user_id'])

    if not user or user.payment_status != "Paid":
        flash("You must complete your payment to access the dashboard.", "warning")
        return redirect(url_for('submit_payment'))

    # Pagination settings
    page = request.args.get('page', 1, type=int)
    per_page = 10

    # Query all referrals for this user
    all_referrals = Referral.query.filter_by(referrer_id=user.id).order_by(Referral.id.desc()).all()
    total_referrals = len(all_referrals)
    total_pages = ceil(total_referrals / per_page)

    paginated_referrals = all_referrals[(page - 1) * per_page : page * per_page]

    processed_referrals = []
    referral_earnings = 0

    for ref in all_referrals:
        referred_user = User.query.get(ref.referred_user_id)
        username = referred_user.username if referred_user else "Unknown"
        date_joined = (
            referred_user.date_joined.astimezone(timezone.utc).strftime('%Y-%m-%d')
            if referred_user and referred_user.date_joined else "Not Available"
        )
        payment_status = ref.status if ref.status else "Pending"

        if payment_status == "Completed":
            referral_earnings += 1500  # Your reward per referral

    for ref in paginated_referrals:
        referred_user = User.query.get(ref.referred_user_id)
        username = referred_user.username if referred_user else "Unknown"
        date_joined = (
            referred_user.date_joined.astimezone(timezone.utc).strftime('%Y-%m-%d')
            if referred_user and referred_user.date_joined else "Not Available"
        )
        payment_status = ref.status if ref.status else "Pending"

        processed_referrals.append({
            "username": username,
            "date_joined": date_joined,
            "payment_status": payment_status
        })

    # Calculate total approved cashouts
    approved_cashouts = CashoutRequest.query.filter_by(user_id=user.id, status='Approved').all()
    total_cashouts = sum(c.amount for c in approved_cashouts)

    # Final referral balance
    referral_balance = max(referral_earnings - total_cashouts, 0)

    # Pass pagination info to frontend
    pagination = {
        "page": page,
        "per_page": per_page,
        "total": total_referrals,
        "total_pages": total_pages,
        "has_next": page < total_pages,
        "has_prev": page > 1,
        "next_num": page + 1,
        "prev_num": page - 1
    }

    return render_template(
        "dashboard.html",
        user=user,
        referrals=processed_referrals,
        total_earnings=referral_balance,
        pagination=pagination
    )

@app.route('/logout')
def logout():
    logout_user()
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for('login'))


@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # ✅ Use environment variables
        admin_username = os.getenv('ADMIN_USERNAME')
        admin_password = os.getenv('ADMIN_PASSWORD')

        if username == admin_username and password == admin_password:
            session['admin_logged_in'] = True
            session['admin_username'] = username
            return redirect(url_for('admin_dashboard'))
        else:
            flash('Invalid admin credentials. Please try again.', 'danger')

    return render_template('admin_login.html')



# Admin Logout
@app.route('/admin/logout')
def admin_logout():
    session.pop('admin_logged_in', None)
    session.pop('admin_username', None)
    flash('Logged out successfully.', 'success')
    return redirect(url_for('admin_login'))


@app.route('/admin_dashboard', methods=['GET', 'POST'])
def admin_dashboard():
    if 'admin_logged_in' not in session or not session['admin_logged_in']:
        flash("Admin login required.", "danger")
        return redirect(url_for('admin_login'))

    # ✅ Pagination for payments
    page = request.args.get('page', 1, type=int)
    payments = Payment.query.order_by(Payment.id.desc()).paginate(page=page, per_page=10)

    # Prepare forms for each payment
    forms = {}
    for payment in payments.items:
        form = PaymentActionForm(prefix=str(payment.id))
        form.payment_id.data = payment.id
        forms[payment.id] = form

    if request.method == 'POST':
        try:
            submitted_form = None
            submitted_payment_id = None
            action = None

            # Detect which form was submitted
            for payment_id, _ in forms.items():
                form = PaymentActionForm(request.form, prefix=str(payment_id))
                if form.validate_on_submit() and str(payment_id) == form.payment_id.data:
                    submitted_form = form
                    submitted_payment_id = payment_id

                    if form.approve.data:
                        action = 'approve'
                    elif form.reject.data:
                        action = 'reject'
                    break

            if not submitted_form or not action:
                flash("Invalid or expired form. Try again.", "danger")
                return redirect(url_for('admin_dashboard'))

            # Fetch payment and associated user
            payment = Payment.query.get(submitted_payment_id)
            if not payment:
                flash("Payment not found.", "danger")
                return redirect(url_for('admin_dashboard'))

            user = User.query.get(payment.user_id)
            if not user:
                flash("User not found for this payment.", "danger")
                return redirect(url_for('admin_dashboard'))

            comment = submitted_form.comment.data.strip()

            if action == 'approve':
                payment.status = 'Approved'
                user.payment_status = 'Paid'

                # ✅ Award referral bonus only after approval
                referral = Referral.query.filter_by(referred_user_id=user.id).first()
                if referral and referral.status != 'Completed':
                    referral.status = 'Completed'

                    referrer = User.query.get(referral.referrer_id)
                    if referrer:
                        referrer.referral_balance += 1500

                        # ✅ Properly create the transaction with a timestamp
                        transaction = Transaction(
                            user_id=referrer.id,
                            amount=1500,
                            type="Referral Bonus",
                            date=datetime.now(timezone.utc)
                        )
                        db.session.add(transaction)

            elif action == 'reject':
                payment.status = 'Rejected'

            # Save admin comment
            payment.admin_comment = comment
            db.session.commit()

            # Notify user
            try:
                subject = f"Payment {payment.status}"
                body = (
                    f"Hi {user.username},\n\n"
                    f"Your payment with Transaction ID {payment.transaction_id} has been {payment.status.lower()}.\n"
                    f"Admin Comment: {comment or 'None'}\n\n"
                    "Thank you for using our platform."
                )
                send_email(user.email, subject, body)
            except Exception:
                flash("Payment updated, but email failed to send.", "warning")

            flash(f"Payment successfully {payment.status.lower()}.", "success")
            return redirect(url_for('admin_dashboard'))

        except Exception as e:
            db.session.rollback()
            flash(f"An error occurred: {str(e)}", "danger")
            return redirect(url_for('admin_dashboard'))

    return render_template('admin_dashboard.html', payments=payments, forms=forms)

@app.route('/admin/cashout_requests', methods=['GET', 'POST'])
def view_cashout_requests():
    if not session.get("admin_logged_in"):
        flash("Unauthorized access.", "danger")
        return redirect(url_for('admin_login'))

    if request.method == 'POST':
        request_id = request.form.get('request_id')
        action = request.form.get('action')
        cashout = CashoutRequest.query.get(request_id)

        if not cashout:
            flash("Cashout request not found.", "danger")
        elif cashout.status.lower() != 'pending':
            flash("This request has already been processed.", "info")
        else:
            if action == 'approve':
                cashout.status = 'Approved'
                flash(f"✅ Cashout of ₦{cashout.amount} approved.", "success")

            elif action == 'reject':
                cashout.status = 'Rejected'

                # Refund balance
                user = cashout.user or User.query.get(cashout.user_id)
                if user:
                    user.referral_balance += cashout.amount
                    db.session.add(user)

                flash("❌ Cashout request rejected and amount refunded.", "warning")
            else:
                flash("Invalid action.", "danger")

            db.session.commit()

        return redirect(url_for('view_cashout_requests'))

    requests = CashoutRequest.query.order_by(CashoutRequest.timestamp.desc()).all()
    return render_template('admin_cashout_requests.html', requests=requests)



@app.route('/admin/ads')
def manage_ads():
    if not session.get("admin_logged_in"):
        flash("Unauthorized access", "danger")
        return redirect(url_for('admin_login'))
    
    ads = AdSlot.query.order_by(AdSlot.created_at.desc()).all()
    return render_template("admin_manage_ads.html", ads=ads)

@app.route('/admin/edit_ad/<int:ad_id>', methods=['GET', 'POST'])
def edit_ad(ad_id):
    if not session.get("admin_logged_in"):
        flash("Unauthorized access", "danger")
        return redirect(url_for('admin_login'))

    ad = AdSlot.query.get_or_404(ad_id)

    if request.method == 'POST':
        ad.ad_title = request.form.get('ad_title', ad.ad_title)
        ad.reward = int(request.form.get('reward', ad.reward))
        ad.duration_seconds = int(request.form.get('duration', ad.duration_seconds))
        db.session.commit()
        flash("✅ Ad updated successfully.", "success")
        return redirect(url_for('manage_ads'))

    return render_template('admin_edit_ad.html', ad=ad)

@app.route('/admin/delete_ad/<int:ad_id>', methods=['POST'])
def delete_ad(ad_id):
    if not session.get("admin_logged_in"):
        flash("Unauthorized access", "danger")
        return redirect(url_for('admin_login'))

    ad = AdSlot.query.get_or_404(ad_id)
    db.session.delete(ad)
    db.session.commit()
    flash("🗑️ Ad deleted.", "info")
    return redirect(url_for('manage_ads'))

@app.route('/update_profile', methods=['GET', 'POST'])
@login_required
def update_profile():
    form = UpdateProfileForm()
    if request.method == 'POST':
        form = UpdateProfileForm()
        if form.validate_on_submit():
            username = request.form['username']
            email = request.form['email']
            password = bcrypt.generate_password_hash(request.form['password']).decode('utf-8')
            
            user = db.session.get(User, session['user_id'])
            user.username = username
            user.email = email
            user.password = password
            
            try:
                db.session.commit()
                flash('Profile updated successfully!', 'success')
                return redirect('/dashboard')
            except Exception as e:
                db.session.rollback()
                flash('Error updating profile', 'error')
                return render_template('update_profile.html', user=user)
    return render_template('update_profile.html', user=db.session.get(User, session['user_id']))

@app.route('/cashout', methods=['GET', 'POST'])
def cashout():
    if 'user_id' not in session:
        flash("You need to log in to access the cashout page.", "danger")
        return redirect(url_for('login'))

    user_id = session['user_id']
    user = User.query.get(user_id)

    if not user:
        flash("User not found.", "danger")
        return redirect(url_for('login'))

    # ✅ Recalculate total referral earnings (same as dashboard)
    all_referrals = Referral.query.filter_by(referrer_id=user.id).all()
    completed_referrals = [ref for ref in all_referrals if ref.status == 'Completed']
    total_referral_earnings = len(completed_referrals) * 1500

    # ✅ Get all approved and pending cashouts
    approved_cashouts = CashoutRequest.query.filter_by(user_id=user.id, status='Approved').all()
    total_cashouts = sum(c.amount for c in approved_cashouts)

    pending_cashouts = CashoutRequest.query.filter_by(user_id=user.id, status='pending').all()
    pending_total = sum(c.amount for c in pending_cashouts)

    # ✅ Calculate available balance consistently
    available_balance = max(total_referral_earnings - total_cashouts - pending_total, 0)

    if request.method == 'POST':
        try:
            amount = request.form.get('amount')
            bank_name = request.form.get('bank_name', '').strip()
            account_number = request.form.get('account_number', '').strip()

            # ✅ Validate inputs
            if not bank_name or not account_number:
                flash("Bank name and account number are required.", "danger")
                return redirect(url_for('cashout'))

            if not amount or not amount.replace('.', '', 1).isdigit():
                flash("Please enter a valid numeric amount.", "danger")
                return redirect(url_for('cashout'))

            amount = float(amount)

            if amount < 15000:
                flash("Minimum cashout is ₦15,000.", "warning")
                return redirect(url_for('cashout'))

            if amount > available_balance:
                flash("Insufficient available balance.", "danger")
                return redirect(url_for('cashout'))

            # ✅ Create cashout request
            cashout = CashoutRequest(
                user_id=user.id,
                amount=amount,
                bank_name=bank_name,
                account_number=account_number,
                status='pending'
            )
            db.session.add(cashout)

            # ✅ Log transaction
            transaction = Transaction(
                user_id=user.id,
                amount=amount,
                type="Withdrawal"
            )
            db.session.add(transaction)

            db.session.commit()

            flash("Cashout request submitted successfully. Admin will review and process shortly.", "success")
            return redirect(url_for('dashboard'))

        except Exception as e:
            db.session.rollback()
            flash(f"An error occurred: {str(e)}", "danger")
            return redirect(url_for('cashout'))

    return render_template(
        'cash_out.html',
        user=user,
        computed_referral_balance=total_referral_earnings,
        available_balance=available_balance
    )



@app.route('/transactions')
@login_required
def transactions():
    if 'user_id' not in session:
        flash("Please log in to view your transactions.", "warning")
        return redirect(url_for('login'))

    try:
        user_id = session['user_id']

        # Fetch all transactions belonging to this user
        all_transactions = Transaction.query.filter_by(user_id=user_id).order_by(Transaction.date.desc()).all()

        final_transactions = []
        handled_referrals = set()

        for txn in all_transactions:
            if txn.type == "Referral Bonus":
                # Check referral record
                referrals = Referral.query.filter_by(referrer_id=user_id).all()

                for ref in referrals:
                    if ref.referred_user_id in handled_referrals:
                        continue  # Avoid duplicates

                    # Mark this referral as handled
                    handled_referrals.add(ref.referred_user_id)

                    # Clone the transaction and modify type label
                    labeled_txn = txn
                    if ref.status == "Completed":
                        labeled_txn.type = "Referral Bonus (Completed)"
                    else:
                        labeled_txn.type = "Referral Bonus (Pending)"
                    
                    final_transactions.append(labeled_txn)
                    break
            else:
                final_transactions.append(txn)

        return render_template('transactions.html', transactions=final_transactions)

    except Exception as e:
        app.logger.error(f"Transaction Error: {e}")
        flash("An error occurred while loading your transaction history.", "danger")
        return redirect(url_for('dashboard'))


# User Payment Submission
@app.route('/submit_payment', methods=['GET', 'POST'])
def submit_payment():
    """
    Handles payment submission by the user.
    Redirects to login after successful submission.
    Prevents multiple submissions for the same payment status.
    """
    if 'user_id' not in session:  # Ensure user is logged in
        flash("Please log in first.", "danger")
        return redirect(url_for('login'))

    user_id = session['user_id']
    user = db.session.get(User, user_id)

    # Restrict access if payment is already approved
    if user.payment_status == "Paid":
        flash("Your payment has been approved. You can now access your dashboard.", "success")
        return redirect(url_for('dashboard'))

    # Check if a payment is already under review (Pending)
    existing_payment = Payment.query.filter_by(user_id=user_id, status="Pending").first()
    if existing_payment:
        flash("Your payment is already under review. Please wait for admin approval.", "warning")
        return redirect(url_for('login'))

    if request.method == 'POST':
        # Retrieve form inputs
        payment_method = request.form.get('payment_method')
        transaction_id = request.form.get('transaction_id')
        payment_date_str = request.form.get('payment_date')

        try:
            payment_date = datetime.strptime(payment_date_str, '%Y-%m-%d').date()  # ✅ Convert to date object
        except ValueError:
            flash("Invalid date format. Use YYYY-MM-DD.", "danger")
            return redirect(request.url)

        amount = request.form.get('amount')
        proof = request.files.get('proof_of_payment')  # ✅ corrected to match the field name

        # Validate inputs
        if not all([payment_method, transaction_id, payment_date, amount]):
            flash("All fields are required.", "danger")
            return redirect(request.url)

        try:
            amount = float(amount)
        except ValueError:
            flash("Invalid amount entered. Please enter a valid number.", "danger")
            return redirect(request.url)

        if not proof:
            flash("No file uploaded.", "danger")
            return redirect(request.url)

        if proof.filename == "":
            flash("No selected file.", "danger")
            return redirect(request.url)

        if proof and allowed_file(proof.filename):
            filename = secure_filename(proof.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            proof.save(filepath)
        else:
            flash("Invalid or missing file. Allowed types: png, jpg, jpeg, pdf.", "danger")
            return redirect(request.url)

        # ✅ Now continue with creating the payment
        payment = Payment(
            user_id=user_id,
            payment_method=payment_method,
            transaction_id=transaction_id,
            payment_date=payment_date,
            amount=amount,
            proof=filename,  # Save just the filename, not the full path
            status="Pending"
        )
        db.session.add(payment)

        # ✅ Handle referral rewards only if referred_by exists
        if user.referred_by:
            referrer = User.query.get(user.referred_by)
            if referrer:
                referrer.referral_balance += 1500  # Reward referrer
                referral = Referral(
                    referrer_id=referrer.id,
                    referred_user_id=user.id,
                    referred_username=user.username,
                    status="Pending"
                )
                db.session.add(referral)

        # ✅ Don't insert referral record if no referrer exists to avoid IntegrityError
        # You may later log these users somewhere else if needed

        # Save changes to the database
        db.session.commit()

        # Notify the user via email
        send_email(user.email, "Payment Submitted",
                   f"Your payment with Transaction ID {transaction_id} has been successfully submitted. Awaiting admin approval.")

        flash("Payment submitted successfully! Awaiting admin approval.", "success")
        return redirect(url_for('login'))  # Redirect to login after submission

    return render_template('submit_payment.html')

@app.route('/watch_ads')
@login_required
def watch_ads():
    user = User.query.get_or_404(session['user_id'])
    now = datetime.now(timezone.utc)    # ✅ recommended
    # Show active ads
    ads = AdSlot.query.filter(
        (AdSlot.expiry_time == None) | (AdSlot.expiry_time > now)
    ).order_by(AdSlot.id.desc()).all()

    # Ads already watched by user
    watched_ids = {
        watch.ad_id for watch in UserAdWatch.query.filter_by(user_id=user.id).all()
    }

    # Show current balance at top
    total_points = user.referral_balance

    return render_template(
        "watch_ads.html",
        ads=ads,
        user=user,
        watched_ids=watched_ids,
        total_points=total_points
    )


@app.route('/admin/create_ad', methods=['GET', 'POST'])
def create_ad():
    if not session.get("admin_logged_in"):
        flash("Unauthorized access.", "danger")
        return redirect(url_for('admin_login'))

    if request.method == 'POST':
        title = request.form.get('ad_title', '').strip()
        reward = int(request.form.get('reward', 10))
        duration = int(request.form.get('duration', 5))
        ad_url = request.form.get('ad_url', '').strip()
        file = request.files.get('ad_file')
        schedule = request.form.get('schedule', '24h')

        expiry_map = {
            "12h": timedelta(hours=12),
            "24h": timedelta(hours=24),
            "3d": timedelta(days=3),
            "7d": timedelta(days=7)
        }
        expiry_time = datetime.now(timezone.utc) + expiry_map.get(schedule, timedelta(days=1))

        if file and file.filename != '':
            if allowed_file(file.filename):
                filename = secure_filename(file.filename)
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(file_path)
                ad_url = url_for('static', filename='uploads/' + filename)
            else:
                flash("Unsupported or unsafe file uploaded.", "danger")
                return redirect(url_for('create_ad'))

        if not ad_url:
            flash("Upload a valid media file or provide a URL.", "danger")
            return redirect(url_for('create_ad'))

        ad = AdSlot(
            ad_title=title,
            ad_url=ad_url,
            reward=reward,
            duration_seconds=duration * 60,
            expiry_time=expiry_time
        )
        db.session.add(ad)
        db.session.commit()

        flash("✅ Ad created successfully.", "success")
        return redirect(url_for('create_ad'))

    return render_template("admin_create_ad.html")


from datetime import datetime, timezone

@app.route('/reward_ad', methods=['POST'])
@login_required
def reward_ad():
    try:
        data = request.get_json()
        ad_id = data.get("ad_id")
        user_id = session['user_id']

        if not ad_id:
            return jsonify({"status": "invalid request"}), 400

        # ✅ Fetch ad
        ad = db.session.get(AdSlot, ad_id)
        if not ad:
            return jsonify({"status": "ad not found"}), 404

        # ✅ Check expiry (ensure aware comparison)
        if ad.expiry_time:
            expiry = ad.expiry_time
            if expiry.tzinfo is None:
                expiry = expiry.replace(tzinfo=timezone.utc)
            if expiry < datetime.now(timezone.utc):
                return jsonify({"status": "ad expired"}), 403

        # ✅ Ensure user exists
        user = db.session.get(User, user_id)
        if not user:
            return jsonify({"status": "user not found"}), 404

        # ✅ Prevent double rewards
        already_watched = UserAdWatch.query.filter_by(user_id=user.id, ad_id=ad.id).first()
        if already_watched:
            return jsonify({"status": "already rewarded"}), 200

        # ✅ Reward and record
        user.ad_points += ad.reward
        watch = UserAdWatch(
            user_id=user.id,
            ad_id=ad.id,
            reward_earned=True,
            timestamp=datetime.utcnow()
        )

        db.session.add(watch)
        db.session.commit()

        return jsonify({"status": "rewarded", "reward": ad.reward}), 200

    except Exception as e:
        app.logger.error(f"/reward_ad error: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/privacy')
def privacy_policy():
    return render_template('privacy.html')

@app.route('/terms')
def terms_of_use():
    return render_template('terms.html')

# Run the app
if __name__ == "__main__":
    with app.app_context():
        db.create_all()

        # Initialize referral balances for existing users
        users = User.query.all()
        for user in users:
            print(f"Before Update: {user.username}, Referral Balance: {user.referral_balance}")
            if user.referral_balance is None:
                user.referral_balance = 0.0
                print(f"Updated: {user.username}, Referral Balance: {user.referral_balance}")
        db.session.commit()

    # Run the app
    port = int(os.environ.get("PORT", 5000))
    app.run(debug=False, host="0.0.0.0", port=port)
