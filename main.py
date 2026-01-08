from dotenv import load_dotenv
load_dotenv()

import os
from flask import Flask, jsonify, request, send_from_directory, render_template,url_for, abort, flash, redirect, session
from flask_session import Session
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import UniqueConstraint
from flask_bcrypt import Bcrypt
from flask_migrate import Migrate
from flask_wtf import FlaskForm
from wtforms import StringField, TextAreaField, DateTimeLocalField, SelectField, PasswordField, FileField, FloatField, SubmitField, BooleanField, DecimalField, IntegerField
from wtforms.validators import DataRequired, Length, NumberRange
from flask_wtf.file import FileField, FileAllowed
from datetime import datetime, date
import os
from werkzeug.utils import secure_filename
from sqlalchemy import or_
from collections import defaultdict
import uuid
from flask import current_app
from flask import send_from_directory
from datetime import datetime
from sqlalchemy.orm import joinedload
from sqlalchemy.exc import IntegrityError



# Absolute path for SQLite database
file_path = os.path.abspath(os.getcwd()) + "/database.db"

app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get("DATABASE_URL")
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY")
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = 'filesystem'
app.config['UPLOAD_FOLDER'] = 'static/uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'xls', 'xlsx'}

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
migrate = Migrate(app, db)
Session(app)

def strftime_filter(dt, fmt):
    if dt is None:
        return ''
    return dt.strftime(fmt)

app.jinja_env.filters['strftime'] = strftime_filter

# Ensure upload folder exists
if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

# User class
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    fullname = db.Column(db.String(255), nullable=False)
    email = db.Column(db.String(255), nullable=False, unique=True)
    username = db.Column(db.String(255),unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    status = db.Column(db.Integer, default=1, nullable=False)

    def __repr__(self):
        return f'User("{self.id}","{self.fullname}","{self.email}","{self.username}","{self.status}")'
    
# User Form
class UserForm(FlaskForm):
    fullname = StringField('Full Name', validators=[DataRequired(message='Full name cannot be empty.'), Length(max=255, message='Full name must be 255 characters or less.')])
    username = StringField('Username', validators=[DataRequired(message='Username cannot be empty.'), Length(max=255, message='Username must be 255 characters or less.')])
    password = PasswordField('Password', validators=[DataRequired(message='Password cannot be empty.')])


# Booking class
class RegularEventBooking(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    booking_type = db.Column(db.String(50), nullable=False)  # regular, event
    meal_type = db.Column(db.String(50), nullable=False)  # breakfast, lunch, dinner
    quantity = db.Column(db.Integer, nullable=False)
    total = db.Column(db.Float, nullable=False)
    date = db.Column(db.String(50), nullable=False)  # ISO format (YYYY-MM-DD)
    status = db.Column(db.String(50), default='Pending', nullable=False)
    remarks = db.Column(db.Text, nullable=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, onupdate=datetime.utcnow, nullable=True)


class PartyBooking(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    nature = db.Column(db.String(50), nullable=False)  # Official/Unofficial
    occasion = db.Column(db.String(100), nullable=False)
    participants = db.Column(db.Integer, nullable=False)
    veg_count = db.Column(db.Integer, nullable=False)
    non_veg_count = db.Column(db.Integer, nullable=False)
    date = db.Column(db.String(50), nullable=False)  # ISO format (YYYY-MM-DD)
    time = db.Column(db.String(50), nullable=False)  # HH:MM
    telephone = db.Column(db.String(20), nullable=False)
    mobile = db.Column(db.String(20), nullable=False)
    menu_items = db.Column(db.Text, nullable=False)
    area_selection = db.Column(db.String(50), nullable=False)  # Bar Room, Lawn Area, Function Hall
    meal_type = db.Column(db.String(50), nullable=False)  # breakfast, lunch, dinner
    total = db.Column(db.Float, nullable=False)
    status = db.Column(db.String(50), default='Pending', nullable=False)
    remarks = db.Column(db.Text, nullable=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, onupdate=datetime.utcnow, nullable=True)

    user = db.relationship('User', backref='party_bookings', lazy=True)


# Admin class
class Admin(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(255), nullable=False)
    password = db.Column(db.String(255), nullable=False)

    def __repr__(self):
        return f'Admin("{self.id}","{self.username}")'

# Slide class
class Slide(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)
    url = db.Column(db.String(255), nullable=False)
    caption = db.Column(db.String(255), nullable=True)


# Home page Gallery
class HomepageGallery(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)
    caption = db.Column(db.String(255), nullable=True)
    date_uploaded = db.Column(db.DateTime, default=datetime.utcnow)

# GalleryPhoto class
class Gallery(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)
    event_name = db.Column(db.String(150), nullable=True)  # e.g., "Diwali 2025"
    caption = db.Column(db.String(255), nullable=True)
    category = db.Column(db.String(50), nullable=False, default='Other')  # Events, Facilities, Food, Other
    year = db.Column(db.Integer, nullable=True)
    date_uploaded = db.Column(db.DateTime, default=datetime.utcnow)

class GalleryForm(FlaskForm):
    photos = FileField(
        'Upload Images',
        validators=[
            FileAllowed(['jpg', 'jpeg', 'png', 'gif', 'webp'], 'Images only!')
        ]
    )
    event_name = StringField('Event Name', validators=[DataRequired()])
    caption = StringField('Caption', validators=[Length(max=255)])
    year = IntegerField('Year', validators=[DataRequired()])
    category = SelectField(
        'Category',
        choices=[
            ('retirement', 'Retirement'),
            ('festivals', 'Festivals'),
            ('parties', 'Parties')
        ],
        validators=[DataRequired()]
    )
    submit = SubmitField('Upload')


# Event class
class Event(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    short_description = db.Column(db.String(100), nullable=False)  # One-line for previews
    full_description = db.Column(db.Text, nullable=False)  # Multi-line for details
    date_time = db.Column(db.DateTime, nullable=False)  # Combined date and time
    location = db.Column(db.String(100), nullable=False)
    image = db.Column(db.String(255), nullable=True)  # Single image
    detail_image = db.Column(db.String(255), nullable=True)    # NEW: Detail photo
    show_in_featured = db.Column(db.Boolean, default=False)
    show_in_upcoming = db.Column(db.Boolean, default=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)


# Event Form
class EventForm(FlaskForm):
    title = StringField('Event Title', validators=[DataRequired(), Length(max=100)])
    short_description = StringField('Short Description (for previews)', validators=[DataRequired(), Length(max=100)])
    full_description = TextAreaField('Full Description (for details page)', validators=[DataRequired()])
    date_time = DateTimeLocalField(
        "Date & Time",
        format="%Y-%m-%dT%H:%M",  # matches HTML datetime-local value format
        validators=[DataRequired()]
    )
    location = StringField('Location', validators=[DataRequired(), Length(max=100)])
    image = FileField('Image Upload (optional)')
    detail_image = FileField('Detail Image (large photo for event page)')
    photos = FileField('Detail Photos (optional, for event details)', render_kw={'multiple': True})
    show_in_featured = BooleanField('Show in Featured Events section on homepage')
    show_in_upcoming = BooleanField('Show in All Upcoming Events section on homepage', default=True)
    submit = SubmitField('Save Event')

# Menu items    

class MenuItem(db.Model):
    __tablename__ = 'menu_item'  # Optional, but good to be explicit

    id = db.Column(db.Integer, primary_key=True)
    section = db.Column(db.String(50), nullable=False)  # breakfast, lunch, etc.
    day = db.Column(db.String(20), nullable=True)       # Only for breakfast
    item_name = db.Column(db.String(200), nullable=False)
    price = db.Column(db.Float, nullable=False)
    description = db.Column(db.Text, nullable=True)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class MenuItemForm(FlaskForm):
    name = StringField('Menu Item Name', validators=[DataRequired(), Length(max=100)])
    meal_type = SelectField('Meal Type', choices=[('Breakfast', 'Breakfast'), ('Lunch', 'Lunch'), ('Dinner', 'Dinner')], validators=[DataRequired()])
    day = SelectField('Day', choices=[('Monday', 'Monday'), ('Tuesday', 'Tuesday'), ('Wednesday', 'Wednesday'), ('Thursday', 'Thursday'), ('Friday', 'Friday'), ('Saturday', 'Saturday'), ('Sunday', 'Sunday')], validators=[DataRequired()])
    cost = FloatField('Cost', validators=[DataRequired(), NumberRange(min=0)])
    image = FileField('Image')
    submit = SubmitField('Add Menu Item')
    description = StringField('Items', validators=[DataRequired(), Length(max=255)])

class MenuPrice(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    category = db.Column(db.String(50), nullable=False)  # regular, event, party
    meal_type = db.Column(db.String(50), nullable=False)  # breakfast, lunch, dinner
    price = db.Column(db.Float, nullable=False)
    __table_args__ = (db.UniqueConstraint('category', 'meal_type', name='unique_category_meal_type'),)


class MenuConfig(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    data = db.Column(db.JSON, nullable=False)  # Stores entire menu as JSON
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    @staticmethod  # ← ADD THIS LINE
    def get_menu():
        config = MenuConfig.query.first()
        if config:
            return config.data
        # Default fallback menu (copy your current hardcoded one here)
        return {
            "breakfast": {
                "Monday": "Poori, Aloo curry, Tea/Horlicks, Banana – ₹50/-",
                "Tuesday": "Dosa (Masala, Onion, Plain), Chutney, Tea/Horlicks, Banana – ₹50/-",
                "Wednesday": "Oil Paratha, Aloo curry, Tea/Horlicks, Banana – ₹50/-",
                "Thursday": "Idli, Chutney, Sambar, Tea/Horlicks, Banana – ₹50/-",
                "Friday": "Utthapam, Chutney, Tea/Horlicks, Banana – ₹50/-",
                "Saturday": "Poori, Vada, Chana curry, Chutney, Tea/Horlicks, Banana – ₹50/-",
                "Sunday": "Aloo Paratha, Pickle, Curd, Tea/Horlicks, Banana – ₹50/-"
            },
            "lunch": [
                "Standard Lunch – ₹100/-",
                "Lunch with Chicken Curry – ₹150/-",
                "Working Lunch (Veg) – ₹200/-",
                "Working Lunch (Non-Veg) – ₹300/-",
                "Special Lunch (Wednesday & Sunday) – ₹150/-"
            ],
            "dinner": [
                "Daily Dinner – ₹120/-",
                "Dinner with Mutton Curry – ₹200/-"
            ],
            "beverages": [
                "Tea – ₹10/-",
                "Coffee – ₹10/-"
            ],
            "leisure": [
                "Omlet – ₹20/-",
                "Noodles – ₹30/-",
                "Veg Manchuria – ₹35/-",
                "Egg Roll – ₹35/-",
                "Chicken Fry – ₹50/-",
                "Fish Fry (2 Pieces) – ₹50/-",
                "Masala Peanuts – ₹25/-",
                "Onion Pakoda – ₹15/-",
                "Soft Drink – ₹20/-",
                "Soda (Small) – ₹10/-",
                "Soda (Big) – ₹20/-"
            ]
        }

# Member class
class Member(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    role = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=True)
    image = db.Column(db.String(255), nullable=True)
    is_executive = db.Column(db.Boolean, default=False)

# Member Form
class MemberForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired(message='Name cannot be empty.'), Length(max=100, message='Name must be 100 characters or less.')])
    role = StringField('Role', validators=[DataRequired(message='Role cannot be empty.'), Length(max=100, message='Role must be 100 characters or less.')])
    description = TextAreaField('Description')
    image = StringField('Image', validators=[])  # Handled manually for file upload

# Session class
class Session(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False, unique=True)
    schedule = db.Column(db.String(100), nullable=False)
    image = db.Column(db.String(255), nullable=True)
    instructor_name = db.Column(db.String(100), nullable=True)
    contact_details = db.Column(db.String(255), nullable=True)  # e.g., phone/email
    course_fee = db.Column(db.Numeric(10, 2), nullable=True)    # e.g., 5000.00

# Session Form
class SessionForm(FlaskForm):
    name = StringField('Session Name', validators=[DataRequired(message='Name cannot be empty.'), Length(max=100, message='Name must be 100 characters or less.')])
    schedule = StringField('Schedule', validators=[DataRequired(message='Schedule cannot be empty.'), Length(max=100, message='Schedule must be 100 characters or less.')])
    image = StringField('Image', validators=[])  # Handled manually for file upload
    instructor_name = StringField('Instructor Name')
    contact_details = StringField('Contact Details (Phone/Email)')
    course_fee = DecimalField('Course Fee (₹)', places=2)


# Bill Class
class MonthlyBillExcel(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    month = db.Column(db.Integer, nullable=False)  # 1-12
    year = db.Column(db.Integer, nullable=False)    
    filename = db.Column(db.String(100), nullable=False)
    upload_date = db.Column(db.DateTime, default=datetime.utcnow)

    __table_args__ = (UniqueConstraint('month', 'year', name='unique_month_year'),)

    def __repr__(self):
        return f"<MonthlyBill {self.month}/{self.year} - {self.filename}>"




# Create DB tables
# Create DB tables and initialize menu items


    # insert admin data
    # admin = Admin(username='Nikhil123',password=bcrypt.generate_password_hash('Nikhil123', 10).decode('utf-8'))
    # admin = Admin(username='OMI',password=bcrypt.generate_password_hash('OMI$123', 10).decode('utf-8'))
    # db.session.add(admin)
    # db.session.commit()

def ensure_admin():
    admin_username = os.getenv("ADMIN_USERNAME")
    admin_password = os.getenv("ADMIN_PASSWORD")

    print("ADMIN_USERNAME:", admin_username)
    print("ADMIN_PASSWORD SET:", bool(admin_password))

    if not admin_username or not admin_password:
        print("Admin credentials not set")
        return

    admin = Admin.query.filter_by(username=admin_username).first()

    if not admin:
        admin = Admin(
            username=admin_username,
            password=bcrypt.generate_password_hash(admin_password).decode("utf-8")
        )
        db.session.add(admin)
        db.session.commit()
        print("Admin created successfully")
    else:
        print("Admin already exists")

with app.app_context():
    db.create_all()
    ensure_admin()


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Public Routes
@app.route('/')
@app.route('/home')
def public_home():
    # Slides for carousel
    slides = Slide.query.all()
    
    # Featured Events (carousel)
    featured_events = Event.query.filter_by(show_in_featured=True)\
        .order_by(Event.date_time.asc()).all()
    
    # Upcoming Events (grid)
    upcoming_events = Event.query.filter_by(show_in_upcoming=True)\
        .order_by(Event.date_time.asc()).all()
    
    # Homepage Gallery Preview - latest 6 photos
    preview_photos = HomepageGallery.query.order_by(
        HomepageGallery.date_uploaded.desc()
    ).all()
    
    # Menu Items
    menu_items = MenuItem.query.all()
    
    # Current Sessions
    sessions = Session.query.all()
    
    # Executive Members
    executive_members = Member.query.filter_by(is_executive=True).all()
    
    return render_template(
        'public/home.html',
        slides=slides,
        featured_events=featured_events,
        upcoming_events=upcoming_events,
        preview_photos=preview_photos,
        menu_items=menu_items,
        sessions=sessions,
        members=executive_members
    )


@app.route('/menu')
def menu():
    sections = ['breakfast', 'lunch', 'dinner', 'beverages', 'leisure']
    menu_data = {section: MenuItem.query.filter_by(section=section).order_by(MenuItem.day, MenuItem.item_name).all() for section in sections}

    return render_template('public/menu.html', menu_data=menu_data)

@app.route('/admin/seed-menu')
def seed_menu():
    if 'admin_id' not in session:  # Keep it admin-only
        flash('Admin access required.', 'danger')
        return redirect(url_for('login'))

    # List of (section, day, item_name, price)
    # day = None for non-breakfast sections
    menu_items = [
        # Breakfast
        ('breakfast', 'Monday', 'Poori, Aloo curry, Tea/Horlicks, Banana', 50.0),
        ('breakfast', 'Tuesday', 'Dosa (Masala, Onion, Plain), Chutney, Tea/Horlicks, Banana', 50.0),
        ('breakfast', 'Wednesday', 'Oil Paratha, Aloo curry, Tea/Horlicks, Banana', 50.0),
        ('breakfast', 'Thursday', 'Idli, Chutney, Sambar, Tea/Horlicks, Banana', 50.0),
        ('breakfast', 'Friday', 'Utthapam, Chutney, Tea/Horlicks, Banana', 50.0),
        ('breakfast', 'Saturday', 'Poori, Vada, Chana curry, Chutney, Tea/Horlicks, Banana', 50.0),
        ('breakfast', 'Sunday', 'Aloo Paratha, Pickle, Curd, Tea/Horlicks, Banana', 50.0),

        # Lunch
        ('lunch', None, 'Standard Lunch', 100.0),
        ('lunch', None, 'Lunch with Chicken Curry', 150.0),
        ('lunch', None, 'Working Lunch (Veg)', 200.0),
        ('lunch', None, 'Working Lunch (Non-Veg)', 300.0),
        ('lunch', None, 'Special Lunch (Wednesday & Sunday)', 150.0),

        # Dinner
        ('dinner', None, 'Daily Dinner', 120.0),
        ('dinner', None, 'Dinner with Mutton Curry', 200.0),

        # Beverages
        ('beverages', None, 'Tea', 10.0),
        ('beverages', None, 'Coffee', 10.0),

        # Leisure Lounge
        ('leisure', None, 'Omlet', 20.0),
        ('leisure', None, 'Noodles', 30.0),
        ('leisure', None, 'Veg Manchuria', 35.0),
        ('leisure', None, 'Egg Roll', 35.0),
        ('leisure', None, 'Chicken Fry', 50.0),
        ('leisure', None, 'Fish Fry (2 Pieces)', 50.0),
        ('leisure', None, 'Masala Peanuts', 25.0),
        ('leisure', None, 'Onion Pakoda', 15.0),
        ('leisure', None, 'Soft Drink', 20.0),
        ('leisure', None, 'Soda (Small)', 10.0),
        ('leisure', None, 'Soda (Big)', 20.0),
    ]

    added_count = 0
    for section, day, name, price in menu_items:
        # Avoid duplicates
        exists = MenuItem.query.filter_by(section=section, day=day, item_name=name).first()
        if not exists:
            item = MenuItem(section=section, day=day, item_name=name, price=price)
            db.session.add(item)
            added_count += 1

    db.session.commit()
    flash(f'Successfully seeded {added_count} menu items!', 'success')
    return redirect(url_for('admin_menu'))  # Redirect to admin menu page

@app.route('/gallery')
def gallery():
    # Get all photos with category and year (for structured gallery)
    gallery_items = Gallery.query.filter(
        Gallery.category.isnot(None),
        Gallery.year.isnot(None)
    ).order_by(Gallery.year.desc(), Gallery.date_uploaded.desc()).all()

    # Dynamic categories from data + 'All'
    unique_categories = sorted({item.category for item in gallery_items if item.category})
    categories = ['All'] + unique_categories

    # Unique years (newest first)
    years = sorted({item.year for item in gallery_items if item.year}, reverse=True)

    return render_template(
        'public/gallery.html',
        gallery_items=gallery_items,
        categories=categories,
        years=years
    )

@app.route('/gallery/<string:category>/<int:year>')
def gallery_year(category, year):
    if category == 'all':
        photos = Gallery.query.filter_by(year=year).order_by(Gallery.date_uploaded.desc()).all()
        title = f"All Photos - {year}"
    else:
        photos = Gallery.query.filter_by(category=category, year=year).order_by(Gallery.date_uploaded.desc()).all()
        title = f"{category.capitalize()} - {year}"

    if not photos:
        flash('No photos found for this selection.', 'info')
        return redirect(url_for('gallery'))

    return render_template(
        'public/gallery_year.html',
        photos=photos,
        year=year,
        category=category,
        title=title
    )

@app.route('/events')
def events():
    events = Event.query.order_by(Event.date_time.asc()).all()
    return render_template('public/events.html', events=events)

@app.route('/event/<int:id>')
def event_detail(id):
    event = Event.query.get_or_404(id)
    return render_template('public/event_detail.html', event=event)

@app.route('/members')
def members():
    members = Member.query.all()
    return render_template('public/members.html', members=members)


# ----------------------- USER SPACE ------------------------
@app.route('/login')
def main_login():
    return render_template('index.html')


@app.route('/user-login', methods=['GET', 'POST'])
def userLogin():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        if not username or not password:
            flash('Please fill all the fields.', 'danger')
            return redirect('/login')
        user = User.query.filter_by(username=username).first()
        if user and bcrypt.check_password_hash(user.password, password):
            session['user_id'] = user.id
            session['username'] = user.username
            flash('Logged in successfully!', 'success')
            return redirect('/')
        else:
            flash('Invalid username or password.', 'danger')
            return redirect('/login')
    return render_template('index.html')


@app.route('/signup', methods=['GET', 'POST'])
def userSignup():
    if request.method == 'POST':
        fullname = request.form.get('fullname')
        email = request.form.get('email')
        username = request.form.get('username')
        password = request.form.get('password')
        confirmpassword = request.form.get('confirmpassword')
        if not all([fullname, email, username, password, confirmpassword]):
            flash('All fields are required.', 'error')
            return redirect('/signup')
        if User.query.filter_by(email=email).first():
            flash('Email already exists.', 'danger')
            return redirect('/signup')
        if User.query.filter_by(username=username).first():
            flash('Username already exists. Please choose another.', 'danger')
            return redirect('/signup')
        if password != confirmpassword:
            flash('Passwords do not match.', 'error')
            return redirect('/signup')
        hash_password = bcrypt.generate_password_hash(password, 10).decode('utf-8')
        user = User(fullname=fullname, email=email, username=username, password=hash_password)
        db.session.add(user)
        db.session.commit()
        flash('Account created successfully!', 'success')
        return redirect('/login')
    return render_template('index.html')

@app.route('/logout')
def userLogout():
    session.clear()
    flash("Logged out successfully", "success")
    return redirect('/')

@app.route('/forgot-password', methods=['GET', 'POST'])
def userChangepassword():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        if not email or not password:
            flash('Please fill all fields', 'danger')
            return redirect('/forgot-password')
        user = User.query.filter_by(email=email).first()
        if user:
            hashed_password = bcrypt.generate_password_hash(password, 10).decode('utf-8')
            user.password = hashed_password
            db.session.commit()
            flash('Password changed successfully', 'success')
        else:
            flash('Invalid email', 'danger')
        return redirect('/forgot-password')
    return render_template('forgot_password.html', title='Change Password')


# ------------------------ ADMIN SPACE -----------------------------------

# Admin login
@app.route('/admin-login', methods=['POST', 'GET'])     
def adminIndex():
    if request.method == "POST":
        username = request.form.get('username')
        password = request.form.get('password')
        if username == "" or password == "":
            flash("Please fill all the details", 'danger')
            return redirect('/login')
        admins = Admin.query.filter_by(username=username).first()
        if admins and bcrypt.check_password_hash(admins.password, password):
            session['admin_id'] = admins.id
            session['admin_name'] = admins.username
            flash("Login successfully", 'success')
            return redirect('/admin/dashboard')
        else:
            flash('Invalid email or password', 'danger')
            return redirect('/login')
    return render_template('index.html', title="Admin login")

# Admin Routes
@app.route('/admin/dashboard', methods=['POST', 'GET'])
def adminDashboard():
    if 'admin_id' not in session:
        flash('Please log in as admin.', 'danger')
        return redirect('/login')
    user_count = User.query.count()  # Get total number of users
    return render_template('admin/dashboard.html',user_count=user_count)

#------------------------ ADMIN USER MANAGEMENT -----------------------------

# Defining the route
@app.route('/admin/manage-users', methods=['GET'])
def manage_users():
    if 'admin_id' not in session:
        flash('Please log in as admin.', 'danger')
        return redirect('/login')
    search_query = request.args.get('search', '')
    if search_query:
        users = User.query.filter(or_(User.fullname.ilike(f'%{search_query}%'), User.username.ilike(f'%{search_query}%'))).all()
    else:
        users = User.query.all()
    form = UserForm()
    return render_template('admin/preview/manage_users.html', users=users, form=form, search_query=search_query)

# Get the users
@app.route('/admin/users', methods=['GET'])
def get_users():
    search_query = request.args.get('search', '')
    if search_query:
        users = User.query.filter(or_(User.fullname.ilike(f'%{search_query}%'), User.username.ilike(f'%{search_query}%'))).all()
    else:
        users = User.query.all()
    return jsonify([{'id': user.id, 'fullname': user.fullname, 'username': user.username} for user in users])

# Add any user
@app.route('/admin/users', methods=['POST'])
def add_user():
    if 'admin_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    form = UserForm()
    if form.validate_on_submit():
        if User.query.filter_by(username=form.username.data).first():
            flash('Username already exists.', 'danger')
            users = User.query.all()
            return render_template('admin/preview/manage_users.html', users=users, form=form)
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user_item = User(
            fullname=form.fullname.data,
            username=form.username.data,
            password=hashed_password,
            email=f"{form.username.data}@example.com"  # Dummy email to satisfy model
        )
        db.session.add(user_item)
        try:
            db.session.commit()
            flash('User added successfully!', 'success')
            return redirect('/admin/manage-users')
        except Exception as e:
            db.session.rollback()
            flash(f'Error adding user: {str(e)}', 'danger')
            users = User.query.all()
            return render_template('admin/preview/manage_users.html', users=users, form=form)
    else:
        for field, errors in form.errors.items():
            for error in errors:
                flash(f'Error in {field}: {error}', 'danger')
        users = User.query.all()
        return render_template('admin/preview/manage_users.html', users=users, form=form)

# Edit users
@app.route('/admin/users/<int:id>', methods=['GET', 'POST'])
def edit_user(id):
    if 'admin_id' not in session:
        flash('Please log in as admin.', 'danger')
        return redirect('/login')
    user_item = User.query.get_or_404(id)
    form = UserForm(obj=user_item)
    if request.method == 'POST':
        if form.validate_on_submit():
            if User.query.filter(User.username == form.username.data, User.id != id).first():
                flash('Username already exists.', 'danger')
                users = User.query.all()
                return render_template('admin/preview/manage_users.html', users=users, form=form, editing=user_item)
            user_item.fullname = form.fullname.data
            user_item.username = form.username.data
            if form.password.data:
                user_item.password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
            db.session.commit()
            flash('User updated successfully!', 'success')
            return redirect('/admin/manage-users')
        else:
            for field, errors in form.errors.items():
                for error in errors:
                    flash(f'Error in {field}: {error}', 'danger')
    users = User.query.all()
    return render_template('admin/preview/manage_users.html', users=users, form=form, editing=user_item)

# Delete user
@app.route('/admin/users/<int:id>/delete', methods=['POST'])
def delete_user(id):
    if 'admin_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    user_item = User.query.get(id)
    if not user_item:
        return jsonify({'error': 'User not found'}), 404
    db.session.delete(user_item)
    db.session.commit()
    flash('User deleted successfully!', 'success')
    return redirect('/admin/manage-users')


#--------------------------- ADMIN EVENTS MANAGEMENT ---------------------------

# Adding and editing the event
@app.route('/admin/events', methods=['GET', 'POST'])
def manage_events():
    if 'admin_id' not in session:
        flash('Please log in as admin.', 'danger')
        return redirect('/login')
    
    form = EventForm()
    event = None
    event_id = request.args.get('event_id', type=int)
    
    if event_id:
        event = Event.query.get_or_404(event_id)
        if request.method == 'GET':
            form.title.data = event.title
            form.short_description.data = event.short_description
            form.full_description.data = event.full_description
            form.date_time.data = event.date_time
            form.location.data = event.location
            # NEW: Load the new flags
            form.show_in_featured.data = event.show_in_featured
            form.show_in_upcoming.data = event.show_in_upcoming

    if form.validate_on_submit():
        is_edit = 'edit_event_submit' in request.form
        event_id_form = request.form.get('event_id', type=int)

        if is_edit:
            event = Event.query.get_or_404(event_id_form)
        else:
            event = Event()

        # Update all fields
        event.title = form.title.data
        event.short_description = form.short_description.data
        event.full_description = form.full_description.data
        event.date_time = form.date_time.data
        event.location = form.location.data
        # NEW: Save the visibility flags
        event.show_in_featured = form.show_in_featured.data
        event.show_in_upcoming = form.show_in_upcoming.data

        # Handle thumbnail image
        if form.image.data and form.image.data.filename != '':
            filename = secure_filename(form.image.data.filename)
            form.image.data.save(os.path.join('static/uploads', filename))
            event.image = filename

        # Handle detail image
        if form.detail_image.data and form.detail_image.data.filename != '':
            filename = secure_filename(form.detail_image.data.filename)
            form.detail_image.data.save(os.path.join('static/uploads', filename))
            event.detail_image = filename

        if not is_edit:
            db.session.add(event)
        db.session.commit()

        flash('Event saved successfully!', 'success')
        return redirect('/admin/events')

    events = Event.query.order_by(Event.date_time.asc()).all()
    return render_template('admin/preview/edit_events.html',
                           form=form, events=events, event=event)

@app.route('/admin/events/delete/<int:id>', methods=['POST'])
def delete_event(id):
    if 'admin_id' not in session:
        flash('Please log in as admin.', 'danger')
        return redirect('/login')
    event = Event.query.get_or_404(id)
    db.session.delete(event)  # Cascade deletes EventPhoto
    db.session.commit()
    flash('Event deleted successfully!', 'success')
    return redirect('/admin/events')
#--------------------------- ADMIN SLIDE SHOW MANAGEMENT ------------------------

# Defining slide show route
@app.route('/admin/edit_slideshow', methods=['GET'])
def edit_slideshow():
    if 'admin_id' not in session:
        flash('Please log in as admin.', 'danger')
        return redirect('/login')
    return render_template("admin/preview/edit_slideshow.html")

# Geting all the photos
@app.route('/api/photos', methods=['GET'])
def get_photos():
    slides = Slide.query.all()
    return jsonify([{'id': slide.id, 'url': slide.url, 'caption': slide.caption} for slide in slides])

# Adding photos
@app.route('/api/photos', methods=['POST'])
def add_photos():
    if 'admin_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    if 'photos' not in request.files:
        return jsonify({'error': 'No photos uploaded'}), 400
    files = request.files.getlist('photos')
    caption = request.form.get('caption', '')
    new_photos = []
    for file in files:
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(file_path)
            url = f"/static/uploads/{filename}"
            slide = Slide(filename=filename, url=url, caption=caption or None)
            db.session.add(slide)
            db.session.commit()
            new_photos.append({'id': slide.id, 'url': slide.url, 'caption': slide.caption})
    return jsonify(new_photos), 201

# Deleting photos
@app.route('/api/photos/<int:id>', methods=['DELETE'])
def delete_photo(id):
    if 'admin_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    slide = Slide.query.get(id)
    if not slide:
        return jsonify({'error': 'Photo not found'}), 404
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], slide.filename)
    if os.path.exists(file_path):
        os.remove(file_path)
    db.session.delete(slide)
    db.session.commit()
    return jsonify({'message': 'Photo deleted'}), 200


#----------------------------- ADMIN HOMEPAGE GALLERY PREVIEW MANAGEMENT -------------------------------

# Defining the route
@app.route('/admin/edit-gallery', methods=['GET', 'POST'])
def edit_gallery():
    if 'admin_id' not in session:
        flash('Please log in as admin.', 'danger')
        return redirect('/login')

    if request.method == 'POST':
        if 'photos' not in request.files:
            flash('No photos selected.', 'danger')
            return redirect(url_for('edit_gallery'))  # ← Always use url_for

        files = request.files.getlist('photos')
        caption = request.form.get('caption', '').strip() or None
        uploaded = 0

        for file in files:
            if file and file.filename and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(file_path)

                photo = HomepageGallery(
                    filename=filename,
                    caption=caption
                )
                db.session.add(photo)
                uploaded += 1

        try:
            if uploaded > 0:
                db.session.commit()
                flash(f'{uploaded} photo(s) uploaded to homepage preview!', 'success')
            else:
                flash('No valid photos were uploaded.', 'warning')
        except Exception as e:
            db.session.rollback()
            flash(f'Error saving photos: {str(e)}', 'danger')

        return redirect(url_for('edit_gallery'))  # ← Always redirect here on success or failure

    # GET request
    photos = HomepageGallery.query.order_by(HomepageGallery.date_uploaded.desc()).all()
    return render_template('admin/preview/edit_gallery.html', photos=photos)


# Get all preview photos (for any AJAX if needed)
@app.route('/admin/gallery-photos', methods=['GET'])
def get_gallery_photos():
    photos = HomepageGallery.query.all()
    return jsonify([
        {
            'id': photo.id,
            'caption': photo.caption or '',
            'url': url_for('static', filename='uploads/' + photo.filename)
        } for photo in photos
    ])

# Delete preview photo
@app.route('/admin/delete-gallery-photo/<int:id>', methods=['POST'])
def delete_gallery_photo(id):
    if 'admin_id' not in session:
        flash('Please log in as admin.', 'danger')
        return redirect('/login')

    photo = HomepageGallery.query.get_or_404(id)

    # Optional: delete file from disk
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], photo.filename)
    if os.path.exists(file_path):
        os.remove(file_path)

    db.session.delete(photo)
    db.session.commit()
    flash('Photo removed from homepage preview.', 'success')
    return redirect(url_for('edit_gallery'))

# ------------------------------- ADMIN GALLERY MANAGEMENT ---------------------------------
@app.route('/admin/gallery', methods=['GET', 'POST'])
def admin_gallery():
    if 'admin_id' not in session:
        flash('Please log in as admin.', 'danger')
        return redirect('/login')

    form = GalleryForm()

    if request.method == 'POST' and form.validate_on_submit():
        files = request.files.getlist('photos')  # ✅ FIXED
        category = form.category.data
        year = form.year.data
        event_name = form.event_name.data.strip()
        caption = form.caption.data.strip() or None

        uploaded_count = 0

        for file in files:
            if file.filename == '':
                continue

            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(file_path)

                photo = Gallery(
                    filename=filename,
                    caption=caption,
                    category=category,
                    year=year,
                    event_name=event_name,
                    date_uploaded=datetime.utcnow()
                )

                db.session.add(photo)
                uploaded_count += 1

        try:
            if uploaded_count > 0:
                db.session.commit()
                flash(f'{uploaded_count} photo(s) uploaded successfully for "{event_name}"!', 'success')
            else:
                flash('No valid photos were uploaded.', 'warning')
        except Exception as e:
            db.session.rollback()
            flash(f'Error uploading photos: {str(e)}', 'danger')

        return redirect(url_for('admin_gallery'))

    gallery_items = Gallery.query.order_by(
        Gallery.year.desc(),
        Gallery.date_uploaded.desc()
    ).all()

    return render_template(
        'admin/individual/gallery.html',
        form=form,
        gallery_items=gallery_items
    )

@app.route('/gallery/event/<string:event_name>')
def gallery_event(event_name):
    # Decode URL (replace - with space if needed)
    event_name = event_name.replace('-', ' ')

    photos = Gallery.query.filter_by(event_name=event_name).order_by(Gallery.date_uploaded.desc()).all()

    if not photos:
        flash('No photos found for this event.', 'info')
        return redirect(url_for('gallery'))

    return render_template('public/gallery_year.html', photos=photos, title=event_name)


@app.route('/admin/gallery/delete/<int:id>', methods=['POST'])
def delete_gallery_item(id):
    if 'admin_id' not in session:
        flash('Admin access required.', 'danger')
        return redirect('/login')

    item = Gallery.query.get_or_404(id)

    file_path = os.path.join(app.config['UPLOAD_FOLDER'], item.filename)
    if os.path.exists(file_path):
        os.remove(file_path)

    db.session.delete(item)
    db.session.commit()
    flash('Photo deleted successfully!', 'success')

    return redirect(url_for('admin_gallery'))


@app.route('/admin/gallery/edit/<int:id>', methods=['GET', 'POST'])
def edit_gallery_item(id):
    if 'admin_id' not in session:
        flash('Admin access required.', 'danger')
        return redirect('/login')

    item = Gallery.query.get_or_404(id)
    form = GalleryForm(obj=item)

    if request.method == 'POST' and form.validate_on_submit():
        item.caption = form.caption.data.strip() or None
        item.category = form.category.data
        item.year = form.year.data
        item.event_name = form.event_name.data.strip()

        if 'photos' in request.files:
            file = request.files['photos']
            if file and file.filename and allowed_file(file.filename):
                old_path = os.path.join(app.config['UPLOAD_FOLDER'], item.filename)
                if os.path.exists(old_path):
                    os.remove(old_path)

                filename = secure_filename(file.filename)
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                item.filename = filename

        db.session.commit()
        flash('Photo updated successfully!', 'success')
        return redirect(url_for('admin_gallery'))

    return render_template(
        'admin/individual/edit_gallery_item.html',
        form=form,
        item=item
    )

#--------------------------- ADMIN MAIN MENU MANAGEMENT ----------------------------

# Admin menu management
@app.route('/admin/menu', methods=['GET', 'POST'])
def admin_menu():
    if 'admin_id' not in session:
        flash('Admin access required.', 'danger')
        return redirect('/login')  # Adjust to your login route

    sections = ['breakfast', 'lunch', 'dinner', 'beverages', 'leisure']

    # Fetch all menu items grouped by section
    menu_data = {section: MenuItem.query.filter_by(section=section).order_by(MenuItem.day, MenuItem.item_name).all() for section in sections}

    if request.method == 'POST':
        action = request.form.get('action')

        if action == 'add':
            section = request.form['section']
            day = request.form.get('day') if section == 'breakfast' else None
            item_name = request.form['item_name']
            price = float(request.form['price'])
            description = request.form.get('description')

            new_item = MenuItem(section=section, day=day, item_name=item_name, price=price, description=description)
            db.session.add(new_item)
            try:
                db.session.commit()
                flash('Menu item added successfully.', 'success')
            except IntegrityError:
                db.session.rollback()
                flash('Item already exists or invalid data.', 'danger')

        elif action == 'edit':
            item_id = int(request.form['item_id'])
            item = MenuItem.query.get_or_404(item_id)
            item.day = request.form.get('day') if item.section == 'breakfast' else None
            item.item_name = request.form['item_name']
            item.price = float(request.form['price'])
            item.description = request.form.get('description')
            db.session.commit()
            flash('Menu item updated successfully.', 'success')

        elif action == 'delete':
            item_id = int(request.form['item_id'])
            item = MenuItem.query.get_or_404(item_id)
            db.session.delete(item)
            db.session.commit()
            flash('Menu item deleted successfully.', 'success')

        return redirect(url_for('admin_menu'))

    return render_template('admin/individual/admin_menu.html', menu_data=menu_data, sections=sections)

@app.route('/admin/menu/delete/<int:id>')
def delete_menu(id):
    if 'user_id' not in session or not User.query.get(session['user_id']).username.startswith('admin'):
        flash('Admin access required.', 'danger')
        return redirect('/login')

    menu_item = MenuItem.query.get_or_404(id)
    db.session.delete(menu_item)
    db.session.commit()
    flash('Menu item deleted successfully!', 'success')
    return redirect('/admin/menu')

#---------------------------- ADMIN MEMBERS MANAGEMENT ------------------------------

# Define the members
@app.route('/admin/edit-members', methods=['GET'])
def edit_members():
    if 'admin_id' not in session:
        flash('Please log in as admin.', 'danger')
        return redirect('/login')
    members = Member.query.all()
    form = MemberForm()
    return render_template('admin/preview/edit_members.html', members=members, form=form)

# Get members
@app.route('/admin/members', methods=['GET'])
def get_members():
    members = Member.query.all()
    return jsonify([{'id': member.id, 'name': member.name, 'role': member.role, 'description': member.description, 'image': member.image, 'is_executive': member.is_executive} for member in members])

# Add members
@app.route('/admin/add-members', methods=['POST'])
def add_member():
    if 'admin_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    form = MemberForm()
    if form.validate_on_submit():
        image_url = None
        if 'image' in request.files:
            file = request.files['image']
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(file_path)
                image_url = f"/static/uploads/{filename}"
            elif file:
                flash('Invalid image format. Only PNG, JPG, JPEG, GIF allowed.', 'danger')
                members = Member.query.all()
                return render_template('admin/preview/edit_members.html', members=members, form=form)
        member = Member(
            name=form.name.data,
            role=form.role.data,
            description=form.description.data,
            image=image_url,
            is_executive='is_executive' in request.form
        )
        db.session.add(member)
        try:
            db.session.commit()
            flash('Member added successfully!', 'success')
            return redirect(url_for('edit_members'))
        except Exception as e:
            db.session.rollback()
            flash(f'Error adding member: {str(e)}', 'danger')
    else:
        for field, errors in form.errors.items():
            for error in errors:
                flash(f'Error in {field}: {error}', 'danger')
    members = Member.query.all()
    return render_template('admin/preview/edit_members.html', members=members, form=form)
    
# Edit members
@app.route('/admin/edit-members/<int:id>', methods=['GET', 'POST'])
def edit_member(id):
    if 'admin_id' not in session:
        flash('Please log in as admin.', 'danger')
        return redirect('/login')
    member = Member.query.get_or_404(id)
    form = MemberForm(obj=member)
    if request.method == 'POST':
        if form.validate_on_submit():
            member.name = form.name.data
            member.role = form.role.data
            member.description = form.description.data
            member.is_executive = 'is_executive' in request.form  # Moved here
            if 'image' in request.files:
                file = request.files['image']
                if file and allowed_file(file.filename):
                    filename = secure_filename(file.filename)
                    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                    file.save(file_path)
                    member.image = f"/static/uploads/{filename}"
                elif file:
                    flash('Invalid image format. Only PNG, JPG, JPEG, GIF allowed.', 'danger')
            try:
                db.session.commit()
                flash('Member updated successfully!', 'success')
                return redirect(url_for('edit_members'))
            except Exception as e:
                db.session.rollback()
                flash(f'Error updating member: {str(e)}', 'danger')
        else:
            for field, errors in form.errors.items():
                for error in errors:
                    flash(f'Error in {field}: {error}', 'danger')
    members = Member.query.all()
    return render_template('admin/preview/edit_members.html', members=members, form=form, editing=member)

# Delete members
@app.route('/api/members/<int:id>/delete', methods=['POST'])
def delete_member(id):
    if 'admin_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    member = Member.query.get(id)
    if not member:
        return jsonify({'error': 'Member not found'}), 404
    db.session.delete(member)
    db.session.commit()
    flash('Member deleted from page!', 'success')
    return redirect('/admin/edit-members')

#----------------------------- Get all the photos from upload folder ----------------------
@app.route('/static/uploads/<filename>')
def serve_uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

#----------------------------- ADMIN SESSIONS MANAGEMENT ---------------------------------
@app.route('/admin/edit-sessions', methods=['GET'])
def edit_sessions():
    if 'admin_id' not in session:
        flash('Please log in as admin.', 'danger')
        return redirect('/login')
    
    sessions = Session.query.all()
    form = SessionForm()
    return render_template('admin/preview/edit_sessions.html', sessions=sessions, form=form)


@app.route('/admin/sessions', methods=['GET'])
def get_sessions():
    sessions = Session.query.all()
    return jsonify([
        {
            'id': session.id,
            'name': session.name,
            'schedule': session.schedule,
            'image': session.image,
            'instructor_name': session.instructor_name or '',
            'contact_details': session.contact_details or '',
            'course_fee': str(session.course_fee) if session.course_fee else ''
        } for session in sessions
    ])


@app.route('/admin/add-sessions', methods=['POST'])
def add_session():
    if 'admin_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    form = SessionForm()
    if form.validate_on_submit():
        image_url = None
        if 'image' in request.files:
            file = request.files['image']
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(file_path)
                image_url = f"/static/uploads/{filename}"
            elif file:
                flash('Invalid image format. Only PNG, JPG, JPEG, GIF allowed.', 'danger')

        session_item = Session(
            name=form.name.data,
            schedule=form.schedule.data,
            image=image_url,
            # NEW FIELDS
            instructor_name=form.instructor_name.data,
            contact_details=form.contact_details.data,
            course_fee=form.course_fee.data if form.course_fee.data else None
        )
        db.session.add(session_item)
        try:
            db.session.commit()
            flash('Session added successfully!', 'success')
            return redirect('/admin/edit-sessions')
        except Exception as e:
            db.session.rollback()
            flash(f'Error adding session: {str(e)}', 'danger')
    
    else:
        for field, errors in form.errors.items():
            for error in errors:
                flash(f'Error in {field}: {error}', 'danger')
    
    sessions = Session.query.all()
    return render_template('admin/preview/edit_sessions.html', sessions=sessions, form=form)


@app.route('/admin/sessions-edit/<int:id>', methods=['GET', 'POST'])
def edit_session(id):
    if 'admin_id' not in session:
        flash('Please log in as admin.', 'danger')
        return redirect('/login')
    
    session_item = Session.query.get_or_404(id)
    form = SessionForm(obj=session_item)
    
    if request.method == 'POST':
        if form.validate_on_submit():
            session_item.name = form.name.data
            session_item.schedule = form.schedule.data
            
            # Handle image update
            if 'image' in request.files:
                file = request.files['image']
                if file and allowed_file(file.filename):
                    filename = secure_filename(file.filename)
                    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                    file.save(file_path)
                    session_item.image = f"/static/uploads/{filename}"
                elif file:
                    flash('Invalid image format. Only PNG, JPG, JPEG, GIF allowed.', 'danger')

            # UPDATE NEW FIELDS
            session_item.instructor_name = form.instructor_name.data
            session_item.contact_details = form.contact_details.data
            session_item.course_fee = form.course_fee.data if form.course_fee.data else None

            db.session.commit()
            flash('Session updated successfully!', 'success')
            return redirect('/admin/edit-sessions')
        else:
            for field, errors in form.errors.items():
                for error in errors:
                    flash(f'Error in {field}: {error}', 'danger')
    
    sessions = Session.query.all()
    return render_template('admin/preview/edit_sessions.html', 
                           sessions=sessions, 
                           form=form, 
                           editing=session_item)


@app.route('/api/delete-sessions/<int:id>/delete', methods=['POST'])
def delete_session(id):
    if 'admin_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    session_item = Session.query.get(id)
    if not session_item:
        return jsonify({'error': 'Session not found'}), 404
    db.session.delete(session_item)
    db.session.commit()
    flash('Session deleted from page!', 'success')
    return redirect('/admin/edit-sessions')

#---------------------------- ADMIN BOOKING ROUTE ----------------------------------------

@app.route('/admin/bookings', methods=['GET'])
def admin_bookings():
    if 'admin_id' not in session:
        flash('Please log in as admin.', 'danger')
        return redirect('/login')

    # Get page number from URL (default to 1)
    page = request.args.get('page', 1, type=int)

    # Pagination settings
    per_page = 15  # Number of bookings per page

    # Regular Bookings
    regular_pagination = db.session.query(RegularEventBooking, User.username)\
        .join(User, RegularEventBooking.user_id == User.id)\
        .filter(RegularEventBooking.booking_type == 'regular')\
        .order_by(RegularEventBooking.timestamp.desc())\
        .paginate(page=page, per_page=per_page, error_out=False)

    # Event Bookings
    event_pagination = db.session.query(RegularEventBooking, User.username)\
        .join(User, RegularEventBooking.user_id == User.id)\
        .filter(RegularEventBooking.booking_type == 'event')\
        .order_by(RegularEventBooking.timestamp.desc())\
        .paginate(page=page, per_page=per_page, error_out=False)

    # Party Bookings
    party_pagination = db.session.query(PartyBooking, User.username)\
        .join(User, PartyBooking.user_id == User.id)\
        .order_by(PartyBooking.timestamp.desc())\
        .paginate(page=page, per_page=per_page, error_out=False)

    return render_template(
        'admin/preview/booking_approval.html',
        regular_bookings=regular_pagination,
        event_bookings=event_pagination,
        party_bookings=party_pagination
    )


@app.route('/admin/bookings/update_regular_event/<int:booking_id>', methods=['POST'])
def update_regular_event_booking_status(booking_id):
    booking = RegularEventBooking.query.get_or_404(booking_id)
    status = request.form.get('status')
    remarks = request.form.get('remarks', '')
    if status not in ['Pending', 'Approved', 'Rejected']:
        flash('Invalid status.', 'danger')
        return redirect('/admin/bookings')
    if status == 'Rejected' and not remarks:
        flash('Remarks are required when rejecting a booking.', 'danger')
        return redirect('/admin/bookings')
    booking.status = status
    booking.remarks = remarks if remarks else booking.remarks
    booking.updated_at = datetime.utcnow()
    db.session.commit()
    flash(f'Booking {status.lower()} successfully!', 'success')
    return redirect('/admin/bookings')


@app.route('/admin/bookings/update_party/<int:booking_id>', methods=['POST'])
def update_party_booking_status(booking_id):
    booking = PartyBooking.query.get_or_404(booking_id)
    status = request.form.get('status')
    remarks = request.form.get('remarks', '')
    if status not in ['Pending', 'Approved', 'Rejected']:
        flash('Invalid status.', 'danger')
        return redirect('/admin/bookings')
    if status == 'Rejected' and not remarks:
        flash('Remarks are required when rejecting a booking.', 'danger')
        return redirect('/admin/bookings')
    # Check for slot conflict when approving
    if status == 'Approved':
        existing_booking = PartyBooking.query.filter(
            PartyBooking.id != booking_id,
            PartyBooking.date == booking.date,
            PartyBooking.time == booking.time,
            PartyBooking.area_selection == booking.area_selection,
            PartyBooking.status == 'Approved'
        ).first()
        if existing_booking:
            flash(f'Cannot approve: The slot for {booking.area_selection} on {booking.date} at {booking.time} is already booked.', 'danger')
            return redirect('/admin/bookings')
    booking.status = status
    booking.remarks = remarks if remarks else booking.remarks
    booking.updated_at = datetime.utcnow()
    db.session.commit()
    flash(f'Booking {status.lower()} successfully!', 'success')
    return redirect('/admin/bookings')


@app.route('/admin/party-calendar')
def admin_party_calendar():
    if 'admin_id' not in session:
        flash('Admin access required.', 'danger')
        return redirect('/login')

    # Efficient query: load User relationship in one go
    party_bookings = PartyBooking.query.options(joinedload(PartyBooking.user)).order_by(PartyBooking.date).all()

    events = []
    for booking in party_bookings:
        # Use fullname from User model
        member_name = booking.user.fullname if booking.user else 'Unknown User'

        # Event title
        title = f"{booking.meal_type.capitalize()} - {booking.occasion} ({booking.participants} guests)"

        # Color based on meal type
        meal = booking.meal_type.lower()
        if 'lunch' in meal:
            color_class = 'bg-info'        # Cyan for Lunch
        elif 'dinner' in meal:
            color_class = 'bg-danger'      # Red for Dinner
        elif 'breakfast' in meal:
            color_class = 'bg-warning text-dark'  # Yellow for Breakfast
        else:
            color_class = 'bg-secondary'

        # Full rich description for tooltip
        description = f"""
            <strong>Booked By:</strong> {member_name}<br>
            <strong>Username:</strong> {booking.user.username if booking.user else 'N/A'}<br>
            <strong>Occasion:</strong> {booking.occasion}<br>
            <strong>Nature:</strong> {booking.nature}<br>
            <strong>Date & Time:</strong> {booking.date} at {booking.time}<br>
            <strong>Participants:</strong> {booking.participants}<br>
            <strong>Veg / Non-Veg:</strong> {booking.veg_count} / {booking.non_veg_count}<br>
            <strong>Area:</strong> {booking.area_selection}<br>
            <strong>Menu Items:</strong> {booking.menu_items.replace('|', ', ')}<br>
            <strong>Total Amount:</strong> ₹{booking.total:.2f}<br>
            <strong>Status:</strong> 
                <span class="badge bg-{'success' if booking.status == 'Approved' else 'warning' if booking.status == 'Pending' else 'danger'}">
                    {booking.status}
                </span><br>
            <strong>Remarks:</strong> {booking.remarks or 'None'}
        """.strip()

        events.append({
            'title': title,
            'start': booking.date,  # YYYY-MM-DD format
            'description': description,
            'className': f'{color_class} text-white border-0 fw-bold'
        })

    return render_template('admin/preview/party_calendar.html', events=events)


#---------------------------- ADMIN BILLING ROUTE ----------------------------------------
@app.route('/admin/upload-bill', methods=['GET', 'POST'])
def admin_upload_bill():
    if 'admin_id' not in session:
        flash('Please log in as admin.', 'danger')
        return redirect('/login')

    if request.method == 'POST':
        if 'month' not in request.form or 'year' not in request.form:
            flash('Month and year are required.', 'danger')
            return redirect(request.url)

        try:
            month = int(request.form['month'])
            year = int(request.form['year'])
        except ValueError:
            flash('Invalid month or year.', 'danger')
            return redirect(request.url)

        file = request.files['file']
        if file.filename == '':
            flash('No file selected.', 'danger')
            return redirect(request.url)

        if not allowed_file(file.filename):
            flash('Only .xlsx and .xls files allowed.', 'danger')
            return redirect(request.url)

        original_filename = secure_filename(file.filename)
        filename = f"bill_{year}_{month:02d}_{original_filename}"
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)

        existing_bill = MonthlyBillExcel.query.filter_by(month=month, year=year).first()

        if existing_bill:
            # Replace old file
            old_path = os.path.join(app.config['UPLOAD_FOLDER'], existing_bill.filename)
            if os.path.exists(old_path) and old_path != filepath:
                os.remove(old_path)
            existing_bill.filename = filename
            existing_bill.upload_date = datetime.utcnow()
            db.session.commit()
            flash(f'Bill for {month:02d}/{year} updated successfully!', 'info')
        else:
            new_bill = MonthlyBillExcel(month=month, year=year, filename=filename)
            db.session.add(new_bill)
            db.session.commit()
            flash(f'Bill for {month:02d}/{year} uploaded successfully!', 'success')

        return redirect(url_for('admin_upload_bill'))

    # GET: Show form + list
    bills = MonthlyBillExcel.query.order_by(
        MonthlyBillExcel.year.desc(),
        MonthlyBillExcel.month.desc()
    ).all()

    return render_template('admin/individual/upload_bill.html', bills=bills)


# NEW: Edit Route
@app.route('/admin/edit-bill/<int:bill_id>', methods=['GET', 'POST'])
def admin_edit_bill(bill_id):
    if 'admin_id' not in session:
        flash('Admin access required.', 'danger')
        return redirect('/login')

    bill = MonthlyBillExcel.query.get_or_404(bill_id)

    if request.method == 'POST':
        try:
            bill.month = int(request.form['month'])
            bill.year = int(request.form['year'])
        except ValueError:
            flash('Invalid month or year.', 'danger')
            return redirect(request.url)

        file = request.files['file']
        if file and file.filename != '':
            if not allowed_file(file.filename):
                flash('Invalid file type.', 'danger')
                return redirect(request.url)

            # Delete old file
            old_path = os.path.join(app.config['UPLOAD_FOLDER'], bill.filename)
            if os.path.exists(old_path):
                os.remove(old_path)

            # Save new file
            original_filename = secure_filename(file.filename)
            new_filename = f"bill_{bill.year}_{bill.month:02d}_{original_filename}"
            new_path = os.path.join(app.config['UPLOAD_FOLDER'], new_filename)
            file.save(new_path)
            bill.filename = new_filename

        bill.upload_date = datetime.utcnow()
        db.session.commit()
        flash('Bill updated successfully!', 'success')
        return redirect(url_for('admin_upload_bill'))

    return render_template('admin/individual/bills.html', bill=bill)


@app.route('/admin/delete-bill/<int:bill_id>', methods=['POST'])
def admin_delete_bill(bill_id):
    if 'admin_id' not in session:
        flash('Admin access required.', 'danger')
        return redirect('/login')

    bill = MonthlyBillExcel.query.get_or_404(bill_id)
    
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], bill.filename)
    if os.path.exists(filepath):
        os.remove(filepath)

    db.session.delete(bill)
    db.session.commit()
    flash(f'Bill for {bill.month:02d}/{bill.year} deleted.', 'success')
    return redirect(url_for('admin_upload_bill'))
#----------------------------- USER Booking Route ----------------------------------------

# User main booking page
@app.route('/booking')
def user_bookings():
    if 'user_id' not in session:
        flash('Please log in to view your bookings.', 'danger')
        return redirect('/login')

    user_id = session['user_id']

    # Get page from URL (default 1)
    page = request.args.get('page', 1, type=int)
    per_page = 10  # Show 10 bookings per page

    # Regular Bookings
    regular_bookings = RegularEventBooking.query.filter_by(
        user_id=user_id, booking_type='regular'
    ).order_by(RegularEventBooking.date.desc(), RegularEventBooking.timestamp.desc())\
     .paginate(page=page, per_page=per_page, error_out=False)

    # Event Bookings
    event_bookings = RegularEventBooking.query.filter_by(
        user_id=user_id, booking_type='event'
    ).order_by(RegularEventBooking.date.desc(), RegularEventBooking.timestamp.desc())\
     .paginate(page=page, per_page=per_page, error_out=False)

    # Party Bookings
    party_bookings = PartyBooking.query.filter_by(
        user_id=user_id
    ).order_by(PartyBooking.date.desc(), PartyBooking.timestamp.desc())\
     .paginate(page=page, per_page=per_page, error_out=False)

    return render_template(
        'user/user_dashboard.html',
        regular_bookings=regular_bookings,
        event_bookings=event_bookings,
        party_bookings=party_bookings
    )


# Regular booking form
@app.route('/book-regular', methods=['GET', 'POST'])
def book_regular():
    if 'user_id' not in session:
        flash('Please log in to book a meal.', 'danger')
        return redirect('/login')

    # Full regular menu with all items
    regular_menu = {
        'breakfast': {'name': 'Daily Breakfast', 'price': 50},
        'lunch': [
            {'name': 'Standard Lunch', 'price': 100},
            {'name': 'Lunch with Chicken Curry', 'price': 150},
            {'name': 'Working Lunch (Veg)', 'price': 200},
            {'name': 'Working Lunch (Non-Veg)', 'price': 300},
            {'name': 'Special Lunch (Wednesday & Sunday)', 'price': 150},
        ],
        'dinner': [
            {'name': 'Daily Dinner', 'price': 120},
            {'name': 'Dinner with Mutton Curry', 'price': 200},
        ],
        'beverages': [
            {'name': 'Tea', 'price': 10},
            {'name': 'Coffee', 'price': 10},
        ],
        'leisure': [
            {'name': 'Omlet', 'price': 20},
            {'name': 'Noodles', 'price': 30},
            {'name': 'Veg Manchuria', 'price': 35},
            {'name': 'Egg Roll', 'price': 35},
            {'name': 'Chicken Fry', 'price': 50},
            {'name': 'Fish Fry (2 Pieces)', 'price': 50},
            {'name': 'Masala Peanuts', 'price': 25},
            {'name': 'Onion Pakoda', 'price': 15},
            {'name': 'Soft Drink', 'price': 20},
            {'name': 'Soda (Small)', 'price': 10},
            {'name': 'Soda (Big)', 'price': 20},
        ]
    }

    today_min = date.today().strftime('%Y-%m-%d')

    if request.method == 'POST':
        try:
            meal_category = request.form['meal_category']
            specific_item = request.form['specific_item']
            quantity = int(request.form['quantity'])
            booking_date = request.form['date']

            # Find price
            price = 0
            if meal_category == 'breakfast':
                price = regular_menu['breakfast']['price']
            else:
                items = regular_menu.get(meal_category, [])
                item = next((i for i in items if i['name'] == specific_item), None)
                if item:
                    price = item['price']

            if price == 0:
                flash('Invalid item selected.', 'danger')
                return redirect(url_for('book_regular'))

            total = price * quantity

            # Prevent duplicate (same category + date)
            existing = RegularEventBooking.query.filter_by(
                user_id=session['user_id'],
                booking_type='regular',
                meal_type=meal_category,
                date=booking_date
            ).first()

            if existing:
                flash(f'You already booked {meal_category} on {booking_date}.', 'warning')
            else:
                booking = RegularEventBooking(
                    user_id=session['user_id'],
                    booking_type='regular',
                    meal_type=meal_category,
                    quantity=quantity,
                    total=total,
                    date=booking_date,
                    remarks=specific_item,
                    status='Confirmed'
                )
                db.session.add(booking)
                db.session.commit()
                flash(f'{specific_item} booked for {booking_date}! Total: ₹{total}', 'success')

            return redirect(url_for('user_bookings'))

        except Exception as e:
            flash('Please fill all fields correctly.', 'danger')
            return redirect(url_for('book_regular'))

    return render_template('user/book_regular.html', regular_menu=regular_menu, today_min=today_min)

# event booking form
@app.route('/book-event', methods=['GET', 'POST'])
def book_event():
    if 'user_id' not in session:
        flash('Please log in to book an event meal.', 'danger')
        return redirect('/login')

    # Event menu (larger quantities, perhaps different pricing)
    event_menu = {
        'lunch': [
            {'name': 'Working Lunch (Veg)', 'price': 200},
            {'name': 'Working Lunch (Non-Veg)', 'price': 300},
        ],
        'dinner': [
            {'name': 'Event Dinner', 'price': 250},
        ]
    }

    today_min = date.today().strftime('%Y-%m-%d')

    if request.method == 'POST':
        try:
            meal_type = request.form['meal_type']
            item_name = request.form['item_name']
            quantity = int(request.form['quantity'])
            booking_date = request.form['date']
            purpose = request.form.get('purpose', '').strip()

            item = next((i for i in event_menu.get(meal_type, []) if i['name'] == item_name), None)
            if not item:
                flash('Invalid item selected.', 'danger')
                return redirect(url_for('book_event'))

            total = item['price'] * quantity

            existing = RegularEventBooking.query.filter_by(
                user_id=session['user_id'],
                booking_type='event',
                meal_type=meal_type,
                date=booking_date
            ).first()

            if existing:
                flash(f'You already have an event booking on {booking_date}.', 'warning')
            else:
                booking = RegularEventBooking(
                    user_id=session['user_id'],
                    booking_type='event',
                    meal_type=meal_type,
                    quantity=quantity,
                    total=total,
                    date=booking_date,
                    remarks=f"{item_name} - Purpose: {purpose or 'N/A'}",
                    status='Pending'  # Events might need approval
                )
                db.session.add(booking)
                db.session.commit()
                flash(f'Event {item_name} booked! Awaiting approval.', 'success')

            return redirect(url_for('user_bookings'))

        except Exception:
            flash('Please fill all fields correctly.', 'danger')
            return redirect(url_for('book_event'))

    return render_template('user/book_event.html', event_menu=event_menu, today_min=today_min)

# Party booking
@app.route('/party_booking', methods=['GET', 'POST'])
def party_booking():
    if 'user_id' not in session:
        flash('Please log in to book a party.', 'danger')
        return redirect('/login')

    # Define party prices (can move to DB later)
    party_prices = {
        'breakfast': 0,  # Usually not priced per person for party, or set if needed
        'lunch': 150,    # Example base price per person
        'dinner': 200
    }

    today_min = date.today().strftime('%Y-%m-%d')

    if request.method == 'POST':
        try:
            nature = request.form['nature']
            occasion = request.form['occasion'].strip()
            participants = int(request.form['participants'])
            veg_count = int(request.form['veg_count'])
            non_veg_count = int(request.form['non_veg_count'])
            date_str = request.form['date']
            time = request.form['time']
            telephone = request.form['telephone'].strip()
            mobile = request.form['mobile'].strip()
            menu_items = request.form['menu_items'].strip()
            area_selection = request.form['area_selection']
            meal_type = request.form['meal_type']

            # Validation
            if nature not in ['Official', 'Unofficial']:
                flash('Invalid nature of party.', 'danger')
                return redirect(url_for('party_booking'))

            if participants < 5:  # Minimum for party
                flash('Minimum 5 participants for party booking.', 'danger')
                return redirect(url_for('party_booking'))

            if veg_count + non_veg_count != participants:
                flash('Veg + Non-Veg count must equal total participants.', 'danger')
                return redirect(url_for('party_booking'))

            if veg_count < 0 or non_veg_count < 0:
                flash('Counts cannot be negative.', 'danger')
                return redirect(url_for('party_booking'))

            if not menu_items:
                flash('Menu items are required.', 'danger')
                return redirect(url_for('party_booking'))

            # Date validation
            try:
                booking_date = datetime.strptime(date_str, '%Y-%m-%d').date()
                if booking_date < date.today():
                    flash('Cannot book party for past dates.', 'danger')
                    return redirect(url_for('party_booking'))
            except ValueError:
                flash('Invalid date.', 'danger')
                return redirect(url_for('party_booking'))

            # Check slot availability
            existing = PartyBooking.query.filter_by(
                date=date_str,
                time=time,
                area_selection=area_selection
            ).first()

            if existing:
                flash(f'This slot ({area_selection} on {date_str} at {time}) is already booked.', 'danger')
                return redirect(url_for('party_booking'))

            # Calculate total (example: base price per person)
            base_price = party_prices.get(meal_type, 150)
            total = base_price * participants

            # Create booking
            booking = PartyBooking(
                user_id=session['user_id'],
                nature=nature,
                occasion=occasion,
                participants=participants,
                veg_count=veg_count,
                non_veg_count=non_veg_count,
                date=date_str,
                time=time,
                telephone=telephone,
                mobile=mobile,
                menu_items=menu_items,
                area_selection=area_selection,
                meal_type=meal_type,
                total=total,
                status='Pending'
            )
            db.session.add(booking)
            db.session.commit()

            flash(f'Party booking for "{occasion}" submitted successfully! Total: ₹{total}', 'success')
            return redirect(url_for('user_bookings'))

        except ValueError:
            flash('Invalid number entered.', 'danger')
            return redirect(url_for('party_booking'))
        except Exception as e:
            flash('An error occurred. Please try again.', 'danger')
            return redirect(url_for('party_booking'))

    return render_template('user/party_booking.html', today_min=today_min, party_prices=party_prices)

@app.route('/party-calendar')
def party_calendar():
    if 'user_id' not in session:
        flash('Please log in to book a party.', 'danger')
        return redirect('/login')

    # Efficient query: load User relationship in one go
    party_bookings = PartyBooking.query.options(joinedload(PartyBooking.user)).order_by(PartyBooking.date).all()

    events = []
    for booking in party_bookings:
        # Use fullname from User model
        member_name = booking.user.fullname if booking.user else 'Unknown User'

        # Event title
        title = f"{booking.meal_type.capitalize()} - {booking.occasion}"

        # Color based on meal type
        meal = booking.meal_type.lower()
        if 'lunch' in meal:
            color_class = 'bg-info'        # Cyan for Lunch
        elif 'dinner' in meal:
            color_class = 'bg-danger'      # Red for Dinner
        elif 'breakfast' in meal:
            color_class = 'bg-warning text-dark'  # Yellow for Breakfast
        else:
            color_class = 'bg-secondary'

        # Full rich description for tooltip
        description = f"""
            <strong>Booked By:</strong> {member_name}<br>
            <strong>Username:</strong> {booking.user.username if booking.user else 'N/A'}<br>
            <strong>Date & Time:</strong> {booking.date} at {booking.time}<br>
            <strong>Area:</strong> {booking.area_selection}<br>
            <strong>Status:</strong> 
                <span class="badge bg-{'success' if booking.status == 'Approved' else 'warning' if booking.status == 'Pending' else 'danger'}">
                    {booking.status}
                </span><br>
            <strong>Remarks:</strong> {booking.remarks or 'None'}
        """.strip()

        events.append({
            'title': title,
            'start': booking.date,  # YYYY-MM-DD format
            'description': description,
            'className': f'{color_class} text-white border-0 fw-bold'
        })

    return render_template('user/user_party_calendar.html', events=events)


#----------------------------- USER BILLS --------------------------------#

@app.route('/bills')
def bills():
    if 'user_id' not in session:
        flash('Please log in to view your bills.', 'danger')
        return redirect('/login')

    # Get all available years
    years = db.session.query(MonthlyBillExcel.year)\
        .distinct()\
        .order_by(MonthlyBillExcel.year.desc())\
        .all()
    years = [y[0] for y in years]  # flatten

    current_year = datetime.now().year

    return render_template('public/bills.html', years=years, current_year=current_year)


@app.route('/bills/<int:year>')
def view_year_bills(year):
    if 'user_id' not in session:
        flash('Please log in to view your bills.', 'danger')
        return redirect('/login')

    # Get all bills for this year
    year_bills = MonthlyBillExcel.query\
        .filter_by(year=year)\
        .order_by(MonthlyBillExcel.month.asc())\
        .all()

    # Months list
    months = [
        'January', 'February', 'March', 'April', 'May', 'June',
        'July', 'August', 'September', 'October', 'November', 'December'
    ]

    # Build bills_data with month name and bill object
    bills_data = []
    for month_idx in range(1, 13):
        bill = next((b for b in year_bills if b.month == month_idx), None)
        bills_data.append({
            'month_name': months[month_idx - 1],
            'bill': bill
        })

    return render_template('public/year_bills.html',
                           year=year,
                           bills_data=bills_data)


@app.route('/download-bill/<filename>')
def download_bill(filename):
    if 'user_id' not in session:
        flash('Please log in to download bills.', 'danger')
        return redirect('/login')
    
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    print(f"Looking for bill at: {file_path}")  # ← Temporary debug
    print(f"File exists: {os.path.exists(file_path)}")  # ← Check this

    if not os.path.exists(file_path):
        flash('Bill file not found on server. Please contact admin.', 'danger')
        return redirect(url_for('bills'))


    try:
        return send_from_directory(app.config['UPLOAD_FOLDER'], filename, as_attachment=True)
    except FileNotFoundError:
        flash('Bill file not found or has been removed.', 'danger')
        return redirect(url_for('bills'))
    except Exception:
        flash('Error downloading bill. Please try again.', 'danger')
        return redirect(url_for('bills'))



@app.context_processor  
def inject_user():
    return dict(logged_in_user=session.get('username'))

@app.route('/test')
def test():
    return render_template('admin/preview/edit_slideshow.html')

if __name__ == "__main__":
    app.run()
