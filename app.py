from flask import Flask, request, render_template, redirect, url_for, jsonify, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Length, Email, EqualTo
import pandas as pd
import threading
import pywhatkit as kit
import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('SQLALCHEMY_DATABASE_URI')
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

progress_status = {
    "total": 0,
    "sent": 0,
    "failed": []
}

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)

@login_manager.user_loader
def load_user(user_id):
    with app.app_context():
        return db.session.get(User, int(user_id))

class SignupForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Sign Up')

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

def send_message(number, message, attachment=None):
    try:
        if attachment:
            kit.sendwhats_image(
                receiver=number, 
                img_path=attachment, 
                caption=message, 
                tab_close=True, 
                close_time=15
            )
        else:
            kit.sendwhatmsg_instantly(
                phone_no=number, 
                message=message, 
                tab_close=True
            )
        progress_status["sent"] += 1
    except Exception as e:
        progress_status["failed"].append(f"Failed to send message to {number}: {str(e)}")

def send_bulk_messages(data, message, attachment=None):
    for index, row in data.iterrows():
        personalized_message = message
        for col in data.columns:
            personalized_message = personalized_message.replace(f"@{col.lower()}", str(row[col]))
        send_message(row['Number'], personalized_message, attachment)

@app.route('/')
@login_required
def index():
    return render_template('index.html')

@app.route('/send', methods=['POST'])
@login_required
def send_message_route():
    global progress_status
    progress_status = {
        "total": 0,
        "sent": 0,
        "failed": []
    }

    file = request.files['file']
    try:
        df = pd.read_csv(file)
        if 'Number' not in df.columns:
            return "CSV file must contain a 'Number' column.", 400
        df['Number'] = df['Number'].astype(str).apply(lambda x: "+" + x)
    except Exception as e:
        return f"Error reading CSV file: {str(e)}", 400

    message = request.form['message']
    attachment_file = request.files.get('attachment')
    attachment = None

    if attachment_file:
        attachment_path = os.path.join('uploads', attachment_file.filename)
        attachment_file.save(attachment_path)
        attachment = attachment_path

    progress_status["total"] = len(df)

    thread = threading.Thread(target=send_bulk_messages, args=(df, message, attachment))
    thread.start()

    return redirect(url_for('progress'))

@app.route('/progress')
@login_required
def progress():
    return render_template('progress.html')

@app.route('/progress_status')
@login_required
def get_progress_status():
    return jsonify(progress_status)

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = SignupForm()
    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data, method='pbkdf2:sha256')
        new_user = User(email=form.email.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        flash('Your account has been created! You can now log in.', 'success')
        return redirect(url_for('login'))
    return render_template('signup.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and check_password_hash(user.password, form.password.data):
            login_user(user)
            return redirect(url_for('index'))
        else:
            flash('Login Unsuccessful. Please check email and password', 'danger')
    return render_template('login.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

if __name__ == '__main__':
    if not os.path.exists('uploads'):
        os.makedirs('uploads')
    with app.app_context():
        db.create_all()
    app.run(debug=True)
