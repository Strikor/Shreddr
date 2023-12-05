from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_mysqldb import MySQL
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from werkzeug.security import generate_password_hash, check_password_hash
from wtforms import StringField, PasswordField, SubmitField, TextAreaField, SelectField, IntegerField, EmailField
from wtforms.validators import DataRequired, Email, EqualTo, ValidationError, NumberRange
from flask_login import LoginManager, login_user, login_required
import os
from flask_login import current_user


app = Flask(__name__, static_url_path='/static')
app.config['SECRET_KEY'] = os.urandom(24)
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:root@localhost/shred'


db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    email = EmailField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    age = IntegerField('Age', validators=[DataRequired(), NumberRange(min=0, max=120)])
    gender = SelectField('Gender', choices=[('M', 'Male'), ('F', 'Female'), ('O', 'Other')], validators=[DataRequired()])
    location = StringField('Location', validators=[DataRequired()])
    bio = TextAreaField('Bio')
    instruments_played = StringField('Instruments Played')
    preferred_genres = StringField('Preferred Genres')
    years_of_experience = IntegerField('Years of Experience', validators=[NumberRange(min=0)])
    submit = SubmitField('Sign Up')

    def __init__(self, *args, **kwargs):
        kwargs['csrf_enabled'] = False
        super(RegistrationForm, self).__init__(*args, **kwargs)

    def validate_email(self, field):
        if User.query.filter_by(email=field.data).first():
            raise ValidationError('Email already registered. Please use a different email address.')


class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class User(db.Model):
    __tablename__ = 'testUsers'
    user_id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    is_active = db.Column(db.Boolean, default=True)
    age = db.Column(db.Integer)
    gender = db.Column(db.String(10))
    location = db.Column(db.String(120))
    bio = db.Column(db.Text)
    instruments_played = db.Column(db.String(120))
    preferred_genres = db.Column(db.String(120))
    years_of_experience = db.Column(db.Integer)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def get_id(self):
        return str(self.user_id)

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm(csrf_enabled=False)
    if form.validate_on_submit():
        try:
            user = User(
                username=form.username.data,
                email=form.email.data,
                age=form.age.data,
                location=form.location.data,
                gender=form.gender.data,
                bio=form.bio.data,
                instruments_played=form.instruments_played.data,
                preferred_genres=form.preferred_genres.data,
                years_of_experience=form.years_of_experience.data
            )
            user.set_password(form.password.data)
            db.session.add(user)
            db.session.commit()
            flash('You have successfully registered!', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            flash('Error: ' + str(e), 'danger')
            print('Error:', e)
    else:
        print("Form data:", form.data)
        print("Form errors:", form.errors)
        flash('Please correct the errors and try again.', 'danger')

    return render_template('register.html', title='Register', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if request.method == 'POST':
        session['email'] = request.form['email']
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        session["user_id"] = user.user_id
        if user and user.check_password(form.password.data):
            login_user(user)
            return redirect(url_for('show_users'))
        else:
            flash('Invalid username or password')
    return render_template('login.html', form=form)

@app.route('/home')
def home():
    return 'Welcome to the home page'


app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = 'root'
app.config['MYSQL_DB'] = 'shred'

mysql = MySQL(app)


@app.route('/users')
def show_users():
    cursor = mysql.connection.cursor()
    cursor.execute("SELECT user_id, username, email, age, gender, location, bio, instruments_played, preferred_genres, years_of_experience FROM testUsers")
    data = cursor.fetchall()
    cursor.close()
    return render_template('users.html', users=data)


@app.route('/user-profile/<int:user_id>')
def user_profile(user_id):
    cursor = mysql.connection.cursor()

    try:
        cursor.execute("SELECT * FROM testUsers WHERE user_id = %s", (user_id,))
        user_data = cursor.fetchone()
        print("Fetched user data:", user_data)
    except Exception as e:
        print("Error while fetching user data:", e)
        return "Error fetching user data", 500
    finally:
        cursor.close()

    if user_data:
        return render_template('profile.html', user=user_data)
    else:
        print("No user found with ID:", user_id)
        return "User not found", 404


def get_logged_in_user_id():
        if current_user.is_authenticated:
            print("Current user's ID:", current_user.id)
            return current_user.id
        else:
            print("user not auth")
            return None

@app.route('/like-user', methods=['POST'])
def like_user():
    current_user_id = session["user_id"]

    liked_user_id = request.form['user_id']

    cursor = mysql.connection.cursor()
    try:
        cursor.execute(
            "INSERT INTO UserLikes (user_id, liked_user_id) VALUES (%s, %s)",
            (current_user_id, liked_user_id)
        )
        mysql.connection.commit()
    except Exception as e:
        print("Error while liking user:", e)
        return "Error in liking the user", 500
    finally:
        cursor.close()

    return redirect(url_for('user_profile', user_id=liked_user_id))

@app.route('/dislike-user', methods=['POST'])
def dislike_user():

    return redirect(url_for('show_users'))

@app.route('/user-likes', methods=['GET'])
def user_likes():
    current_user_id = session["user_id"]

    cursor = mysql.connection.cursor()
    try:
        cursor.execute("SELECT u.user_id, u.username FROM UserLikes ul JOIN testUsers u ON ul.user_id = u.user_id WHERE ul.liked_user_id = %s", (current_user_id,))
        liked_users = cursor.fetchall()
    except Exception as e:
        print("Error while fetching liked users:", e)
        return "Error fetching liked users", 500
    finally:
        cursor.close()

    return render_template('user_likes.html', liked_users=liked_users)


@app.route('/searchSettings')
def form():
    return render_template('searchSettings.html')


@app.route('/search', methods=['POST', 'GET'])
def search():
    selectStr = "user_id, username, age, gender, location, bio, instruments_played, preferred_genres, years_of_experience"
    queryStr = f"SELECT {selectStr} FROM testUsers WHERE 1=1"
    params = []

    if request.method == 'POST':
        print(queryStr)

        print(request.form)
        cursor = mysql.connection.cursor()
        years_of_experience = request.form['years_of_experience']
        instruments_played = request.form.getlist('instruments_played')
        preferred_genres = request.form.getlist('preferred_genres')

        if years_of_experience:
            queryStr += " AND years_of_experience >= %s"
            params.append(years_of_experience)
        if instruments_played:
            queryStr += " AND (" + ' OR '.join(['instruments_played LIKE %s'] * len(instruments_played)) + ")"
            params.extend(['%' + instrument + '%' for instrument in instruments_played])
        if preferred_genres:
            queryStr += " AND (" + ' OR '.join(['preferred_genres LIKE %s'] * len(preferred_genres)) + ")"
            params.extend(['%' + genre + '%' for genre in preferred_genres])

        cursor.execute(queryStr, params)
        users = cursor.fetchall()
        cursor.close()
        return render_template('results.html', users=users)

    return "Fill out the Search Form"


if __name__ == '__main__':
    app.run(host='localhost', port=8080, debug=True)