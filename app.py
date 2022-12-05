from flask import Flask, render_template, url_for, flash, redirect, request
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, EmailField,TextAreaField, PasswordField, validators
from wtforms.validators import DataRequired
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_migrate import Migrate
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf.file import FileField
from werkzeug.utils import secure_filename
import uuid as uuid
import os

#create a Flsk instance.
app = Flask(__name__)

#add database
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:''@localhost/naapurit'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

#secretkey
app.config['SECRET_KEY'] = "mysecretkey"

#initialize DB
db = SQLAlchemy(app)
migrate = Migrate(app, db)

UPLOAD_FOLDER = 'static/images/'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

#create a model
class Users(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False, unique=True)
    name = db.Column(db.String(200), nullable=False)
    email = db.Column(db.String(200), nullable=False, unique=True)
    password_hash = db.Column(db.String(128), nullable=False)
    date_added = db.Column(db.DateTime, default=datetime.utcnow)
    
   
    
    @property
    def password(self):
        raise AttributeError('Password is not readable')
    
    @password.setter
    def password(self, password):
        self.password_hash = generate_password_hash(password)
        
    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)
    #create string
    def __repr__(self):
        return '<Name %r>' % self.id

#Form Class
class NamerForm(FlaskForm):
    name = StringField("Your name:", [validators.Length(min=4, max=25)])
    username = StringField("Username:", [validators.Length(min=4, max=25)])
    email = StringField("Your email:", validators=[DataRequired()])
    password_hash = PasswordField("Create your password:", [validators.DataRequired(), validators.EqualTo('confirm', message='Passwords must match!')])
    confirm = PasswordField("Repeat the password:")
    profile_pic = FileField("Profile Pic")
    submit = SubmitField("Submit")
    
#login fild 
class PasswordForm(FlaskForm):
    email = EmailField("Your email:", validators=[DataRequired()])
    password_hash = PasswordField("Your password:", [validators.DataRequired(), validators.EqualTo('confirm', message='Passwords must match!')])
    submit = SubmitField("Submit")
    
    
class TechnicalSupport(FlaskForm):
    name = StringField("Your name:")
    email = StringField("Your email address:", validators=[DataRequired()])
    phone = StringField("Your phone number:")
    message = TextAreaField("Write your message:", validators=[DataRequired()])
    submit = SubmitField("Send")
    
    
    
class Technical_issues(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    email = db.Column(db.String(50), nullable=False)
    phone = db.Column(db.String(20), nullable=False)
    message = db.Column(db.Text, nullable=False)
    date_added = db.Column(db.DateTime, default=datetime.utcnow)
    
#Delete user
@app.route('/delete/<int:id>')
@login_required
def delete(id):
	# Check logged in id vs. id to delete
	if id == current_user.id:
		user_to_delete = Users.query.get_or_404(id)
		name = None
		form = NamerForm()

		try:
			db.session.delete(user_to_delete)
			db.session.commit()
			flash("User Deleted Successfully!!")

			our_users = Users.query.order_by(Users.date_added)
			return render_template("signup.html", 
			form=form,
			name=name,
			our_users=our_users)

		except:
			flash("Whoops! There was a problem deleting user, try again...")
			return render_template("dashboard.html", 
			form=form, name=name,our_users=our_users)
	else:
		flash("Sorry, you can't delete that user! ")
		return redirect(url_for('dashboard'))

#Create LoginForm
class LoginForm(FlaskForm):
    username = StringField("Username:", validators=[DataRequired()])
    password = PasswordField("Password:", validators=[DataRequired()])
    submit = SubmitField("Submit")

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return Users.query.get(int(user_id))

#create login page
@app.route('/login',methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = Users.query.filter_by(username=form.username.data).first()
        if user:
            #check hash
            if check_password_hash(user.password_hash, form.password.data):
                login_user(user)
                flash("You are logged in!")
                return redirect(url_for('dashboard'))
            else:
                flash("Wrong password = Try again!")
        else:
            flash("That user does not exist = Try again!")  
            
    return render_template("login.html", form=form)


#route decorator
@app.route('/')
def index():
    return render_template("index.html")

# Create Dashboard Page 
@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
        form = NamerForm()
        id = current_user.id
        name_to_update = Users.query.get_or_404(id)
        if request.method == "POST":
                name_to_update.name = request.form['name']
                name_to_update.email = request.form['email']
                name_to_update.username = request.form['username']


                # Check for profile pic
                if request.files['profile_pic']:
                        name_to_update.profile_pic = request.files['profile_pic']

                        # Grab Image Name
                        pic_filename = secure_filename(name_to_update.profile_pic.filename)
		                # Set UUID
                        pic_name = str(uuid.uuid1()) + "_" + pic_filename
		                # Save That Image
                        saver = request.files['profile_pic']

                        # Change it to a string to save to db
                        name_to_update.profile_pic = pic_name
                        try:
                                db.session.commit()
                                saver.save(os.path.join(app.config['UPLOAD_FOLDER'], pic_name))
                                flash("User Updated Successfully!")
                                return render_template("dashboard.html", 
					                    form=form,
					                    name_to_update = name_to_update)
                        except:
                                flash("Error!  Looks like there was a problem...try again!")
                                return render_template("dashboard.html", 
					                    form=form,
					                    name_to_update = name_to_update)
                else:
                        db.session.commit()
                        flash("User Updated Successfully!")
                        return render_template("dashboard.html", 
				                form=form, 
				                name_to_update = name_to_update)
        else:
                return render_template("dashboard.html", 
				                form=form,
				                name_to_update = name_to_update,
				                id = id)

				               

        
   

# Create Dashboard Page 
@app.route('/technical_support', methods=['GET', 'POST'])
def technical_support():
    name = None
    form = TechnicalSupport()
    #validate
    if form.validate_on_submit():
        name = form.name.data
        form.name.data = ''
    return render_template("technical_support.html",
                           name = name,
                           form = form)


#create logout page
@app.route('/logout',methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    flash("You have been logged out!")
    return redirect(url_for('login'))


#Create Signup
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    name = None
    form = NamerForm()
    #validate
    if form.validate_on_submit():
        user = Users.query.filter_by(email=form.email.data).first()
        if user is None: 
            #hash the password
            hashed_pw = generate_password_hash(form.password_hash.data)
            user = Users(name=form.name.data, username=form.username.data, email=form.email.data,  password_hash=hashed_pw)
            db.session.add(user)
            db.session.commit()
            
        name = form.name.data
        form.name.data = ""
        form.email.data = " "
        form.password_hash.data = " "
        flash("You are regestered successfully! Now you can login!")
        return redirect(url_for('login'))
    return render_template("signup.html",
                           name = name,
                           form = form)


@app.route('/news') 
def news():
    return render_template("news.html")


#error pages
@app.errorhandler(404)
def page_not_found(e):
    return render_template("404.html"), 404

@app.errorhandler(500)
def page_not_found(e):
    return render_template("500.html"), 500