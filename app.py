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
from wtforms.widgets import TextArea
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


# Create a Blog Post model
class Posts(db.Model):
	id = db.Column(db.Integer, primary_key=True)
	title = db.Column(db.String(255))
	content = db.Column(db.Text)
	author = db.Column(db.String(255))
	date_posted = db.Column(db.DateTime, default=datetime.utcnow)
	slug = db.Column(db.String(255))

class PostForm(FlaskForm):
    title = StringField("Title", validators=[DataRequired()])
    content = StringField("Content", validators=[DataRequired()], widget=TextArea())
    author = StringField("Author", validators=[DataRequired()])
    slug = StringField("Slug", validators=[DataRequired()])
    submit = SubmitField("Submit")


# Add Post Page
@app.route('/add_post', methods=['GET', 'POST'])
def add_post():
    form = PostForm()

    if form.validate_on_submit():
        post = Posts(title=form.title.data, content=form.content.data, author=form.author.data, slug=form.slug.data)
        # Clear The Form
        form.title.data = ''
        form.content.data = ''
        form.author.data = ''
        form.slug.data = ''

        # Add post data to database
        db.session.add(post)
        db.session.commit()

        # Return a Message
    
        flash("Uusi viesti lähetetty onnistuneesti!")
    
    return render_template("add_post.html", form=form)
      
@app.route('/vaihtokauppa', methods=['GET', 'POST'])
def vaihtokauppa():
     return render_template("vaihtokauppa.html")
    
#create a model
class Users(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False, unique=True)
    name = db.Column(db.String(200), nullable=False)
    email = db.Column(db.String(200), nullable=False, unique=True)
    password_hash = db.Column(db.String(128), nullable=False)
    profile_pic =db.Column(db.String(1000), nullable=True)
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
    name = StringField("Nimi:", [validators.Length(min=4, max=25)])
    username = StringField("Käyttäjänimi:", [validators.Length(min=4, max=25)])
    email = StringField("email:", validators=[DataRequired()])
    password_hash = PasswordField("Luo oma salasana:", [validators.DataRequired(), validators.EqualTo('confirm', message='Passwords must match!')])
    confirm = PasswordField("Toista salasana:")
    profile_pic = FileField("")
    submit = SubmitField("Lähetä")
    
#login field 
class PasswordForm(FlaskForm):
    email = EmailField("email:", validators=[DataRequired()])
    password_hash = PasswordField("salasana:", [validators.DataRequired(), validators.EqualTo('confirm', message='Passwords must match!')])
    submit = SubmitField("Lähetä")
    
    
class TechnicalSupport(FlaskForm):
    name = StringField("Nimi:")
    email = StringField("email:", validators=[DataRequired()])
    phone = StringField("puhelinnumero:")
    message = TextAreaField("Kirjoita viesti:", validators=[DataRequired()])
    submit = SubmitField("Lähetä")
    
    
    
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
			flash("Käyttäjä poistettu onnistuneesti!!")

			our_users = Users.query.order_by(Users.date_added)
			return render_template("login.html", 
			form=form,
			name=name,
			our_users=our_users)

		except:
			flash("Käyttäjää ei voi poistaa. Yritä uudelleen!")
			return render_template("dashboard.html", 
			form=form, name=name,our_users=our_users)
	else:
		flash("Käyttäjää ei voi poistaa! ")
		return redirect(url_for('dashboard'))

#Create LoginForm
class LoginForm(FlaskForm):
    username = StringField("Käyttäjänimi:", validators=[DataRequired()])
    password = PasswordField("Salasana:", validators=[DataRequired()])
    submit = SubmitField("Lähetä")

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
                flash("Olet kirjautunut sisään!")
                return redirect(url_for('kotisivu'))
            else:
                flash("Virheellinen salasana. Yritä uudelleen!")
        else:
            flash("Käyttäjää ei ole olemassa. Yritä uudelleen!")  
            
    return render_template("login.html", form=form)


#route decorator
@app.route('/')
def index():
    return render_template("index.html")


@app.route('/varaus')
@login_required
def varaus():
    return render_template("varaus.html")

@app.route('/kotisivu')
@login_required
def kotisivu():
    return render_template("kotisivu.html")


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
                    flash("Muutokset on päivitetty onnistuneesti!")
                    return render_template("dashboard.html", 
					                    form=form,
					                    name_to_update = name_to_update)
                except:
                    flash("Tapahtui virhe, yritä uudelleen.")
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
@login_required
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
    flash("Olet kirjautunut ulos!")
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
        flash("Olet rekisteröitynyt onnistuneesti! Nyt voit kirjautua sisään!")
        return redirect(url_for('login'))
    return render_template("signup.html",
                           name = name,
                           form = form)


@app.route('/news') 
@login_required
def news():
    return render_template("news.html")


#error pages
@app.errorhandler(404)
def page_not_found(e):
    return render_template("404.html"), 404

@app.errorhandler(500)
def page_not_found(e):
    return render_template("500.html"), 500