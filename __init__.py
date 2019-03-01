from flask import Flask, render_template, redirect, url_for, flash, request
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField, BooleanField, TextAreaField
from wtforms.validators import DataRequired, Length, Email, EqualTo
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from flask_bcrypt import Bcrypt
from flask_login import UserMixin, LoginManager, login_user, current_user, logout_user, login_required
from flask_migrate import Migrate

app = Flask(__name__)
app.config['SECRET_KEY']="get yours"
POSTGRES = {
    'user': 'postgres',
    'pw': 'tunga',
    'db': 'fblog',
    'host': 'localhost',
    'port': '5432',
}

#app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://%(user)s:%(pw)s@%(host)s:%(port)s/%(db)s' % POSTGRES
app.config['SQLALCHEMY_DATABASE_URI'] = f"postgresql://{POSTGRES['user']}:{POSTGRES['pw']}@{POSTGRES['host']}:{POSTGRES['port']}/{POSTGRES['db']}"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
migrate = Migrate(app, db)
bcrypt = Bcrypt(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'#route to go to before accessing login_required route

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)


#models
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    posts = db.relationship('Post', backref='author', lazy=True, cascade="all, delete-orphan")#this is a relationship not a column
    comments = db.relationship('Comment', backref='commenter', lazy=True, cascade="all, delete-orphan")#this is a relationship not a column

    def __repr__(self):
        return f"User('{self.username}', '{self.email}')"

class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    date_posted = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    content = db.Column(db.Text, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    comments = db.relationship('Comment', backref='author', lazy=True, cascade="all, delete-orphan")#this is a relationship not a column

    def __repr__(self):
        return f"User('{self.title}', '{self.date_posted}')"

class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    date_posted = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    content = db.Column(db.Text, nullable=False)
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)


#forms
class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=20)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Sign Up')

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember = BooleanField('Remember Me')
    submit = SubmitField('Login')

class PostForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired()])
    content = TextAreaField('Content', validators=[DataRequired()])
    submit = SubmitField('Post')

class CommentForm(FlaskForm):
    content = TextAreaField('Content', validators=[DataRequired()])
    submit = SubmitField('Comment')

#routes
@app.route("/", methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        pw_hash = bcrypt.generate_password_hash(form.password.data).decode("utf-8", "ignore")
        user = User(username = form.username.data, email = form.email.data, password = pw_hash)
        db.session.add(user)
        db.session.commit()
        #flash(form.name.data)
        return redirect(url_for('results'))
    return render_template('register.html', form=form)

@app.route("/login", methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user, remember=form.remember.data)
            return redirect(url_for('results'))        
        else:
            return "wrong password"
    return render_template('login.html', form = form)

@app.route("/results")
@login_required
def results():
    users = User.query.all()
    return render_template('results.html', users=users)

@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))

@app.route("/home")
def home():
    return render_template('home.html')

@app.route("/new_post", methods=['GET', 'POST'])
@login_required
def new_post():
    form = PostForm()
    if form.validate_on_submit():
        post = Post(title = form.title.data, content = form.content.data, author = current_user)
        db.session.add(post)
        db.session.commit()
        return redirect(url_for('posts'))
    return render_template('new_post.html', form=form)

@app.route("/edit_post/<int:post_id>", methods=['GET', 'POST'])
@login_required
def edit_post(post_id):
    post = Post.query.filter_by(id=post_id).first()
    if post.author != current_user:
        abort(403)
    form = PostForm()
    if form.validate_on_submit():
        post.title = form.title.data
        post.content = form.content.data
        db.session.commit()
        #flash('Post has been succesfully updated', 'success')
        return redirect(url_for('post', post_id=post.id))
    elif request.method == 'GET':
        #prepopulating the fields
        form.title.data = post.title
        form.content.data = post.content
    return render_template('edit_post.html', form=form)

@app.route("/posts")
@login_required
def posts():
    posts = Post.query.all()
    return render_template('posts.html', posts = posts)

@app.route("/post/<int:post_id>")
@login_required
def post(post_id):
    post = Post.query.filter_by(id=post_id).first()
    comments = Comment.query.filter_by(id=post_id)
    return render_template('post.html', post = post, comments = comments)

@app.route("/delete_post/<int:post_id>")
@login_required
def delete_post(post_id):
    post = Post.query.filter_by(id=post_id).first()
    if post.author != current_user:
        abort(403)
    db.session.delete(post)
    db.session.commit()
    return render_template('posts.html')

@app.route("/new_comment/<int:post_id>", methods=['GET', 'POST'])
@login_required
def comment(post_id):
    post = Post.query.filter_by(id=post_id).first()
    form = CommentForm()
    if form.validate_on_submit():
        comment = Comment(content = form.content.data, post_id = post.id, commenter = current_user)
        db.session.add(post)
        db.session.commit()
        return redirect(url_for('posts'))
    return render_template('comment.html', form=form)
