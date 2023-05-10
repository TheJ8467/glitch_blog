
import functools

from flask import Flask, render_template, redirect, url_for, flash, abort, request
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import CreatePostForm, LoginForm, CommentForm
from flask_gravatar import Gravatar
from forms import RegisterForm

from flask_gravatar import Gravatar

import os
import psycopg2

conn = psycopg2.connect(os.environ['DATABASE_URL'])


app = Flask(__name__)

app.config['SECRET_KEY'] = '8BYkEfBA6O6donzWlSihBXox7C0sKR6b'
ckeditor = CKEditor(app)
Bootstrap(app)


##CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL').replace("://", "ql://", 1)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

gravatar = Gravatar(app)

##CONFIGURE TABLES

def get_gravatar_url(email, size=100):
    return gravatar(email, size=size)

app.jinja_env.filters['gravatar_url'] = get_gravatar_url


class User(UserMixin, db.Model):
    __tablename__ = "user"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(1000))

    blog_posts = relationship("BlogPost", back_populates="user")
    comments = relationship("Comment", back_populates="user")

class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    author = db.Column(db.String(250), nullable=False)
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"))

    user = relationship("User", back_populates="blog_posts")
    comments = relationship("Comment", back_populates="blog_posts")

class Comment(db.Model):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)
    body = db.Column(db.Text, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    post_id = db.Column(db.Integer, db.ForeignKey("blog_posts.id"))

    user = relationship("User", back_populates="comments")
    blog_posts = relationship("BlogPost", back_populates="comments")

with app.app_context():
    db.create_all()

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def admin_only(function): # function은 이 경우 보호될 함수라고 보면 됨.
    @functools.wraps(function)  # 메타데이터 보존
    def wrapper(*args, **kwargs):
        if current_user.id != 1:
            abort(403)
        return function(*args, **kwargs)
    return wrapper

@app.route('/')
def get_all_posts():
    posts = BlogPost.query.all()
    is_admin = False
    if current_user.is_authenticated:
        is_login = True
        if current_user.id == 1:
            is_admin = True
    else:
        is_login = False

    return render_template("index.html", all_posts=posts, is_login=is_login, is_admin=is_admin)


@app.route('/register', methods=['POST', 'GET'])
def register():
    is_login = False
    form = RegisterForm()
    if form.validate_on_submit():
        email = form.email.data
        hash_and_salted_password = generate_password_hash(
            form.password.data,
            method='pbkdf2:sha256',
            salt_length=8
        )
        name = form.name.data

        user = User.query.filter_by(email=email).first()

        new_user = User(
            email=email,
            password=hash_and_salted_password,
            name=name,
        )

        if user:
            flash("You're already signed up with that email. Please log in instead!")
            return redirect('/login')
        else:
            db.session.add(new_user)
            db.session.commit()
            return redirect(url_for("get_all_posts"))
    return render_template("register.html", form=form, is_login=is_login)


@app.route('/login', methods=['GET', 'POST'])
def login():
    is_login = False
    form = LoginForm()
    if current_user.is_authenticated:
        return render_template('index.html')

    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data
        user = User.query.filter_by(email=email).first()

        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('get_all_posts'))
        elif not user:
            flash("Email does not exist, please try again")
        else:
            flash("Password is incorrect, please try again.")

    return render_template("login.html", form=form)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))

@app.route("/post/<int:post_id>", methods=['POST', 'GET'])
def show_post(post_id):
    is_login = False
    is_admin = False
    
    requested_post = BlogPost.query.get(post_id)
    form = CommentForm()

    if current_user.is_authenticated:
        is_login = True
        if current_user.id == 1:
            is_admin = True
        
        if form.validate_on_submit():
            text = form.comment.data
            new_comment = Comment(
                body=text,
                user_id=current_user.id,
                post_id=post_id
            )
            user = User.query.get(new_comment.user_id)
            user.comments.append(new_comment)
            blog_post = BlogPost.query.get(new_comment.post_id)
            blog_post.comments.append(new_comment)
            db.session.add(new_comment)
            db.session.commit()
            all_comments = Comment.query.all()

            return render_template("post.html", post=requested_post, all_comments=all_comments, author=user, form=form,
                                   is_login=is_login, is_admin=is_admin)
        else:
            all_comments = Comment.query.all()
            return render_template("post.html", post=requested_post, all_comments=all_comments, form=form,
                                   is_login=is_login, is_admin=is_admin)  
    else:
        all_comments = Comment.query.all()
    
    if request.method == 'POST' and not current_user.is_authenticated:
        flash("You need to login or register to comment")
        return redirect('/login')
      
    

    return render_template("post.html", post=requested_post, form=form, is_login=is_login, all_comments=all_comments,
                           is_admin=is_admin)

  
  
# @app.route("/post/<int:post_id>", methods=['POST', 'GET'])
# def show_post(post_id):
#     is_login = False
#     is_admin = False

#     if current_user.is_authenticated:
#         is_login = True
#         if current_user.id == 1:
#             is_admin = True
#     requested_post = BlogPost.query.get(post_id)
#     form = CommentForm()
#     if request.method == 'POST' and not current_user.is_authenticated:
#         flash("You need to login or register to comment")
#         return redirect('/login')
#     if current_user.is_authenticated:
#         if form.validate_on_submit():
#             text = form.comment.data
#             new_comment = Comment(
#                 body=text,
#                 user_id=current_user.id,
#                 post_id=post_id
#             )
#             user = User.query.get(new_comment.user_id)
#             user.comments.append(new_comment)
#             blog_post = BlogPost.query.get(new_comment.post_id)
#             blog_post.comments.append(new_comment)
#             db.session.add(new_comment)
#             db.session.commit()
#             all_comments = Comment.query.all()

#             return render_template("post.html", post=requested_post, all_comments=all_comments, author=user, form=form,
#                                    is_login=is_login, is_admin=is_admin)

#         else:
#             all_comments = Comment.query.all()
#             return render_template("post.html", post=requested_post, all_comments=all_comments, form=form,
#                                    is_login=is_login, is_admin=is_admin)

#     else:
#         all_comments = Comment.query.all()

#     return render_template("post.html", post=requested_post, form=form, is_login=is_login, all_comments=all_comments,
#                            is_admin=is_admin)


@app.route("/about")
def about():
    is_login = False

    if current_user.is_authenticated:
        is_login = True
    return render_template("about.html", is_login=is_login)


@app.route("/contact")
def contact():
    is_login = False

    if current_user.is_authenticated:
        is_login = True
    return render_template("contact.html", is_login=is_login)


@app.route("/new-post", methods=['POST', 'GET'])
@login_required
@admin_only
def add_new_post():
    is_login = False

    if current_user.is_authenticated:
        is_login = True
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author=current_user.name,
            date=date.today().strftime("%B %d, %Y"),
            user_id = current_user.id,
        )

        user = User.query.get(new_post.user_id)
        user.blog_posts.append(new_post)

        db.session.add(new_post)
        db.session.commit()

        return redirect(url_for("get_all_posts", is_login=is_login))
    return render_template("make-post.html", form=form, is_login=is_login)


@app.route("/edit-post/<int:post_id>", methods=['POST', 'GET'])
@login_required
@admin_only
def edit_post(post_id):
    is_login = False

    if current_user.is_authenticated:
        is_login = True
        
    post = BlogPost.query.get(post_id)
    
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        body=post.body
    )
    
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.author = current_user.name
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id, is_login=is_login))

    return render_template("make-post.html", form=edit_form, is_login=is_login)


@app.route("/delete/<int:post_id>")
@login_required
@admin_only
def delete_post(post_id):
    is_login = False

    if current_user.is_authenticated:
        is_login = True
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts', is_login=is_login))


if __name__ == "__main__":
    app.run(host='0.0.0.0', port=8000)
