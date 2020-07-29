from flask import Flask, render_template, redirect, session, flash
from flask_debugtoolbar import DebugToolbarExtension
from models import connect_db, db, User, Feedback
from forms import RegisterForm, LoginForm, FeedbackForm, ChangePassword, EmailForm
from sqlalchemy.exc import IntegrityError
from flask_migrate import Migrate
from flask_mail import Mail, Message
from threading import Thread
import secrets

app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = "postgres:///feedback"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SQLALCHEMY_ECHO"] = True
app.config["SECRET_KEY"] = "abc123"
app.config['DEBUG_TB_INTERCEPT_REDIRECTS'] = False

# configuration for sending emails
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USE_SSL'] = True
app.config['MAIL_USERNAME'] = ""  # Add your gmail user name here
app.config['MAIL_PASSWORD'] = ""  # ADD your password here


mail = Mail(app)

connect_db(app)

migrate = Migrate(app, db)

db.create_all()

toolbar = DebugToolbarExtension(app)


@app.route("/")
def homepage():
    """redirect to the register page"""

    return redirect('/register')


@app.route("/check-email", methods=["GET", "POST"])
def check_email():
    """Password change: produces form for confirming user email"""

    form = EmailForm()
    if form.validate_on_submit():
        user = User.query.filter(User.email == form.email.data).first()
        secret_token = secrets.token_urlsafe(20)

        if user:
            user.reset_token = secret_token
            db.session.commit()

            send_mail_async(user)
            flash("A link has been sent to your email to reset your password", "success")

            return redirect('/check-email')
        else:
            form.email.errors = ["We do not have this email in our system"]

    return render_template('check_email.html', form=form)


@app.route("/password-change/<token>", methods=["GET", "POST"])
def change_password(token):
    """ produces form for changing password"""

    user = User.query.filter(User.reset_token == token).first()
    if user:
        form = ChangePassword()
        if form.validate_on_submit():
            pwd = form.password.data
            user.update_password(pwd)
            user.reset_token = None
            db.session.commit()
            flash("You have successfully changed your password", 'success')
            return redirect('/login')
        return render_template('change_password.html', form=form)


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user: produce form & handle form submission."""
    if 'username' in session:
        username = session['username']
        return redirect(f"/users/{username}")

    form = RegisterForm()

    if form.validate_on_submit():
        username = form.username.data
        pwd = form.password.data
        email = form.email.data
        first_name = form.first_name.data
        last_name = form.last_name.data

        user = User.register(username, pwd, email, first_name, last_name)
        db.session.add(user)

        try:
            db.session.commit()
        except IntegrityError:
            form.username.errors.append('Username taken. Please pick another')
            return render_template('register.html', form=form)

        session["username"] = user.username
        flash("welcome! Successfully Created Your Account!", "success")

        return redirect(f"/users/{user.username}")
    else:

        return render_template('register.html', form=form)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Produce login form or handle login."""

    if 'username' in session:
        username = session['username']
        return redirect(f"/users/{username}")

    form = LoginForm()

    if form.validate_on_submit():
        name = form.username.data
        pwd = form.password.data

        # authenticate will return a user or False
        user = User.authenticate(name, pwd)

        if user:
            session["username"] = user.username  # keep logged in
            flash(f"Welcome Back, {user.username}!", "info")
            return redirect(f"/users/{user.username}")

        else:
            form.username.errors = ["Bad name/password"]

    return render_template("login.html", form=form)
# end-login


@app.route("/users/<username>")
def profile(username):
    """User profile page"""

    if authorization_flashes(username):
        return redirect('/register')

    user = User.query.get_or_404(username)
    if user.is_admin:
        feedback = Feedback.query.all()
    else:
        feedback = Feedback.query.filter(Feedback.username == username)

    return render_template("profile.html", user=user, feedback=feedback)


@app.route("/users/<username>/delete", methods=["POST"])
def delete_profile(username):
    """delete the profile of a particular user"""
    if authorization_flashes(username):
        return redirect('/register')
    user = User.query.get_or_404(username)
    db.session.delete(user)
    db.session.commit()
    return redirect('/logout')


@ app.route("/users/<username>/feeback/add", methods=["GET", "POST"])
def add_feedback(username):
    """ routes to form for adding feedback to user profile"""

    if authorization_flashes(username):
        return redirect('/register')
    form = FeedbackForm()
    user = User.query.get_or_404(username)

    if form.validate_on_submit():
        content = form.content.data
        title = form.title.data
        new_feedback = Feedback(
            title=title, content=content, username=session['username'])
        db.session.add(new_feedback)
        db.session.commit()
        flash('Feedback Created!', "success")
        return redirect(f'/users/{username}')

    return render_template("add_feedback.html", form=form, user=user)


@ app.route("/feedback/<feedback_id>/update", methods=["GET", "POST"])
def update_feedback(feedback_id):
    """ routes to a form that updates feedback on user profile"""
    feedback = Feedback.query.get_or_404(feedback_id)
    if authorization_flashes(feedback.username):
        return redirect('/register')
    form = FeedbackForm(obj=feedback)

    if form.validate_on_submit():
        feedback.content = form.content.data
        feedback.title = form.title.data
        db.session.commit()
        flash('Feedback Updated!', "success")
        return redirect(f'/users/{feedback.username}')

    return render_template("update_feedback.html", form=form, user=feedback.user)


@app.route("/feedback/<feedback_id>/delete", methods=["POST"])
def delete_feedback(feedback_id):
    """ deletes feedback from user profile"""
    feedback = Feedback.query.get_or_404(feedback_id)
    if authorization_flashes(feedback.username):
        return redirect('/register')
    db.session.delete(feedback)
    db.session.commit()
    return redirect(f'/users/{feedback.username}')


@app.route("/logout")  # This should be a post request!!!!
def logout():
    """Logs user out and redirects to homepage."""

    session.pop("username")
    flash("Goodbye!", "info")

    return redirect("/login")


def authorization_flashes(username):
    """flash appropriage message if user isn't authorized on a page"""
    if "username" not in session:
        flash("You must be logged in to view!", "danger")
        return True

    elif session["username"] != username:
        flash("You are not authorized to be here", "danger")
        return True

    # alternatively, can return HTTP Unauthorized status:
    #
    # from werkzeug.exceptions import Unauthorized
    # raise Unauthorized()


###################### Two functions for sending emails##########################
def send_email(app, msg):

    with app.app_context():
        mail.send(msg)


def send_mail_async(user):
    msg = Message()
    msg.subject = "guess where I'm sending this from"
    msg.recipients = ['']  # Add recipient email here
    msg.sender = ['']  # Add sender email here
    msg.html = render_template('reset_email.html', user=user)

    Thread(target=send_email, args=(app, msg)).start()
