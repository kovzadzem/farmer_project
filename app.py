from flask import Flask, render_template, redirect, url_for, flash
from flask_login import (
    LoginManager,
    login_user,
    logout_user,
    login_required,
    current_user
)
from werkzeug.security import generate_password_hash, check_password_hash

from models import db, User
from forms import RegisterForm, LoginForm

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret-key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db.init_app(app)

# --------------------
# LOGIN MANAGER
# --------------------
login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@login_manager.unauthorized_handler
def unauthorized():
    flash('გთხოვთ გაიაროთ ავტორიზაცია', 'warning')
    return redirect(url_for('login'))


# --------------------
# ROUTES
# --------------------

@app.route('/')
def home():
    return render_template('home.html')


@app.route('/about')
def about():
    return render_template('about.html')


@app.route('/blog')
def blog():
    return render_template('blog.html')


@app.route('/map')
def map_page():
    return render_template('map.html')


@app.route('/farmers')
def farmers():
    return render_template('farmer.html')


@app.route('/cart')
@login_required
def cart():
    cart_items = [
        {
            "name": "Potato",
            "farm": "Raisi",
            "price": 20,
            "image": "/static/img/potato.jpg"
        }
    ]

    subtotal = 186.5
    delivery = 5
    total = subtotal + delivery

    return render_template(
        "cart.html",
        cart_items=cart_items,
        subtotal=subtotal,
        delivery=delivery,
        total=total
    )


@app.route('/favorites')
@login_required
def favorites():
    return render_template('favorites.html')


# --------------------
# PROFILE
# --------------------
@app.route('/profile')
@login_required
def profile():
    return render_template('profile.html')


# --------------------
# REGISTER
# --------------------
@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('profile'))

    form = RegisterForm()

    if form.validate_on_submit():

        existing_user = User.query.filter_by(
            username=form.username.data
        ).first()

        if existing_user:
            flash('ეს username უკვე გამოყენებულია', 'danger')
            return render_template('register.html', form=form)

        hashed_password = generate_password_hash(
            form.password.data,
            method='pbkdf2:sha256'
        )

        user = User(
            username=form.username.data,
            password=hashed_password
        )

        db.session.add(user)
        db.session.commit()

        login_user(user)
        return redirect(url_for('profile'))

    return render_template('register.html', form=form)


# --------------------
# LOGIN
# --------------------
@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('profile'))

    form = LoginForm()

    if form.validate_on_submit():
        user = User.query.filter_by(
            username=form.username.data
        ).first()

        if user and check_password_hash(
            user.password,
            form.password.data
        ):
            login_user(user)
            return redirect(url_for('profile'))
        else:
            flash('არასწორი username ან password', 'danger')

    return render_template('login.html', form=form)


# --------------------
# LOGOUT
# --------------------
@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('წარმატებით გამოხვედი', 'info')
    return redirect(url_for('login'))


# --------------------
# LOCAL RUN ONLY
# --------------------
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run()
