from app import app
from flask import render_template, request, redirect, url_for, flash, abort, g, jsonify, make_response
from .forms import RegistrationForm, LoginForm, EmailForm, PasswordForm, CompleteForm
from .models import User, PrivateDetails
from app import db
from flask_login import login_required, current_user, login_user,  logout_user
from .security import generate_confirmation_token, confirm_token
from .email import send_email
from sqlalchemy.exc import IntegrityError


@app.errorhandler(404)
def page_not_found(e):
    return make_response(jsonify({'error': 'Page not found',
                                'code': 404)}
    # return render_template('404.html'), 404


@app.errorhandler(500)
def server_error(e):
    return make_response(jsonify({'error':'Internal server error',
                                'code':500})
    # return render_template('500'.html'), 500


@app.before_request
def before_request():
    if current_user.is_authenticated:
        return jsonify({
            'msg': 'User already logged in',
            'url': '/index'
            'code': 200
            })

        #  return redirect(url_for('index'))


@app.route('/')
@login_required
def index():
    return jsonify({
        'code': 200,
        'status': True
    })

    #  return render_template('index.html')


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(full_name=form.full_name.data, email=form.email.data, username=form.username.data, password=form.password.data,
                    email_confirmed=False)
        try:
            db.session.add(user)
            db.session.commit()
        except IntegrityError:
            db.session.rollback()

            #  The following lines of code
            #  is the confirmation email being sent
            #  to the  user

        token = generate_confirmation_token(user.email)

        confirm_url = url_for('confirm_email', token=token, _external=True)

        html = render_template('activate.html', confirm_url=confirm_url)

        subject = 'Please confirm your Email'

        # send_email function was imported from
        # the email file

        send_email(user.email, subject, html)

        return jsonify({
            'status': True,
            'code': 200,
            'msg': 'A confirmation email has been sent to you',
            'url':  '/complete/signup'
        })

    else:

        return jsonify({
            'status': False,
            'msg': 'Please check your post form'
        })

    #  return render_template('register.html', form=form)






@app.route('/complete/signup', methods=['GET', 'POST'])
def complete_signup():

    form = CompleteRegistrationForm()

    if form.validate_on_submit():
        user = CompleteRegistrationForm(address=form.address.data, city=form.city.data, state=form.state.data,
                                         poatal_code=form.postal_code.data, phone_number=form.phone_number.data,
                                         date_of_birth=form.date_of_birth.data)
        db.session.add(user)
        db.session.commit()

        return redirect(url_for('login'))

    return render_template('test.html', form=form)


@app.route('/confirm/<token>')
def confirm_email(token):
    """
     the try ... except bit at the beginning to check that the token is valid.
      The token contains a timestamp, so we can tell ts.loads() to raise an exception if it is older than max_age.
      In this case, we’re setting max_age to 86400 seconds, i.e. 24 hours.
    :param token:
    :return:
    """
    try:
        email = confirm_token(token)
    except Exception as e:
        return jsonify({
            'msg': 'The confirmation link is invalid or has expired, danger',
            'status': False,
            'code': 404
        })
        # flash('The confirmation link is invalid or has expired.', 'danger')
        #  abort(404)

    user = User.query.filter_by(email=email).first()
    if user.email_confirmed:
        return jsonify(message='Email has already benn confirmed please login')
    # flash('Email has already been confirmed Please login')
    else:
        user.email_confirmed = True
        db.session.add(user)
        db.session.commit()
        return jsonify({
            'status': True,
            'msg': 'Your email has been confirmed',
            'url': '/login'
        })
    #  return redirect(url_for('login'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()

    if form.validate_on_submit():

        user = User.query.filter_by(username=form.username.data).first()

        if user is not None and user.verify_password(form.password.data):

            if user.email_confirmed:

                login_user(user, form.remember_me.data)

                return jsonify({
                    'status': True,
                    'code': 200,
                    'msg': 'Login Successful',
                    'url': url_for(request.args.get('next') or 'index')
                })
                #  return redirect(request.args.get('next') or url_for('index'))
            return jsonify({
                'status': False,
                'message': 'Email has/nt been verified, you can/t login at the moment',
                'url': '/'
            })
            #  flash('Mail not configured')
        else:
            return jsonify({
                'msg': 'Invalid Login Credentials',
                'Status': False,
                'url': '/login'
            }
            )
        #  flash('invalid login credentials')
    # return render_template('login.html', form=form)


@app.route('/reset/password', methods=['POST'])
def reset():
    form = EmailForm()

    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()

        if user.email_confirmed:
            subject = 'Password reset requested'
            token = generate_confirmation_token(user.email)
            recover_url = url_for('reset_with_token', token=token, _external=True)
            html = render_template('recover.html', recover_url=recover_url)
            send_email(user.email, subject, html)
            flash('A confirmation link to reset your password has been sent to you')
            return redirect(url_for('login'))
        else:
            flash('This Email hasnt been confirmed yet')
            return 'Email not confirmed'

    return render_template('reset.html', form=form)


@app.route('/reset/<token>')
def reset_with_token(token):
    try:
        email = confirm_token(token, expiration=3600)

    except Exception as e:
        flash('The confirmation link is invalid or has expired.', 'danger')
        abort(400)
    form = PasswordForm()

    if form.validate_on_submit():
        user = User.query.filter_by(email=email).first()
        user = form.password.data

        db.session.add(user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('reset_password.html', form=form)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return jsonify({
        'msg': 'You have been logged out',
        'url': '/login'
    })
    # return redirect(url_for('login'))
