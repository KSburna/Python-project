"""
Module docstring: This module provides functionality
for Cellmart wesite developed using flask.
"""
import re
import json
import logging

from datetime import datetime
from flask import Flask, request, redirect, url_for, session
from flask import render_template

# Create thelogger
logger = logging.getLogger('failed_login_attempts')
logger.setLevel(logging.INFO)

# Create a file handler
handler = logging.FileHandler('failed_login_attempts.log')
logger.addHandler(handler)

app = Flask(__name__)
app.secret_key = '12345678'


@app.route('/')
# ‘/’ URL is bound with home() function.
def home():
    """
    Render the home page.

    This function checks whether the user is logged in or not. If the user is logged in,
    it returns the index.html template with the username of the logged-in user.

    Returns:
        A rendered template of 'index.html' with the username if the user is logged in,
        otherwise, the template without the username.
    """
    products = get_all_products()
    # check whether user is logged or not
    if 'user' in session:
        return render_template('index.html', username=session[
            'user']['name'], products=products)  # return index.html with username of logged user

    return render_template('index.html', products=products)


@app.route('/login')
# ‘/login’ URL is bound with login() function.
def login():
    """
    Render the login page.

    Thisfunction chceks whether the user is already logged-in. If user is logged in,
    it redirects them to cart page.If the user arrived at the login page after registration,
    they will see a registration success message.

    Returns:
        A rendered template of 'login.html'. If the user is logged in, it may also redirect
        them to the cart page. If the user arrived after registration,
        they will see a success message.
    """
    # check whether user is logged or not
    if 'username' in session:
        return redirect(url_for('cart'))  # redirect to cart page if user is already logged
    registered = request.args.get('registered')  # get registered url parameter
    error_msg = request.args.get('error_msg')  # get registered url parameter

    #  if user landed to loging page after registraion, user will see a regisration success message
    if registered:
        return render_template('login.html',
                success_message='You have successfully been registered. please login...')
    if error_msg:
        return render_template('login.html',
                error_message=error_msg)
    return render_template('login.html')


@app.route('/login', methods=['POST'])
# ‘/login’ URL is bound with login_action() function.
def login_action():
    """
    Perform login action.

    This fnuction is bound to the '/login' URL and handles POST requests.
    It retrieves the email and password from the request form, attempts to authenticate
    the user, and if successful, saves the email in the session and redirects the user to
    the cart page. If the authentication fails, it rendres the login page again with an
    error message indicating invalid login credentials.

    Returns:
        If authentication is successful, redirects the user to the cart page.
        If authentication fails, renders the 'login.html' template with an error message.

    Raises:
        An erro: If 'email' or 'password' fields are missing in the request form.
    """
    #  get email and password from request
    email = request.form['email']
    password = request.form['password']
    #authenticate user and if login credentials are valid save email in
    #session and redirect user to cart page

    logged_user = authenticate_user(email, password)

    if logged_user:
        session['user'] = logged_user  # Store email in session
        return redirect(url_for('home'))

    # Log the failed login attempt
    ip_address = request.remote_addr
    logger.info("Failed login attempt for EMAIL :: %s from IP :: %s address at TIME :: %s",
            email, ip_address, datetime.now().strftime('%Y-%m-%d %H:%M:%S'))

    #show an error message to the user if login credentials are not valid.
    return render_template('login.html',email=email,password=password,
                               error_message='Invalid login credentials!')


@app.route('/register', methods=['GET'])
# ‘/register’ URL is bound with register() function.
def register():
    """
    Render the registrtion page.

    This function checks whether the user is already logged in. If the usr is logged in,
    it redirects them to the cart page. If the user is not logged in, it renders registration
    page where the user can signup for a account.

    Returns:
        A rendered template of 'register.html'. If the user is already logged in,
        it may also redirect
        them to the cart page.
    """
    # check whether user is logged or not
    if 'user' in session:
        return redirect(url_for('home'))  # redirect to cart page if user is already logged
    #  return registration page tp the user if user has no any active sessions
    return render_template('register.html')

@app.route('/register', methods=['POST'])
# ‘/register’ URL is bound with register_action() function.
def register_action():
    """
    Register new user.

    This function receives a POST request with user registration data,
    including name, email, and password. It checks if the provided
    email already exists in the system and, if the password
    meets the complexity requirements. If all checks pass, the user
    details are stored in a text file for registration completion.
    If there are any errors, such as duplicate username/email or
    invalid password,a appropriate errr message displayes.

    Returns:
        - If successful, it redirects to login page with a success message.
        - If there are errors in registration request, renders
          registration pagewith appropriate eror messages.
    """
    #  get name, email and password which are submitted by user
    name = request.form['name']
    email = request.form['email']
    password = request.form['password']
    confirm_password = request.form['confirm_password']

    error_message = None

    # check if passwords do not match
    if password != confirm_password:
        error_message = 'passwords do not match!'

    # check if email is already is registered in the system
    elif is_email_exist(email):
        error_message = 'email already exists!'

    # Check password complexity
    elif not is_valid_password(password):
        error_message = ('Password must be at least 12 characters long and contain at least '
                         '1 uppercase, 1 lowercase, 1 number, and 1 special character')

    # if there is an error in the registration request, return error message
    if error_message is not None:
        return render_template('register.html', error_message=error_message, email=email,
                                                    name=name)

    # if there is no any errors, Store user details in a text file to complte the registration
    with open('user_details.txt', 'a', encoding='utf-8') as user_details_file:
        user_details_file.write(f'{name},{email},{password}\n')

    # Redirect to login page with success message
    return redirect(url_for('login', registered=True))


@app.route('/checkout')
# ‘/’ URL is bound with checkout() function.
def checkout():
    
    # check whether user is logged or not
    if 'user' in session:
        product_id = request.args.get('id')
        product = get_product_by_id(product_id)
        # if user has a active session get the username from the session
        username = session['user']['name']
        return render_template('checkout.html', username=username, product=product)
    # return login page to the user if user does not have an active session
    return redirect(url_for('login'))

@app.route('/about')
def about():
    if 'user' in session:
        return render_template('about.html', username=session[
            'user']['name']) 

    return render_template('about.html')

@app.route('/pay', methods=['POST'])
def pay():
    if request.method == 'POST':
        # Get the order details from the form
        username = session['user']['email']
        delivery_address = request.form.get('delivery_address')
        product_id = request.form.get('product_id')
        quantity = int(request.form.get('quantity'))
        product = get_product_by_id(product_id)
        price = float(product['price'])
        total = price*quantity

        # Prepare order details as a dictionary
        order_details = {
            "username": username,
            "product_id": product_id,
            "delivery_address": delivery_address,
            "product_name": product['name'],
            "quantity": quantity,
            "price": price,
            "total": total
        }

        # Save the order details to the text file in JSON format
        with open('orders.txt', 'a') as file:
            file.write(json.dumps(order_details) + '\n')

        return redirect(url_for('orders'))

@app.route('/orders')
# ‘/’ URL is bound with orders() function.
def orders():
    # check whether user is logged or not
    if 'user' in session:
        # if user has a active session get the username from the session
        name = session['user']['name']
        username = session['user']['email']
        user_orders = fetch_orders_by_username(username)
        return render_template('my-orders.html', username=name, orders=user_orders)
    # return login page to the user if user does not have an active session
    return redirect(url_for('login'))

def fetch_orders_by_username(username):
    orders = []
    with open('orders.txt', 'r') as file:
        for line in file:
            order = json.loads(line)
            if order['username'] == username:
                orders.append(order)
    return orders

@app.route('/password-update', methods=['POST'])
# ‘/’ URL(post) is bound with password_update_action() function.
def password_update_action():
    """
    uodate password action
    """
    #  get new password which is submitted by user
    new_password = request.form['password']

    error_message = None

    # Check password complexity
    if not is_valid_password(new_password):
        error_message = ('Password must be at least 12 characters long and contain at least'
                        ' 1 uppercase, 1 lowercase, 1 number, and 1 special character')

    email = session['user']['email']

    # Update thepassword in user_details.txt if there ix no errors
    if error_message is None:
        # Open the user_details.txt file in read mode
        with open('user_details.txt', 'r', encoding='utf-8') as file:
            lines = file.readlines()
        # Find the line corresponding to the user and update th password
        for i, line in enumerate(lines):
            name, email_db, _ = line.strip().split(',')
            if email_db == email:
                lines[i] = f'{name},{email},{new_password}\n'
                break
        # Writethe updated line to file
        with open('user_details.txt', 'w', encoding='utf-8') as file:
            file.writelines(lines)

        # Redirect to passwordupdate page with success message
        return redirect(url_for('password_update', success_msg=
                                'Your password has been successfully updated.'))

    # If there are errors, render the template with the error message
    return render_template('password-update.html', error_message=error_message,
                                                    username=session['user']['name'])
@app.route('/password-update')
# ‘/’ URL is bound with password_update() function.
def password_update():
    """
    Render the password update page.

    If  user has n active session, the function get the username from the session.
    If the user is logged in, it renders the password update page. If there's a success message
    parameter in the URL, it's displayed to the user. If the user is not logged in, it redirects
    them to the login page with an error message.

    Returns:
        If the user is logged in, renders the password update page.
        If the user is not logged in, redirects to login page with an error message
    """

    # check whether user is logged or not
    if 'user' in session:
        success_msg = request.args.get('success_msg')  # get registered url parameter
        if success_msg:
            return render_template('password-update.html',
                                   username=session['user']['name'],
                                     success_message=success_msg)
        return render_template('password-update.html', username=session['user']['name'])

    # return login page to the user if user does not have an active session
    return redirect(url_for('login',
                             error_msg='you are required to log-in to perform password update'))

@app.route('/logout')
# ‘/’ URL is bound with logout() function.
def logout():
    """
    Logout user.

    This function remove username from session, in roder to logging out the user.
    After removing the username from session, it redirect  user to  login page.

    Returns:
        Redirects to the login page after removing the username from the session.
    """
    # Remove the username from the session if it's there
    session.pop('user', None)
    # after remove username from sesion, redirect the user to login page
    return redirect(url_for('login'))

# this function validates password complexity
def is_valid_password(password):
    """
    Validate password complexity.

    This function checks whether the given password meet required complexity criteria:
    - At least 12 characters long
    - Contains at least 1 lowercase letter
    - Contains at least 1uppercase letter
    - Contains at least 1 digit
    - Contains at least 1 special character

    Args:
        password (str): The password to validate.

    Returns:
        bool: Trueif, the password meets the complexity criteria, False otherwise.
    """
    # validate length
    if len(password) < 12:
        return False
    # check for lowercase charactor
    if not re.search("[a-z]", password):
        return False
    # check for uppercase charactor
    if not re.search("[A-Z]", password):
        return False
    # check for a number
    if not re.search("[0-9]", password):
        return False
    # check for a special charactor
    if not re.search("[!@#$%^&*()_+=]", password):
        return False
    return True
    """
    Checks if email already exist in user_details.txt.

    Args:
        email (str):  email to check for existence.

    Returns:
        bool: True if the email already exists,not False.
    """
    with open('user_details.txt', 'r', encoding='utf-8') as user_details_file:
        for line in user_details_file:
            user, email_db, _ = line.strip().split(',')
            if email_db == email:
                return True
    return False


# this method check if email already exists
def is_email_exist(email):
    """
    Check if email already exists in user_details.txt.

    Args:
        email (str):  email address to check for existence in fil.

    Returns:
        bool: True if the email already exists,if not False .
    """
    with open('user_details.txt', 'r', encoding='utf-8') as user_details_file:
        for line in user_details_file:
            _, mail, _ = line.strip().split(',')
            if mail == email:
                return True
    return False

def get_product_by_id(product_id):
    with open('products.txt', 'r') as file:
        for line in file:
            product = json.loads(line)
            if product['id'] == int(product_id):
                return product
    return None

def get_all_products():
    products = []
    with open('products.txt', 'r') as file:
        for line in file:
            product = json.loads(line)
            products.append(product)
    return products

# this method authenticate user with username and password
def authenticate_user(email, password):
    """
    Authenticates user with email & password.

    This method chec if the provided email and password match any users
    credentials stored in 'user_details.txt' file.

    Args:
        email (str):  email to authenticate.
        password (str): password to authenticate.

    Returns:
        bool: True if the email and password match, ifnot otherwise.
    """
    with open('user_details.txt', 'r', encoding='utf-8') as user_details_file:
        for line in user_details_file:
            name, email_db, stored_password = line.strip().split(',')
            if email_db == email and stored_password == password:
                return {"name":name, "email":email}
    return None

class User:
    def __init__(self, username, email):
        self.username = username
        self.email = email

    def __str__(self):
        return f"Username: {self.username}, Email: {self.email}"

# main driver
if __name__ == '__main__':
    from waitress import serve
    serve(app, host="0.0.0.0", port=8080)
    app.run()
