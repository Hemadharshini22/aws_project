from flask import Flask, render_template, request, redirect, url_for, session, flash
from datetime import datetime
import boto3
from botocore.exceptions import ClientError
from decimal import Decimal
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = 'secret_key_123'

# --- AWS CONFIGURATION ---
REGION = 'us-east-1'

# Connect to AWS Services
dynamodb = boto3.resource('dynamodb', region_name=REGION)
sns = boto3.client('sns', region_name=REGION)

# DynamoDB Tables
users_table = dynamodb.Table('Users')
admin_table = dynamodb.Table('AdminUsers')

# [IMPORTANT] PASTE YOUR REAL SNS TOPIC ARN HERE
SNS_TOPIC_ARN = 'arn:aws:sns:us-east-1:123456789012:YOUR_TOPIC_NAME'

# --- HELPER FUNCTIONS ---

def send_notification(subject, message):
    """Sends an email alert via AWS SNS"""
    try:
        sns.publish(
            TopicArn=SNS_TOPIC_ARN,
            Subject=subject,
            Message=message
        )
    except ClientError as e:
        print(f"Error sending notification: {e}")

def get_user_from_db(username):
    """Fetches user data from DynamoDB"""
    try:
        response = users_table.get_item(Key={'username': username})
        if 'Item' in response:
            return response['Item']
    except ClientError:
        pass
    return None

# --- CORE ROUTES ---

@app.route('/')
def home():
    if 'user' in session:
        if session.get('role') == 'admin':
            return redirect(url_for('admin_dashboard'))
        return redirect(url_for('dashboard'))
    return render_template('index.html')

# --- ADMIN ROUTES ---

@app.route('/admin_login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        response = admin_table.get_item(Key={'username': username})
        
        # SECURITY CHECK: Verify Hash instead of plain text
        if 'Item' in response and check_password_hash(response['Item']['password'], password):
            session['user'] = username
            session['role'] = 'admin'
            return redirect(url_for('admin_dashboard'))
        else:
            flash('Invalid Admin Credentials', 'error')
            
    return render_template('admin_login.html')

@app.route('/admin_dashboard')
def admin_dashboard():
    if session.get('role') != 'admin':
        return redirect(url_for('admin_login'))
    
    response = users_table.scan()
    all_users = response.get('Items', [])
    
    total_users = len(all_users)
    total_money = sum(float(user['balance']) for user in all_users)
    users_dict = {u['username']: u for u in all_users}
    
    return render_template('admin_dashboard.html', 
                           total_users=total_users, 
                           total_money=total_money, 
                           all_users=users_dict)

# --- USER ROUTES ---

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']
        
        if get_user_from_db(username):
            flash('Username already taken.', 'error')
        else:
            hashed_pw = generate_password_hash(password)
            
            users_table.put_item(Item={
                'username': username,
                'password': hashed_pw, 
                'email': email,
                'balance': Decimal('0.0'),
                'transactions': []
            })
            
            send_notification(
                "CAPSTONE BANK: New Client Registry", 
                f"CONFIDENTIAL ALERT: A new customer account for '{username}' has been successfully created."
            )
            
            flash('Account created! Please login.', 'success')
            return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        user = get_user_from_db(username)
        
        if user and check_password_hash(user['password'], password):
            session['user'] = username
            session['role'] = 'user'
            return redirect(url_for('dashboard'))
        else:
            flash('Wrong username or password.', 'error')
    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    if session.get('role') == 'admin':
        return redirect(url_for('admin_dashboard'))

    user = get_user_from_db(session.get('user'))
    if not user: return redirect(url_for('login'))
    
    recent = user.get('transactions', [])[-5:][::-1]
    return render_template('dashboard.html', user=session['user'], balance=float(user['balance']), transactions=recent)
@app.route('/deposit', methods=['GET', 'POST'])
def deposit():
    username = session.get('user')
    if not username: return redirect(url_for('login'))

    if request.method == 'POST':
        amount = Decimal(request.form['amount'])
        password = request.form['password']
        user = get_user_from_db(username)

        if not check_password_hash(user['password'], password):
            flash('Wrong password.', 'error')
        elif amount <= 0:
            flash('Amount must be positive.', 'error')
        else:
            new_balance = user['balance'] + amount
            user['transactions'].append({
                'type': 'Deposit', 
                'amount': amount, 
                'date': datetime.now().strftime("%Y-%m-%d %H:%M")
            })
            
            users_table.put_item(Item={
                'username': username,
                'password': user['password'], 
                'email': user['email'],
                'balance': new_balance,
                'transactions': user['transactions']
            })
            
            if amount >= 5000:
                send_notification(
                    "CAPSTONE BANK: High-Value Alert", 
                    f"SECURITY ALERT: User '{username}' deposited ${amount}."
                )

            flash(f'Deposited ${amount}', 'success')
            return redirect(url_for('dashboard'))
            
    return render_template('deposit.html')

@app.route('/withdraw', methods=['GET', 'POST'])
def withdraw():
    username = session.get('user')
    if not username: return redirect(url_for('login'))

    if request.method == 'POST':
        amount = Decimal(request.form['amount'])
        password = request.form['password']
        user = get_user_from_db(username)

        if not check_password_hash(user['password'], password):
            flash('Wrong password.', 'error')
        elif amount > user['balance']:
            flash('Insufficient funds.', 'error')
        else:
            new_balance = user['balance'] - amount
            user['transactions'].append({
                'type': 'Withdrawal', 
                'amount': amount, 
                'date': datetime.now().strftime("%Y-%m-%d %H:%M")
            })
            
            users_table.put_item(Item={
                'username': username,
                'password': user['password'],
                'email': user['email'],
                'balance': new_balance,
                'transactions': user['transactions']
            })
            flash(f'Withdrew ${amount}', 'success')
            return redirect(url_for('dashboard'))
            
    return render_template('withdraw.html')

@app.route('/transfer', methods=['GET', 'POST'])
def transfer():
    sender_name = session.get('user')
    if not sender_name: return redirect(url_for('login'))

    if request.method == 'POST':
        receiver_name = request.form['receiver']
        amount = Decimal(request.form['amount'])
        password = request.form['password']
        
        sender = get_user_from_db(sender_name)
        receiver = get_user_from_db(receiver_name)

        if not check_password_hash(sender['password'], password):
            flash('Wrong password.', 'error')
        elif amount > sender['balance']:
            flash('Insufficient funds.', 'error')
        elif not receiver:
            flash(f'User "{receiver_name}" does not exist.', 'error')
        elif receiver_name == sender_name:
            flash('Cannot transfer to yourself.', 'error')
        else:
            sender['balance'] -= amount
            sender['transactions'].append({'type': f'Transfer to {receiver_name}', 'amount': amount, 'date': datetime.now().strftime("%Y-%m-%d %H:%M")})
            users_table.put_item(Item=sender)
            
            receiver['balance'] += amount
            receiver['transactions'].append({'type': f'Received from {sender_name}', 'amount': amount, 'date': datetime.now().strftime("%Y-%m-%d %H:%M")})
            users_table.put_item(Item=receiver)
            
            if amount >= 5000:
                send_notification(
                    "CAPSTONE BANK: High-Value Alert", 
                    f"SECURITY ALERT: Large transfer of ${amount} from {sender_name} to {receiver_name}."
                )

            flash(f'Sent ${amount} to {receiver_name}', 'success')
            return redirect(url_for('dashboard'))

    return render_template('transfer.html')

@app.route('/statement')
def statement():
    user = get_user_from_db(session.get('user'))
    if not user: return redirect(url_for('login'))
    return render_template('statement.html', transactions=reversed(user.get('transactions', [])))

@app.route('/profile')
def profile():
    user = get_user_from_db(session.get('user'))
    if not user: return redirect(url_for('login'))
    return render_template('profile.html', username=user['username'], email=user['email'])

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('home'))

@app.route('/contact')
def contact():
    return render_template('contact.html')

if __name__ == '__main__':
    try:
        if 'Item' not in admin_table.get_item(Key={'username': 'admin'}):
            admin_pw_hash = generate_password_hash('admin123')
            admin_table.put_item(Item={'username': 'admin', 'password': admin_pw_hash})
            print("Admin account created with SECURE HASH.")
    except:
        pass

    app.run(host='0.0.0.0', port=5000, debug=True)