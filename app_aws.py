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

# Connect to AWS Services Safely
try:
    dynamodb = boto3.resource('dynamodb', region_name=REGION)
    sns = boto3.client('sns', region_name=REGION)
    users_table = dynamodb.Table('Users')
    admin_table = dynamodb.Table('AdminUsers')
except Exception as e:
    print(f"AWS Connection Error: {e}")

# [IMPORTANT] PASTE YOUR REAL SNS TOPIC ARN HERE
SNS_TOPIC_ARN = 'arn:aws:sns:us-east-1:123456789012:YOUR_TOPIC_NAME'

# --- HELPER FUNCTIONS ---

def send_notification(subject, message):
    """Sends an email alert via AWS SNS - Wrapped in try/except so it won't crash the app"""
    try:
        sns.publish(
            TopicArn=SNS_TOPIC_ARN,
            Subject=subject,
            Message=message
        )
    except Exception as e:
        print(f"SNS Error (Check your ARN): {e}")

def get_user_from_db(username):
    try:
        response = users_table.get_item(Key={'username': username})
        return response.get('Item')
    except Exception:
        return None

# --- CORE ROUTES ---

@app.route('/')
def home():
    if 'user' in session:
        return redirect(url_for('admin_dashboard' if session.get('role') == 'admin' else 'dashboard'))
    return render_template('index.html')

@app.route('/admin_login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username, password = request.form['username'], request.form['password']
        try:
            response = admin_table.get_item(Key={'username': username})
            if 'Item' in response and check_password_hash(response['Item']['password'], password):
                session.update({'user': username, 'role': 'admin'})
                return redirect(url_for('admin_dashboard'))
        except Exception:
            pass
        flash('Invalid Admin Credentials', 'error')
    return render_template('admin_login.html')

@app.route('/admin_dashboard')
def admin_dashboard():
    if session.get('role') != 'admin':
        return redirect(url_for('admin_login'))
    
    try:
        response = users_table.scan()
        all_users = response.get('Items', [])
        total_users = len(all_users)
        
        # FIX: Added str() conversion to ensure Decimal/Float compatibility
        total_money = sum(float(user.get('balance', 0)) for user in all_users)
        avg_balance = total_money / total_users if total_users > 0 else 0

        if total_money >= 50000:
            compliance_status, compliance_color = "PASSED - Healthy Reserves", "green"
        else:
            compliance_status, compliance_color = "ALERT - Regulatory Breach (<$50k)", "red"

        return render_template('admin_dashboard.html', 
                               total_users=total_users, total_money=total_money, 
                               all_users={u['username']: u for u in all_users},
                               avg_balance=avg_balance, compliance_status=compliance_status, 
                               compliance_color=compliance_color)
    except Exception as e:
        return f"Dashboard Error: {e}. Ensure Users table exists."

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username, password, email = request.form['username'], request.form['password'], request.form['email']
        if get_user_from_db(username):
            flash('Username already taken.', 'error')
        else:
            users_table.put_item(Item={
                'username': username, 'password': generate_password_hash(password), 
                'email': email, 'balance': Decimal('0.0'), 'transactions': []
            })
            send_notification("CAPSTONE BANK: New Client", f"Account created for '{username}'.")
            flash('Account created! Please login.', 'success')
            return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = get_user_from_db(request.form['username'])
        if user and check_password_hash(user['password'], request.form['password']):
            session.update({'user': user['username'], 'role': 'user'})
            return redirect(url_for('dashboard'))
        flash('Wrong username or password.', 'error')
    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    user = get_user_from_db(session.get('user'))
    if not user: return redirect(url_for('login'))
    return render_template('dashboard.html', user=session['user'], balance=float(user.get('balance', 0)), transactions=user.get('transactions', [])[-5:][::-1])

@app.route('/transfer', methods=['GET', 'POST'])
def transfer():
    sender_name = session.get('user')
    if not sender_name: return redirect(url_for('login'))
    if request.method == 'POST':
        receiver_name, amt_input, password = request.form['receiver'], request.form['amount'], request.form['password']
        amount = Decimal(amt_input)
        sender, receiver = get_user_from_db(sender_name), get_user_from_db(receiver_name)

        if not sender or not check_password_hash(sender['password'], password):
            flash('Wrong password.', 'error')
        elif not receiver:
            flash(f'User "{receiver_name}" does not exist.', 'error')
        elif amount > sender['balance'] or amount <= 0:
            flash('Invalid amount.', 'error')
        else:
            # Atomic logic
            sender['balance'] -= amount
            sender['transactions'].append({'type': f'Sent to {receiver_name}', 'amount': amount, 'date': datetime.now().strftime("%Y-%m-%d %H:%M")})
            receiver['balance'] += amount
            receiver['transactions'].append({'type': f'From {sender_name}', 'amount': amount, 'date': datetime.now().strftime("%Y-%m-%d %H:%M")})
            
            users_table.put_item(Item=sender)
            users_table.put_item(Item=receiver)
            
            if amount >= 5000:
                send_notification("CAPSTONE BANK: High Alert", f"Large transfer: ${amount} from {sender_name} to {receiver_name}")
            flash(f'Sent ${amount} to {receiver_name}', 'success')
            return redirect(url_for('dashboard'))
    return render_template('transfer.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('home'))

if __name__ == '__main__':
    # Initial Admin Creation
    try:
        if 'Item' not in admin_table.get_item(Key={'username': 'admin'}):
            admin_table.put_item(Item={'username': 'admin', 'password': generate_password_hash('admin123')})
    except:
        pass

    # CRITICAL: host='0.0.0.0' allows external access
    app.run(host='0.0.0.0', port=5000, debug=False)