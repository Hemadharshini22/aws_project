from flask import Flask, render_template, request, redirect, url_for, session, flash
from datetime import datetime
import boto3
from decimal import Decimal
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = 'secret_key_123'

# --- AWS CONFIGURATION ---
REGION = 'us-east-1'

# Connect to DynamoDB
try:
    dynamodb = boto3.resource('dynamodb', region_name=REGION)
    users_table = dynamodb.Table('Users')
    admin_table = dynamodb.Table('AdminUsers')
except Exception as e:
    print(f"Error connecting to AWS: {e}")

# --- HELPER FUNCTIONS ---

def get_user_from_db(username):
    try:
        response = users_table.get_item(Key={'username': username})
        return response.get('Item')
    except Exception:
        return None

# --- ROUTES ---

@app.route('/')
def home():
    if 'user' in session:
        return redirect(url_for('admin_dashboard' if session.get('role') == 'admin' else 'dashboard'))
    return render_template('index.html')

# --- ADMIN ROUTES ---

@app.route('/admin_login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        try:
            # Check Admin Table
            response = admin_table.get_item(Key={'username': username})
            if 'Item' in response:
                stored_hash = response['Item']['password']
                if check_password_hash(stored_hash, password):
                    session['user'] = username
                    session['role'] = 'admin'
                    return redirect(url_for('admin_dashboard'))
        except Exception as e:
            print(f"Login Error: {e}")
            
    flash('Invalid Admin Credentials', 'error')
    return render_template('admin_login.html')

@app.route('/admin_dashboard')
def admin_dashboard():
    # Security Check
    if session.get('role') != 'admin':
        return redirect(url_for('admin_login'))
    
    try:
        # 1. Fetch all users from DynamoDB
        response = users_table.scan()
        user_list = response.get('Items', [])
        
        # 2. Calculate Stats
        total_users = len(user_list)
        
        # Convert Decimal to float for calculations
        total_money = sum(float(user.get('balance', 0)) for user in user_list)
        avg_balance = total_money / total_users if total_users > 0 else 0

        # 3. Compliance Check
        if total_money >= 50000:
            compliance_status = "PASSED - Healthy Reserves"
            compliance_color = "green"
        else:
            compliance_status = "ALERT - Regulatory Breach (<$50k)"
            compliance_color = "red"

        # 4. Prepare Data for Template
        # We convert the list to a dictionary {username: user_data} so the HTML loop works correctly
        users_dict = {u['username']: u for u in user_list}

        return render_template('admin_dashboard.html', 
                               total_users=total_users, 
                               total_money=total_money, 
                               all_users=users_dict, 
                               avg_balance=avg_balance, 
                               compliance_status=compliance_status, 
                               compliance_color=compliance_color)
                               
    except Exception as e:
        return f"Dashboard Error: {e}"

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
            # Initialize user in DynamoDB
            users_table.put_item(Item={
                'username': username, 
                'password': generate_password_hash(password), 
                'email': email, 
                'balance': Decimal('0.0'), 
                'transactions': []
            })
            flash('Account created! Please login.', 'success')
            return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = get_user_from_db(request.form['username'])
        if user and check_password_hash(user['password'], request.form['password']):
            session['user'] = user['username']
            session['role'] = 'user'
            return redirect(url_for('dashboard'))
        flash('Wrong username or password.', 'error')
    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    if session.get('role') == 'admin':
        return redirect(url_for('admin_dashboard'))

    user = get_user_from_db(session.get('user'))
    if not user: return redirect(url_for('login'))
    
    # Get last 5 transactions
    txns = user.get('transactions', [])[-5:][::-1]
    
    return render_template('dashboard.html', 
                           user=session['user'], 
                           balance=float(user.get('balance', 0)), 
                           transactions=txns)

@app.route('/deposit', methods=['GET', 'POST'])
def deposit():
    if not session.get('user'): return redirect(url_for('login'))
    
    if request.method == 'POST':
        try:
            amount = Decimal(request.form['amount'])
            user = get_user_from_db(session['user'])
            
            if check_password_hash(user['password'], request.form['password']):
                if amount <= 0:
                    flash('Amount must be positive.', 'error')
                else:
                    user['balance'] += amount
                    user['transactions'].append({
                        'type': 'Deposit', 
                        'amount': amount, 
                        'date': datetime.now().strftime("%Y-%m-%d %H:%M")
                    })
                    users_table.put_item(Item=user)
                    flash(f'Deposited ${amount}', 'success')
                    return redirect(url_for('dashboard'))
            else:
                flash('Incorrect Password', 'error')
        except Exception:
            flash('Error processing deposit', 'error')
    return render_template('deposit.html')

@app.route('/withdraw', methods=['GET', 'POST'])
def withdraw():
    if not session.get('user'): return redirect(url_for('login'))
    
    if request.method == 'POST':
        try:
            amount = Decimal(request.form['amount'])
            user = get_user_from_db(session['user'])
            
            if not check_password_hash(user['password'], request.form['password']):
                flash('Incorrect Password', 'error')
            elif amount > user['balance']:
                flash('Insufficient Funds', 'error')
            elif amount <= 0:
                flash('Amount must be positive', 'error')
            else:
                user['balance'] -= amount
                user['transactions'].append({
                    'type': 'Withdraw', 
                    'amount': amount, 
                    'date': datetime.now().strftime("%Y-%m-%d %H:%M")
                })
                users_table.put_item(Item=user)
                flash(f'Withdrew ${amount}', 'success')
                return redirect(url_for('dashboard'))
        except Exception:
            flash('Error processing withdraw', 'error')
    return render_template('withdraw.html')

@app.route('/transfer', methods=['GET', 'POST'])
def transfer():
    sender_name = session.get('user')
    if not sender_name: return redirect(url_for('login'))
    
    if request.method == 'POST':
        try:
            receiver_name = request.form['receiver']
            amount = Decimal(request.form['amount'])
            password = request.form['password']
            
            sender = get_user_from_db(sender_name)
            receiver = get_user_from_db(receiver_name)

            if not sender or not check_password_hash(sender['password'], password):
                flash('Wrong password.', 'error')
            elif not receiver:
                flash(f'User "{receiver_name}" does not exist.', 'error')
            elif amount > sender['balance'] or amount <= 0:
                flash('Invalid amount.', 'error')
            elif sender_name == receiver_name:
                flash('Cannot transfer to yourself.', 'error')
            else:
                # Update Sender
                sender['balance'] -= amount
                sender['transactions'].append({
                    'type': f'Sent to {receiver_name}', 
                    'amount': amount, 
                    'date': datetime.now().strftime("%Y-%m-%d %H:%M")
                })
                
                # Update Receiver
                receiver['balance'] += amount
                receiver['transactions'].append({
                    'type': f'From {sender_name}', 
                    'amount': amount, 
                    'date': datetime.now().strftime("%Y-%m-%d %H:%M")
                })
                
                users_table.put_item(Item=sender)
                users_table.put_item(Item=receiver)
                
                flash(f'Sent ${amount} to {receiver_name}', 'success')
                return redirect(url_for('dashboard'))
        except Exception:
             flash('Transfer Failed', 'error')
    return render_template('transfer.html')

@app.route('/statement')
def statement():
    user = get_user_from_db(session.get('user'))
    if not user: return redirect(url_for('login'))
    # Show statement page (newest transactions first)
    return render_template('statement.html', transactions=user.get('transactions', [])[::-1])

@app.route('/profile')
def profile():
    user = get_user_from_db(session.get('user'))
    if not user: return redirect(url_for('login'))
    return render_template('profile.html', username=session['user'], email=user['email'])

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('home'))

if __name__ == '__main__':
    # Initial Admin Creation (Run once if table is empty)
    try:
        if 'Item' not in admin_table.get_item(Key={'username': 'admin'}):
            admin_table.put_item(Item={'username': 'admin', 'password': generate_password_hash('admin123')})
    except:
        pass

    app.run(host='0.0.0.0', port=5000, debug=True)