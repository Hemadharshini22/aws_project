from flask import Flask, render_template, request, redirect, url_for, session, flash
from datetime import datetime

app = Flask(__name__)
app.secret_key = 'secret_key_123'  

# --- DATABASE (Dictionary) ---
users_db = {
    "admin": {
        "password": "admin123",
        "email": "admin@skybank.com",
        "balance": 1000000.0,  
        "transactions": []
    }
} 

# --- HELPER: SAFETY CHECK ---
def get_logged_in_user():
    if 'user' not in session:
        return None
    username = session['user']
    if username not in users_db:
        session.clear() 
        return None
    return users_db[username]

# --- ROUTES ---

@app.route('/')
def home():
    if get_logged_in_user():
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
        
        # Check  admin credentials
        if username == 'admin' and users_db.get('admin')['password'] == password:
            session['user'] = 'admin'
            session['role'] = 'admin' 
            return redirect(url_for('admin_dashboard'))
        else:
            flash('Invalid Admin Credentials', 'error')
            
    return render_template('admin_login.html')

@app.route('/admin_dashboard')
def admin_dashboard():
    if session.get('user') != 'admin' or session.get('role') != 'admin':
        return redirect(url_for('admin_login'))
    
    # 1. Calculate Standard Stats 
    total_users = 0
    total_money = 0
    
    for username, data in users_db.items():
        if username == 'admin': continue 
        total_users += 1
        total_money += data['balance']

    # 2. Manager Report Logic 
    avg_balance = total_money / total_users if total_users > 0 else 0

    # 3. Compliance Monitor Logic
    if total_money >= 50000:
        compliance_status = "PASSED - Healthy Reserves"
        compliance_color = "green"
    else:
        compliance_status = "ALERT - Regulatory Breach (<$50k)"
        compliance_color = "red"
    
    return render_template('admin_dashboard.html', 
                           total_users=total_users, 
                           total_money=total_money, 
                           all_users=users_db,
                           avg_balance=avg_balance,             
                           compliance_status=compliance_status, 
                           compliance_color=compliance_color)   

# --- STANDARD USER ROUTES ---

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']
        
        if username in users_db:
            flash('Username already taken.', 'error')
        else:
            # Create new user
            users_db[username] = {
                'password': password,
                'email': email,
                'balance': 0.0,
                'transactions': []
            }
            flash('Account created! Please login.', 'success')
            return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        user = users_db.get(username)
        if user and user['password'] == password:
            session['user'] = username
            session['role'] = 'user' 
            return redirect(url_for('dashboard'))
        else:
            flash('Wrong username or password.', 'error')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('home'))

@app.route('/dashboard')
def dashboard():
    if session.get('role') == 'admin':
        return redirect(url_for('admin_dashboard'))

    user = get_logged_in_user()
    if not user: return redirect(url_for('login'))
    
    # Show last 5 transactions
    recent = user['transactions'][-5:][::-1]
    return render_template('dashboard.html', user=session['user'], balance=user['balance'], transactions=recent)

@app.route('/deposit', methods=['GET', 'POST'])
def deposit():
    user = get_logged_in_user()
    if not user: return redirect(url_for('login'))

    if request.method == 'POST':
        try:
            amount = float(request.form['amount'])
            password = request.form['password']

            if user['password'] != password:
                flash('Wrong password. Deposit failed.', 'error')
            elif amount <= 0:
                flash('Amount must be positive.', 'error')
            else:
                user['balance'] += amount
                txn = {'type': 'Deposit', 'amount': amount, 'date': datetime.now().strftime("%Y-%m-%d %H:%M")}
                user['transactions'].append(txn)
                flash(f'Deposited ${amount}', 'success')
                return redirect(url_for('dashboard'))
        except ValueError:
            flash('Invalid amount entered.', 'error')
            
    return render_template('deposit.html')

@app.route('/withdraw', methods=['GET', 'POST'])
def withdraw():
    user = get_logged_in_user()
    if not user: return redirect(url_for('login'))

    if request.method == 'POST':
        try:
            amount = float(request.form['amount'])
            password = request.form['password']

            if user['password'] != password:
                flash('Wrong password. Withdraw failed.', 'error')
            elif amount > user['balance']:
                flash('Insufficient funds.', 'error')
            elif amount <= 0:
                flash('Amount must be positive.', 'error')
            else:
                user['balance'] -= amount
                txn = {'type': 'Withdrawal', 'amount': amount, 'date': datetime.now().strftime("%Y-%m-%d %H:%M")}
                user['transactions'].append(txn)
                flash(f'Withdrew ${amount}', 'success')
                return redirect(url_for('dashboard'))
        except ValueError:
             flash('Invalid amount entered.', 'error')
            
    return render_template('withdraw.html')

@app.route('/transfer', methods=['GET', 'POST'])
def transfer():
    user = get_logged_in_user()
    if not user: return redirect(url_for('login'))

    if request.method == 'POST':
        try:
            receiver_username = request.form['receiver']
            amount = float(request.form['amount'])
            password = request.form['password']

            if user['password'] != password:
                flash('Wrong password. Transfer failed.', 'error')
            elif amount > user['balance']:
                flash('Insufficient funds.', 'error')
            elif amount <= 0:
                flash('Amount must be positive.', 'error')
            elif receiver_username not in users_db:
                flash(f'User "{receiver_username}" does not exist.', 'error')
            elif receiver_username == session['user']:
                flash('You cannot transfer money to yourself.', 'error')
            else:
                receiver = users_db[receiver_username]
                
                # Deduct from sender
                user['balance'] -= amount
                user['transactions'].append({
                    'type': f'Transfer to {receiver_username}', 
                    'amount': amount, 
                    'date': datetime.now().strftime("%Y-%m-%d %H:%M")
                })
                
                # Add to receiver
                receiver['balance'] += amount
                receiver['transactions'].append({
                    'type': f'Received from {session["user"]}', 
                    'amount': amount, 
                    'date': datetime.now().strftime("%Y-%m-%d %H:%M")
                })
                
                flash(f'Successfully sent ${amount} to {receiver_username}', 'success')
                return redirect(url_for('dashboard'))
        except ValueError:
            flash('Invalid input.', 'error')

    return render_template('transfer.html')

@app.route('/statement')
def statement():
    user = get_logged_in_user()
    if not user: return redirect(url_for('login'))
    return render_template('statement.html', transactions=reversed(user['transactions']))

@app.route('/profile')
def profile():
    user = get_logged_in_user()
    if not user: return redirect(url_for('login'))
    return render_template('profile.html', username=session['user'], email=user['email'])

@app.route('/contact')
def contact():
    return render_template('contact.html')

if __name__ == '__main__':
    app.run(debug=True, port=5000)