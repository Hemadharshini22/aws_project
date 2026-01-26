from flask import Flask, render_template, request, redirect, url_for, session, flash
from datetime import datetime

app = Flask(__name__)
app.secret_key = 'secret_key_123'  # Needed for login sessions

# --- DATABASE (Dictionary) ---
# I added the ADMIN user here so it exists when you start the app.
users_db = {
    "admin": {
        "password": "admin123",
        "email": "admin@capstonebank.com",
        "balance": 1000000.0,  # Admin starts with $1 Million
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

# --- ADMIN ROUTES (NEW) ---

@app.route('/admin_login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        # Check specifically for admin
        if username == 'admin' and users_db.get('admin')['password'] == password:
            session['user'] = 'admin'
            session['role'] = 'admin' # Mark as Admin
            return redirect(url_for('admin_dashboard'))
        else:
            flash('Invalid Admin Credentials', 'error')
            
    return render_template('admin_login.html')

@app.route('/admin_dashboard')
def admin_dashboard():
    # Security: Kick out if not admin
    if session.get('user') != 'admin' or session.get('role') != 'admin':
        return redirect(url_for('admin_login'))
    
    # Calculate totals for the dashboard cards
    total_users = len(users_db) - 1  # Subtract 1 to exclude the admin
    total_money = sum(user['balance'] for user in users_db.values())
    
    return render_template('admin_dashboard.html', 
                           total_users=total_users, 
                           total_money=total_money, 
                           all_users=users_db)

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
            session['role'] = 'user' # Mark as Normal User
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
    # If admin tries to go here, send them to their own dashboard
    if session.get('role') == 'admin':
        return redirect(url_for('admin_dashboard'))

    user = get_logged_in_user()
    if not user: return redirect(url_for('login'))
    
    recent = user['transactions'][-5:][::-1]
    return render_template('dashboard.html', user=session['user'], balance=user['balance'], transactions=recent)

@app.route('/deposit', methods=['GET', 'POST'])
def deposit():
    user = get_logged_in_user()
    if not user: return redirect(url_for('login'))

    if request.method == 'POST':
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
            
    return render_template('deposit.html')

@app.route('/withdraw', methods=['GET', 'POST'])
def withdraw():
    user = get_logged_in_user()
    if not user: return redirect(url_for('login'))

    if request.method == 'POST':
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
            
    return render_template('withdraw.html')

@app.route('/transfer', methods=['GET', 'POST'])
def transfer():
    user = get_logged_in_user()
    if not user: return redirect(url_for('login'))

    if request.method == 'POST':
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
            
            user['balance'] -= amount
            user['transactions'].append({
                'type': f'Transfer to {receiver_username}', 
                'amount': amount, 
                'date': datetime.now().strftime("%Y-%m-%d %H:%M")
            })
            
            receiver['balance'] += amount
            receiver['transactions'].append({
                'type': f'Received from {session["user"]}', 
                'amount': amount, 
                'date': datetime.now().strftime("%Y-%m-%d %H:%M")
            })
            
            flash(f'Successfully sent ${amount} to {receiver_username}', 'success')
            return redirect(url_for('dashboard'))

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