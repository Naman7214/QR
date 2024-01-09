from flask import Flask, render_template, request, redirect, url_for, send_file, jsonify, session, g
import threading
import time
import random
import qrcode
import io
import base64
import sqlite3

app = Flask(__name__)
app.config['DATABASE'] = 'students.db'
app.secret_key = '6NWMu7ewCqm7GX6tbG0hOJmU8QNWZ2A5'

# Initialize attendance_status
attendance_status = {'qr_data': '', 'qr_image': ''}
 

def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(app.config['DATABASE'])
        db.row_factory = sqlite3.Row
    return db


def init_db():
    with app.app_context():
        db = get_db()
        with app.open_resource('schema.sql', mode='r') as f:
            db.cursor().executescript(f.read())
        db.commit()


def close_db(e=None):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()


def query_db(query, args=(), one=False):
    cur = get_db().execute(query, args)
    result = cur.fetchall()
    cur.close()
    column_names = [column[0] for column in cur.description]

    if not result:
        return None

    if one:
        return dict(zip(column_names, result[0]))

    return [dict(zip(column_names, row)) for row in result]


# Function to generate a unique 6-digit key
def generate_unique_key():
    key = ''.join([str(random.randint(0, 9)) for _ in range(6)])
    # print(key)
    # Insert the key into the QR_key table
    db = get_db()
    db.execute('INSERT INTO QR_key (key_field) VALUES (?)', (key,))
    db.commit()

    return key


# Function to generate a QR code
def generate_qr_code(qr_data):
    img = qrcode.make(qr_data)
    img_buffer = io.BytesIO()
    img.save(img_buffer)
    img_str = base64.b64encode(img_buffer.getvalue()).decode('utf-8')
    return img_str


# Function to generate a QR code based on teacher input
def generate_qr_code_from_input(subject_name, time_slot, date):
    key = generate_unique_key()
    qr_data = f"{subject_name}_{time_slot}_{date}_{key}"
    img_str = generate_qr_code(qr_data)

    # Fetch all student records from the students table
    students = query_db('SELECT roll_no, name FROM students')

    # Insert student records into Temp_attendance for the given subject, time slot, and date
    db = get_db()
    for student in students:
        db.execute('INSERT INTO Temp_attendance (rollno, stdname, subject, date, time, attendance) VALUES (?, ?, ?, ?, ?, ?)',
                   (student['roll_no'], student['name'], subject_name, date, time_slot, 0))

    # Commit the changes
    db.commit()

    # Update attendance_status with subject name, time slot, date, and key
    with threading.Lock():
        attendance_status['qr_data'] = qr_data
        attendance_status['subject_name'] = subject_name
        attendance_status['time_slot'] = time_slot
        attendance_status['date'] = date
        attendance_status['key'] = key
        attendance_status['qr_image'] = img_str

    return {'qr_data': qr_data, 'qr_image': img_str}


# Function to generate QR codes in the background
def generate_qr_code_background_input():
    global attendance_status
    lock = threading.Lock()
    with app.app_context():
        while True:
            # Generate a unique QR code data based on the current time
            key = generate_unique_key()

            with lock:
                qr_data = f"{attendance_status.get('subject_name', 'Unknown')}_{attendance_status.get('time_slot', 'Unknown')}_{attendance_status.get('date', 'Unknown')}_{key}"
                img_str = generate_qr_code(qr_data)

                # Update attendance_status
                attendance_status['qr_data'] = qr_data
                attendance_status['key'] = key
                attendance_status['qr_image'] = img_str

                # Insert the key into the QR_key table
                db = get_db()
                db.execute('INSERT INTO QR_key (key_field) VALUES (?)', (key,))
                db.commit()

            time.sleep(20)


# Start a separate thread to generate QR codes in the background
qr_thread = threading.Thread(target=generate_qr_code_background_input)
qr_thread.daemon = True
qr_thread.start()

# Initialize the database
with app.app_context():
    init_db()

# Route to display the QR code on the webpage
@app.route('/')
def index():
    return render_template('index.html', qr_data=attendance_status['qr_data'], qr_image=attendance_status['qr_image'])


# Route to serve the QR code image
@app.route('/qr_image')
def qr_image():
    return send_file(io.BytesIO(base64.b64decode(attendance_status['qr_image'])), mimetype='image/png')


# Route to display the input page for the teacher
@app.route('/input', methods=['GET', 'POST'])
def input():
    if request.method == 'POST':
        subject_name = request.form['subject_name']
        time_slot = request.form['time_slot']
        date = request.form['date']
        result = generate_qr_code_from_input(subject_name, time_slot, date)
        return render_template('index.html', qr_data=result['qr_data'], qr_image=result['qr_image'])
    return render_template('input.html')


# Route to display the registration page for students
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        roll_no = request.form['roll_no']
        name = request.form['name']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        # Check if the password and confirm_password match
        if password != confirm_password:
            return render_template('register.html', error='Passwords do not match')

        # Check if the roll_no is already in the database
        existing_user = query_db('SELECT * FROM students WHERE roll_no = ?', (roll_no,), one=True)
        if existing_user:
            return render_template('register.html', error='Roll number already exists')

        # Insert the new user into the database
        db = get_db()
        db.execute('INSERT INTO students (roll_no, name, password) VALUES (?, ?, ?)', (roll_no, name, password))
        db.commit()

        # Redirect to the login page after successful registration
        return redirect(url_for('login'))

    return render_template('register.html')


# Route to display the login page for students
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        roll_no = request.form['roll_no']
        password = request.form['password']

        user = query_db('SELECT * FROM students WHERE roll_no = ?', (roll_no,), one=True)

        # Check if the user exists and the password is correct
        if user and user['password'] == password:
            # Create a session for the logged-in student
            session['roll_no'] = user['roll_no']
            session['name'] = user['name']

            # Redirect to the QR scanner page after successful login
            return redirect(url_for('qr_scanner'))

        # Incorrect roll number or password
        return render_template('login.html', error='Invalid roll number or password')

    return render_template('login.html')

@app.route('/admin_login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Check if the user is an admin
        admin = query_db('SELECT * FROM Admins WHERE Username = ? AND Password = ?', (username, password), one=True)
        if admin:
            # Create a session for the logged-in admin
            session['admin_username'] = admin['Username']
            session['admin_dept'] = admin['Dept']
            session['admin_class'] = admin['Class']

            # Redirect to the admin dashboard after successful login
            return redirect(url_for('admin_dashboard'))

        # Incorrect username or password
        return render_template('admin_login.html', error='Invalid username or password')

    return render_template('admin_login.html')



@app.route('/qr_scanner')
def qr_scanner():
    # Check if the user is logged in
    if 'roll_no' not in session:
        # Redirect to the login page if not logged in
        return redirect(url_for('login'))

    # User is logged in, render the QR scanner page
    return render_template('qr_scanner.html')


# Route to process the detected QR code on the server
@app.route('/process_qr_code', methods=['POST'])
def process_qr_code():
    data = request.get_json()
    qr_code = data.get('qr_code')

    # Process the QR code and extract information
    qr_parts = qr_code.split('_')

    if len(qr_parts) == 4:
        subject_name, time_slot, date, key = qr_parts

        # Verify the key against the last generated key in QR_key
        last_generated_key = query_db('SELECT key_field FROM QR_key ORDER BY id DESC LIMIT 1 OFFSET 4', one=True)
        if last_generated_key and key == last_generated_key['key_field']:
            # Key is valid, update attendance in Temp_attendance for the logged-in student
            roll_no = session.get('roll_no')
            db = get_db()
            db.execute('UPDATE Temp_attendance SET attendance = 1 WHERE rollno = ? AND subject = ? AND date = ? AND time = ?',
                       (roll_no, subject_name, date, time_slot))
            db.commit()

            # Respond with a success message
            return jsonify({'message': 'QR code processed successfully'})

    # Invalid QR code format or key
    return jsonify({'error': 'Invalid QR code format or key'})


@app.route('/admin_dashboard')
def admin_dashboard():
    # Check if the user is logged in as an admin
    if 'admin_username' not in session:
        # Redirect to the admin login page if not logged in
        return redirect(url_for('admin_login'))

    # Admin is logged in, render the admin dashboard page
    return render_template('admin_dashboard.html')


@app.route('/profile')
def profile():
    name = session.get('name')
    roll_no = session.get('roll_no')
    return jsonify({'username': name, 'roll_no': roll_no})


# Route to logout and end the session
@app.route('/logout')
def logout():
    session.clear()
    return jsonify({'message': 'Logged out successfully'})


if __name__ == '__main__':
    app.run(debug=True)
