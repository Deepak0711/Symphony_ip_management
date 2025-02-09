from flask import Flask, redirect, url_for, render_template, request, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
import csv, io,openpyxl,os
from werkzeug.security import generate_password_hash, check_password_hash
import logging

app = Flask(__name__)
app.secret_key = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'
db = SQLAlchemy(app)

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# User Model
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    role = db.Column(db.String(10), nullable=False)  # 'admin' or 'user'

# Machine Model
class Machine(db.Model):
    ip_address = db.Column(db.String(15), primary_key=True)
    model = db.Column(db.String(100), nullable=False)
    serial_number = db.Column(db.String(100), nullable=False)
    os = db.Column(db.String(100), nullable=False)
    rack_number = db.Column(db.String(100), nullable=False)
    team_name = db.Column(db.String(100), nullable=False)
    user = db.Column(db.String(100), nullable=False)
    owner = db.Column(db.String(100), nullable=False)
    comment = db.Column(db.Text, nullable=True)
    setup_details = db.Column(db.Text, nullable=True)
    num_interfaces = db.Column(db.Integer, nullable=False)
    # New relationship: a machine can have many requests.
    requests = db.relationship('MachineRequest', backref='machine', lazy=True)

# New Model: MachineRequest
class MachineRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    machine_ip = db.Column(db.String(15), db.ForeignKey('machine.ip_address'), nullable=False)
    requester_name = db.Column(db.String(100), nullable=False)
    reason = db.Column(db.Text, nullable=False)

# Load user callback for Flask-Login
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


with app.app_context():
    db.create_all()
    # Check if admin user exists, if not create one
    admin_user = User.query.filter_by(username='admin').first()
    if not admin_user:
        # Get the admin password from environment variables
        admin_password = os.getenv('ADMIN_PASSWORD')
        if not admin_password:
            raise Exception("ADMIN_PASSWORD environment variable not set.")

        # Hash the password
        hashed_password = generate_password_hash(admin_password, method='pbkdf2:sha256', salt_length=16)

        admin_user = User(username='admin', password=hashed_password, role='admin')
        db.session.add(admin_user)
        db.session.commit()
        print("Admin user created with username 'admin'.")


# Routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            flash('Logged in successfully!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Invalid username or password', 'error')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out successfully!', 'success')
    return redirect(url_for('index'))

@app.route('/machines')
def list_machines():
    machines = Machine.query.all()
    return render_template('machines.html', machines=machines)

@app.route('/machine/add', methods=['GET', 'POST'])
@login_required
def add_machine():
    if current_user.role != 'admin':
        flash('You do not have permission to perform this action.', 'error')
        return redirect(url_for('list_machines'))

    if request.method == 'POST':
        ip_address = request.form['ip_address']
        model = request.form['model']
        serial_number = request.form['serial_number']
        os = request.form['os']
        rack_number = request.form['rack_number']
        team_name = request.form['team_name']
        user_field = request.form['user']
        owner = request.form['owner']
        comment = request.form['comment']
        setup_details = request.form['setup_details']
        num_interfaces = request.form['num_interfaces']

        new_machine = Machine(
            ip_address=ip_address,
            model=model,
            serial_number=serial_number,
            os=os,
            rack_number=rack_number,
            team_name=team_name,
            user=user_field,
            owner=owner,
            comment=comment,
            setup_details=setup_details,
            num_interfaces=num_interfaces
        )
        db.session.add(new_machine)
        db.session.commit()
        flash('Machine added successfully!', 'success')
        return redirect(url_for('list_machines'))
    return render_template('add_machine.html')

@app.route('/machine/delete/<string:ip_address>')
@login_required
def delete_machine(ip_address):
    if current_user.role != 'admin':
        flash('You do not have permission to perform this action.', 'error')
        return redirect(url_for('list_machines'))

    machine = Machine.query.get_or_404(ip_address)
    db.session.delete(machine)
    db.session.commit()
    flash('Machine deleted successfully!', 'success')
    return redirect(url_for('list_machines'))

@app.route('/machine/edit/<string:ip_address>', methods=['GET', 'POST'])
@login_required
def edit_machine(ip_address):
    if current_user.role != 'admin':
        flash('You do not have permission to perform this action.', 'error')
        return redirect(url_for('list_machines'))

    machine = Machine.query.get_or_404(ip_address)
    if request.method == 'POST':
        machine.model = request.form['model']
        machine.serial_number = request.form['serial_number']
        machine.os = request.form['os']
        machine.rack_number = request.form['rack_number']
        machine.team_name = request.form['team_name']
        machine.user = request.form['user']
        machine.owner = request.form['owner']
        machine.comment = request.form['comment']
        machine.setup_details = request.form['setup_details']
        machine.num_interfaces = request.form['num_interfaces']
        db.session.commit()
        flash('Machine updated successfully!', 'success')
        return redirect(url_for('list_machines'))
    return render_template('edit_machine.html', machine=machine)

# New route: Request a machine
@app.route('/machine/request/<string:ip_address>', methods=['GET', 'POST'])
def request_machine(ip_address):
    # Optionally prevent admin users from making requests:
    if current_user.is_authenticated and current_user.role == 'admin':
        flash('Admins cannot request machines.', 'error')
        return redirect(url_for('list_machines'))
    machine = Machine.query.get_or_404(ip_address)
    if request.method == 'POST':
        requester_name = request.form['requester_name']
        reason = request.form['reason']
        new_request = MachineRequest(
            machine_ip=machine.ip_address,
            requester_name=requester_name,
            reason=reason
        )
        db.session.add(new_request)
        db.session.commit()
        flash('Machine request submitted successfully!', 'success')
        return redirect(url_for('list_machines'))
    return render_template('request_machine.html', machine=machine)


# New route: Approve a machine request (admin only)
@app.route('/machine/approve_request/<int:request_id>')
@login_required
def approve_request(request_id):
    # Only admin users can approve requests.
    if current_user.role != 'admin':
        flash('You do not have permission to perform this action.', 'error')
        return redirect(url_for('list_machines'))

    # Get the machine request by its id (or 404 if not found)
    machine_request = MachineRequest.query.get_or_404(request_id)

    # Retrieve the corresponding machine
    machine = Machine.query.get_or_404(machine_request.machine_ip)

    # Update the machine's user field to the requester name
    machine.user = machine_request.requester_name

    # Delete the request since it has been approved
    db.session.delete(machine_request)
    db.session.commit()

    flash('Machine request approved successfully!', 'success')
    return redirect(url_for('list_machines'))


# New route: Reject a machine request (admin only)
@app.route('/machine/reject_request/<int:request_id>')
@login_required
def reject_request(request_id):
    # Only admin users can reject requests.
    if current_user.role != 'admin':
        flash('You do not have permission to perform this action.', 'error')
        return redirect(url_for('list_machines'))

    # Retrieve the machine request by its ID (or return 404 if not found)
    machine_request = MachineRequest.query.get_or_404(request_id)

    # Delete the request from the database (rejecting it)
    db.session.delete(machine_request)
    db.session.commit()

    flash('Machine request rejected and deleted successfully!', 'success')
    return redirect(url_for('list_machines'))


# New route: Import machines from a CSV file (admin only)
@app.route('/machine/import_csv', methods=['GET', 'POST'])
@login_required
def import_csv():
    if current_user.role != 'admin':
        flash('You do not have permission to perform this action.', 'error')
        return redirect(url_for('list_machines'))

    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file part in the request.', 'error')
            return redirect(request.url)
        file = request.files['file']
        if file.filename == '':
            flash('No file selected.', 'error')
            return redirect(request.url)

        # Determine file extension
        ext = file.filename.split('.')[-1].lower()
        count = 0

        try:
            if ext == 'csv':
                # Process CSV file
                stream = io.StringIO(file.stream.read().decode("UTF8"), newline=None)
                csv_input = csv.DictReader(stream)
                for row in csv_input:
                    # Skip if a machine with this IP already exists.
                    if Machine.query.get(row['ip_address']):
                        continue
                    new_machine = Machine(
                        ip_address=row['ip_address'],
                        model=row['model'],
                        serial_number=row['serial_number'],
                        os=row['os'],
                        rack_number=row['rack_number'],
                        team_name=row['team_name'],
                        user=row['user'],
                        owner=row['owner'],
                        comment=row.get('comment', None),
                        setup_details=row.get('setup_details', None),
                        alam_comments=row.get('alam_comments', None),
                        num_interfaces=int(row['num_interfaces'])
                    )
                    db.session.add(new_machine)
                    count += 1

            elif ext in ['xlsx', 'xlsm']:
                # Process XLSX file using openpyxl
                in_memory_file = io.BytesIO(file.read())
                workbook = openpyxl.load_workbook(in_memory_file, data_only=True)
                sheet = workbook.active
                # Assume the first row contains headers
                header_row = next(sheet.iter_rows(min_row=1, max_row=1, values_only=True))
                headers = [str(cell).strip() for cell in header_row]

                for row in sheet.iter_rows(min_row=2, values_only=True):
                    row_dict = dict(zip(headers, row))
                    if Machine.query.get(row_dict['ip_address']):
                        continue
                    new_machine = Machine(
                        ip_address=row_dict['ip_address'],
                        model=row_dict['model'],
                        serial_number=row_dict['serial_number'],
                        os=row_dict['os'],
                        rack_number=row_dict['rack_number'],
                        team_name=row_dict['team_name'],
                        user=row_dict['user'],
                        owner=row_dict['owner'],
                        comment=row_dict.get('comment', None),
                        setup_details=row_dict.get('setup_details', None),
                        alam_comments=row_dict.get('alam_comments', None),
                        num_interfaces=int(row_dict['num_interfaces']) if row_dict.get(
                            'num_interfaces') is not None else 0
                    )
                    db.session.add(new_machine)
                    count += 1
            else:
                flash('Unsupported file format. Please upload a CSV or XLSX file.', 'error')
                return redirect(request.url)

            db.session.commit()
            flash(f'{count} machines imported successfully!', 'success')
            return redirect(url_for('list_machines'))
        except Exception as e:
            flash(f'Error importing file: {str(e)}', 'error')
            return redirect(request.url)

    return render_template('import_csv.html')
# Run the application
if __name__ == '__main__':
    app.run(debug=True)
