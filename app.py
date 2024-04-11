from flask import Flask, render_template, redirect, request, url_for, flash, jsonify, session
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, SelectField, BooleanField, HiddenField
from wtforms.validators import DataRequired, Length, EqualTo
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, login_user, login_required, logout_user, current_user, UserMixin
from werkzeug.security import generate_password_hash



import requests




app = Flask(__name__)
app.config['SECRET_KEY'] = 'GOMAAAAAAARUSSSSSS'
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://gomarus:G0marus@172.23.145.240:3306/3dprinten'  # Change this to your database URI
#app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://Gomarus:Gomarus.sto@localhost:3306/3dprinten'  
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)

login_manager.login_view = 'login'
login_manager.init_app(app)



class Login(db.Model, UserMixin):
    userid = db.Column(db.Integer, primary_key=True, autoincrement=True)
    username = db.Column(db.String(255), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    level = db.Column(db.Integer, nullable=False)
    status = db.Column(db.String(50), nullable=False)

    def get_id(self):
        return str(self.userid)
    
class Printers(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    printerid = db.Column(db.String(255), nullable=False)
    merk = db.Column(db.String(255), nullable=False)
    naam = db.Column(db.String(255), nullable=False)
    adres = db.Column(db.String(255), nullable=False)
    poort = db.Column(db.Integer, nullable=False)
    admin_api = db.Column(db.String(255))
    user_api = db.Column(db.String(255))
    status = db.Column(db.Integer, nullable=False)
    
@login_manager.user_loader
def load_user(user_id):
    return Login.query.get(int(user_id))
    

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=20)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Sign Up')
    csrf_token = HiddenField('CSRF Token', validators=[DataRequired()], id='user_csrf_token')
    
class PrinterForm(FlaskForm):
    printerid = StringField('PrinterID', validators=[DataRequired(), Length(min=1)])
    merk = StringField('Merk', validators=[DataRequired(), Length(min=1)])
    naam = StringField('Naam', validators=[DataRequired(), Length(min=1)])
    adres = StringField('Adres', validators=[DataRequired(), Length(min=1)])
    poort = StringField('Port', validators=[DataRequired(), Length(min=1)])
    admin_api = StringField('admin_api', validators=[DataRequired(), Length(min=1)])
    user_api = StringField('user_api', validators=[DataRequired(), Length(min=1)])
    submit = SubmitField('maak printer aan', id='printer_submit')
    csrf_token = HiddenField('CSRF Token', validators=[DataRequired()], id='printer_csrf_token')


class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=20)])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')
    
class UserForm(FlaskForm):
    level = SelectField('Level', choices=[(1, 'User'), (0, 'Admin'),(2, 'Super user')])
    delete = BooleanField('Delete')
    
        
        
def get_printer_data(printer_id):
    # Retrieve printer data from the database based on the printer_id
    printer = Printers.query.filter_by(printerid=printer_id).first()
    if printer:
        return printer.adres, printer.user_api, printer.poort
    else:
        return None, None


@app.route('/')
def index():
    if 'username' in session:
        username = session['username']
        user = Login.query.filter_by(username=username).first()
        return render_template('index.html', username=username, user_level=user.level, logged_in=True)
    else:
        return render_template('index.html',  name=current_user, logged_in=False)
    
@app.route('/home')
def home():
    if current_user.is_authenticated:
        knoppen = [1, 2, 3, 4, 5]  # Replace with your actual button IDs       
        CRprinters = {}  # Dictionary to store printer data
        FLprinters = {}

        for knop in knoppen:
            CRprinter = Printers.query.filter_by(printerid=knop, merk="Creality", status=1).first()
            if CRprinter:
                CRprinters[knop] = CRprinter
                
        for knop in knoppen:
            FLprinter = Printers.query.filter_by(printerid=knop, merk="Flsun").first()
            if FLprinter:
                FLprinters[knop] = FLprinter

        return render_template('home.html', username=current_user.username, FLprinters=FLprinters, CRprinters=CRprinters, user_level=current_user.level, logged_in=True)
    else:
        return render_template('index.html', name=current_user, logged_in=False)
    
@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = Login.query.filter_by(username=form.username.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user)  # Log in the user using Flask-Login
            flash('Het inloggen is gelukt!', 'success')
            return redirect(url_for('home'))
        else:
            flash('Het inloggen is niet gelukt, probeer het opniew.', 'danger')
    return render_template('login.html', form=form)
        

@app.route('/admin_dashboard', methods=['GET', 'POST'])
@login_required
def admin_dashboard():
    userlist = Login.query.all()

    form = RegistrationForm()
    # Handle form submission
    if form.validate_on_submit():
        existing_user = Login.query.filter_by(username=form.username.data).first()

        if existing_user:
            flash('Error: De gebruikersnaam is al in gebruik, kies alstublieft een andere gebruikersnaam.', 'danger')
        else:
            hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
            new_user = Login(username=form.username.data, password=hashed_password, level=2, status='active')

            db.session.add(new_user)
            db.session.commit()

            flash('Het account is aangemaakt! de gebruiker kan nu inloggen.', 'success')

        return redirect(url_for('admin_dashboard'))

    # Handle user updates and deletions
    if request.method == 'POST':
        for item in userlist:
            level_key = f"level_{item.userid}"
            delete_key = f"delete_{item.userid}"

            item.level = int(request.form.get(level_key, 1))
            if request.form.get(delete_key):
                db.session.delete(item)

        # Commit changes after the loop
        db.session.commit()

        # Redirect to refresh the page after handling the form
        return redirect(url_for('admin_dashboard'))
    
    
    return render_template('admin_dashboard.html', form=form, userlist=userlist, username=current_user.username, user_level=current_user.level, logged_in=True) 

@app.route('/print_dashboard', methods=['GET', 'POST'])
def print_dashboard():
    printerlist = Printers.query.all()
    form = PrinterForm()

    if form.validate_on_submit():
        new_printer = Printers(
            printerid=form.printerid.data,
            merk=form.merk.data,
            naam=form.naam.data,
            adres=form.adres.data,
            poort=form.poort.data,
            admin_api=form.admin_api.data,
            user_api=form.user_api.data,
            status=0
            
        )
        db.session.add(new_printer)
        db.session.commit()
        flash('De printer is aangemaakt', 'success')
        return redirect(url_for('print_dashboard'))
    
        # Handle user updates and deletions
    if request.method == 'POST':
        for item in printerlist:
            printerid_key= f"printerid_{item.id}"
            adres_key = f"adres_{item.id}"
            poort_key = f"poort_{item.id}"
            admin_api_key = f"admin_api_{item.id}"
            user_api_key = f"user_api_{item.id}"
            status_key = f"status_{item.id}"
            delete_key = f"delete_{item.id}"

            if request.form.get(delete_key):
                db.session.delete(item)
            else:
                printerid = request.form.get(printerid_key, item.printerid)
                adres= request.form.get(adres_key, item.adres)
                poort= request.form.get(poort_key, item.poort)
                admin_api = request.form.get(admin_api_key, item.admin_api)
                user_api = request.form.get(user_api_key, item.user_api)
                status = request.form.get(status_key, item.status)

                # Update the printer details in the database
                item.printerid = printerid
                item.adres = adres
                item.poort = poort
                item.admin_api = admin_api
                item.user_api = user_api
                item.status = status

        # Commit deletions to the database
        db.session.commit()

        # Commit changes to the database
        db.session.commit()

        # Redirect to refresh the page after handling the form
        return redirect(url_for('print_dashboard'))


    return render_template('print_dashboard.html', form=form, user_level=current_user.level,username=current_user.username, printerlist=printerlist, logged_in=True)

@app.route('/logout', methods=['GET', 'POST'])
def logout():
    # Clear the session to log the user out
    session.clear()
    return redirect(url_for('index'))

@app.route('/printen/<int:printer_id>')
def printen(printer_id):
    
    # Retrieve data from the database based on the printer_id
    address, user_api, poort = get_printer_data(printer_id)
    if address is None:
        return "Printer niet gevonden", 404
    

    # Construct the URL using the address, port, and user_api
    print("URL:", user_api)
    url = f'http://{address}:{poort}/api/printer'
    params = {'history': 'true', 'limit': 2}
    headers = {'X-Api-Key': user_api}
    constructed_url = url + '?' + '&'.join([f"{key}={value}" for key, value in params.items()])
    print("Constructed URL:", constructed_url)
    response = requests.get(constructed_url, headers=headers)

    
    # Check if the request was successful
    if response.status_code == 200:
        printer_info = response.json()
        print("Printer Info:", printer_info)
        # Extract temperature of the bed from the response
        printer_data = printer_info
    else:
        print("Het is niet gelukt om data op te halen")
        printer_data = None

    if response.status_code == 403:
        printer_data = "API niet correct"
        print("De API sleutel is niet correct")
    
    # Render the printen.html template, passing the retrieved data to it
    return render_template('printen.html', constructed_url=constructed_url, printer_id=printer_id,user_api=user_api, address=address, printer_data=printer_data, username=current_user.username, user_level=current_user.level, logged_in=True)
    

@app.route('/restart_octoprint', methods=['POST'])
def printen(printer_id):
    address, user_api, poort = get_printer_data(printer_id)


    url = f'http://{address}:{poort}/api/system/commands/core/restart'
    headers = {'X-Api-Key': user_api}
    response = requests.post(url, headers=headers)
    
    if response.status_code == 204:  # Successful POST request (204 No Content)
        return redirect(url_for('home'))  # Redirect back to the homepage or any other desired page
    else:
        return "Failed to restart OctoPrint"  # Handle error case

    
@app.route('/upload', methods=['POST'])
def upload_file():
    # Check if the request contains file data
    if 'file' not in request.files:
        return jsonify({'error': 'No file part'})

    file = request.files['file']

    # Check if the file name is empty
    if file.filename == '':
        return jsonify({'error': 'No selected file'})

    # You can perform additional checks on the file here if needed

    # Save the file to a specific location
    file.save('static/' + file.filename)

    # Get other form data
    select = request.form.get('select')
    print_val = request.form.get('print')

    # Do something with the other form data if needed

    return jsonify({'message': 'File uploaded successfully'})
    
if __name__ == '__main__':
    db.create_all()
    app.run(debug=True)
